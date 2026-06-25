// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.29;

/// @title CGGMP21 Library
/// @notice Library for verifying CGGMP21 threshold-ECDSA signatures through the
/// Lux on-chain `cggmp21Verify` precompile at
/// `0x0800000000000000000000000000000000000003`.
///
/// @dev DECOMPLECTION. This library does ONE thing: turn a CGGMP21
/// `(threshold, totalSigners, pubkey, signature, hash)` into a boolean by
/// framing the calldata the on-chain precompile expects and staticcalling it
/// under a strict success-word check. It holds no state, enforces no policy,
/// and never reverts on a cryptographic "false". Ownership / threshold policy
/// lives in the Safe; pubkey↔owner binding lives in {SafeCGGMP21Signer} / the
/// account, which commit `keccak256(pubkey)`.
///
/// CRYPTOGRAPHIC IDENTITY. CGGMP21 (`github.com/luxfi/crypto/cggmp21`,
/// <https://eprint.iacr.org/2021/060>) is the Canetti–Gennaro–Goldfeder–
/// Makriyannis–Peled UC-secure t-of-n threshold ECDSA protocol with
/// identifiable aborts. Its verification operation is *literally identical* to
/// single-party secp256k1 ECDSA.Verify: a signature produced by a CGGMP21
/// signing ceremony is a standard `(r, s, v)` ECDSA signature over the message,
/// valid under the aggregated group public key. The precompile therefore
/// recovers the signer from `(r, s, v)` and asserts the recovered key equals the
/// supplied aggregated `pubkey`; the dedicated `0x0800..0003` slot binds the
/// verification to "this came from a CGGMP21 ceremony".
///
/// SOUNDNESS OF `(threshold, totalSigners)`. The precompile checks only the
/// STRUCTURAL constraint `0 < threshold <= totalSigners`; these two integers are
/// advisory metadata. The real cryptographic soundness comes from the standard
/// ECDSA signature recovering to the committed group key, which is DKG-derived
/// from the actual t-of-n configuration. An attacker cannot forge a signature
/// that recovers to the group key without `threshold` honest shares; lying about
/// `(t, n)` does not create a forgery oracle. This matches the precompile's own
/// `threshold == 0 || threshold > totalSigners` rejection.
///
/// WIRE FORMAT (must match `github.com/luxfi/precompile/cggmp21`.Run
/// byte-for-byte — a RAW packed layout, NOT an ABI-encoded call: the precompile
/// reads `input[0:4]` directly as the threshold and does NOT strip a 4-byte
/// function selector):
///
///     threshold:uint32(4) ‖ totalSigners:uint32(4) ‖ pubkey:65 ‖ msgHash:32 ‖ signature:65
///
/// `pubkey` is the uncompressed secp256k1 group key `0x04 ‖ x ‖ y` (65 bytes);
/// `signature` is the ECDSA `r ‖ s ‖ v` (65 bytes, `v ∈ {0, 1}` or `{27, 28}`).
/// The total input is a fixed 170 bytes.
///
/// FAIL-CLOSED. {verify} treats anything other than the precompile's exact
/// success word `bytes32(1)` — revert, wrong-size return, zero word, missing
/// precompile — as `false`. Mirrors `luxfi/safe/contracts/pq/PQVerifier.sol`.
library CGGMP21 {
    /// @notice The canonical on-chain address of the CGGMP21 threshold-ECDSA
    /// verify precompile (Lux Threshold-Signatures range `0x0800`).
    address internal constant PRECOMPILE = 0x0800000000000000000000000000000000000003;

    /// @notice Uncompressed secp256k1 public key length: `0x04 ‖ x ‖ y`.
    uint256 internal constant PUBKEY_LEN = 65;

    /// @notice ECDSA signature length: `r ‖ s ‖ v`.
    uint256 internal constant SIGNATURE_LEN = 65;

    /// @notice Fixed total precompile input length:
    /// threshold(4) + totalSigners(4) + pubkey(65) + msgHash(32) + sig(65).
    uint256 internal constant INPUT_LEN = 170;

    /// @notice Whether `(threshold, totalSigners)` satisfy the precompile's
    /// structural constraint `0 < threshold <= totalSigners`.
    /// @param threshold The minimum number of signers required (t).
    /// @param totalSigners The total number of signers (n).
    /// @return ok True iff the threshold is structurally valid.
    function isValidThreshold(uint32 threshold, uint32 totalSigners) internal pure returns (bool ok) {
        return threshold > 0 && threshold <= totalSigners;
    }

    /// @notice Whether `pubkey` is a structurally-valid uncompressed secp256k1
    /// key: exactly 65 bytes with the `0x04` uncompressed prefix.
    /// @param pubkey The candidate public key bytes.
    /// @return ok True iff the key is 65 bytes and prefixed `0x04`.
    function isValidPubkey(bytes memory pubkey) internal pure returns (bool ok) {
        return pubkey.length == PUBKEY_LEN && pubkey[0] == 0x04;
    }

    /// @notice Verify a CGGMP21 threshold-ECDSA signature over the 32-byte
    /// `hash` against the aggregated `pubkey`, asserting the structural
    /// `(threshold, totalSigners)` metadata.
    /// @dev Rejects up-front on a structurally invalid threshold, a wrong-shaped
    /// public key, or a wrong-length signature (the precompile would reject
    /// these anyway, but the checks keep the framed call canonical). Then frames
    /// the exact raw wire bytes and staticcalls {PRECOMPILE} fail-closed.
    /// @param hash The 32-byte message digest that was signed (the Safe tx hash).
    /// @param threshold The minimum number of signers (t) — advisory metadata.
    /// @param totalSigners The total number of signers (n) — advisory metadata.
    /// @param pubkey The uncompressed secp256k1 aggregated group key (65 bytes).
    /// @param sig The ECDSA signature `r ‖ s ‖ v` (65 bytes).
    /// @return ok True iff the precompile returned the exact success word.
    function verify(bytes32 hash, uint32 threshold, uint32 totalSigners, bytes memory pubkey, bytes memory sig)
        internal
        view
        returns (bool ok)
    {
        if (!isValidThreshold(threshold, totalSigners)) return false;
        if (!isValidPubkey(pubkey)) return false;
        if (sig.length != SIGNATURE_LEN) return false;

        // threshold:uint32(4) ‖ totalSigners:uint32(4) ‖ pubkey(65) ‖ hash(32) ‖ sig(65)
        bytes memory input = abi.encodePacked(threshold, totalSigners, pubkey, hash, sig);
        return _callStrict(input);
    }

    /// @notice Staticcall {PRECOMPILE} with `input`, returning true iff the
    /// call succeeded AND returned exactly the 32-byte word `bytes32(1)`.
    /// @dev Fail-closed on staticcall failure, any `returndatasize != 32`, any
    /// returned word != 1, and a missing precompile (`returndatasize == 0`).
    /// @param input The framed precompile calldata.
    /// @return ok Whether the strict success word was returned.
    function _callStrict(bytes memory input) private view returns (bool ok) {
        assembly ("memory-safe") {
            let success := staticcall(gas(), PRECOMPILE, add(input, 0x20), mload(input), 0x00, 0x20)
            ok := and(success, and(eq(returndatasize(), 0x20), eq(mload(0x00), 1)))
        }
    }
}
