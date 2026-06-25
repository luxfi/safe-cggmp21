// SPDX-License-Identifier: BSD-3-Clause
pragma solidity =0.8.29;

import {CGGMP21} from "./CGGMP21.sol";
import {IERC1271, ILegacyERC1271} from "./interfaces/IERC1271.sol";

/// @title Safe CGGMP21 Signer
/// @notice Safe smart-account owner that verifies CGGMP21 threshold-ECDSA
/// signatures through the `cggmp21Verify` precompile, making a single CGGMP21
/// aggregated group key a first-class Safe owner via EIP-1271.
///
/// @dev ONE key, ONE owner. The owner commits to a single
/// `(threshold, totalSigners, pubKeyHash)` triple at construction; all three are
/// `immutable`, so the contract holds NO mutable storage and `isValidSignature`
/// is a pure `view` (side-stepping the Safe's state-changing-EIP-1271-validator
/// guard entirely).
///
/// BINDING. We commit only `keccak256(pubkey)`, not the 65-byte key — one
/// 32-byte immutable, and an attacker cannot present a different key whose
/// keccak256 matches (second-preimage resistance). The full key is supplied at
/// verify time inside the signature blob and re-hashed against the commitment,
/// closing the "attacker supplies an arbitrary public key" attack. The threshold
/// metadata `(t, n)` is additionally pinned.
///
/// REPLAY. The Safe passes the EIP-712 Safe-transaction hash, bound to this
/// Safe / chain / nonce, so a CGGMP21 signature over it is valid for exactly one
/// Safe / chain / nonce.
///
/// SIGNATURE PAYLOAD: `abi.encode(bytes pubkey, bytes cggmp21Signature)`.
contract SafeCGGMP21Signer is IERC1271, ILegacyERC1271 {
    /// @notice The minimum number of signers (t) this owner verifies under.
    uint32 private immutable _THRESHOLD;
    /// @notice The total number of signers (n) this owner verifies under.
    uint32 private immutable _TOTAL_SIGNERS;
    /// @notice keccak256 of the committed CGGMP21 aggregated public key.
    bytes32 private immutable _PUBKEY_HASH;

    /// @notice `(threshold, totalSigners)` violate `0 < t <= n`.
    error InvalidThreshold();
    /// @notice The supplied public key is not a valid uncompressed secp256k1 key.
    error InvalidPublicKey();

    /// @param threshold The minimum number of signers required (t).
    /// @param totalSigners The total number of signers (n).
    /// @param pubkey The uncompressed secp256k1 aggregated group key (65 bytes)
    /// to bind this owner to.
    constructor(uint32 threshold, uint32 totalSigners, bytes memory pubkey) {
        require(CGGMP21.isValidThreshold(threshold, totalSigners), InvalidThreshold());
        require(CGGMP21.isValidPubkey(pubkey), InvalidPublicKey());
        _THRESHOLD = threshold;
        _TOTAL_SIGNERS = totalSigners;
        _PUBKEY_HASH = keccak256(pubkey);
    }

    /// @notice The committed public-key hash (for off-chain reference / tooling).
    function pubKeyHash() external view returns (bytes32) {
        return _PUBKEY_HASH;
    }

    /// @notice Checks if the given signature is valid for the given message.
    /// @param message The message to be verified (the Safe tx hash).
    /// @param signature `abi.encode(bytes pubkey, bytes cggmp21Signature)`.
    /// @return ok Whether or not the signature is valid.
    function _isValidSignature(bytes32 message, bytes calldata signature) public view returns (bool ok) {
        (bytes memory pubkey, bytes memory cggmp21Signature) = abi.decode(signature, (bytes, bytes));
        if (keccak256(pubkey) != _PUBKEY_HASH) return false;
        return CGGMP21.verify(message, _THRESHOLD, _TOTAL_SIGNERS, pubkey, cggmp21Signature);
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 message, bytes calldata signature) public view returns (bytes4 magicValue) {
        if (_isValidSignature(message, signature)) {
            magicValue = IERC1271.isValidSignature.selector;
        }
    }

    /// @inheritdoc ILegacyERC1271
    function isValidSignature(bytes memory message, bytes calldata signature) public view returns (bytes4 magicValue) {
        if (_isValidSignature(keccak256(message), signature)) {
            magicValue = ILegacyERC1271.isValidSignature.selector;
        }
    }
}
