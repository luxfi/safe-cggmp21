// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {CGGMP21} from "contracts/CGGMP21.sol";

/// @notice A stand-in for the on-chain `cggmp21Verify` precompile
/// (`0x0800..0003`), used in `forge test` where the Go precompile is not present.
///
/// @dev GROUND-TRUTH ABI CONFORMANCE. This mock does NOT re-implement
/// threshold ECDSA. It asserts the *calldata framing*: it returns the
/// precompile's exact success word `bytes32(1)` iff the incoming calldata is
/// byte-for-byte equal to a reference `input` blob whose keccak256 is stored in
/// slot 0. That blob is a real Known-Answer-Test vector produced by
/// `precompile/cmd/safekatdump` (a genuine secp256k1 ECDSA signature under a
/// 2-of-3 CGGMP21 group key), independently *proven to verify against the real
/// Go precompile* by `precompile/cmd/safekatverify`. Therefore: if
/// {CGGMP21.verify}'s framed calldata matches this blob, the real precompile
/// would accept it too; any drift in the RAW wire layout (field order, an
/// accidental ABI selector, wrong pubkey/sig widths) changes the calldata and
/// this mock returns zero — failing the test. The expected hash is injected via
/// `vm.store` after `etch`, so the same deployed code can serve any KAT.
contract MockCGGMP21Precompile {
    fallback(bytes calldata input) external returns (bytes memory) {
        bytes32 expected;
        assembly {
            expected := sload(0)
        }
        bool ok = keccak256(input) == expected;
        return abi.encode(ok ? bytes32(uint256(1)) : bytes32(0));
    }
}

contract CGGMP21Test is Test {
    // KAT components loaded from tests/kat.json (real vector, proven against
    // the Go precompile by safekatverify).
    uint32 internal threshold;
    uint32 internal parties;
    bytes internal pubkey;
    bytes32 internal msgHash;
    bytes internal sig;
    bytes internal expectedInput;

    function setUp() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/tests/kat.json"));
        threshold = uint32(vm.parseJsonUint(json, ".threshold"));
        parties = uint32(vm.parseJsonUint(json, ".parties"));
        pubkey = vm.parseJsonBytes(json, ".pubkey");
        msgHash = bytes32(vm.parseJsonBytes(json, ".msgHash"));
        sig = vm.parseJsonBytes(json, ".sig");
        expectedInput = vm.parseJsonBytes(json, ".input");

        // Install the mock at the real precompile address and pin the expected
        // calldata hash.
        vm.etch(CGGMP21.PRECOMPILE, type(MockCGGMP21Precompile).runtimeCode);
        vm.store(CGGMP21.PRECOMPILE, bytes32(uint256(0)), keccak256(expectedInput));
    }

    /// @notice The library frames calldata that byte-matches the KAT input the
    /// real precompile accepts, so {CGGMP21.verify} returns true.
    function test_Verify_KAT() public view {
        assertTrue(CGGMP21.verify(msgHash, threshold, parties, pubkey, sig), "CGGMP21 KAT must verify");
    }

    /// @notice Independent, self-contained proof the library frames the
    /// precompile calldata EXACTLY as the Go `Run()` parses it — a RAW packed
    /// layout with NO ABI selector:
    ///   threshold:uint32(4) || totalSigners:uint32(4) || pubkey(65) || msgHash(32) || sig(65)
    function test_CalldataFramingMatchesPrecompileABI() public view {
        bytes memory framed = abi.encodePacked(threshold, parties, pubkey, msgHash, sig);
        assertEq(keccak256(framed), keccak256(expectedInput), "framing must equal precompile wire bytes");
        assertEq(framed.length, expectedInput.length, "framed length must equal precompile input length");
        // 4 (t) + 4 (n) + 65 (pubkey) + 32 (msgHash) + 65 (sig) = 170.
        assertEq(framed.length, 4 + 4 + 65 + 32 + 65, "CGGMP21 input size");
        assertEq(framed.length, CGGMP21.INPUT_LEN, "CGGMP21.INPUT_LEN");
    }

    /// @notice A tampered signature changes the calldata, so the precompile
    /// (and thus {CGGMP21.verify}) rejects it — fail-closed.
    function test_Verify_RejectsTamperedSignature() public view {
        bytes memory bad = bytes.concat(sig);
        bad[10] ^= 0xFF;
        assertFalse(CGGMP21.verify(msgHash, threshold, parties, pubkey, bad), "tampered sig must not verify");
    }

    /// @notice A wrong message changes the calldata, so verification fails.
    function test_Verify_RejectsWrongMessage() public view {
        bytes32 wrong = keccak256("not the signed message");
        assertFalse(CGGMP21.verify(wrong, threshold, parties, pubkey, sig), "wrong message must not verify");
    }

    /// @notice A different public key changes the calldata, so verification fails.
    function test_Verify_RejectsWrongPubkey() public view {
        bytes memory otherPk = bytes.concat(pubkey);
        otherPk[1] ^= 0xFF;
        assertFalse(CGGMP21.verify(msgHash, threshold, parties, otherPk, sig), "wrong pubkey must not verify");
    }

    /// @notice A structurally invalid threshold (t > n, or t == 0) is rejected
    /// before any precompile call.
    function test_Verify_RejectsBadThreshold() public view {
        assertFalse(CGGMP21.verify(msgHash, 5, 3, pubkey, sig), "t > n must not verify");
        assertFalse(CGGMP21.verify(msgHash, 0, 3, pubkey, sig), "t == 0 must not verify");
    }

    /// @notice A wrong-length public key is rejected before any precompile call.
    function test_Verify_RejectsWrongPubkeyLength() public view {
        bytes memory shortPk = new bytes(pubkey.length - 1);
        assertFalse(CGGMP21.verify(msgHash, threshold, parties, shortPk, sig), "short pubkey must not verify");
    }

    /// @notice A public key without the 0x04 uncompressed prefix is rejected.
    function test_Verify_RejectsNonUncompressedPubkey() public view {
        bytes memory badPrefix = bytes.concat(pubkey);
        badPrefix[0] = 0x02; // compressed-style prefix on a 65-byte blob
        assertFalse(CGGMP21.verify(msgHash, threshold, parties, badPrefix, sig), "non-0x04 prefix must not verify");
    }

    /// @notice A wrong-length signature is rejected before any precompile call.
    function test_Verify_RejectsWrongSignatureLength() public view {
        bytes memory shortSig = new bytes(64);
        assertFalse(CGGMP21.verify(msgHash, threshold, parties, pubkey, shortSig), "short sig must not verify");
    }

    /// @notice Strict success-word check: a precompile that returns a non-1
    /// word is treated as failure.
    function test_Verify_FailClosedOnNonOneWord() public {
        // Re-pin to a hash that the framed calldata will NOT match.
        vm.store(CGGMP21.PRECOMPILE, bytes32(uint256(0)), keccak256("never matches"));
        assertFalse(CGGMP21.verify(msgHash, threshold, parties, pubkey, sig), "non-success word must be false");
    }

    /// @notice The published precompile address is the canonical CGGMP21 slot in
    /// the Lux Threshold-Signatures range.
    function test_PrecompileAddress() public pure {
        assertEq(CGGMP21.PRECOMPILE, address(0x0800000000000000000000000000000000000003));
    }

    /// @notice Threshold validity helper.
    function test_IsValidThreshold() public pure {
        assertTrue(CGGMP21.isValidThreshold(2, 3));
        assertTrue(CGGMP21.isValidThreshold(3, 3));
        assertFalse(CGGMP21.isValidThreshold(0, 3));
        assertFalse(CGGMP21.isValidThreshold(4, 3));
    }

    /// @notice Public-key validity helper: 65 bytes with the 0x04 prefix.
    function test_IsValidPubkey() public view {
        assertTrue(CGGMP21.isValidPubkey(pubkey));
        bytes memory shortPk = new bytes(64);
        assertFalse(CGGMP21.isValidPubkey(shortPk));
        bytes memory badPrefix = bytes.concat(pubkey);
        badPrefix[0] = 0x03;
        assertFalse(CGGMP21.isValidPubkey(badPrefix));
    }
}
