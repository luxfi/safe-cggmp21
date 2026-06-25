// SPDX-License-Identifier: BSD-3-Clause
pragma solidity =0.8.29;

import {CGGMP21} from "./CGGMP21.sol";
import {ISafe} from "./interfaces/ISafe.sol";
import {IERC165, ISafeTransactionGuard} from "./interfaces/ISafeTransactionGuard.sol";

/// @title Safe CGGMP21 Co-Signer
/// @notice A Safe transaction guard that additionally requires every Safe
/// transaction to be co-signed by a committed CGGMP21 threshold-ECDSA key. Add
/// it with `setGuard`; thereafter `execTransaction` reverts unless the appended
/// CGGMP21 co-signature verifies over the Safe-tx hash AND recovers to the
/// committed group key.
///
/// @dev DECOMPLECTION: the guard enforces ONE policy — "a valid CGGMP21
/// co-signature for this owner's key must be present". The cryptographic verify
/// is delegated wholly to {CGGMP21}; pubkey↔owner binding is the committed
/// `keccak256(pubkey)`.
///
/// CO-SIGNATURE LAYOUT. The co-signature is appended to the Safe `signatures`
/// bytes as a self-describing, ABI-encoded `(bytes pubkey, bytes
/// cggmp21Signature)` tuple whose total length is `coSignatureLength`. The guard
/// slices exactly the trailing `coSignatureLength` bytes and `abi.decode`s them
/// — `abi.decode` validates the offsets/lengths and reverts on a malformed tail,
/// failing closed before any precompile call.
contract SafeCGGMP21CoSigner is ISafeTransactionGuard {
    /// @notice The minimum number of signers (t) this co-signer verifies under.
    uint32 private immutable _THRESHOLD;
    /// @notice The total number of signers (n) this co-signer verifies under.
    uint32 private immutable _TOTAL_SIGNERS;
    /// @notice keccak256 of the committed CGGMP21 aggregated public key.
    bytes32 private immutable _PUBKEY_HASH;
    /// @notice The exact byte length of the appended co-signature tuple.
    uint256 private immutable _COSIG_LEN;

    /// @notice The transaction was not co-signed by the committed CGGMP21 key.
    error Unauthorized();
    /// @notice `(threshold, totalSigners)` violate `0 < t <= n`.
    error InvalidThreshold();
    /// @notice The supplied public key is not a valid uncompressed secp256k1 key.
    error InvalidPublicKey();

    /// @param threshold The minimum number of signers required (t).
    /// @param totalSigners The total number of signers (n).
    /// @param pubkey The uncompressed secp256k1 aggregated group key (65 bytes)
    /// to bind this co-signer to.
    constructor(uint32 threshold, uint32 totalSigners, bytes memory pubkey) {
        require(CGGMP21.isValidThreshold(threshold, totalSigners), InvalidThreshold());
        require(CGGMP21.isValidPubkey(pubkey), InvalidPublicKey());
        _THRESHOLD = threshold;
        _TOTAL_SIGNERS = totalSigners;
        _PUBKEY_HASH = keccak256(pubkey);
        // abi.encode(bytes pubkey, bytes sig) = 0x40 head (two offsets) +
        // 0x20 len + ceil32(65) + 0x20 len + ceil32(65), each tail padded to a
        // 32-byte boundary.
        _COSIG_LEN = 0x40 + 0x20 + _ceil32(CGGMP21.PUBKEY_LEN) + 0x20 + _ceil32(CGGMP21.SIGNATURE_LEN);
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) external view virtual override returns (bool) {
        return interfaceId == type(ISafeTransactionGuard).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    /// @notice The expected length of the appended CGGMP21 co-signature tuple.
    function coSignatureLength() external view returns (uint256) {
        return _COSIG_LEN;
    }

    /// @inheritdoc ISafeTransactionGuard
    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures,
        address
    ) external view {
        bytes32 safeTxHash;
        unchecked {
            uint256 nonce = ISafe(msg.sender).nonce() - 1;
            safeTxHash = ISafe(msg.sender).getTransactionHash(
                to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce
            );
        }

        // The co-signature is the trailing `_COSIG_LEN` bytes of `signatures`.
        require(signatures.length >= _COSIG_LEN, Unauthorized());
        bytes calldata coSignature = signatures[signatures.length - _COSIG_LEN:];
        (bytes memory pubkey, bytes memory cggmp21Signature) = abi.decode(coSignature, (bytes, bytes));

        require(keccak256(pubkey) == _PUBKEY_HASH, Unauthorized());
        require(CGGMP21.verify(safeTxHash, _THRESHOLD, _TOTAL_SIGNERS, pubkey, cggmp21Signature), Unauthorized());
    }

    /// @inheritdoc ISafeTransactionGuard
    function checkAfterExecution(bytes32, bool) external pure {}

    /// @notice Rounds `n` up to the next 32-byte boundary.
    function _ceil32(uint256 n) private pure returns (uint256) {
        return (n + 31) & ~uint256(31);
    }
}
