// SPDX-License-Identifier: BSD-3-Clause
pragma solidity =0.8.29;

import {CGGMP21} from "./CGGMP21.sol";
import {IERC4337, PackedUserOperation} from "./interfaces/IERC4337.sol";

/// @title CGGMP21 Account
/// @notice An ERC-4337 account whose user operations are authorised by a
/// committed CGGMP21 threshold-ECDSA key, verified through the `cggmp21Verify`
/// precompile.
///
/// @dev BINDING. The account commits `(threshold, totalSigners,
/// keccak256(pubkey))` at construction. The user-operation signature carries the
/// full aggregated public key and CGGMP21 signature; the key is re-hashed
/// against the commitment, then the signature is verified over `userOpHash`.
/// This pins the account to a SPECIFIC group key.
///
/// REPLAY. `userOpHash` is bound by the EntryPoint to this account, the chain id
/// and the nonce, so a CGGMP21 signature over it authorises exactly one
/// operation.
///
/// SIGNATURE PAYLOAD: `abi.encode(bytes pubkey, bytes cggmp21Signature)`.
contract CGGMP21Account is IERC4337 {
    /// @notice The supported ERC-4337 entry point contract.
    address private immutable _ENTRY_POINT;
    /// @notice The minimum number of signers (t) this account verifies under.
    uint32 private immutable _THRESHOLD;
    /// @notice The total number of signers (n) this account verifies under.
    uint32 private immutable _TOTAL_SIGNERS;
    /// @notice keccak256 of the committed CGGMP21 aggregated public key.
    bytes32 private immutable _PUBKEY_HASH;

    /// @notice Attempt to call a function reserved for the entry point.
    error UnsupportedEntryPoint();
    /// @notice `(threshold, totalSigners)` violate `0 < t <= n`.
    error InvalidThreshold();
    /// @notice The supplied public key is not a valid uncompressed secp256k1 key.
    error InvalidPublicKey();

    /// @param entryPoint The ERC-4337 entry point contract.
    /// @param threshold The minimum number of signers required (t).
    /// @param totalSigners The total number of signers (n).
    /// @param pubkey The uncompressed secp256k1 aggregated group key (65 bytes)
    /// to bind this account to.
    constructor(address entryPoint, uint32 threshold, uint32 totalSigners, bytes memory pubkey) {
        require(CGGMP21.isValidThreshold(threshold, totalSigners), InvalidThreshold());
        require(CGGMP21.isValidPubkey(pubkey), InvalidPublicKey());
        _ENTRY_POINT = entryPoint;
        _THRESHOLD = threshold;
        _TOTAL_SIGNERS = totalSigners;
        _PUBKEY_HASH = keccak256(pubkey);
    }

    receive() external payable {}

    /// @notice Function must be called by the entry point.
    modifier onlyEntryPoint() {
        require(msg.sender == _ENTRY_POINT, UnsupportedEntryPoint());
        _;
    }

    /// @inheritdoc IERC4337
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        if (missingAccountFunds != 0) {
            assembly ("memory-safe") {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }

        (bytes memory pubkey, bytes memory cggmp21Signature) = abi.decode(userOp.signature, (bytes, bytes));
        if (keccak256(pubkey) != _PUBKEY_HASH) return 1;
        return CGGMP21.verify(userOpHash, _THRESHOLD, _TOTAL_SIGNERS, pubkey, cggmp21Signature) ? 0 : 1;
    }

    /// @notice Execute a transaction.
    /// @param target The call target.
    /// @param value The native token value to send.
    /// @param data The call data.
    function execute(address target, uint256 value, bytes calldata data) external onlyEntryPoint {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, data.offset, data.length)

            if iszero(call(gas(), target, value, ptr, data.length, 0, 0)) {
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
        }
    }
}
