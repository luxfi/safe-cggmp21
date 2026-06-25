# safe-cggmp21

## Overview

> [!WARNING]
> Code in this repository is not audited and may contain serious security holes. Use at your own risk.

`safe-cggmp21` integrates **CGGMP21** (Canetti–Gennaro–Goldfeder–Makriyannis–Peled
UC-secure t-of-n threshold ECDSA) with the Safe smart account by calling the
on-chain `cggmp21Verify` precompile at
`0x0800000000000000000000000000000000000003`. A CGGMP21 ceremony emits a standard
`(r, s, v)` secp256k1 ECDSA signature valid under the aggregated group key. It
mirrors the structure of `safe-frost` (verifier library + Safe signer/co-signer +
ERC-4337 account + interfaces + Foundry tests), but the cryptographic
verification is delegated to a luxd-native precompile rather than implemented in
Solidity.

## Package Information

- **Type**: solidity (Foundry) + rust workspace stub
- **Repository**: github.com/luxfi/safe-cggmp21
- **Precompile**: `0x0800000000000000000000000000000000000003` (Lux Threshold-Signatures `0x0800` range)
- **Verify wire format**: `threshold:uint32(4) ‖ totalSigners:uint32(4) ‖ pubkey:65 ‖ msgHash:bytes32(32) ‖ signature:65`
- **pubkey**: uncompressed secp256k1 `0x04 ‖ x ‖ y` (65 bytes); **signature**: ECDSA `r ‖ s ‖ v` (65 bytes)
- **Reference precompile**: github.com/luxfi/precompile/cggmp21

## Directory Structure

```
.
contracts            CGGMP21.sol verifier + SafeCGGMP21Signer/CoSigner + CGGMP21Account
contracts/interfaces ISafe / ISafeTransactionGuard / IERC1271 / IERC4337 / IERC165
lib/forge-std        vendored forge-std for `forge test`
tests                CGGMP21.t.sol (KAT + framing + reject suite)
tests/kat.json       real known-answer-test vector (proven vs the Go precompile)
```

## Key Files

- `contracts/CGGMP21.sol` — the decomplected verifier library (frame + strict staticcall).
- `tests/CGGMP21.t.sol` — `test_CalldataFramingMatchesPrecompileABI` pins the wire format.
- `foundry.toml` — solc 0.8.29, via-IR, `fs_permissions` for `tests/kat.json`.

## Design notes (Hickey-simple, decomplected)

- **One concern per place.** CGGMP21.sol does ONLY calldata-framing + strict
  staticcall. Key↔owner binding lives in the Safe wrappers; threshold/ownership
  policy lives in the Safe itself. The `verify` signature never changes when a
  new scheme is added — each scheme is its own orthogonal slot.
- **`(t, n)` is advisory.** The precompile checks only `0 < threshold <=
  totalSigners`; soundness comes from a valid ECDSA signature recovering to the
  committed DKG-derived group key. Lying about `(t, n)` does not create a forgery
  oracle.
- **Fail-closed.** A valid result is ONLY: staticcall success AND
  `returndatasize == 32` AND the returned word `== 1`. Revert, wrong-size
  return, zero word, or a missing precompile are all `false`. Mirrors
  `luxfi/safe/contracts/pq/PQVerifier.sol::_callStrict`.
- **Raw wire, no selector.** The precompile parses a raw packed layout; the
  Solidity must NOT prepend an ABI function selector.

## Build & Test

```sh
forge build
forge test
```

## Regenerating the KAT fixture

```sh
cd ../precompile
SDKROOT=$(xcrun --show-sdk-path) CGO_ENABLED=1 go run ./cmd/safekatdump   > /tmp/safe_kats.json
SDKROOT=$(xcrun --show-sdk-path) CGO_ENABLED=1 go run ./cmd/safekatverify < /tmp/safe_kats.json   # asserts each KAT verifies on the real precompile
```

---

*Auto-generated for AI assistants. Mirrors the safe-frost template.*
