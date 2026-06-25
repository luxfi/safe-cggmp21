> [!WARNING]
> Code in this repository is not audited and may contain serious security holes. Use at your own risk.

# Safe + CGGMP21

This repository brings **CGGMP21** threshold-ECDSA signatures to the
[Safe](https://safe.global) smart account on the Lux C-Chain EVM. CGGMP21 is the
Canetti–Gennaro–Goldfeder–Makriyannis–Peled UC-secure t-of-n threshold ECDSA
protocol (eprint.iacr.org/2021/060). A CGGMP21 signing ceremony emits a
**standard `(r, s, v)` secp256k1 ECDSA signature** that is valid under the
aggregated group public key — byte-for-byte indistinguishable from a single-party
ECDSA signature.

Unlike `safe-frost` — which ships a self-contained secp256k1 Schnorr verifier in
Solidity — CGGMP21 verification is performed by the on-chain **`cggmp21Verify`
precompile at `0x0800000000000000000000000000000000000003`** (the Lux
Threshold-Signatures `0x0800` range). The Solidity in this repository is a thin,
decomplected adapter: it frames the precompile's exact calldata, staticcalls it
under a strict success-word check, and binds the verified key to a Safe owner.

`safe-cggmp21` supports the same three use cases as `safe-frost`:

- as a Safe **signer** (an EIP-1271 owner — SafeCGGMP21Signer)
- as a Safe **co-signer** (a transaction guard — SafeCGGMP21CoSigner)
- as an **ERC-4337 account** (CGGMP21Account)

## Precompile

| Field | Value |
| --- | --- |
| Address | `0x0800000000000000000000000000000000000003` |
| Verify ABI (raw wire format) | `threshold:uint32(4) ‖ totalSigners:uint32(4) ‖ pubkey:65 ‖ msgHash:bytes32(32) ‖ signature:65` |
| `pubkey` | uncompressed secp256k1 group key `0x04 ‖ x ‖ y` (65 bytes) |
| `signature` | ECDSA `r ‖ s ‖ v` (65 bytes, `v ∈ {0, 1}` or `{27, 28}`) |
| Return value | 32-byte word: `bytes32(1)` iff valid, `bytes32(0)` otherwise (never reverts on a cryptographic false) |
| Reference implementation | [`github.com/luxfi/precompile/cggmp21`](https://github.com/luxfi/precompile/cggmp21) |

The "message" for every Safe use is the 32-byte Safe-transaction hash (or the
ERC-4337 `userOpHash`), which is EIP-712-bound to the Safe address, chain id and
nonce — so a signature authorises exactly one Safe / chain / nonce.

> [!NOTE]
> `(threshold, totalSigners)` is **advisory metadata**. The precompile checks only
> the structural constraint `0 < threshold <= totalSigners`; soundness comes
> entirely from a valid ECDSA signature recovering to the committed,
> DKG-derived group key. Lying about `(t, n)` does not create a forgery oracle —
> an attacker still cannot produce a signature that recovers to the group key
> without the honest shares.

> [!IMPORTANT]
> The precompile reads its calldata as a **raw packed layout**, not an
> ABI-encoded function call — there is no 4-byte selector. `CGGMP21.sol` frames the
> bytes exactly as the Go `Run()` parses them (it reads `input[0:4]` directly as
> the threshold). Sending an ABI-encoded call (with a selector) would misalign
> every field.

## Contracts

- **`contracts/CGGMP21.sol`** — the verifier library. One function, `verify(...)`,
  that frames `(threshold, totalSigners)`, the uncompressed public key, the
  32-byte hash and the `(r, s, v)` signature into the precompile's wire format and
  strict-staticcalls `0x0800…0003`. Holds no state and enforces no policy
  (decomplected: dispatch only). Rejects up-front on a structurally invalid
  threshold, a wrong-shaped public key, or a wrong-length signature.
- **`contracts/SafeCGGMP21Signer.sol`** — an EIP-1271 validator that makes a
  single CGGMP21 group key a first-class Safe owner. Commit the key once via
  `addOwnerWithThreshold`; the Safe's `checkNSignatures` validates this owner's
  slice through the `v = 0` contract-signature path. M-of-N thresholds mixing
  ECDSA, secp256r1 and CGGMP21 owners work natively.
- **`contracts/SafeCGGMP21CoSigner.sol`** — a Safe transaction guard requiring
  every `execTransaction` to additionally carry a valid CGGMP21 co-signature.
- **`contracts/CGGMP21Account.sol`** — an ERC-4337 account authorised by a
  committed CGGMP21 key.

### Key binding

An owner / account commits `(threshold, totalSigners, keccak256(pubkey))` at
construction. All three are `immutable`, so the validators are stateless `view`
functions and side-step the Safe's state-changing-validator guard. The full
65-byte key is supplied at verify time inside the signature blob and re-hashed
against the commitment, closing the "attacker supplies an arbitrary key" attack
via second-preimage resistance — and pinning the owner / account to a SPECIFIC
group key.

### Signature payload

The contract-signature / userOp signature payload is
`abi.encode(bytes pubkey, bytes cggmp21Signature)` — a standard ABI `(bytes, bytes)`
tuple of the uncompressed secp256k1 group key (65 bytes) and the `(r, s, v)`
ECDSA signature (65 bytes).

## Building & testing

```sh
forge build
forge test
```

The tests prove `verify()` against a **real known-answer-test (KAT) vector** — a
2-of-3 CGGMP21 ceremony signature whose `(r, s, v)` recovers to the aggregated
group key. The KAT was generated by `lux/precompile/cmd/safekatdump` and
independently **proven to verify against the real Go precompile** by
`lux/precompile/cmd/safekatverify`, so the bytes the Solidity frames are known to
be accepted on-chain.

Because the precompile is a luxd-native Go precompile (absent from a stock
Foundry EVM), the tests install a mock at `0x0800…0003` via `vm.etch` whose sole
job is to assert **calldata-framing conformance**: it returns the success word
iff the incoming calldata is byte-for-byte identical to the proven KAT input. Any
drift in the wire format (field order, length-prefix widths, an accidental ABI
selector) changes the calldata and the test fails. The headline test is
`CGGMP21.t.sol::test_CalldataFramingMatchesPrecompileABI`.

The fixture lives at `tests/kat.json`.

## Integration with the Lux ecosystem

This package is part of the Lux blockchain ecosystem.

- GitHub: https://github.com/luxfi
- Docs: https://docs.lux.network
- Sibling PQ Safe variants: `luxfi/safe-pulsar` (ML-DSA), `luxfi/safe-magnetar`
  (SLH-DSA), `luxfi/safe-corona` (Ring-LWE)
- Verifier precompile family: `luxfi/precompile`
