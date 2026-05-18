# CLAUDE.md — QLSA Codebase Guide

## Project Overview

QLSA aggregates N ML-DSA-65 (FIPS 204) post-quantum signatures into a single
Circle STARK proof (~90–200 KB) for O(1) on-chain verification.

**Research prototype — not production-ready.**

## Repository Structure

```
core/           ML-DSA-65 keys, signing, Merkle tree, batch creation
stark_stwo/     Rust: Stwo Circle STARK prover + ML-DSA-65 verifier (PyO3 ext)
stark/          Python wrappers: prove_batch, prove_mldsa_batch, witness pipeline V4–V22
aggregator/     Mempool, Batcher, AggregatorNode, FastAPI HTTP API
contracts/      Solidity: BatchRegistryV2, QLSAVerifierV4, CM31.sol, QM31.sol, MerkleVerifier.sol
sdk/python/     Python SDK: LocalClient, HttpClient, Wallet, WitnessStatus
sdk/js/         TypeScript SDK: AggregatorClient, types
testnet/        e2e.py, deploy.sh, submit.py, monitor.py
tests/          Python test suite (pytest)
benchmarks/     bench_core.py, bench_stark.py, bench_poly_circuits.py, bench_witnesses.py
```

## Key Commands

```bash
# Run all Python tests (~243 passing when PyO3 ext installed)
pytest tests/ -v

# Run only tests that do NOT need the PyO3 extension
pytest tests/ --ignore=tests/test_stark_stwo.py -v

# Type check (CI scope)
mypy core/ aggregator/ --strict --ignore-missing-imports --exclude 'aggregator/api'

# Build and install the Rust PyO3 extension (required for STARK tests)
cd stark_stwo && maturin develop --features python --release && cd ..

# Run Rust tests (210 passing, 85 ignored slow STARK integration tests)
cargo +nightly-2025-07-01 test --manifest-path stark_stwo/Cargo.toml

# Run Rust tests including slow STARK integration tests
cargo +nightly-2025-07-01 test --manifest-path stark_stwo/Cargo.toml -- --include-ignored

# Run Solidity tests
cd contracts && npx hardhat test

# Run TypeScript SDK tests
cd sdk/js && npm test

# E2E dry-run (no blockchain required)
python -m testnet.e2e --txs 8 --dry-run
```

## Core Invariants

| Constant | Value | Source |
|----------|-------|--------|
| Q (ML-DSA modulus) | 8 380 417 | FIPS 204 §4 |
| N (poly degree) | 256 | FIPS 204 §4 |
| K / L (ML-DSA-65) | 6 / 5 | FIPS 204 §4 |
| D (t1 shift) | 13 | FIPS 204 §4 |
| GAMMA1 | 2^19 | ML-DSA-65 |
| NORM_BOUND | 524 092 | γ₁ − β |
| OMEGA | 55 | ML-DSA-65 max hint weight |
| LAMBDA_BYTES (c̃) | 48 bytes | ML-DSA-65 |
| onchain_commitment | 16 bytes | Blake2s(proof[:32] ∥ c_tilde[:32])[:16] |
| V22 STARK columns | 3,217 | 649+1523+295+649+24+15+61 main + 1 preproc |

## Important Modules

### `stark/prover.py`
- `prove_batch(batch)` → `ProofResult` — hash-chain STARK proof
- `prove_mldsa_batch(entries)` → `MldsaBatchResult` — batch ML-DSA verify + STARK
- `prove_mldsa_sig_witness_stark(pk, msg, sig)` → `MldsaWitnessResult` — full witness pipeline
- `verify_mldsa_witness_stark(result)` → `bool`
- `verify_mldsa_hash_check(pk, msg, result)` → `bool` — off-circuit FIPS 204 hash step
- `NORM_BOUND: int = 524_092`

**V22 pipeline (current production):**
- `prove_mldsa_witness_stark_v22(a_hat, z, c, t1, hints, k, l, c_tilde, merkle_root)` → `MldsaWitnessResult`
- `verify_mldsa_witness_stark_v22(result)` → `bool`

All prior versions (V4–V21) remain available for comparison and regression testing.

### `stark_stwo/src/mldsa_verify_stark.rs`

**V22 proof struct and pipeline (7-component single STARK):**
```
VerifyMldsaProofV22
  prove_verify_mldsa_v22(a_hat, z, c, t1, hints, k, l, c_tilde, merkle_root)
  verify_mldsa_witness_v22(proof)
```
All 7 circuits in one FRI commitment (3216 main trace columns + 1 preproc):
```
NttBatch(LOG=10, 649) + AzFull(LOG=8, 1523) + Ct1Full(LOG=8, 295)
+ InttBatch(LOG=10, 649) + WPrimeFull(LOG=8, 24)
+ NormCheckBatch(LOG=8, 15) + UseHintBatchV2(LOG=8, 61 + 1 preproc)
```
Fiat-Shamir transcript: `c_tilde` → `merkle_root` → Tree0 → Tree1 → fingerprints

### `stark_stwo/src/lib.rs`
- `prove_full_mldsa_witness_combined(z, c, t1, a_hat, hints, c_tilde_seed, extra_binding)` — low-level 7-component prover; V21 passes `&[]` for `extra_binding`, V22 passes `merkle_root`
- `verify_full_mldsa_witness_combined(…, c_tilde_seed, extra_binding)` — matching verifier

### `aggregator/batcher.py`
- `BatchResult` — wraps `Batch` + `proof`, `commitment`, `witness_bundle`, `witness_commitment`
- `Batcher.try_batch(prove_witnesses=False)` — respects `min_batch_size`
- `Batcher.force_batch(prove_witnesses=False)` — ignores `min_batch_size`

### `aggregator/api.py`
- `POST /transactions` — submit signed tx (validates signature at ingestion)
- `POST /batch/run?prove_witnesses=false` — respects min_batch_size
- `POST /batch/flush?prove_witnesses=false` — forces batch from mempool
- `GET /stats`, `GET /health`

### `sdk/python/qlsa/`
- `Wallet` — generate ML-DSA-65 keypair, sign transactions, context manager wipes key
- `LocalClient` — in-process, `.submit()`, `.run_cycle()`, `.flush()`, `.prove_witness(tx)`
- `HttpClient` — HTTP, same API, `.prove_witness()` runs locally (no server call)
- `WitnessStatus` — `has_witness`, `onchain_commitment`, `c_tilde_hex`, `max_norms`
- `BatchStatus` — `is_proven`, `has_witness`, `witness_commitment`

## Serialization Note

All `VerifyMldsaProof*` structs in `stark_stwo/src/mldsa_verify_stark.rs` use
`bincode::Encode`/`Decode` (NOT serde) because serde does not support `[i64; 256]` arrays.
Always use `bincode::encode_to_vec` / `bincode::decode_from_slice` with these types.

## On-Chain Verifier Components (MVP-4)

### `contracts/src/verifier/CM31.sol`
Complex extension of M31: `GF(2^31-1)[i] / (i²+1)`.
- Encoding: `uint64` packed as `(a << 32) | b` where `a = re`, `b = im`
- Operations: `pack/re/im`, `add/sub/mul/neg/inv/conj/scale`, `fromBytes8LE`

### `contracts/src/verifier/QM31.sol`
Quartic extension: `CM31[u] / (u² - R)` where `R = CM31(2, 1) = 2 + i` (matches Stwo).
- Encoding: `uint128` packed as `(c0 << 64) | c1` where each component is CM31 (`uint64`)
- Operations: `pack/c0/c1`, `add/sub/mul/neg/inv`, `fromCM31/fromM31`, `fromBytes16LE`
- FRI: `friLinearFold(fPlus, fMinus, alpha)` — linear combination fold step for real M31 inputs

### `contracts/src/verifier/MerkleVerifier.sol`
Blake2s binary Merkle inclusion proofs matching Stwo's trace tree structure.
- `hashLeaf(uint32[] colValues)` — hash M31 column values as LE uint32 words
- `hashPair(left, right)` — Blake2s(left ‖ right) for internal nodes
- `verify(root, leafHash, index, depth, siblings)` — calldata variant
- `verifyMem / verifyColumns / verifyColumnsMem` — memory variants for internal use

### `contracts/src/verifier/TwoChannel.sol`
Stwo's `Blake2sM31Channel` replicated in Solidity — the Fiat-Shamir transcript engine.
- Matches `Blake2sM31Channel` from `stwo/src/core/channel/blake2s.rs` exactly (verified by Rust cross-check vectors from Stwo 2.2.0).
- State: `struct State { bytes32 digest; uint32 nDraws; }` — digest is 32 bytes of 8 LE M31 words.
- `Blake2sM31Hash(data)`: `Blake2s-256(data)` then `reduce_to_m31` on each 4-byte LE chunk.
  - `reduce_to_m31(w)`: `r = (w & 0x7FFFFFFF) + (w >> 31); if r >= P: r -= P`
- Operations:
  - `init()` → zero-state
  - `mixRoot(state, root)` — `digest = Blake2sM31Hash(digest ‖ root); nDraws = 0`
  - `mixU32s(state, uint32[])` — `digest = Blake2sM31Hash(digest ‖ words_le); nDraws = 0`
  - `drawU32sRaw(state) → bytes32` — `input = digest ‖ nDraws_le4 ‖ 0x00; nDraws++`
  - `drawSecureFelt(state) → uint128` — words [w0,w1,w2,w3] → QM31 `c0=(w0<<32|w1), c1=(w2<<32|w3)`
  - `drawQueries(state, logDomainSize, n) → uint256[]` — FRI query indices in `[0, 2^logDomainSize)`

### `contracts/src/verifier/CirclePoint.sol`
Circle group arithmetic over M31 for Stwo FRI domain verification.
- Generator G = (2, 1268011823), group order 2^31
- `isOnCircle(x, y)` — checks x²+y² = 1 mod P
- `pointAdd(x1,y1, x2,y2)` — circle group law: `(x1x2−y1y2, x1y2+x2y1)`
- `pointDouble(x, y)` — doubling: `(2x²−1, 2xy)`
- `genMul(scalar)` — double-and-add scalar multiplication of G
- `cosetAt(logN, idx)` — CanonicCoset domain point; `initial_index = 2^(30-logN)`, `step = 2^(31-logN)`
- `circleFold(fPlus, fMinus, alpha, yInv) → uint128` — circle→line fold: `(f+ + f−) + α·(f+ − f−)·yInv`
- `lineFold(fPlus, fMinus, alpha, xInv) → uint128` — line→point fold (same formula, uses x⁻¹)
- Cross-checked against Stwo 2.2.0 Rust test vectors (3 tests in `stark_stwo/src/lib.rs`)

### `contracts/src/QLSAVerifierV4.sol`
Verifier with on-chain Merkle query + correct circle FRI fold check.
- Accepts: `(proof, commitment, merkleRoot, queryHints)` where queryHints is ABI-encoded (11 fields)
- Checks: commitment binding → trace root consistency (proof[8:40]) → Merkle inclusion → circle fold
- `queryHints` 11-field format:
  ```solidity
  abi.encode(
      bytes32 traceRoot, uint32[] queryValues, uint256 queryIndex, uint256 treeDepth,
      bytes32[] merkleSiblings, uint128 friAlpha,
      uint128 fPlus, uint128 fMinus, uint128 foldedValue,
      uint256 queryPointX, uint256 queryPointY
  )
  ```
- Circle fold check: (a) point on circle, (b) point == cosetAt(treeDepth, queryIndex), (c) circleFold matches
- Requires `viaIR: true` in hardhat.config.js (11-field ABI decode exceeds stack depth without it)

## Multi-Component STARK Pattern

When adding a new combined STARK (mixed-size components):
1. Twiddles at `max(LOG_N_ROWS) + LOG_BLOWUP + 1`
2. `TraceLocationAllocator::default()` if no preproc columns; `new_with_preprocessed_columns(&[pc_is_init_uh()])` when UseHintBatchV2 is included
3. Tree 0: preprocessed columns (UseHint `is_init_uh`); Tree 1: all main trace columns
4. Fingerprint each component's output and `channel.mix_u32s(&fp)` in data-pipeline order
5. Verifier must replay `mix_u32s` calls in the **exact same order** as the prover

## Active Branch

Development: `claude/review-repo-structure-E4kPW`

## Known Limitations (Research Prototype)

1. On-chain verifier: QLSAVerifierV4 verifies Merkle inclusion + first FRI fold; full FRI verifier is MVP-4 final
2. ML-DSA verify cross-check: off-circuit (Rust, pre-proof); AIR circuits prove arithmetic witness only
3. Hash AIR: upgraded to Poseidon2-over-M31 (replaced H(a,b)=a³+b); full RPO256 in MVP-4
4. FRI LOG_BLOWUP=4 → blowup=16 → ~120-bit soundness (full 128-bit needs LOG_BLOWUP=6, blowup=64)
5. `wipe_key()`: Rust `zeroize` wrapper (volatile writes) — Python-side liboqs copies still not guaranteed

## Security Hardening (implemented)

- **Public key validation**: `derive_address()` rejects non-ML-DSA key lengths at source
- **API rate limiting**: per-IP sliding-window (100 tx/min, 20 batch ops/min)
- **On-chain nonce registry**: `submitBatchWithNonces()` in `BatchRegistryV2` enforces strictly
  increasing per-sender nonces — prevents replay of any previously finalized transaction
- **Key wipe**: `wipe_key()` backed by Rust `wipe_bytes` (zeroize crate, volatile_set) — primary key buffer is securely zeroed; Python-side copies from liboqs signing remain best-effort
- **c_tilde Fiat-Shamir binding**: ML-DSA challenge bytes mixed into channel before Tree0 commit (V19+)
- **Merkle root Fiat-Shamir binding**: batch Merkle root mixed into channel after c_tilde (V22) — proof is cryptographically specific to one batch

## CI Pipeline

| Job | Trigger | What runs |
|-----|---------|-----------|
| `python` | push/PR | pytest (all tests + stark_stwo), mypy, bandit, pip-audit |
| `rust` | push/PR | cargo build + smoke test (`stark/`) |
| `stark_stwo` | push/PR | cargo test + build + smoke test |
| `sdk_js` | push/PR | tsc --noEmit + jest (22 tests) |
| `contracts` | push/PR | hardhat compile + test (8 tests) |
| `deploy` | manual | deploy QLSAVerifierFull + BatchRegistryV2 |
