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
contracts/      Solidity: BatchRegistryV2, QLSAVerifierFull, Blake2s.sol
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

# Run Rust tests (208 passing, 85 ignored slow STARK integration tests)
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

1. On-chain verifier: Blake2s commitment binding only — no full FRI verifier (MVP-4)
2. ML-DSA verify cross-check: off-circuit (Rust, pre-proof); AIR circuits prove arithmetic witness only
3. Hash AIR: upgraded to Poseidon2-over-M31 (replaced H(a,b)=a³+b); full RPO256 in MVP-4
4. FRI blowup=4: ~60-bit soundness (production needs ≥128-bit, blowup≥8)
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
