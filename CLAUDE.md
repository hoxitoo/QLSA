# CLAUDE.md — QLSA Codebase Guide

## Project Overview

QLSA aggregates N ML-DSA-65 (FIPS 204) post-quantum signatures into a single
Circle STARK proof (~90–200 KB) for O(1) on-chain verification.

**Research prototype — not production-ready.**

## Repository Structure

```
core/           ML-DSA-65 keys, signing, Merkle tree, batch creation
stark_stwo/     Rust: Stwo Circle STARK prover + ML-DSA-65 verifier (PyO3 ext)
stark/          Python wrappers: prove_batch, prove_mldsa_batch, witness pipeline V4–V23
aggregator/     Mempool, Batcher, AggregatorNode, FastAPI HTTP API
contracts/      Solidity: BatchRegistryV2/V3/V4/V5, QLSAVerifierV4/V5/V6/V7/V8/V9/V10/V11/V12/V13/VFRI/VFRI2/VFRI3/VFRI4/VFRI5/VFRI6/VFRI7/VFRI8/VFRI9, CM31.sol, QM31.sol, MerkleVerifier.sol, Poseidon2MerkleVerifier.sol, Poseidon2MerkleVerifierW.sol, Poseidon2Channel.sol
sdk/python/     Python SDK: LocalClient, HttpClient, Wallet, WitnessStatus
sdk/js/         TypeScript SDK: AggregatorClient, types
testnet/        e2e.py, deploy.sh, submit.py, monitor.py
tests/          Python test suite (pytest)
benchmarks/     bench_core.py, bench_stark.py, bench_poly_circuits.py, bench_witnesses.py
```

## Key Commands

```bash
# Run all Python tests (~552 passing when PyO3 ext installed; ~350 without PyO3)
pytest tests/ -v

# Run only tests that do NOT need the PyO3 extension
pytest tests/ --ignore=tests/test_stark_stwo.py -v

# Type check (CI scope)
mypy core/ aggregator/ --strict --ignore-missing-imports --exclude 'aggregator/api'

# Build and install the Rust PyO3 extension (required for STARK tests)
cd stark_stwo && maturin develop --features python --release && cd ..

# Run Rust tests (315 passing, 88 ignored slow STARK integration tests)
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
| V23 STARK columns | 3,505 | V22 + 288 RangeQBatch + 1 preproc |

## Important Modules

### `stark/prover.py`
- `prove_batch(batch)` → `ProofResult` — hash-chain STARK proof
- `prove_mldsa_batch(entries)` → `MldsaBatchResult` — batch ML-DSA verify + STARK
- `prove_mldsa_sig_witness_stark(pk, msg, sig)` → `MldsaWitnessResult` — full witness pipeline
- `verify_mldsa_witness_stark(result)` → `bool`
- `verify_mldsa_hash_check(pk, msg, result)` → `bool` — off-circuit FIPS 204 hash step
- `NORM_BOUND: int = 524_092`

**V22 pipeline (7-component single STARK):**
- `prove_mldsa_witness_stark_v22(a_hat, z, c, t1, hints, k, l, c_tilde, merkle_root)` → `MldsaWitnessResult`
- `verify_mldsa_witness_stark_v22(result)` → `bool`

**V23 pipeline (current production — 8-component single STARK + RangeQBatch):**
- `prove_mldsa_witness_stark_v23(a_hat, z, c, t1, hints, k, l, c_tilde, merkle_root)` → `MldsaWitnessResult`
- `verify_mldsa_witness_stark_v23(result)` → `bool`
- Adds `RangeQBatch(LOG=8, 288 cols)` proving `az_hat[i][p] ∈ [0, Q)` for all K output polynomials
- Closes the primary soundness gap in AzFull multiplication constraints

All prior versions (V4–V22) remain available for comparison and regression testing.

### `stark_stwo/src/mldsa_verify_stark.rs`

**V23 proof struct and pipeline (8-component single STARK, current production):**
```
VerifyMldsaProofV23
  prove_verify_mldsa_v23(a_hat, z, c, t1, hints, k, l, c_tilde, merkle_root)
  verify_mldsa_witness_v23(proof)
```
All 8 circuits in one FRI commitment (3504 main trace columns + 1 preproc):
```
NttBatch(LOG=10, 649) + AzFull(LOG=8, 1523) + Ct1Full(LOG=8, 295)
+ InttBatch(LOG=10, 649) + WPrimeFull(LOG=8, 24)
+ NormCheckBatch(LOG=8, 15) + UseHintBatchV2(LOG=8, 61 + 1 preproc)
+ RangeQBatch(LOG=8, 288)  ← NEW: az_hat ∈ [0, Q) range check
```

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
- `prove_witnesses=True` generates VFRI7 + VFRI8 + VFRI9 cross-bound proofs for tx[0];
  `BatchResult` carries `vfri{7,8,9}_{proof,commitment,hints}_{log10,log8}` fields and
  `has_vfri7/has_vfri8/has_vfri9` properties; API and Python SDK expose
  `has_vfri9` / `vfri9_commitment_log10` / `vfri9_commitment_log8` alongside the VFRI7/VFRI8 fields

### `aggregator/api.py`
- `POST /transactions` — submit signed tx; response includes `tx_hash` (64-char hex) when accepted
- `POST /batch/run?prove_witnesses=false` — respects min_batch_size
- `POST /batch/flush?prove_witnesses=false` — forces batch from mempool
- `GET /stats`, `GET /health`, `GET /node/config`
- `GET /batches?limit=50` — list recent batches, newest-first (1–200)
- `GET /batch/{batch_id}` — batch status by UUID
- `GET /batch/{batch_id}/witness` — witness/proof status
- `GET /batch/{batch_id}/transactions` — ordered list of tx hashes in batch; 404 if not found
- `GET /transaction/{tx_hash}` — tx lifecycle status: `"pending"` (in mempool), `"batched"` (batch_id set), 404 if unknown
- `GET /mempool?limit=100` — current size, capacity, first N pending tx hashes (FIFO)
- Rate limiting: 100 tx/min, 20 batch ops/min, 200 reads/min (shared across read endpoints)
- `python -m aggregator [--host HOST] [--port PORT] [--reload]` — start the HTTP server

### `sdk/python/qlsa/`
- `Wallet` — generate ML-DSA-65 keypair, sign transactions, context manager wipes key; `is_wiped` property; `sign_transaction()` raises `ValueError` after `wipe()`
- `LocalClient` — in-process, `.submit()`, `.run_cycle()`, `.flush()`, `.prove_witness(tx)`, `.history(limit=None)`, `.get_transaction(tx_hash)`, `.get_mempool(limit=100)`, `.get_batch_transactions(batch_id)`
- `HttpClient` — HTTP, same API, `.prove_witness()` runs locally; `.history(limit=50)` (newest-first, 1–200); `.wait_for_batch(batch_id, *, timeout=60.0, poll_interval=2.0)` polling helper; `.get_transaction(tx_hash)`, `.get_mempool(limit=100)`, `.get_batch_transactions(batch_id)`
- `TransactionBuilder` — auto-nonce counter with `.next_nonce` and `.reset_nonce(n=0)`
- `WitnessStatus` — `has_witness`, `onchain_commitment`, `c_tilde_hex`, `max_norms`
- `BatchStatus` — `is_proven`, `has_witness`, `witness_commitment`
- `TransactionStatus` — `tx_hash`, `status` ("pending"|"batched"|"unknown"), `batch_id?`
- `MempoolStatus` — `size`, `capacity`, `tx_hashes`
- `SubmitResult.tx_hash` — set when `accepted=True`
- PEP 561 compliant (`py.typed` marker included)

## Serialization Note

All `VerifyMldsaProof*` structs in `stark_stwo/src/mldsa_verify_stark.rs` use
`bincode::Encode`/`Decode` (NOT serde) because serde does not support `[i64; 256]` arrays.
Always use `bincode::encode_to_vec` / `bincode::decode_from_slice` with these types.

## On-Chain Verifier Components (MVP-4)

### `contracts/src/verifier/CM31.sol`
Complex extension of M31: `GF(2^31-1)[i] / (i²+1)`.
- Encoding: `uint64` packed as `(a << 32) | b` where `a = re`, `b = im`
- Operations: `pack/re/im`, `add/sub/mul/neg/inv/conj/scale`, `fromBytes8LE`

### `contracts/src/verifier/Poseidon2M31.sol`
Poseidon2 permutation over M31 (GF(2^31-1)), matching Stwo 2.2.0 Rust exactly.
- Parameters: t=2 state, α=5 S-box (x^5), 8 full rounds, MDS=[[3,1],[1,3]]
- Round constants: SHA-256 IV/K values reduced mod P
- Gas: ~1000 gas per permute (8 rounds × 6 mulmod + 4 add)
- Operations: `permute(s0, s1)`, `compress(left, right)`, `sponge(values[])`
- 16 tests cross-checked against Stwo 2.2.0 Rust (Poseidon2M31.test.js)
- Cross-check vectors: `permute(0,0)→(204783406,774225216)`, `sponge([1..8])→(1628177261,1519148168)`

### `contracts/src/verifier/QM31.sol`
Quartic extension: `CM31[u] / (u² - R)` where `R = CM31(2, 1) = 2 + i` (matches Stwo).
- Encoding: `uint128` packed as `(c0 << 64) | c1` where each component is CM31 (`uint64`)
- Operations: `pack/c0/c1`, `add/sub/mul/neg/inv`, `fromCM31/fromM31`, `fromBytes16LE`
- FRI: `friLinearFold(fPlus, fMinus, alpha)` — linear combination fold step for real M31 inputs

### `contracts/src/verifier/Blake2sYul.sol`
Yul-assembly optimised Blake2s-256 — same interface as `Blake2s.sol`, with `_compress()` fully in
`assembly ("memory-safe")`.  Working state v0..v15 as Yul local variables; `G` as inline Yul
function with multi-return `(ra,rb,rc,rd)`.  Active hash backend for MerkleVerifier and TwoChannel.
9 RFC 7693 test vectors verified (Blake2sYul.test.js).

### `contracts/src/verifier/MerkleVerifier.sol`
Blake2s binary Merkle inclusion proofs matching Stwo's trace tree structure.
Uses Blake2sYul as the hash backend.
- `hashLeaf(uint32[] colValues)` — hash M31 column values as LE uint32 words
- `hashPair(left, right)` — Blake2s(left ‖ right) for internal nodes
- `verify(root, leafHash, index, depth, siblings)` — calldata variant
- `verifyMem / verifyColumns / verifyColumnsMem` — memory variants for internal use

### `contracts/src/verifier/TwoChannel.sol`
Stwo's `Blake2sM31Channel` replicated in Solidity — the Fiat-Shamir transcript engine.
Uses Blake2sYul as the hash backend.
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
Verifier with on-chain Merkle query + correct circle FRI fold check (single query).
- Accepts: `(proof, commitment, merkleRoot, queryHints)` where queryHints is ABI-encoded (11 fields flat)
- Checks: commitment binding → trace root consistency (proof[8:40]) → Merkle inclusion → circle fold
- `queryHints` 11-field flat encoding:
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

### `contracts/src/QLSAVerifierV5.sol`
Multi-query verifier — extends V4 by verifying N independent FRI queries per call.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature as V4)
- `queryHints` is ABI-encoded `QueryHints[]` (array of structs, not flat fields):
  ```solidity
  abi.encode(
      tuple(bytes32,uint32[],uint256,uint256,bytes32[],uint128,uint128,uint128,uint128,uint256,uint256)[]
  )
  ```
- All queries share the same trace root (proof[8:40]); each query independently verified.
- Constants: `MIN_QUERIES = 1`, `MAX_QUERIES = 64`.
- Security note: security = log_blowup × n_queries + pow_bits (Stwo PcsConfig formula).
  Current STARK config: LOG_BLOWUP=6 (blowup=64), N_FRI_QUERIES=20, POW_BITS=10 → 130-bit security.
- 26 tests: single-query backward compat, 2/3/4-query acceptance, per-query rejection.

### `contracts/src/BatchRegistryV3.sol`
On-chain batch registry that uses `IQLSAVerifierV4` (4-param verify with queryHints).
- `submitBatch(merkleRoot, commitment, starkProof, queryHints)` — passes hints to verifier
- `submitBatchWithNonces(merkleRoot, commitment, proof, queryHints, senders, newNonces)` — with replay protection
- All nonce/ownership/event logic identical to BatchRegistryV2
- 24 tests: deployment, finalization, replay protection, nonces, end-to-end with QLSAVerifierV5 + real hints

### `contracts/src/QLSAVerifierV6.sol`
Multi-query FRI verifier with Fiat-Shamir query derivation — closes the cherry-pick vulnerability in V5.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` ABI encoding: identical to V5 (`QueryHints[]` struct array)
- All queries must share the same `treeDepth` (single FRI domain)
- Query positions derived on-chain: `TwoChannel.init() → mixRoot(embeddedRoot) → drawQueries(treeDepth, N)`
- Each hint's `queryIndex` must equal the channel-derived index for that slot — caller cannot choose positions
- 24 tests: constants, valid 1/2-query, Fiat-Shamir enforcement (wrong/swapped/zero index), treeDepth mismatch,
  proof-level rejections, per-query rejections, wrong embedded root

### `contracts/src/QLSAVerifierV7.sol`
Full Fiat-Shamir binding: derived `friAlpha` + derived query indices — closes the remaining cherry-pick vulnerability in V6.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` ABI encoding: identical to V5/V6 (`QueryHints[]` struct array)
- Channel transcript order: `init() → mixRoot(embeddedRoot) → drawSecureFelt() → drawQueries(treeDepth, N)`
- Each hint's `friAlpha` must equal the channel-derived QM31 folding challenge
- Each hint's `queryIndex` must equal the channel-derived index for that slot
- 25 tests: constants, valid 1/2-query, friAlpha enforcement (wrong alpha, correct alpha + wrong fold,
  second-query wrong alpha), query index enforcement, treeDepth mismatch, proof-level rejections,
  per-query rejections, wrong embedded root

### `contracts/src/QLSAVerifierV8.sol`
Composition binding: `fPlus`/`fMinus` proved to be the correct QM31 linear combination of committed column values.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- New hint fields: `queryValuesNeg[]` (column values at antipodal index) + `merkleSiblingsNeg[]` (Merkle proof)
- `antipodalIdx = (queryIdx + domainSize/2) mod domainSize` — gives circle-group complement (−x, y)
- Channel transcript: `mixRoot → drawSecureFelt [compAlpha] → drawSecureFelt [friAlpha] → drawQueries`
- `fPlus  = Σ_j [compAlpha^j · QM31.fromM31(queryValues[j])]` verified on-chain
- `fMinus = Σ_j [compAlpha^j · QM31.fromM31(queryValuesNeg[j])]` verified on-chain
- Antipodal position independently Merkle-verified in same trace commitment tree
- 26 tests: constants, valid 1/2-query, fPlus/fMinus binding, antipodal Merkle, Fiat-Shamir, proof-level/per-query rejections

### `contracts/src/QLSAVerifierV9.sol`
OODS quotient check: `fPlus`/`fMinus` linked to polynomial evaluations at the OODS point z.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` encoding changed to `abi.encode(uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg, QueryHints[])` — OODS evals are global (shared across all queries), not per-query
- Channel transcript: `mixRoot → drawSecureFelt [z_x] → mixU32s(oodsEvalsPos) → mixU32s(oodsEvalsNeg) → drawSecureFelt [compAlpha] → drawSecureFelt [friAlpha] → drawQueries`
- OODS quotient check (multiplication form — avoids QM31.inv):
  - `fPlus  · (p.x − z_x) == Σ_j[α^j · col_j(p)]  − Σ_j[α^j · oodsEvalPos_j]`
  - `fMinus · (−p.x − z_x) == Σ_j[α^j · col_j(−p)] − Σ_j[α^j · oodsEvalNeg_j]`
- Denominator zero-check: rejects if `p.x == ±z_x` (degenerate OODS point)
- `QueryHints` struct: identical 13 fields as V8; meaning of `fPlus`/`fMinus` changes to OODS quotient values
- 27 tests: constants, valid 1/2-query, OODS eval tampering, fPlus/fMinus quotient binding, queryValues tampering, empty/mismatched eval arrays, inherited Fiat-Shamir/Merkle/fold rejections

### `contracts/src/QLSAVerifierV10.sol`
FRI layer 1 decommitment: circle-fold outputs committed in a dedicated Merkle tree, binding foldedValue to the prover's committed polynomial.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` encoding: `abi.encode(uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg, bytes32 friLayer1Root, QueryHints[])`
- FRI layer 1 tree: `2^treeDepth` leaves; leaf j = `Blake2s(qm31Words(foldedValue_j))` for each circle-domain position j
- Channel transcript: `mixRoot → z_x → mixU32s(oodsPos) → mixU32s(oodsNeg) → compAlpha → friAlpha → mixRoot(friLayer1Root) → drawQueries`
- Per-query check: `MerkleVerify(friLayer1Root, Blake2s(qm31Words(foldedValue)), queryIndex, treeDepth, friL1Siblings)`
- `QueryHints` struct: 14 fields (adds `friL1Siblings: bytes32[]` over V9's 13)
- JS fixture computes foldedValues for ALL `2^treeDepth` circle positions to build the complete FRI layer 1 tree before drawing query indices
- 32 tests: constants, valid 1/2-query, FRI L1 tampering (root/siblings/value), channel binding (root changes query indices), inherited OODS/Fiat-Shamir/trace-Merkle rejections

### `contracts/src/QLSAVerifierV11.sol`
FRI layer 2: line fold step reducing circle-fold outputs from N→N/2, with a second Merkle decommitment.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` encoding: `abi.encode(uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg, bytes32 friLayer1Root, bytes32 friLayer2Root, QueryHints[])`
- Line fold pairs FRI layer 1 positions j and j+N/2: `G(x_j)` and `G(−x_j)` fold to `lineFolded[j]`
  - `gPlus = foldedValue` if `idx < N/2`, else `friL1SiblingValue`
  - `gMinus` is the other; `xInv = M31.inv(cosetAt(treeDepth, lineIdx).x)`
  - `lineFolded = lineFold(gPlus, gMinus, friAlpha2, xInv)` (same formula as circleFold but using x⁻¹)
- FRI layer 2 tree: `2^(treeDepth−1)` leaves at line domain positions; depth = `treeDepth−1`
- Channel transcript: `... → mixRoot(friLayer1Root) → friAlpha2 → mixRoot(friLayer2Root) → drawQueries`
- Per-query: sibling foldedValue Merkle-verified in friLayer1Root, line fold computed on-chain, lineFoldedValue Merkle-verified in friLayer2Root
- `QueryHints` struct: 18 fields (adds `friL1SiblingValue`, `friL1SiblingProof`, `lineFoldedValue`, `friL2Siblings` over V10's 14)
- Requires `treeDepth ≥ 2` (FRI layer 2 tree must have at least 2 leaves)
- 31 tests: constants, valid 1/2-query, FRI L2 tampering, sibling enforcement, channel binding, inherited OODS/Fiat-Shamir/trace-Merkle

### `contracts/src/QLSAVerifierV12.sol`
FRI layer 3: second line fold with doubled-x twiddle, reducing N/2 → N/4 values.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` encoding: `abi.encode(uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg, bytes32 friLayer1Root, bytes32 friLayer2Root, bytes32 friLayer3Root, QueryHints[])`
- Second line fold pairs FRI layer 2 positions j and j+N/4 using **doubled-x twiddle**:
  - `doubleX = 2·cosetAt(treeDepth, lineIdx2).x² − 1` (x-coord of doubled circle point)
  - Mathematical proof: `doubleX(j) + doubleX(j+N/4) = 2(x_j²+y_j²)−2 = 0` in M31, so they are negatives
  - `lineFolded2 = lineFold(gPlus2, gMinus2, friAlpha3, M31.inv(doubleX))`
- FRI layer 3 tree: `2^(treeDepth−2)` leaves; depth = `treeDepth−2`
- Channel transcript: `... → mixRoot(friLayer2Root) → friAlpha3 → mixRoot(friLayer3Root) → drawQueries`
- Per-query: sibling in FRI L2 Merkle-verified, second fold computed on-chain, lineFoldedValue2 Merkle-verified in friLayer3Root
- `QueryHints` struct: 22 fields (adds `l2SiblingValue`, `l2SiblingProof`, `lineFoldedValue2`, `friL3Siblings` over V11's 18)
- Requires `treeDepth ≥ 3` (FRI layer 3 tree must have at least 2 leaves)
- 36 tests: constants, valid 1/2-query, FRI L3 tampering, L2-sibling enforcement, channel binding, inherited OODS/Fiat-Shamir/trace-Merkle

### `contracts/src/QLSAVerifierV13.sol`
FRI layer 4: third line fold with T₄(x) twiddle, reducing N/4 → N/8 values.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` encoding: `abi.encode(uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg, bytes32 friLayer1Root, bytes32 friLayer2Root, bytes32 friLayer3Root, bytes32 friLayer4Root, QueryHints[])`
- Third fold pairing: FRI L3 positions j and j+N/8, twiddle = T₄(x_j) = 2·(2·x_j²−1)²−1
  - Mathematical proof: T₄(cos θ) = cos(4θ) (Chebyshev identity), so T₄(x_j) + T₄(x_{j+N/8}) = cos(4θ)+cos(4θ+π) = 0 ✓
- FRI layer 4 tree: `2^(treeDepth−3)` leaves; depth = `treeDepth−3`
- Channel transcript: `... → mixRoot(friLayer3Root) → friAlpha4 → mixRoot(friLayer4Root) → drawQueries`
- `QueryHints` struct: 26 fields (adds `l3SiblingValue`, `l3SiblingProof`, `lineFoldedValue3`, `friL4Siblings` over V12's 22)
- Requires `treeDepth ≥ 4` (FRI L4 tree must have at least 2 leaves)
- 34 tests: constants, valid 1/2-query, FRI L4 tampering, L3-sibling enforcement, channel binding, inherited OODS/Fiat-Shamir/trace-Merkle

### `contracts/src/QLSAVerifierVFRI.sol`
Parametric multi-round FRI verifier — generalises V11/V12/V13 with K = `friLayerRoots.length − 1` line fold rounds.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` encoding: `abi.encode(uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg, bytes32[] friLayerRoots, QueryHints[])`
- `FoldHint` struct: `(siblingValue, siblingProof, foldedValue, merkleProof)` — one entry per fold round per query
- `QueryHints` struct: 14 base fields + `friL1Siblings` + `FoldHint[] folds`
- Twiddle for fold round k: T_{2^k}(x_j) computed by k iterations of `t → 2t²−1` starting from `cosetAt(treeDepth, lineIdx_k).x`
- Channel transcript: `mixRoot(traceRoot) → z_x → mixU32s(oodsPos) → mixU32s(oodsNeg) → compAlpha → friAlpha → mixRoot(friLayerRoots[0]) → for k: friAlphas[k] = drawSecureFelt(); mixRoot(friLayerRoots[k+1]) → drawQueries`
- Requires `friLayerRoots.length ≥ 2` (at least one fold round) and `treeDepth ≥ numFolds + 1`
- Constants: `MAX_FOLD_ROUNDS = 28`
- 46 tests: 5 configurations (numFolds=1/2/3/4 + input validation + Fiat-Shamir + trace-Merkle enforcement); tests across treeDepth=2/3/4/5

### `contracts/src/QLSAVerifierVFRI2.sol`
VFRI + last-layer constant-polynomial check — closes the final FRI soundness gap.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` encoding: `abi.encode(uint128 lastLayerValue, uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg, bytes32[] friLayerRoots, QueryHints[])`
- Last-layer check: verifier reconstructs the expected Merkle root of a constant tree of depth `treeDepth − K` where every leaf = `hashLeaf(qm31Words(lastLayerValue))`, then asserts it equals `friLayerRoots[K]`
  - `node = hashLeaf(qm31ToWords(c)); for i in 0..lastDepth: node = hashPair(node, node)`
  - Because per-query Merkle proofs already bind each final fold value into `friLayerRoots[K]`, and the constant-tree check proves all leaves equal `c`, every query's final fold is cryptographically fixed to `c`
- All other structures (FoldHint, QueryHints, VerifyCtx, transcript) identical to VFRI
- 41 tests: 4 treeDepth/numFolds configurations + input validation + Fiat-Shamir + constant-polynomial specifics (constant tree root verification, non-constant tree rejection, consistent-but-wrong value rejection)

### `stark_stwo/src/vfri2_bridge.rs` — V23 VFRI3 hint bridge (MVP-4)

**`gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, batch_merkle_root, n_queries, num_folds)`**

Combines V23's NttBatch (649 cols) + InttBatch (649 cols) = 1298 trace columns (both LOG=10)
and generates VFRI3-compatible ABI-encoded hints. Returns `(proof_bytes, commitment_hex, abi_hints)`.

Architecture:
- Step 1: `build_trace(z,c,t1)` → NttBatch trace (649 cols)
- Step 2: `build_trace(a_hat, z_hat)` → az_hat; `build_trace(c_hat, t1_hat)` → ct1_hat
- Step 3: `build_trace(az_hat, ct1_hat)` → InttBatch trace (649 cols)
- Step 4: combine → 1298 cols at LOG=10 (1024 rows each)
- Step 5: `gen_vfri3_hints_from_cols_nfolds` → VFRI3 Fiat-Shamir + OODS + FRI fold chain

**Gas scale finding:** 1298 cols require ~120M gas for on-chain OODS mixing (exceeds 16.7M cap).
On-chain verification of full V23 components requires OODS batching (algebraic hash, e.g. RPO256).

Python wrapper: `stark/prover.py::gen_mldsa_v23_vfri3_hints()` → `MldsaV23VFRI3HintResult`
Tests: `tests/test_stark_stwo.py` — 6 Python tests (schema, deterministic, batch_root_binding,
consistent_with_v23_ntt, validation_errors, multi_query)
JS test: `contracts/test/QLSAVerifierVFRI3MldsaV23NttE2E.test.js` — 9 tests
  (structural checks, rejection paths, gas-scale boundary documentation)

### `contracts/src/QLSAVerifierVFRI3.sol`
VFRI3 — non-constant last-layer polynomial bounded-degree check (MVP-4).
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` encoding: `abi.encode(uint128[] lastLayerCoeffs, uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg, bytes32[] friLayerRoots, QueryHints[])`
- Last-layer check: prover supplies all `2^(treeDepth−K)` evaluations of the last-layer polynomial; verifier builds actual Merkle tree and asserts root == `friLayerRoots[K]`
  - If `lastLayerCoeffs.length == 1`: constant-tree optimization (same as VFRI2, gas-efficient)
  - Otherwise: `nodes[i] = hashLeaf(qm31Words(coeffs[i]))`; tree built bottom-up with `hashPair`
  - `MAX_LAST_LAYER_SIZE = 65536` (2^16 evaluations max on-chain)
- Per-query Merkle proofs already bind each final fold into `friLayerRoots[K]`, completing the bounded-degree argument
- 43 tests: 4 treeDepth/numFolds configurations × constant+non-constant paths, array size validation, single-element tamper, Fiat-Shamir enforcement, trace-Merkle enforcement

### `contracts/src/QLSAVerifierVFRI4.sol`
VFRI4 — VFRI3 with Poseidon2 OODS sponge commitment (MVP-4).
- Extends VFRI3 by replacing `mixU32s(allOodsEvals)` with `mixU32s(Poseidon2Sponge(oodsFlat).words)`
- Transcript change: `mixRoot → z_x → mixU32s([p2(pos_m31s).s0, p2(pos_m31s).s1, p2(neg_m31s).s0, p2(neg_m31s).s1]) → compAlpha`
- Channel receives exactly 4 M31 words for OODS commitment regardless of column count
- `queryHints` encoding: identical to VFRI3 (oodsEvalsPos/Neg still provided for composition computation)
- Security: Poseidon2-over-M31 collision resistance (128-bit, t=2, α=5, R_F=8)
- Passes NttBatch E2E (1 poly / 55 cols / 1 query / 9 folds) within 16.7 M gas
- VFRI3 hints are NOT accepted by VFRI4 (different transcript → different query indices)
- 11+10 JS tests + 6+6+6 Python tests (NttBatch + Poseidon2 AIR + V23 NttBatch)
- Rust bridges:
  - `gen_vfri4_hints_from_cols_nfolds` — generic VFRI4 from flat columns
  - `gen_ntt_batch_vfri4_hints_nfolds` — ML-DSA NttBatch (1 poly = 55 cols, fits 15M gas)
  - `gen_poseidon2_vfri4_real` — Poseidon2 AIR (7 cols) end-to-end
  - `gen_mldsa_v23_vfri4_hints` — V23 NttBatch+InttBatch (1298 cols, gas > 15M)
- Python wrappers:
  - `gen_ntt_batch_vfri4_hints` → `NttBatchVFRI4HintResult`
  - `gen_poseidon2_vfri4_hints` → `Poseidon2VFRI4HintResult`
  - `gen_mldsa_v23_vfri4_hints` → `MldsaV23VFRI4HintResult` (n_cols=1298)
- Gas scale findings (2026-05-21):
  - 55 cols (1 poly): ~7.4 s, fits in 15 M gas ✓
  - 649 cols (12 poly, V23 NttBatch): ~120 M gas — exceeds cap (O(n_cols) composition)
  - 1298 cols (V23 full): ~240 M gas estimated — Poseidon2 OODS sponge fixes OODS mixing but not composition
- Note: VFRI4 is the architectural foundation for VFRI5 (composition polynomial batching). The per-query O(n_cols) composition computation is the next bottleneck to solve.

### `contracts/src/QLSAVerifierVFRI5.sol`
VFRI5 — VFRI4 with composition polynomial Merkle tree (`compRoot`), eliminating per-query O(n_cols) work.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` encoding: `abi.encode(uint128[] lastLayerCoeffs, uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg, bytes32 compRoot, bytes32[] friLayerRoots, QueryHints[])`
  - `compRoot` is a **static bytes32** (placed inline at head slot 3, NOT an offset pointer)
  - Head = 6 × 32 = 192 bytes
- `QueryHints` struct (11 fields: 7 static + 4 dynamic, head = 352 bytes):
  - Removed: `queryValues[]`, `queryValuesNeg[]`, `merkleSiblings[]`, `merkleSiblingsNeg[]`
  - Added: `compValue` (F(p) = Σ α^j · col_j(p)), `compProof[]`, `compValueNeg`, `compProofNeg[]`
  - Fields: `queryIndex, treeDepth, compValue, compProof[], compValueNeg, compProofNeg[], foldedValue, queryPointX, queryPointY, friL1Siblings[], folds[]`
- Transcript: `mixRoot(traceRoot) → z_x → Poseidon2Sponge(oodsPos,oodsNeg) → compAlpha → mixRoot(compRoot) [NEW] → friAlpha → fold rounds → drawQueries`
- `_buildCtx` computes `oodsComboPos/Neg = Σ α^j · oodsEval_j` ONCE (O(n_cols)); no per-query column sum
- `_verifyQuery` Merkle-verifies `compValue` in `compRoot`, derives `fPlus/fMinus` as OODS quotients
- Gas analysis (2026-05-21):
  - Per-query calldata: 48.9 KB for 649 cols vs 90.6 KB for VFRI4 (1.9× smaller)
  - For 1 query: ~same gas as VFRI4 (O(n_cols) oodsCombo computed once per call)
  - For n_queries: VFRI5 is O(n_cols + n_queries × treeDepth) vs VFRI4's O(n_cols × n_queries)
  - 649-col NttBatch with 1 query still exceeds 15M gas (oodsCombo bottleneck)
  - VFRI6 will move oodsCombo off-chain (prover provides precomputed value + commitment)
- VFRI4 hints are NOT accepted by VFRI5 (different ABI layout — QueryHints struct incompatible)
- 5 Rust tests + 6 Python tests + 12 JS E2E tests
- Rust bridge: `gen_vfri5_hints_from_cols_nfolds`, `gen_ntt_batch_vfri5_hints_nfolds`
- Python wrapper: `gen_ntt_batch_vfri5_hints` → `NttBatchVFRI5HintResult`

### `contracts/src/QLSAVerifierVFRI6.sol`
VFRI6 — VFRI5 with off-chain OODS combo, eliminating O(n_cols) on-chain work entirely.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` encoding: `abi.encode(uint128 oodsComboPos, uint128 oodsComboNeg, bytes32 compRoot, bytes32[] friLayerRoots, QueryHints[])`
  - `oodsComboPos`, `oodsComboNeg` are static uint128 scalars (head slots 0–1)
  - `compRoot` is static bytes32 (head slot 2)
  - Head = 5 × 32 = 160 bytes
- `QueryHints` struct: **identical to VFRI5** (11 fields: 7 static + 4 dynamic)
- Transcript (KEY changes from VFRI5):
  - No Poseidon2 sponge
  - `compAlpha` drawn BEFORE OODS combo is mixed (avoids circular dependency)
  - `mixU32s([c0re(comboPos), c0im, c1re, c1im, c0re(comboNeg), c0im, c1re, c1im])` — 8 M31 words
  - Full: `mixRoot(traceRoot) → z_x → compAlpha → mixU32s(8 combo words) → mixRoot(compRoot) → friAlpha → fold rounds → drawQueries`
- `_buildCtx`: no `_compositionQM31`, no `_qm31ArrayToM31s`, no Poseidon2 import
- Soundness: Schwartz-Zippel OODS quotient argument — if `(compValue − oodsComboPos)/(p.x − z_x)` is low-degree for random p, then `oodsComboPos = F(z_x)` with overwhelming probability
- Gas analysis (2026-05-22):
  - Per-query calldata: **7.2 KB** for any n_cols at LOG=10 (O(1) — same for 649 and 1298 cols!)
  - **649-col NttBatch (1 query) PASSES within 15M gas** ✓ (vs VFRI5: >15M gas)
  - **1298-col NttBatch+InttBatch (1 query) PASSES within 15M gas** ✓ (same gas as 649-col)
  - **2206-col LOG=8 group (1 query) PASSES within 15M gas** ✓ (5.3 KB hints, shorter Merkle paths at depth=8)
  - O(n_cols) work eliminated on-chain: only 8 M31 words mixed per call regardless of trace size
  - Hint size depends on tree_depth and num_folds, not n_cols: depth=10 → 7.2 KB; depth=8 → 5.3 KB
- VFRI5 hints are NOT accepted by VFRI6 (different ABI layout + transcript)
- 15 Rust tests + 17 Python tests + 33 JS E2E tests
- Rust bridges:
  - `gen_vfri6_hints_from_cols_nfolds` — generic VFRI6 from flat columns
  - `gen_ntt_batch_vfri6_hints_nfolds` — ML-DSA NttBatch (1 poly = 649 cols)
  - `gen_mldsa_v23_vfri6_hints` — V23 LOG=10 group: NttBatch+InttBatch (1298 cols)
  - `gen_mldsa_v23_vfri6_hints_log8` — V23 LOG=8 group: AzFull+Ct1Full+RangeQBatch+WPrimeFull+NormCheckBatch+UseHintBatchV2 (2206 cols)
- Python wrappers:
  - `gen_ntt_batch_vfri6_hints` → `NttBatchVFRI6HintResult`
  - `gen_mldsa_v23_vfri6_hints` → `MldsaV23VFRI6HintResult` (n_cols=1298)
  - `gen_mldsa_v23_vfri6_hints_log8` → `MldsaV23VFRI6Log8HintResult` (n_cols=2206)
- Together, the two LOG groups cover the full V23 trace (3504 main cols) via two separate VFRI6 calls

### `contracts/src/QLSAVerifierVFRI7.sol`
VFRI7 — VFRI6 + `mixRoot(merkleRoot)` before `drawQueries` in the Fiat-Shamir transcript (MVP-5 Priority 2).
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` ABI encoding: **identical to VFRI6** (`abi.encode(uint128, uint128, bytes32, bytes32[], QueryHints[])`)
- Transcript change vs VFRI6:
  - VFRI6: `... → mixRoot(friLayerRoots[K]) → drawQueries`
  - VFRI7: `... → mixRoot(friLayerRoots[K]) → mixRoot(merkleRoot) → drawQueries`
- Effect: FRI query indices depend on `merkleRoot`. When `BatchRegistryV4` uses cross-bound roots, an adversary mixing proofs from different witnesses gets mismatched query indices and fails on-chain Merkle verification.
- Cross-proof binding in `BatchRegistryV4.submitBatch()`:
  - `traceRoot10 = proofLog10[8:40]`, `traceRoot8 = proofLog8[8:40]` (extracted via assembly)
  - `boundRoot10 = keccak256(batchRoot ‖ traceRoot8)` — passed to VFRI7 for LOG=10
  - `boundRoot8  = keccak256(batchRoot ‖ traceRoot10)` — passed to VFRI7 for LOG=8
- VFRI6 hints are NOT accepted by VFRI7 (different Fiat-Shamir path → different query indices)
- 11 Rust tests (smoke, deterministic, differs-from-vfri6, cross-bound-smoke/deterministic/batch-root-changes/trace-roots-cross/bad-root-length)
- Rust bridges:
  - `gen_vfri7_hints_from_cols_nfolds` — generic VFRI7 from flat columns
  - `gen_mldsa_v23_vfri7_hints` — V23 LOG=10 group (1298 cols)
  - `gen_mldsa_v23_vfri7_hints_log8` — V23 LOG=8 group (2206 cols)
  - `gen_mldsa_v23_vfri7_cross_bound_hints` — two-pass cross-binding generator using `sha3::Keccak256`
    - Pass 1: generate with `batch_root` to extract trace roots from `proof[8:40]`
    - Pass 2: regenerate with `bound_root_10` / `bound_root_8` computed from cross trace roots
    - Returns `(proof10, commit10_hex, hints10, proof8, commit8_hex, hints8)`
- Python wrappers:
  - `gen_mldsa_v23_vfri7_hints` → `MldsaV23VFRI7HintResult` (n_cols=1298)
  - `gen_mldsa_v23_vfri7_hints_log8` → `MldsaV23VFRI7Log8HintResult` (n_cols=2206)
  - `gen_mldsa_v23_vfri7_cross_bound_hints` → `FullV23VFRI7CrossBoundHintResult`
- 16 JS E2E tests (`QLSAVerifierVFRI7E2E.test.js`): fixture structural checks, cross-bound root derivation, `verify() == true` for both LOG groups, wrong-merkleRoot rejection, raw-batchRoot rejection, BatchRegistryV4 integration (finalize + replay + Log10ProofInvalid)
- Fixture: `contracts/test/fixtures/full_v23_vfri7_cross_bound_e2e.json`

### `contracts/src/BatchRegistryV4.sol` (updated for cross-proof binding)
- `submitBatch()` and `submitBatchWithNonces()` both now extract trace roots from proof bytes via `calldataload(proof.offset + 8)` and compute cross-bound roots before calling the verifier
- Verifier receives `boundRoot10`/`boundRoot8` instead of raw `batchRoot`

### `contracts/src/verifier/Poseidon2MerkleVerifier.sol` (VFRI8)
Poseidon2 binary Merkle inclusion proofs — Poseidon2 replacement for MerkleVerifier.sol.
- `hashLeaf(uint32[] colValues)` — rate-1 Poseidon2 sponge over M31 column values (matches `hash_leaf_cols_p2` in vfri2_bridge.rs):
  `s=(0,0); for v in colValues: s0=(s0+v)%P; permute(s0,s1); return bytes32(s0)`
- `hashPair(left, right)` — `bytes32(Poseidon2M31.compress(uint256(left), uint256(right)))`
- Node encoding: `bytes32(uint256(m31_value))` — M31 value in low 32 bits (28 leading zero bytes)
- `verify(root, leafHash, index, depth, siblings)` — calldata variant
- `verifyMem(...)` — memory variant

### `contracts/src/verifier/Poseidon2Channel.sol` (VFRI8)
Poseidon2 duplex sponge Fiat-Shamir channel — Poseidon2 replacement for TwoChannel.sol.
- State: `struct State { uint32 s0; uint32 s1; uint32 nDraws; }`
- `init()` → zero-state
- `_absorb(word)` — two-subtraction M31 reduction (handles arbitrary u32 values: `w < 2^32 = 2P+2`); then `s0 = (s0+w)%P; permute(s0,s1)`
- `mixRoot(state, root)` — `absorb(uint32(uint256(root))); nDraws = 0`
- `mixU32s(state, words[])` — absorb each word; `nDraws = 0`
- `_drawPair()` — saves (w0=s0, w1=s1); mixes `s0=(s0+nDraws)%P`; permutes; increments `nDraws`; returns SAVED (w0,w1)
- `drawSecureFelt(state)` — two `_drawPair` calls → QM31 as `uint128 = (CM31(w0,w1) << 64) | CM31(w2,w3)`
- `drawQueries(state, logDomainSize, n)` — repeated `_drawPair` calls; each pair yields 2 candidate indices via `w & mask`

### `contracts/src/QLSAVerifierVFRI8.sol` (VFRI8)
VFRI8 — VFRI7 with Poseidon2 Merkle trees and Fiat-Shamir channel.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` ABI encoding: **identical to VFRI7** (`abi.encode(uint128, uint128, bytes32, bytes32[], QueryHints[])`)
- Hash backend change vs VFRI7:
  - `TwoChannel` → `Poseidon2Channel` (Fiat-Shamir channel)
  - `MerkleVerifier` → `Poseidon2MerkleVerifier` (Merkle path verification)
  - `Blake2s.hash` unchanged in `_checkCommitment` (outer binding, cheap single call)
- Transcript: identical structure to VFRI7 but all absorb/mix/draw operations use Poseidon2 sponge
- Gas: 20 queries × 2 paths × depth=10 × ~1000 gas/permute ≈ 400K gas (Merkle) + ~5M (rest) ≈ 5.4M total
- **Fits within 15M gas on Ethereum mainnet** ✓
- Rust bridges: `gen_vfri8_hints_from_cols_nfolds`, `gen_mldsa_v23_vfri8_hints`, `gen_mldsa_v23_vfri8_hints_log8`, `gen_mldsa_v23_vfri8_cross_bound_hints`
- Python wrappers: `gen_mldsa_v23_vfri8_hints` → `MldsaV23VFRI8HintResult`, `gen_mldsa_v23_vfri8_hints_log8` → `MldsaV23VFRI8Log8HintResult`, `gen_mldsa_v23_vfri8_cross_bound_hints` → `FullV23VFRI8CrossBoundHintResult`
- M31 reduction: `_absorb` uses two conditional subtractions for arbitrary u32 values (matches Rust `p2_absorb` fix)

### `contracts/src/BatchRegistryV5.sol`
On-chain registry for VFRI8 proofs — identical logic to BatchRegistryV4 with VFRI8 verifier.
- Uses `QLSAVerifierVFRI8` (implements `IQLSAVerifierV4`) for both LOG=10 and LOG=8 proof checks
- Cross-proof binding: identical to BatchRegistryV4 (`boundRoot10 = keccak256(merkleRoot ‖ traceRoot8)`, `boundRoot8 = keccak256(merkleRoot ‖ traceRoot10)`)
- Commitment format: Blake2s(proof[:32] ‖ merkleRoot)[:16] — unchanged (outer binding)
- Events, errors, nonce registry, `MAX_SENDERS = 3000`: all identical to BatchRegistryV4
- Verifier address is a constructor parameter (`setVerifier()` upgrade path) — VFRI9 plugs in without a new registry

### `contracts/src/verifier/Poseidon2MerkleVerifierW.sol` (VFRI9)
WIDE Poseidon2 Merkle verification — nodes carry BOTH sponge words (62-bit content).
- Node encoding: `bytes32` where `uint256(node) = (s0 << 32) | s1` (bytes[24..28]=s0, bytes[28..32]=s1)
- `hashLeaf(uint32[] colValues)` — rate-1 sponge; returns `(s0 << 32) | s1` (matches Rust `hash_leaf_cols_p2w`)
- `hashPair(left, right)` — duplex compress: `state=(l0,l1); absorb r0; permute; absorb r1; permute` (matches `hash_pair_p2w`)
- Rationale: VFRI8's 31-bit nodes (s0 only) have ~2^15.5 birthday collision cost; 62-bit nodes raise this to ~2^31 — the t=2 maximum (128-bit binding requires t≥4 / RPO256)

### `contracts/src/verifier/Poseidon2Channel.sol` — VFRI9 additions
- `mixRootW(state, root)` — absorb wide P2 node root as 2 BE u32 words (bytes[24..28], bytes[28..32]); `nDraws = 0`
- `mixRootFull(state, root)` — absorb ALL 32 bytes of a root as 8 BE u32 words; `nDraws = 0`.
  VFRI8's `mixRoot` only absorbed the low 4 bytes, binding just 31 bits of full-width roots
  (embedded Stwo trace root, batch merkle root) into Fiat-Shamir.
- Match Rust `P2Channel::mix_root_w` / `mix_root_full` in vfri2_bridge.rs

### `contracts/src/QLSAVerifierVFRI9.sol`
VFRI9 — VFRI8 + last-layer FRI check + wide Poseidon2 nodes + full-root Fiat-Shamir absorption.
- Implements `IQLSAVerifierV4` (same 4-param `verify` signature)
- `queryHints` ABI encoding (6 head slots = 192 bytes):
  `abi.encode(uint128 oodsComboPos, uint128 oodsComboNeg, bytes32 compRoot, uint128[] lastLayerEvals, bytes32[] friLayerRoots, QueryHints[])`
- **Last-layer bounded-degree check** (closes the soundness gap left open in VFRI5..VFRI8):
  prover supplies all `2^(treeDepth−K)` evaluations of the final FRI layer; verifier rebuilds
  the Merkle tree (wide nodes) and asserts root == `friLayerRoots[K]`. Combined with the
  per-query Merkle proofs into `friLayerRoots[K]`, every query's final fold value is fixed
  to the committed last layer. `MAX_LAST_LAYER_SIZE = 65536`.
- Hash backend: `Poseidon2MerkleVerifierW` (wide nodes); channel: `Poseidon2Channel` with
  `mixRootFull(embeddedRoot)` / `mixRootW(compRoot, friLayerRoots[*])` / `mixRootFull(merkleRoot)`
- `QueryHints` struct: identical to VFRI8 (11 fields)
- Proof version marker: `proof[0:8] = 3` (little-endian; VFRI8 uses 2)
- VFRI8 hints are NOT accepted (different ABI head + transcript + node format)
- 10 Rust tests + 10 Python tests (@needs_ext) + 1 @needs_oqs + 21 JS E2E tests
- Rust bridges: `gen_vfri9_hints_from_cols_nfolds`, `gen_mldsa_v23_vfri9_hints`,
  `gen_mldsa_v23_vfri9_hints_log8`, `gen_mldsa_v23_vfri9_cross_bound_hints`
- Python wrappers: `gen_mldsa_v23_vfri9_hints` → `MldsaV23VFRI9HintResult`,
  `gen_mldsa_v23_vfri9_hints_log8` → `MldsaV23VFRI9Log8HintResult`,
  `gen_mldsa_v23_vfri9_cross_bound_hints` → `FullV23VFRI9CrossBoundHintResult`,
  `prove_mldsa_sig_vfri9_stark(pk, msg, sig, batch_merkle_root)` — from a real ML-DSA-65 signature
- Fixture: `contracts/test/fixtures/full_v23_vfri9_cross_bound_e2e.json` (seed=16600, n_queries=1, num_folds=3)
- BatchRegistryV5 deploys with the VFRI9 address — finalize/replay verified in E2E

### `contracts/src/verifier/Poseidon2M31T4.sol` (MVP-6 groundwork)
Poseidon2 t=4 permutation over M31 — cross-checked bit-exact against `stark_stwo/src/poseidon2_t4.rs`.
- Parameters: t=4 state, α=5 (x^5), R_F=8 external rounds, R_P=21 internal rounds
- External matrix M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]] (8-addition fast path)
- Internal matrix J + diag(1,2,3,4): `out_i = (Σ s_j) + μ_i·s_i`
- Round constants: SHA-256 K[0..53] reduced mod P (external K[0..32], internal K[32..53])
- `permute(s0,s1,s2,s3)` — full t=4 permutation
- `compress(l0,l1,r0,r1) → (out0, out1)` — 2-to-1 for 124-bit wide nodes (collision ~2^62)
- `sponge(values[]) → (s0, s1)` — rate-2 capacity-2; odd-length flag in capacity cell s[3]
- Cross-check vectors (frozen in `poseidon2_t4.rs::test_reference_vectors`):
  `permute(0,0,0,0) → (201_095_161, 440_871_427, 944_955_487, 992_273_343)`
  `permute(1,2,3,4) → (1_706_601_437, 1_471_208_702, 244_698_605, 2_091_016_348)`
  `compress([1,2],[3,4]) → (1_706_601_437, 1_471_208_702)`
  `sponge([1..8]) → (1_315_656_215, 594_434_174)`
- 11 JS tests (`Poseidon2M31T4.test.js`) + 12 Rust tests (`poseidon2_t4.rs`)
- VFRI10 (t=4 channel + Merkle + verifier) not yet wired — see Known Limitations #6

## Multi-Component STARK Pattern

When adding a new combined STARK (mixed-size components):
1. Twiddles at `max(LOG_N_ROWS) + LOG_BLOWUP + 1`
2. `TraceLocationAllocator::default()` if no preproc columns; `new_with_preprocessed_columns(&[pc_is_init_uh()])` when UseHintBatchV2 is included
3. Tree 0: preprocessed columns (UseHint `is_init_uh`); Tree 1: all main trace columns
4. Fingerprint each component's output and `channel.mix_u32s(&fp)` in data-pipeline order
5. Verifier must replay `mix_u32s` calls in the **exact same order** as the prover

## Active Branch

Development: `claude/review-repo-structure-E4kPW`

## Branch & Merge Workflow (Claude instructions)

`main` is a **protected branch** — direct `git push origin main` is always rejected with HTTP 403.

**Default mode — development sandbox:**
All work stays on the feature branch `claude/review-repo-structure-E4kPW`.
Commit and push to that branch freely. **Never create a PR or merge into `main` unless the user explicitly asks.**

**When the user explicitly asks to merge / update main**, follow these steps:
1. Commit all pending changes on `claude/review-repo-structure-E4kPW`.
2. Push the branch: `git push -u origin claude/review-repo-structure-E4kPW`.
3. Create a PR via `mcp__github__create_pull_request` (owner=hoxitoo, repo=QLSA, base=main).
4. Merge the PR via `mcp__github__merge_pull_request` (merge_method="merge").
5. Sync local main: `git fetch origin main && git checkout main && git reset --hard origin/main`.
6. Switch back to dev branch: `git checkout claude/review-repo-structure-E4kPW`.

**Trigger phrases** (explicit user request required): "замерджи в main", "обнови main", "смержи ветку", "merge into main", "push to main", "update main".

## Known Limitations (Research Prototype)

1. On-chain verifier: QLSAVerifierVFRI3 + Blake2sYul passes NttBatch E2E (1 poly / 55 cols / 1 query / 9 folds, within 16.7 M gas). **Scale finding (2026-05-20):** V23 NttBatch has 649 cols (12 polys); on-chain OODS mixing for 649 cols requires ~120 M gas — exceeds eth_call cap. Full V23 on-chain verification requires OODS batching (algebraic hash combining columns, e.g. RPO256 hash AIR) before VFRI3 can be wired to production ML-DSA proofs.
2. ML-DSA verify cross-check: off-circuit (Rust, pre-proof); AIR circuits prove arithmetic witness only
3. Hash AIR: upgraded to Poseidon2-over-M31 (replaced H(a,b)=a³+b); full RPO256 in MVP-4
4. FRI LOG_BLOWUP=6 → blowup=64, N_FRI_QUERIES=20, POW_BITS=10 → 6×20+10 = 130-bit soundness (PcsConfig security_bits formula: log_blowup × n_queries + pow_bits)
5. `wipe_key()`: Rust `zeroize` wrapper (volatile writes) — Python-side liboqs copies still not guaranteed
6. Poseidon2 t=2 permutation: channel sponge state is 62 bits and VFRI9 wide Merkle nodes are 62 bits — collision/transcript attacks at ~2^31 remain possible in principle; 128-bit binding requires t≥4 or RPO256 hash AIR (MVP-6). VFRI9 reaches the t=2 maximum. **MVP-6 groundwork (2026-06-12):** Poseidon2 t=4 permutation implemented and cross-checked Rust↔Solidity (`stark_stwo/src/poseidon2_t4.rs` + `contracts/src/verifier/Poseidon2M31T4.sol`) — R_F=8 + R_P=21, α=5, M4 external matrix, J+diag(1,2,3,4) internal, SHA-256 K[0..53] constants; rate-2 capacity-2 sponge with capacity-cell odd-length flag; `compress` for 124-bit wide nodes (collision ~2^62). VFRI10 (t=4 channel + Merkle + verifier) not yet wired.
7. Last-layer FRI check: implemented in VFRI9 (2026-06-10). VFRI5–VFRI8 remain in the repo WITHOUT it for regression — do not deploy them to production.

## Security Hardening (implemented)

- **Public key validation**: `derive_address()` rejects non-ML-DSA key lengths at source
- **API rate limiting**: per-IP sliding-window (100 tx/min, 20 batch ops/min)
- **On-chain nonce registry**: `submitBatchWithNonces()` in `BatchRegistryV2` enforces strictly
  increasing per-sender nonces — prevents replay of any previously finalized transaction
- **Key wipe**: `wipe_key()` backed by Rust `wipe_bytes` (zeroize crate, volatile_set) — primary key buffer is securely zeroed; Python-side copies from liboqs signing remain best-effort
- **c_tilde Fiat-Shamir binding**: ML-DSA challenge bytes mixed into channel before Tree0 commit (V19+)
- **Merkle root Fiat-Shamir binding**: batch Merkle root mixed into channel after c_tilde (V22) — proof is cryptographically specific to one batch
- **Cross-proof binding** (MVP-5 Priority 2): `QLSAVerifierVFRI7` mixes `merkleRoot` before `drawQueries`. `BatchRegistryV4` passes `boundRoot10 = keccak256(batchRoot ‖ traceRoot8)` / `boundRoot8 = keccak256(batchRoot ‖ traceRoot10)` — mixing proofs from different witnesses fails Merkle verification
- **`HttpClient._decode_json()`** (2026-06-03): all 7 `resp.json()` call-sites in `HttpClient` wrapped; `json.JSONDecodeError` → `RuntimeError` with endpoint name + 200-char body preview — proxy/CDN HTML error pages no longer cause unhandled exceptions
- **`testnet/e2e.py` sender_key** (2026-06-03): eliminated redundant `hashlib.sha3_256(tx.public_key).digest()` — `tx.sender` already contains this value as hex; `import hashlib` removed
- **`Wallet._wiped` flag** (2026-06-04): `sign_transaction()` raises `ValueError` with clear message after `wipe()` — callers discover misuse at the call-site rather than receiving a signing failure from zeroed key material; `is_wiped` property exposes the flag for introspection
- **Mempool deduplication** (2026-06-05): `Mempool.add()` raises `DuplicateTxError` if the same `tx_hash` is already pending — prevents batches from containing duplicate transactions; duplicate submissions return `accepted=False` to the caller
- **Bandit B104 nosec** (2026-06-06): `aggregator/__main__.py:32` — `# nosec B104` on the `"0.0.0.0"` default; binding all interfaces is intentional for a server entry point, address is runtime-configurable via `--host`/`HOST`
- **VFRI9 last-layer FRI check** (2026-06-10): `QLSAVerifierVFRI9` rebuilds the final FRI layer Merkle tree from prover-supplied evaluations and asserts root == `friLayerRoots[K]` — closes the bounded-degree soundness gap open since VFRI5
- **Wide Poseidon2 Merkle nodes** (2026-06-10): `Poseidon2MerkleVerifierW` — node = `(s0 << 32) | s1` (62-bit), node collision cost 2^15.5 → 2^31; t≥4/RPO256 needed for 128-bit (documented limitation)
- **Full-root Fiat-Shamir absorption** (2026-06-10): VFRI9 `mixRootFull` binds all 32 bytes of the embedded trace root and batch merkle root (VFRI8 bound only the low 4 bytes of each)
- **Prover failure recovery** (2026-06-10): `Batcher` returns transactions to the mempool and retries (up to `MAX_PROOF_RETRIES=3` per batch) when the STARK prover crashes unexpectedly; `ProverUnavailableError` (extension missing) still yields the documented unproven degraded mode
- **`Mempool.prepend_batch` overflow accounting** (2026-06-10): returns the list of dropped transactions (oldest kept, newest dropped) instead of silent loss; `dropped_count` metric added; `AggregatorNode` rejects `mempool_capacity < min_batch_size` (silently-dead-node config)
- **Bearer-token auth on batch endpoints** (2026-06-10): `POST /batch/run` and `POST /batch/flush` require `Authorization: Bearer $QLSA_API_TOKEN` when the env var is set (constant-time comparison); unset = open with a startup warning (research default)

## CI Pipeline

| Job | Trigger | What runs |
|-----|---------|-----------|
| `python` | push/PR | pytest (all tests + stark_stwo), mypy, bandit, pip-audit |
| `rust` | push/PR | cargo build + smoke test (`stark/`) |
| `stark_stwo` | push/PR | cargo test + build + smoke test |
| `sdk_js` | push/PR | tsc --noEmit + jest (22 tests) |
| `contracts` | push/PR | hardhat compile + test (8 tests) |
| `deploy` | manual | deploy QLSAVerifierFull + BatchRegistryV2 |
