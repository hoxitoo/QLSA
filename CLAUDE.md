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
contracts/      Solidity: BatchRegistryV2/V3, QLSAVerifierV4/V5/V6/V7/V8/V9/V10/V11/V12/V13/VFRI/VFRI2/VFRI3, CM31.sol, QM31.sol, MerkleVerifier.sol
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

1. On-chain verifier: QLSAVerifierVFRI3 completes the on-chain FRI protocol — K parametric line-fold rounds + non-constant last-layer polynomial bounded-degree check (full evaluation array → Merkle root); each query verifies: trace Merkle (p + −p), composition binding, OODS quotient, circle fold, FRI L1, K×(sibling Merkle + Chebyshev-twiddle line fold + FRI layer Merkle), all with full Fiat-Shamir; remaining: RPO256 hash AIR, full OODS wiring to real STARK proof
2. ML-DSA verify cross-check: off-circuit (Rust, pre-proof); AIR circuits prove arithmetic witness only
3. Hash AIR: upgraded to Poseidon2-over-M31 (replaced H(a,b)=a³+b); full RPO256 in MVP-4
4. FRI LOG_BLOWUP=6 → blowup=64, N_FRI_QUERIES=20, POW_BITS=10 → 6×20+10 = 130-bit soundness (PcsConfig security_bits formula: log_blowup × n_queries + pow_bits)
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
