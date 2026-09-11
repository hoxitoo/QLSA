# CLAUDE.md — QLSA Codebase Guide

## Project Overview

QLSA aggregates N ML-DSA-65 (FIPS 204) post-quantum signatures into a single
Circle STARK proof (~90–200 KB) for O(1) on-chain verification.

**Research prototype — not production-ready.**

## Repository Structure

```
core/           ML-DSA-65 keys, signing, Merkle tree, batch creation
stark_stwo/     Rust: Stwo Circle STARK prover + ML-DSA-65 verifier (PyO3 ext)
stark/          Python wrappers: prove_batch, prove_mldsa_batch, V23 witness pipeline
aggregator/     Mempool, Batcher, AggregatorNode, FastAPI HTTP API
contracts/      Solidity: BatchRegistryV5 (direct) / V7 (recursive); QLSAVerifierVFRI11 (t=8),
                VFRI12 (t=16), Recursive; verifier/ — M31, QM31, CM31, CirclePoint, Blake2s,
                Poseidon2 t=8 and t=16 backends, RecursiveChannelReplay
sdk/python/     Python SDK: LocalClient, HttpClient, Wallet, WitnessStatus
sdk/js/         TypeScript SDK: AggregatorClient, types
testnet/        e2e.py (--stack v8/v7), deploy_v7.sh, deploy_v8.sh, submit.py (V5/V7 submitters), monitor.py
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

# Run Rust tests (323 passing, 90 ignored slow STARK integration tests)
cargo +nightly-2025-07-01 test --manifest-path stark_stwo/Cargo.toml

# Run Rust tests including slow STARK integration tests
cargo +nightly-2025-07-01 test --manifest-path stark_stwo/Cargo.toml -- --include-ignored

# Run Solidity tests
cd contracts && npx hardhat test

# Run Solidity tests where egress blocks binaries.soliditylang.org (sandboxes):
# use the solc npm package's JS compiler instead of a downloaded binary
cd contracts && npm install --no-save solc@0.8.35 && QLSA_LOCAL_SOLCJS=1 npx hardhat test

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

Prior witness pipelines (V4–V22) were removed with the Ф1 narrowing; they are in git
history at commit `f2020d9` (the parent of this change). V23 is the only pipeline that ships.

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
- `prove_witnesses=True` generates cross-bound witness proofs for tx[0] under the protocols
  named in `Batcher.witness_protocols` (`vfri11` by default, `recursive` for the V7 path).
  `BatchResult.witness_proofs` is the live mapping; the `vfriN_*` / `has_vfriN` attributes
  remain as read-only views so the HTTP API keeps its shape, and report empty for a
  protocol that no longer exists.

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

## On-Chain Contracts

> **Narrowed 2026-09-11 (Ф1).** This section used to catalogue 28 verifiers, 7
> registries and 13 hash backends. All but the shipping set were removed: an
> external audit is priced by volume, VFRI5–VFRI8 sat in `src/` carrying a "do
> not deploy" note, and every extra version was a place for these docs to drift
> from the code — which had happened three times. Everything removed is in git
> history at commit `f2020d9` (the parent of this change).

### Shipping set

| file | role |
|---|---|
| `IQLSAVerifierV4.sol` | the 4-param `verify` interface every verifier implements |
| `QLSAVerifierVFRI11.sol` | **production** — VFRI9 protocol on Poseidon2 **t=8** (4-word/124-bit nodes, collision ~2^62). Dual `submitBatch` **6,058,052 gas** in one tx |
| `QLSAVerifierVFRI12.sol` | the **t=16** branch (8-word/248-bit nodes, ~2^124 ≈ 128-bit). Dual `submitBatch` **15,432,163 gas**; only 8% headroom and fixed at 16-bit FRI (q=2 exceeds the cap) |
| `QLSAVerifierRecursive.sol` | outer verifier — a STARK proving "I verified a VFRI11 STARK". `verifyRecursive` **2,290,000 gas**, constant in batch size |
| `BatchRegistryV5.sol` | direct path; both V23 trace groups in ONE transaction with cross-proof binding |
| `BatchRegistryV7.sol` | recursive path; two cross-bound recursive bundles |

`queryHints` ABI is **byte-identical across VFRI11 and VFRI12** (6 head slots:
`abi.encode(uint128 oodsComboPos, uint128 oodsComboNeg, bytes32 compRoot,
uint128[] lastLayerEvals, bytes32[] friLayerRoots, QueryHints[])`). Only the hash
backend differs, which is why hints from one are rejected by the other — a
regression test in `QLSAVerifierVFRI11E2E.test.js` pins exactly that.

Cross-proof binding (both registries):
`boundRoot10 = keccak256(merkleRoot ‖ traceRoot8)`,
`boundRoot8 = keccak256(merkleRoot ‖ traceRoot10)`.

### Supporting libraries (`contracts/src/verifier/`)

`M31`, `QM31`, `CM31` (field arithmetic), `CirclePoint` (circle group + FRI
folds), `Blake2s`/`Blake2sYul` (outer commitment), `RecursiveChannelReplay`
(on-chain Fiat-Shamir replay, byte-identical to the Rust reference), and the two
Poseidon2 backends: `Poseidon2M31T8` + `Poseidon2MerkleVerifierT8` +
`Poseidon2ChannelT8`, and the same trio at T16.

**Which backend ships is deliberately still open** — the choice between t=8 (gas
headroom) and t=16 (128-bit nodes) is made after Ф2 measures what membership
proofs and the tree root cost. See `ROADMAP.md`.

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

> **0. THE TRUST-MODEL GAP — read first.** The on-chain proof establishes the
> ML-DSA *arithmetic* relations for a committed witness. It does NOT establish
> that a signature exists: the FIPS 204 hash step (`c̃ = SHAKE-256(μ ‖
> w1Encode(w1'))`, `c = SampleInBall(c̃)`) is outside the circuit, so a prover can
> satisfy every constraint with a self-chosen `(z, c, t1)` and no signature.
> `c̃` is Fiat-Shamir-bound but not tied to `w1'` by any constraint. The shipped
> prover DOES run a full `ml_dsa_verify` in Rust before extracting the witness
> (`extract_mldsa_witness_py` refuses invalid signatures), so an honest aggregator
> cannot prove a forgery — but that check is off-chain and the contract cannot see
> it. Closing this requires SHAKE-256/Keccak-f[1600] as an AIR: **not started, not
> scheduled**. Also: only `tx[0]` of a batch gets a witness proof, so "N signatures
> in one proof" is not what the deployed contracts enforce.


1. On-chain verifier: QLSAVerifierVFRI3 + Blake2sYul passes NttBatch E2E (1 poly / 55 cols / 1 query / 9 folds, within 16.7 M gas). **Scale finding (2026-05-20):** V23 NttBatch has 649 cols (12 polys); on-chain OODS mixing for 649 cols requires ~120 M gas — exceeds eth_call cap. Full V23 on-chain verification requires OODS batching (algebraic hash combining columns, e.g. RPO256 hash AIR) before VFRI3 can be wired to production ML-DSA proofs.
2. ML-DSA verify cross-check: off-circuit (Rust, pre-proof); AIR circuits prove arithmetic witness only
3. Hash AIR: upgraded to Poseidon2-over-M31 (replaced H(a,b)=a³+b); full RPO256 in MVP-4
4. FRI LOG_BLOWUP=6 → blowup=64, N_FRI_QUERIES=20, POW_BITS=10 → 6×20+10 = 130-bit soundness (PcsConfig security_bits formula: log_blowup × n_queries + pow_bits)
5. `wipe_key()`: Rust `zeroize` wrapper (volatile writes) — Python-side liboqs copies still not guaranteed
6. **Node-width ladder (concluded).** Merkle-node collision cost is set by node WIDTH, not by
the permutation family: t=2/t=4 truncate nodes to 2 M31 words (~2^31), t=8 carries 4 words
(124-bit, ~2^62), t=16 carries 8 words (248-bit, ~2^124 ≈ 128-bit, matching Stwo's native
Poseidon2-16). The ladder is complete on-chain and both shipping rungs are cross-checked
bit-exact Rust↔Solidity. The t=2 and t=4 backends and the VFRI3–VFRI10 verifiers that used
them were removed in the Ф1 narrowing (commit `f2020d9`); the detailed build log is in
`docs/roadmap/recursion.md`.
**R4.22 — t=16 (128-bit node collision) verifies a full V23 batch in ONE transaction (2026-07-31):**
the "VFRI12 is SKIPPED" decision above is **SUPERSEDED**. `QLSAVerifierVFRI12.sol` (the VFRI11
protocol on a t=16 hash backend: `Poseidon2MerkleVerifierT16` + `Poseidon2ChannelT16`,
**8-word/248-bit nodes → ~2^124 ≈ 128-bit**) finalizes both full-V23 groups through
`BatchRegistryV5.submitBatch` at **15,436,509 gas in one transaction** (per group: LOG=10
**9,036,930** / LOG=8 **6,511,542**), inside the 16,777,216 (2^24) cap with 8% headroom. The
`SKIPPED` reasoning ("same gas wall ~4× worse, could never deploy production V23") was an
extrapolation from an unoptimised permutation — the same error R4.8 corrected for t=8.
**Scope:** this is the MERKLE NODE / transcript collision bound. The fixtures use `n_queries=1`
(16-bit FRI soundness), matching the VFRI11 fixture for comparability; production 130-bit FRI
soundness needs 20 queries, where DIRECT verification does not fit a transaction at any hash
width — that remains recursion's job. The two bounds are independent.
Two implementation findings, both from measuring rather than reasoning:
(a) the first build came in at **3.57×** a t=8 group against a **1.79×** permutation ratio, and the
whole gap was the ABSORB COUNT — the channel had inherited rate-1 absorb from t=2/t=4/t=8, so each
8-word root cost 8 permutations instead of 1. t=16's sponge has rate 8; rate-1 wastes 7/8 of its
bandwidth for no security (capacity, not rate, sets the collision bound). Rate-8 absorb cut LOG=10
by 24% and LOG=8 by 31% — that is what brought the pair under the cap. (b) a constant padding flag
left `mix_u32s([1,2,3])` and `mix_u32s([1,2,3,0])` absorbing to the same state (both pad to the same
8 cells); the pad now adds `8-k`, encoding the block length.
Also: the FRI chain is parameterised over the hash backend (`P2Backend`/`P2Chan`) so VFRI11 and
VFRI12 share ONE implementation and cannot drift from the ABI encoder (the R4.1 discipline);
VFRI12's `verify()` is split into a guard frame and a work frame because the wider backend makes the
Yul stack allocator fail on VFRI11's shape (codegen only — identical checks, order, transcript).
Ladder complete on-chain: t=2/t=4 (2^31) → t=8 (2^62) → **t=16 (2^124)**.
**R4.23 — the two production bounds still cannot be reached together (2026-07-31):** measured, a
t=16 RECURSION does not fit. The recursion's on-chain cost is dominated by verifying the OUTER
proof (the recursive circuit's own trace — 87 cols at `outer_log=14`, independent of inner size);
on the real production outer trace (inner `n_queries=20`) that verify costs **5,441,919 gas at t=8
but 16,044,328 at t=16** — 96% of the per-tx cap for ONE group, where `BatchRegistryV7` needs two
plus the inner channel replay and last-layer check. So today:
`recursion (t=8)` = 130-bit FRI **but ~2^62 nodes**; `VFRI12 direct` = ~2^124 nodes **but 16-bit
FRI** (q=1 — q=2 already exceeds the cap). Neither reaches both. Closing the gap needs the outer
verify roughly 2.3× cheaper at t=16; the obvious knobs do not give it (raising `outer_folds` shrinks
the last-layer rebuild but grows the fold-chain Merkle work, netting ~1M). Probe:
`contracts/test/OuterWidthProbe.test.js` + `write_outer_width_probe`.
**This also corrects an error of mine:** the 1.79× permutation ratio recorded in R4.22 came from
`estimateGas` on single external calls, which charges the shared 21,000 tx base to both widths and
so understates the ratio. The marginal cost is **3.04×** (t=8 12,306 / t=16 37,377), which is what
the 2.47–2.95× end-to-end ratios were showing all along. The 15,436,509 figure is unaffected — it
is a sent-transaction `gasUsed` — but "t=16 is cheaper per bit of node capacity" was wrong: it is
~1.5× dearer per bit.

**R4.8 — the gas wall was implementation overhead, not width (2026-07-30):** every gas figure above
was measured against a Solidity Poseidon2 whose per-permutation cost was ~97% overhead: `uint256[8]
memory` state plumbing plus a branchy `if (r >= P) r -= P` on every linear-layer addition (t=8:
~106k gas per permute, of which the field arithmetic is ~3k). Two measurement errors compounded it:
(a) a `gasLimit` above 2^24 is **rejected before execution** (`transaction gas limit … greater than
the cap`), so the "exceeds 29M" honest path had never actually run; (b) `estimateGas` over-provisions
transactions with nested calls (63/64 rule per frame) and reported 18.17M for a `submitBatch` whose
real `gasUsed` is 6.06M — **measure `gasUsed` of a sent tx, never `estimateGas`**. Rewriting
`Poseidon2M31T8` and `Poseidon2M31T4` with the state on the stack (`permute8`/`compress4`/`sponge4`)
and **lazy modular reduction** (linear layers add without `mod P`; exact because add/mul mod P are
ring homomorphisms and every S-box `mulmod` reduces its own output — reduce only on the way out;
magnitude peaks ≈2^80 for t=8, ≈2^99 for t=4, far under 2^256) cut per-permute cost ~3.5–3.8×.
Bit-exactness is guaranteed by the 47 existing cross-check tests against the FROZEN Rust reference
vectors (unchanged Rust). Result: **full-V23 t=8 verify LOG=10 3.34M / LOG=8 2.63M, dual `submitBatch`
6.06M in ONE tx; t=4 dual `submitBatch` 3.74M in ONE tx; full `verifyRecursive` 2.29M with `ok=true`.**
So **t=8 (2^62) is production-deployable in a single transaction** — a node-collision upgrade over the
t=4 stack — and the recursion's on-chain contour is closed with ~7× headroom. Recursion remains the
path to 128-bit (t=16 inner hash) and to on-chain cost that is CONSTANT in batch size, which permutation
width alone never delivers. See `docs/roadmap/recursion.md` § R4.8.
7. Last-layer FRI check: implemented in VFRI9 (2026-06-10). VFRI5–VFRI8 remain in the repo WITHOUT it for regression — do not deploy them to production.
8. **Recursion (2026-06-17, IN PROGRESS):** production gas target. A STARK proves "I verified a VFRI11 STARK"; the outer proof is constant-size (~5M gas) and the inner verifier circuit can use any-width hash (t=16/RPO256) for free. The full AIR gadget set is built (R0.1–R3.6, `stark_stwo/src/recursive/`, 90 tests): QM31 arithmetic, FRI fold/OODS, inner-hash Merkle path, Fiat-Shamir absorb+draw, per-query composition (single + N-query aggregation), leaf-hash integration. **Audit (2026-06-17) — C1/C2 CLOSED for `recursive_verifier`** (the flagship composition gadget): **[C1 fixed]** the verifier-fixed claimed final is carried in pinned `fin0..fin3` preprocessed columns + an `is_output`-gated in-circuit constraint `is_output·(out−fin)=0` (a prover computing X can't claim Y≠X; regression `test_forged_output_cannot_prove`); **[C2 fixed]** selectors + output columns come from one canonical source `build_preproc`, and `verify_*` recomputes their commitment root via `canonical_preproc_root` (`CommitmentSchemeProver::roots()`) and rejects a mismatch — a forged `is_step≡0` no longer verifies (regression `test_forged_selector_rejected`; previously verified `true`). **R3.7 follow-up progress:** C2 preprocessed-pinning ported to (a) all four recursion sub-gadgets (`merkle_path_air`/`channel_air`/`transcript_draw_air`/`fri_fold_chain_air` — each `build_preproc(...)` + `canonical_preproc_root` + `test_forged_preproc_rejected`) AND (b) **all five production `is_init_uh` verifiers in `lib.rs`** (`verify_use_hint_batch_v2`, `verify_norm_use_hint_combined`, `verify_az_ct1_norm_use_hint_combined`, `verify_full_mldsa_witness_combined` V21/V22, `verify_full_mldsa_witness_v23`) via `canonical_uh_preproc_root(max_log)` + `build_preproc_v2` — a forged `is_init_uh≡0` (which would relax the hint-weight accumulator reset → could bypass the OMEGA bound) no longer verifies; honest V21/V22/V23 roundtrips still pass. **C2 is now closed for EVERY preprocessed-column verifier in the codebase** (2026-06-17): + the Poseidon2 hash-chain verifier `verify_hash_chain_poseidon2` (via `poseidon2_air::build_preprocessed` + `canonical_hashchain_preproc_root`). No verifier accepts an unpinned Tree 0. **First multi-gadget recursive composition (R3.8):** `recursive/composition.rs` proves `recursive_verifier` + `merkle_path` in ONE multi-component STARK — per-query fold chain → `hashLeaf(finalFold)` → Merkle root, value-bound end-to-end (finalFold pinned via fin cols; leaf pinned in merkle via C1 leaf-binding; combined Tree 0 pinned). `prove_query_membership` / `verify_query_membership`, 3 tests. **N-query composition (R3.9):** `prove_queries_membership` proves N fold chains + N Merkle paths in one proof (VFRI11 shape) via **multi-path merkle** (`merkle_path_air::build_trace_multi`/`build_preproc_multi`/`prove_paths_multi` — N paths in one component, AIR unchanged). 101 recursive tests. **FRI cherry-pick closed for the fold challenge (R3.10):** design realization — the cheap Poseidon2 channel (absorb roots → draw challenges) stays **on-chain**, so challenges are public inputs to the recursive proof and **no logup is needed** (downgrades 1a from "logup research" to "mechanical pinning"). `recursive_verifier` pins ALL verifier-fixed challenge inputs in-circuit (a `QueryChallenges` bundle: `alpha` fold challenge, `z_x` OODS point, `px` query point, `inv` twiddle — 17 preproc columns) with equality constraints, so a prover can't cherry-pick any of them (`test_forged_alpha_cannot_prove`, `test_forged_zx_inv_px_cannot_prove`). **1a fully closed for the per-query verifier.** **Audit R3.12 (2026-07-10) — C1 root-binding closed for `merkle_path_air`:** the claimed Merkle `root` is pinned in-circuit (`is_root`/`root` preproc columns + `is_root·(s0 − root_pinned)=0` on each path's last real compression's last round row); previously it was only Fiat-Shamir-mixed, so a malicious prover could prove a FALSE root claim with adversarial siblings — an honest proof couldn't be reused, but a fresh dishonest one verified (regression `test_forged_root_cannot_prove`). `depth` became an explicit public input of `verify_merkle_path`/`verify_query_membership` (fixes the pinned-root row), matching on-chain `MerkleVerifier.verify(root, leaf, index, depth, siblings)`. The single-/N-query composition is now value-bound end-to-end fully in-circuit: fin (fold output) → hashLeaf → leaf (pinned) → path → root (pinned). The same audit added the missing input caps (`MAX_QUERIES`/`MAX_NUM_FOLDS`/`MAX_DEPTH`/log_size range/trace-capacity) to `composition` and multi-path prove/verify entry points, closing panic/OOM paths on hostile inputs (division-by-zero at depth=0, OOB preproc writes, 2^40 allocations). **104 recursive tests (453 total, 0 warnings).** **R3.13 (2026-07-13) — wide inner-hash primitive:** `recursive/poseidon2_t8_air.rs` arithmetizes the Poseidon2 **t=8** compression (`compress_t8`, 4-word/124-bit nodes → ~2^62 node collision) as a provable AIR — the wide analogue of the t=2 `poseidon2_merkle_air`, and the hash the recursion must replicate to verify a VFRI11 inner proof (its FRI-layer trees use the t=8 backend). One round per row (4 external + 14 internal + 4 external), `sq`/`sbox` S-box helper columns (degree ≤3), exact `mat_external`/`mat_internal` linear layers, C2 preprocessed pinning (40 main + 11 preproc cols). Validated by rebuilding the honest trace from the already-cross-checked `permute_t8` reference. 7 tests. **R3.14 (2026-07-13) — wide Merkle-path AIR:** `recursive/merkle_path_t8_air.rs` authenticates a path over 4-word (124-bit) nodes via `compress_t8` — the wide analogue of `merkle_path_air` (t=2), the path the recursion replicates to verify a VFRI11 FRI-layer decommitment (node collision 2^15.5 → 2^62). Reuses `poseidon2_t8_air`'s round arithmetization, chained across `depth` compressions of 22 rounds; the cross-compression `cur` chain uses the same `out[-1]` adjacency trick as the t=2 path. 45 main + 22 preproc cols; C1 index/leaf/root binding (all in-circuit, matching on-chain `Poseidon2MerkleVerifierT8.verify`) + C2 pinning; 11 tests (reference-driven + roundtrip depth 1/3/5 + wrong-root/-leaf/-index/tampered + forged-root/-preproc). **R3.15 (2026-07-13) — wide (t=8) composition:** `recursive/composition_t8.rs` proves `recursive_verifier` + `merkle_path_t8` in ONE STARK — the t=8 analogue of `composition`, swapping the inner hash from t=2 (31-bit nodes) to t=8 (4-word nodes → 2^62 collision), the hash a VFRI11 FRI-layer decommitment uses. The QM31 fold-chain component is unchanged; the connection binds `leaf4 = qm31_leaf_hash_t8(finalFold)` (deterministic public function of the pinned finalFold) into `merkle_path_t8`'s pinned 4-word leaf columns. Value-bound end-to-end fully in-circuit: finalFold (pinned) → hashLeaf_t8 → leaf4 (pinned) → t=8 path → root (pinned). `prove_query_membership_t8`/`verify_query_membership_t8`, 3 tests. **R3.16 (2026-07-16) — N-query wide composition (VFRI11 shape on t=8):** `prove_queries_membership_t8`/`verify_queries_membership_t8` prove N fold chains + N wide Merkle paths in ONE STARK, built on new multi-path t=8 builders (`merkle_path_t8_air::build_trace_multi`/`build_preproc_multi`; AIR unchanged — per-row `is_first_path`/`is_root` selectors gate each path's block). Per-query leaves recomputed as `qm31_leaf_hash_t8(final)` and pinned; every path root pinned in-circuit; input caps from the start (R3.12 lesson). **127 recursive total (476 total, 0 warnings).** **R3.17 (2026-07-16) — the 128-bit inner hash:** `poseidon2_t16.rs` implements the Poseidon2 **t=16** permutation (R_F=8, R_P=14, α=5; M_E=circ(2·M4,M4,M4,M4); M_I=J+diag(1..16), invertibility asserted; RC by the documented SHA-256 domain rule) with a rate-8/cap-8 sponge and 2-to-1 compression over **8-word (248-bit) nodes → ~2^124 ≈ 128-bit node collision** — the FINAL ladder rung, matching Stwo's native Poseidon2-16 width. `recursive/poseidon2_t16_air.rs` arithmetizes `compress_t16` (80 main + 19 preproc cols, same one-round-per-row + sq/sbox helper pattern as t=8; generic 16-cell linear-layer exprs cross-checked against the reference), C2-pinned. 6+7 tests. **R3.18 (2026-07-16) — the 128-bit inner-hash stack COMPLETE:** `merkle_path_t16_air` (8-word-node path, 89 main + 38 preproc cols, C1 index/leaf/root + C2, multi-path builders) + `composition_t16` (single- AND N-query VFRI11 shape) bind `leaf8 = qm31_leaf_hash_t16(finalFold)` end-to-end fully in-circuit at **~2^124 ≈ 128-bit node collision**: finalFold → hashLeaf_t16 → leaf8 → t=16 path → root (all pinned). The inner-hash ladder (t=2 → t=8 → t=16) is complete in-circuit — each rung a pure hash-backend swap, composition pattern unchanged. 11+5 tests, **150 recursive total (505 total, 0 warnings).** **R4.1 (2026-07-16) — the recursion verifies the REAL VFRI11 pipeline:** the hint generator's FRI chain is factored into a shared `vfri11_fri_chain` helper (pure code motion; the ABI generator and the new bridge consume ONE implementation and cannot drift), and `gen_vfri11_recursion_inputs` extracts per-query recursion inputs — StepOp, fold rounds with index-oriented twiddle inverses (an operand swap equals a NEGATED inverse: (b−a)·inv = (a−b)·(P−inv)), and the final fold's Merkle path into the COMMITTED last-layer tree — with a hard (not debug-only) invariant that the extracted chain reproduces the committed layer value. E2E: `prove_queries_membership_t8` over real data verifies, finals equal the real fold outputs, every path lands on the genuine `friLayerRoots[K]`, the bridge's trace root equals the ABI proof's `[8..40]`, and a tampered root is rejected; orientation-coverage test at depth 5 × 3 folds × 6 queries. **"Root vs committed FRI-layer root" closed at the Rust level. 507 total tests, 0 warnings.** **Audit R3.13–R4.1 (2026-07-16) — C1 input/output binding closed in the compression AIRs:** a crypto+code audit found that `poseidon2_t8_air`/`poseidon2_t16_air` `prove_compress`/`verify_compress` bound the claimed `(left,right,node)` triple to the trace only via Fiat-Shamir `mix_public`, so a malicious prover could prove a FALSE `compress(FAKE_left,FAKE_right)=node` claim (same class as R3.12; latent — these fns are called only from `#[cfg(test)]` modules, composition uses the already-pinned Merkle-path AIRs). Fixed by pinning `raw_pin[0..T]` (is_first-gated) + `node_pin[0..T/2]` (is_node-gated) in-circuit + rebuilding them in `canonical_preproc_root`/`verify_compress` (regressions `test_forged_input_cannot_prove` in both). Also added t=16 matrix naive cross-checks (M_E=circ(2·M4,…)/M_I=J+diag(1..16) independently verified) + stale-doc/capacity-literal fixes. All other new code verified clean (C1/C2 in Merkle paths, composition end-to-end binding, R4.1 orientation trick + byte-identical refactor, full node widths, M_I invertibility, no secrets). **513 total tests, 152 recursive, 0 warnings.** Remaining: on-chain channel-replay + `QLSAVerifierRecursive.sol` + `BatchRegistryV7`. **Audit R4.2–R4.7 (2026-07-26):** the on-chain recursion layer was audited (crypto + code). [HIGH, fixed] `QLSAVerifierRecursive.verifyRecursive` bound only 2 of 8 `InnerPublics` fields — `bound = keccak(traceRoot‖lastLayerRoot)` left the OODS combos, compRoot, interior fold roots, batchRoot, treeDepth and nQueries swappable while still returning ok=true; the binding now hashes EVERY public field (shared Rust `outer_binding_root` mirrored byte-for-byte by `outerBindingRoot(InnerPublics)`), with a regression asserting the root moves for each of the seven previously-unbound fields. [MEDIUM, fixed] added the missing MAX_FOLD_ROUNDS cap to the channel replay (both sides). [LOW, fixed] `build_trace_multi_raw` scoped to `pub(crate)`; redundant calldata→memory copies removed; stale NatSpec gas claim corrected to the measured >29M limit; tautological test assertion replaced; E2E fixture extended with compAlpha/friAlpha/friAlphas. See `docs/roadmap/recursion.md` § R3.8–R4.7.

## Security Hardening (implemented)

- **Public key validation**: `derive_address()` rejects non-ML-DSA key lengths at source
- **API rate limiting**: per-IP sliding-window (100 tx/min, 20 batch ops/min)
- **On-chain nonce registry**: `submitBatchWithNonces()` in `BatchRegistryV2` enforces strictly
  increasing per-sender nonces — prevents replay of any previously finalized transaction
- **Key wipe**: `wipe_key()` backed by Rust `wipe_bytes` (zeroize crate, volatile_set) — primary key buffer is securely zeroed; Python-side copies from liboqs signing remain best-effort
- **c_tilde Fiat-Shamir binding**: ML-DSA challenge bytes mixed into channel before Tree0 commit (V19+)
- **Merkle root Fiat-Shamir binding**: batch Merkle root mixed into channel after c_tilde (V22) — proof is cryptographically specific to one batch
- **Cross-proof binding** (introduced with VFRI7, now carried by VFRI11/VFRI12): the verifier mixes `merkleRoot` before `drawQueries`. `BatchRegistryV5`/`V7` pass `boundRoot10 = keccak256(batchRoot ‖ traceRoot8)` / `boundRoot8 = keccak256(batchRoot ‖ traceRoot10)` — mixing proofs from different witnesses fails Merkle verification
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
- **Off-chain replay guard** (2026-06-14 audit): `AggregatorNode.submit()` raises `ReplayedTxError` if a tx whose hash is still in the retained batch history (`_tx_to_batch`, ≤`_MAX_HISTORY` batches) is re-submitted — closes the gap where a batched tx (no longer pending, so past the mempool's hash-dedup) could be re-batched; the on-chain nonce registry remains the durable backstop. API returns `"transaction already batched"`, `accepted=False`
- **Submit error-text hardening** (2026-06-14 audit): `POST /transactions` no longer echoes raw `str(exc)`; `ValueError`→`"invalid transaction"` (detail logged server-side via `logging.getLogger(__name__)`), `MempoolFullError`→`"mempool full"` — stops leaking internal validation/capacity specifics
- **`/stats` overflow observability** (2026-06-14 audit): `mempool_dropped` (txs lost to `prepend_batch` overflow during prover-crash recovery) is now surfaced so operators can detect silent loss
- **Production-build hygiene** (2026-06-14 audit): `vfri2_bridge.rs` test module gained the missing `#[cfg(test)]` gate (test fixtures `make_v23_inputs`/`make_vfri5_polys`/`make_log8_hints` no longer compiled into the shipped library); `poseidon2_t4.rs` `m31_mul` import moved to its test module — release build is now warning-free
- **FRI generator depth guard** (2026-06-14 audit): the generic hint generators validate `tree_depth ∈ 2..=30` (mirrors the on-chain `logDomainSize > 30` guard), preventing the `coset_at` shift underflow for oversized depths (defense-in-depth; V23 wrappers always use fixed depth 8/10)
- **Testnet nonce mapping fixed** (2026-07-30): the on-chain registries store 0 for an unseen sender
  and enforce `newNonce > stored`, so the smallest submittable nonce is 1 — but `testnet/e2e.py`
  passed the 0-based `tx.nonce` straight through, making EVERY non-dry-run submission revert with
  `SenderNonceTooLow(provided=0, expected=1)` for the sender of tx[0] (all three stacks: v4, v6, v7).
  Only ever reachable on a real submit, which is why `--dry-run` never surfaced it. Fixed at the one
  boundary where the conventions meet: `testnet.e2e.build_sender_nonces()` maps `tx.nonce → nonce+1`,
  preserving strict monotonicity; 7 regression tests in `tests/test_testnet_nonces.py`. Found by
  verifying a FRESHLY generated v7 proof against a deployed `BatchRegistryV5` (full loop: ML-DSA-65
  signature → V23 → VFRI11 → `submitBatchWithNonces` finalized at 6,150,487 gas)
- **t=8 (2^62) node binding becomes deployable** (2026-07-30, R4.8): the Poseidon2 Solidity rewrite
  (stack state + lazy reduction, bit-exact against the frozen Rust vectors) brought a full-V23 t=8
  dual `submitBatch` from ">100M gas / unverifiable" to **6,058,052 gas in one transaction**. The
  production stack can therefore move from t=4 (Merkle node collision ~2^31) to t=8 (~2^62) without
  a per-transaction split — the largest available soundness gain short of recursion + t=16

## CI Pipeline

| Job | Trigger | What runs |
|-----|---------|-----------|
| `python` | push/PR | pytest (all tests + stark_stwo), mypy, bandit, pip-audit |
| `rust` | push/PR | cargo build + smoke test (`stark/`) |
| `stark_stwo` | push/PR | cargo test + build + smoke test |
| `sdk_js` | push/PR | tsc --noEmit + jest (22 tests) |
| `contracts` | push/PR | hardhat compile + test (8 tests) |
| `deploy` | manual | deploy QLSAVerifierFull + BatchRegistryV2 |
