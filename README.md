# QLSA — Post-Quantum Rollup Infrastructure

Aggregate thousands of post-quantum signatures into a single constant-size proof.

**O(1) on-chain verification. No trusted setup. Quantum-safe by design.**

---

> **⚠ NOT PRODUCTION READY — Research Prototype**
>
> This codebase is a **research prototype / testnet demonstrator**.
> It has **not** undergone an external cryptographic audit.
> Known architectural limitations include:
> - Off-chain STARK proof: `LOG_BLOWUP=6`, `N_FRI_QUERIES=20`, `POW_BITS=10` → 130-bit soundness
> - On-chain verifier (VFRI7) spot-checks `n_queries` hints per call. Default `n_queries=1` → **16-bit on-chain soundness** (6×1+10). Gas-efficient for testnet; production target is n=3–5 (28–40 bits) pending gas optimization.
> - Full 130-bit on-chain soundness (n=20) requires ~300M gas per group — exceeds mainnet block limit; solution deferred to MVP-4 (recursive batching or PoW nonce verification on-chain).
> - Hash AIR upgraded to Poseidon2-over-M31; full RPO256 hash AIR is MVP-4
>
> **Do not deploy to mainnet or use with real funds without a full external audit.**

---

## The Problem

Post-quantum cryptography is inevitable — but it breaks blockchain scalability.

| Signature | Size | 3000 tx block |
|----------|------:|--------------:|
| ECDSA (current) | ~70 bytes | ~220 KB |
| ML-DSA-65 (FIPS 204) | ~2,420 bytes | ~7.2 MB |

A direct migration causes **~30–40x overhead per block**, collapsing throughput.

> The bottleneck is not cryptography — it is infrastructure.

---

## The Solution

QLSA is **not a new signature scheme**.

It is a **post-quantum aggregation layer** that makes PQ signatures usable at scale.

- Aggregate **N** ML-DSA signatures
- Produce **1 STARK proof** of constant size (~90–200 KB)
- Verify on-chain at O(1) cost

---

## Properties

- O(1) on-chain verification
- No trusted setup (FRI-based STARK)
- Post-quantum secure (lattice + hash)
- Deployable as L2 (no hard fork required)
- Crypto-agile (algorithm versioning supported)

---

## Current Status

**MVP-5 complete** (2026-05-25). **V23 dual-VFRI7 production pipeline with cross-proof binding** — 8-component STARK + O(1)-gas on-chain verification + security audit (2026-05-30).

| Component | Status |
|-----------|--------|
| `core/` — ML-DSA keys, signing, Merkle tree, batch | ✅ Done |
| `stark_stwo/src/mldsa/` — Pure Rust ML-DSA-65 verifier (FIPS 204) | ✅ Done |
| `stark_stwo/` — Stwo Circle STARK prover (Rust), 130-bit FRI security | ✅ Done |
| ML-DSA arithmetic AIR circuits (8 components → 1 STARK, **V23**) | ✅ Done |
| `stark/` — Python prover/verifier wrappers V4–V23, witness pipeline, dual-VFRI7 hint generators | ✅ Done |
| `contracts/` — BatchRegistry(V2/V3/**V4**), QLSAVerifier(V4–V13/VFRI/VFRI2/VFRI3/**VFRI4/VFRI5/VFRI6/VFRI7**), CM31/QM31/MerkleVerifier | ✅ Done |
| `aggregator/` — Mempool, Batcher, AggregatorNode, rate limiting, HTTP API | ✅ Done |
| Tests — **210 Rust** (non-ignored) + **~237 Python** (no PyO3) + **39 TS** + **847 Hardhat** | ✅ Done |
| `sdk/` — Python SDK (Wallet, LocalClient, HttpClient, WitnessStatus) + JS SDK | ✅ Done |
| Phase 6 — Sepolia testnet: first batch finalized (4 tx, 3234-byte proof, 9.16 s) | ✅ Done |
| **V22** — All 7 ML-DSA circuits in 1 STARK + Merkle root Fiat-Shamir binding | ✅ Done |
| **V23** — V22 + RangeQBatch (288 cols) — az_hat ∈ [0,Q) closes AzFull soundness gap | ✅ Done |
| **QLSAVerifierVFRI2** — K-round FRI + constant last-layer check (on-chain FRI complete) | ✅ Done |
| **QLSAVerifierVFRI3** — Non-constant last-layer polynomial check (MVP-4 bounded-degree) | ✅ Done |
| **QLSAVerifierVFRI4** — VFRI3 + Poseidon2 OODS sponge (O(1) channel for any column count) | ✅ Done |
| **QLSAVerifierVFRI5** — VFRI4 + composition polynomial Merkle tree (eliminates per-query O(n_cols)) | ✅ Done |
| **QLSAVerifierVFRI6** — VFRI5 + off-chain OODS combo (O(1) gas for 1298 and 2206 cols alike) | ✅ Done |
| **BatchRegistryV4** — Dual-VFRI7 registry requiring both LOG=10 + LOG=8 cross-bound proofs | ✅ Done |
| **Full V23 dual-VFRI6 E2E** — Both trace groups (3504 cols) verified ≤ 15M gas each; 12.5 KB calldata | ✅ Done |
| **Security hardening** — MAX_SENDERS cap, y=0 circle-fold guard, .gitignore fixes, history eviction | ✅ Done (2026-05-22) |
| **QLSAVerifierVFRI7** — VFRI6 + `mixRoot(merkleRoot)` before `drawQueries` (cross-proof binding) | ✅ Done (MVP-5, 2026-05-25) |
| **BatchRegistryV4 cross-bound** — `boundRoot = keccak256(batchRoot ‖ traceRootOther)` passed to VFRI7 | ✅ Done (2026-05-25) |
| **Full aggregator + SDK VFRI7 wiring** — Batcher, HTTP API, Python SDK, TypeScript SDK | ✅ Done (2026-05-25) |
| **Security audit (2026-05-25)** — input validation hardening, dead code fix, defensive Solidity checks | ✅ Done (2026-05-25) |
| **Security audit (2026-05-30 round-1)** — TRUSTED_PROXIES env config, amount≥1 validation, dead code removal, GET /batch/{id}, fri_security_bits SDK field, exception safety in submit.py | ✅ Done (2026-05-30) |
| **Security + code audit (2026-05-30 round-2)** — IP validation, hex normalization, GET rate limiting, UUID batch_id validation, pubkey size check, deque history, O(1) batch index, N_FRI_QUERIES env guard | ✅ Done (2026-05-30) |
| **SDK + API audit (2026-06-03)** — `GET /node/config` endpoint + NodeConfig model (Python + TS), `prove_witnesses` param in HttpClient/TS SDK, Docker env var documentation (`N_FRI_QUERIES`, `TRUSTED_PROXIES`), DI-based HttpClient testing | ✅ Done (2026-06-03) |
| **SDK enhancements (2026-06-03)** — `get_witness_status()` in LocalClient + HttpClient (mirrors TS SDK), `LocalClient.health()` API parity, `TransactionBuilder` auto-nonce counter (`start_nonce`, `next_nonce`), `getWitnessStatus` TS tests | ✅ Done (2026-06-03) |

---

## Architecture

### Layer 1 — Signing

- ML-DSA-65 (FIPS 204)
- Address = `SHA3-256(pubkey)`

### Layer 2 — Aggregation (off-chain)

- Collect transactions (mempool → batcher)
- Verify ML-DSA-65 signatures (pure Rust FIPS 204 verifier, off-circuit)
- Build Merkle tree with SHA3-512 → `merkle_root`
- Generate Stwo Circle STARK proof (V23) — all 8 arithmetic circuits in **1 FRI commitment**
  - Fiat-Shamir transcript binds both `c_tilde` (ML-DSA challenge) and `merkle_root` (batch)
  - RangeQBatch proves az_hat[j][p] ∈ [0, Q) — closes the AzFull multiplication soundness gap
- `onchain_commitment` = Blake2s(proof[:32] ∥ c_tilde[:32])[:16]

### Layer 3 — Verification (on-chain)

- **BatchRegistryV4** (dual-VFRI7): two independent VFRI7 `verify()` calls — LOG=10 and LOG=8 groups
- Cross-proof binding: `boundRoot10 = keccak256(batchRoot ‖ traceRoot8)`, `boundRoot8 = keccak256(batchRoot ‖ traceRoot10)` — FRI query indices depend on the other group's trace commitment
- Each VFRI7 call runs ≤ 15M gas regardless of column count (O(1) in n_cols)
- Combined calldata: ~12.5 KB (7.2 KB LOG=10 + 5.3 KB LOG=8)
- Store `merkle_root` + both commitments on-chain (nonce-ordered replay protection)

---

## Tech Stack

### Cryptographic Core

- **ML-DSA-65** — FIPS 204 (liboqs-python 0.14.1 + pure Rust verifier)
- **SHA3-512** — Merkle hashing
- **SHA3-256** — address scheme
- **Blake2s-256** — proof commitment binding

### STARK Layer

| Stage | Stack | Status |
|-------|-------|--------|
| Active | Stwo 2.2.0 (Circle STARK, Rust nightly-2025-07-01) | Active |
| Legacy | Winterfell v0.13.1 | Archived |

**ML-DSA arithmetic circuits (V23 — all 8 in one STARK proof, current production):**

| Circuit | LOG | Columns | Proves |
|---------|----:|--------:|--------|
| NttBatch | 10 | 649 | NTT(z, c, t1) → z_hat, c_hat, t1_hat |
| AzFull | 8 | 1523 | A·z matrix-vector product (NTT domain) |
| Ct1Full | 8 | 295 | c·t1 polynomial product (NTT domain) |
| InttBatch | 10 | 649 | INTT(az_hat, ct1_hat) → az_out, ct1_out |
| WPrimeFull | 8 | 24 | w′ = az_out − ct1_out |
| NormCheckBatch | 8 | 15 | ‖z‖∞ ≤ γ₁ − β per coefficient |
| UseHintBatchV2 | 8 | 61+1 | UseHint(w′, hints) → w1_prime |
| **RangeQBatch** ← NEW | 8 | **288** | **az_hat[j][p] ∈ [0, Q) — closes AzFull soundness gap** |
| **Total** | | **3505** | **Full ML-DSA.Verify arithmetic witness + range check** |

**Sub-proof reduction history:**

| Version | Sub-proofs | Key change |
|---------|:----------:|-----------|
| V17 | 5 | NormCheck+UseHint merged |
| V18 | 4 | INTT+WPrime merged |
| V19 | 3 | NTT+Az+Ct1 merged |
| V20 | 2 | INTT+WPrime+Norm+UseHint merged |
| **V21** | **1** | **All 7 components — single FRI commitment** |
| **V22** | **1** | **+ Merkle root Fiat-Shamir binding** |
| **V23** | **1** | **+ RangeQBatch (az_hat ∈ [0,Q)) — closes soundness gap** |

### Infrastructure

- Python 3.10+
- `liboqs-python==0.14.1`
- Solidity + Hardhat (OpenZeppelin v5)
- Deployed on Ethereum Sepolia testnet

---

## Security Notes

| Issue | Severity | Status |
|-------|----------|--------|
| On-chain FRI verifier — full multi-round FRI with OODS | Critical | ✅ Done (VFRI2/VFRI3, 2026-05-19) |
| FRI soundness — `N_FRI_QUERIES=3` default (22-bit) | High | ✅ Fixed (LOG_BLOWUP=6, 20 queries, POW_BITS=10 → 130-bit, 2026-05-19) |
| ML-DSA verification inside AIR circuit | Critical | ✅ Done (V21: 1 STARK proof, 2026-05-16) |
| Merkle root not a public input of the STARK proof | Critical | ✅ Done (V22: Fiat-Shamir binding, 2026-05-16) |
| AzFull multiplication soundness gap (az_hat not range-checked) | High | ✅ Closed (V23: RangeQBatch 288 cols, 2026-05-20) |
| M31 wrap-around soundness gap in multiplication | High | ✅ Closed (Q-range check AIR, 2026-05-14) |
| c_tilde not bound to STARK proof | High | ✅ Done (Fiat-Shamir mixing, 2026-05-14) |
| No replay protection on-chain | High | ✅ Done (`submitBatchWithNonces()`, BatchRegistryV2) |
| On-chain OODS O(n_cols) gas bottleneck | High | ✅ Done (VFRI6: off-chain combo, O(1) gas, 2026-05-22) |
| `submitBatchWithNonces` O(n²) dedup — no sender count cap | Medium | ✅ Fixed (`MAX_SENDERS = 3000` in V2/V3/V4, 2026-05-22) |
| `_history` list unbounded growth (memory leak) | Medium | ✅ Fixed (capped at 1000 entries with eviction, 2026-05-22) |
| Circle fold y=0 — M31.inv panic on identity point | Low | ✅ Fixed (explicit y==0 guard in VFRI4/5/6, 2026-05-22) |
| `stark_stwo/target/` not in .gitignore | Low | ✅ Fixed (.gitignore updated, 2026-05-22) |
| Non-constant-time Merkle root comparison | Medium | ✅ Fixed (`hmac.compare_digest`, 2026-05-20) |
| X-Forwarded-For spoofing in rate limiter | Medium | ✅ Fixed (take rightmost IP, 2026-05-20) |
| Rate limiter eviction thread-safety (KeyError race) | Medium | ✅ Fixed (`dict.pop` + evict both windows, 2026-05-20) |
| Missing k/l bounds check in combined STARK | Medium | ✅ Fixed (`_validate_mldsa65_inputs`, 2026-05-20) |
| Solidity MerkleVerifier uncapped depth (overflow at depth≥256) | Medium | ✅ Fixed (`depth > 32` guard, 2026-05-20) |
| CM31.fromBytes8LE no M31 range check | Medium | ✅ Fixed (`require(a < P && b < P)`, 2026-05-20) |
| treeDepth upper bound missing in V11/V12/V13 | Low | ✅ Fixed (`> 30` guard added, 2026-05-20) |
| API rate limiting | Medium | ✅ Done (100 tx/min, 20 batch ops/min per IP) |
| On-chain n_queries=1 → 16-bit soundness (gas constraint) | High | Open (gas optimisation deferred to MVP-4; n configurable via `N_FRI_QUERIES` env var) |
| Private key zeroing in Python is best-effort | Medium | Open (Rust `wipe_bytes` via `zeroize`; Python-side copy unavoidable) |
| Hash AIR `H(a,b) = a³+b` not cryptographic | Low | ✅ Done (Poseidon2-over-M31, 2026-05-16) |
| Non-constant last FRI layer (bounded-degree check) | High | ✅ Done (QLSAVerifierVFRI3, 2026-05-19) |
| No cross-proof binding between LOG=10 and LOG=8 groups | Medium | ✅ Done (VFRI7: `mixRoot(merkleRoot)` before `drawQueries`; BatchRegistryV4 cross-bound roots, 2026-05-25) |
| `deserialize_public_key` accepted any-size bytes | Medium | ✅ Fixed (ML-DSA key size validation, 2026-05-25) |
| Dead code in `gen_mldsa_v23_vfri7_cross_bound_hints` (`pass` block) | Low | ✅ Fixed (raises `ValueError` when folds differ, 2026-05-25) |
| Silent sender truncation in `submit.py` | Medium | ✅ Fixed (`_validate_senders` raises on wrong-size input, 2026-05-25) |
| `TwoChannel.drawQueries` uint256 overflow (`logDomainSize >= 256`) | Low | ✅ Fixed (`require(logDomainSize <= 31)` guard, 2026-05-25) |
| `TRUSTED_PROXIES` hardcoded — operators could not add their own reverse proxy without code change | Medium | ✅ Fixed (configurable via `TRUSTED_PROXIES` env var, 2026-05-30) |
| `Transaction.amount = 0` accepted by SDK but rejected by API — silent mismatch | Medium | ✅ Fixed (`amount ≥ 1` enforced in `__post_init__`, 2026-05-30) |
| `Mempool.prepend_batch()` silently dropped transactions when full | Medium | ✅ Fixed (`logging.warning` on drop, 2026-05-30) |
| `Batch.stark_commitment_onchain()` dead code — always raised `ValueError` with real commitments | Bug | ✅ Fixed (method removed, 2026-05-30) |
| `wait_and_verify` caught all `Exception` — masked real network errors | Medium | ✅ Fixed (only "not found" suppressed, 2026-05-30) |
| No `GET /batch/{id}` endpoint — clients could not query batch status without re-proving | Low | ✅ Fixed (endpoint added to HTTP API, 2026-05-30) |
| `WitnessStatus.fri_security_bits` missing from Python SDK | Low | ✅ Fixed (field added: `6 × n_fri_queries + 10`, 2026-05-30) |
| `fastapi`/`httpx` duplicated in both `requirements-api.txt` and `requirements-dev.txt` | Low | ✅ Fixed (`-r requirements-api.txt` reference, 2026-05-30) |
| `TRUSTED_PROXIES` env value not IP-validated — malformed token added to whitelist | Medium | ✅ Fixed (`ipaddress.ip_address()` + warning+skip, 2026-05-30) |
| `public_key`/`signature` not normalized to lowercase in API validators | Low | ✅ Fixed (`.lower()` added, matching sender/recipient, 2026-05-30) |
| GET `/batch/*` endpoints unrate-limited — O(n) history scan DoS vector | Medium | ✅ Fixed (200 req/min per IP, 2026-05-30) |
| `batch_id` accepted any string — no UUID format validation | Low | ✅ Fixed (`uuid.UUID()` guard, HTTP 400 on bad format, 2026-05-30) |
| `Transaction.public_key` not size-validated in `__post_init__` | Medium | ✅ Fixed (validates against ML-DSA sizes {1312, 1952, 2592} B, 2026-05-30) |
| `create_batch()` algorithm not validated before first `verify()` call | Low | ✅ Fixed (early check at function entry, 2026-05-30) |
| `node._history` list slice eviction — new list allocated every eviction cycle | Medium | ✅ Fixed (`deque(maxlen=1000)` + O(1) `_batch_index` dict, 2026-05-30) |
| `N_FRI_QUERIES` env var unchecked — crash on non-integer value at startup | Medium | ✅ Fixed (`try/except ValueError` + range `[1, 64]` check, 2026-05-30) |
| `batcher.py` used root logger — module-level filtering impossible | Low | ✅ Fixed (`logging.getLogger(__name__)`, 2026-05-30) |
| `HttpClient.submit()` missing `KeyError` guard on response parsing | Low | ✅ Fixed (`try/except KeyError` matching pattern of `run_cycle`/`flush`, 2026-05-30) |
| No `GET /node/config` endpoint — clients had to hard-code n_fri_queries / batch size limits | Low | ✅ Fixed (endpoint + `NodeConfig` model in Python SDK, TypeScript SDK, 2026-06-03) |
| `HttpClient.run_cycle/flush` ignored `prove_witnesses` param — always sent without flag | Low | ✅ Fixed (`?prove_witnesses=true` query param forwarded; same fix in TypeScript SDK, 2026-06-03) |
| `Dockerfile` had no env var documentation — operators unaware of `N_FRI_QUERIES`/`TRUSTED_PROXIES` | Low | ✅ Fixed (documented `ENV` defaults with security trade-off comments; `docker-compose.yml` pass-through, 2026-06-03) |

For the full cryptography and security analysis, see `context.md`.

---

## Performance

| Metric | Value |
|--------|-------|
| Batch size | up to 3,000 tx |
| Proof size (hash chain STARK) | ~90–200 KB |
| On-chain verification | O(1) |
| Sepolia first batch (4 tx) | 3,234-byte proof, 9.16 s |
| V23 STARK columns | 3,504 main + 1 preproc (8 components, 1 FRI commitment) |
| VFRI7 LOG=10 gas (1298 cols, 1 query) | ≤ 15M gas |
| VFRI7 LOG=8 gas (2206 cols, 1 query) | ≤ 15M gas |
| Dual-VFRI7 combined calldata | ~12.5 KB |
| V23 slow test (full witness) | ~95 s (optimized build, `#[ignore]`) |

Benchmarks: `/benchmarks/bench_core.py`, `bench_stark.py`, `bench_poly_circuits.py`, `bench_witnesses.py`.

---

## Repository Structure

```text
QLSA/
├── core/               # ML-DSA keys, signing, Merkle tree, batch
├── stark/              # Python prover/verifier wrappers V4–V23, witness pipeline
├── stark_stwo/         # Stwo Circle STARK prover (Rust), ML-DSA arithmetic circuits
├── aggregator/         # Mempool, Batcher, AggregatorNode, HTTP API
├── contracts/          # Solidity: BatchRegistry(V2/V3/V4), QLSAVerifier(V4–V13/VFRI–VFRI7), CM31/QM31/MerkleVerifier
├── sdk/python/         # Python SDK: Wallet, LocalClient, HttpClient, WitnessStatus
├── sdk/js/             # TypeScript SDK: AggregatorClient
├── benchmarks/         # bench_core, bench_stark, bench_poly_circuits, bench_witnesses
├── testnet/            # e2e.py, deploy.sh, submit.py, monitor.py (Sepolia)
├── tests/              # 178 Python tests (no PyO3) + 317 with PyO3 ext (pytest)
├── context.md          # Technical decisions, architecture log, security risk table
└── README.md
```

---

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | ML-DSA keys, signing, Merkle tree, batch | ✅ Done |
| Phase 2 | Stwo Circle STARK prover (hash chain AIR) | ✅ Done |
| Phase 3 | Solidity contracts (BatchRegistry + verifier) | ✅ Done |
| Phase 3+ | M31 library + QLSAVerifierV2 + FRI blowup | ✅ Done |
| Phase 3++ | Blake2s.sol + QLSAVerifierV3 + QLSAVerifierFull | ✅ Done |
| MVP-4 (partial) | CM31/QM31 field libs + MerkleVerifier + QLSAVerifierV4–V13 | ✅ Done |
| Phase 4 | Aggregator: Mempool, Batcher, AggregatorNode | ✅ Done |
| Phase 5 | SDK: Python + JavaScript + HTTP API | ✅ Done |
| MVP-3 | ML-DSA batch verifier (Rust FIPS 204) + STARK bridge | ✅ Done |
| **Phase 6** | **Testnet deployment — Sepolia, first batch 2026-05-05** | ✅ Done |
| **MVP-3+** | **All 7 ML-DSA circuits → 1 STARK proof (V21) + Merkle root binding (V22)** | ✅ Done |
| **QLSAVerifierVFRI2** | **K-round parametric FRI + constant last-layer check (full on-chain FRI protocol)** | ✅ Done |
| **Security fix** | **LOG_BLOWUP=6, N_FRI_QUERIES=20, POW_BITS=10 → 130-bit FRI soundness** | ✅ Done |
| **QLSAVerifierVFRI3** | **Non-constant last-layer polynomial bounded-degree check (MVP-4 complete)** | ✅ Done |
| **VFRI3 bridges** | **Generic `gen_vfri3_hints_from_cols` + Poseidon2 + ML-DSA NttBatch VFRI3 bridges; E2E contract stack** | ✅ Done |
| **V23** | **RangeQBatch 8th component — az_hat ∈ [0,Q) range check closes AzFull soundness gap** | ✅ Done |
| **Security audit** | **Constant-time Merkle verify, rate-limit thread safety, input validation, Solidity depth guards** | ✅ Done |
| **MVP-5** | **Cross-proof binding VFRI7 + aggregator/SDK VFRI7 wiring + security audit** | ✅ Done (2026-05-25) |
| MVP-4 final | RPO256 hash AIR + Yul-optimised Blake2s + full V23 OODS wiring (20 queries, blowup 64) | ⏳ Next |

---

## Risks & Mitigations

### 1. ML-DSA inside STARK (main research challenge)

**Status: Solved (V21/V22).**

All 8 ML-DSA.Verify arithmetic components (NTT, Az, Ct1, INTT, WPrime, NormCheck, UseHint, **RangeQBatch**) now run inside a single Circle STARK FRI proof (3,505 trace columns). The proof is cryptographically bound to both the ML-DSA challenge (`c_tilde`) and the batch Merkle root via Fiat-Shamir transcript mixing. The new RangeQBatch component closes the primary soundness gap: AzFull's 23-bit decomposition of multiplications is now completed by an explicit proof that all K=6 output coefficients az_hat[j][p] lie in [0, Q).

**On-chain FRI (QLSAVerifierVFRI2):** completes the FRI protocol chain — OODS quotient check, K parametric line-fold rounds with Fiat-Shamir alphas and index derivation, constant last-layer polynomial check (reconstructs expected Merkle root and asserts it equals `friLayerRoots[K]`).

Remaining for production: non-constant last-layer bounded-degree check (MVP-4 final).

### 2. Aggregator trust model

Off-chain signature verification runs outside the STARK proof (pre-proof cross-check).

**Planned mitigation:**
- Fraud proofs
- Permissionless aggregators

### 3. Adoption timeline

PQ adoption is inevitable, but gradual.

**Focus areas:** CBDCs, government systems, long-term archival infrastructure.

---

## Economics (Draft)

- Users pay a fee for batch inclusion
- Aggregators receive rewards proportional to gas saved vs naive verification
- Future: fraud-proof penalties, decentralized aggregator market

---

## Future Extensions

- Threshold signatures (`t-of-n`)
- Multi-party aggregation
- Non-constant last FRI layer: on-chain bounded-degree polynomial check (MVP-4 final)
- FRI blowup ≥ 8 for mainnet (LOG_BLOWUP=6 → 130-bit soundness already achieved)
- Native PQ rollup chain

---

## Why Now

- NIST finalized PQC standards (FIPS 203–205, 2024)
- Quantum threat: "harvest now, decrypt later" is active
- Stwo deployed on Starknet Mainnet (November 2025)
- PQ migration window is open — but narrowing

### External Validation (May 2026)

Quantus published *"The State of Quantum: What Crypto Can't Afford to Ignore"* (May 27, 2026), independently confirming the same problem QLSA solves:

> *"A standard ECDSA transaction carries roughly 97 bytes of signature and public key. The same transaction using ML-DSA-87 carries almost 7187 bytes — a 74× increase that would sharply minimise the number of transactions per block without architectural changes."*

Their proposed solution: **STARK-style proof aggregation + Poseidon2** to move verification off-chain.

This is exactly QLSA's architecture — Circle STARK (Stwo) + Poseidon2 OODS sponge + O(1) on-chain verification. The key architectural difference: Quantus builds a new L1 blockchain requiring bootstrap from scratch; QLSA is a **drop-in aggregation layer** on top of existing chains (Ethereum, no hard-fork required).

Source: Quantus, *"The State of Quantum: What Crypto Can't Afford to Ignore"*, May 27, 2026.

---

## Contributing

Early-stage deep-tech research project.

Looking for contributors in: Cryptography, ZK / STARKs, Blockchain infrastructure.

---

## License

Apache 2.0

---

**Disclaimer:** QLSA is experimental research software. Do not use in production systems.
