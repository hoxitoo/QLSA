# QLSA — Post-Quantum Rollup Infrastructure

Aggregate thousands of post-quantum signatures into a single constant-size proof.

**O(1) on-chain verification. No trusted setup. Quantum-safe by design.**

---

> **⚠ NOT PRODUCTION READY — Research Prototype**
>
> This codebase is a **research prototype / testnet demonstrator**.
> It has **not** undergone an external cryptographic audit.
> Known architectural limitations include:
> - `LOG_BLOWUP=6` → blowup=64, `N_FRI_QUERIES=20`, `POW_BITS=10` → 130-bit FRI soundness
> - On-chain FRI verifier: QLSAVerifierVFRI3 completes K-round FRI + non-constant last-layer polynomial check (bounded-degree); RPO256 hash AIR pending
> - Hash AIR upgraded to Poseidon2-over-M31; full RPO256 is MVP-4
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

**Phase 6 complete** (Sepolia testnet live since 2026-05-05). **V23 production pipeline** — 8-component STARK closing the AzFull multiplication soundness gap.

| Component | Status |
|-----------|--------|
| `core/` — ML-DSA keys, signing, Merkle tree, batch | ✅ Done |
| `stark_stwo/src/mldsa/` — Pure Rust ML-DSA-65 verifier (FIPS 204) | ✅ Done |
| `stark_stwo/` — Stwo Circle STARK prover (Rust), 130-bit FRI security | ✅ Done |
| ML-DSA arithmetic AIR circuits (8 components → 1 STARK, **V23**) | ✅ Done |
| `stark/` — Python prover/verifier wrappers V4–V23, witness pipeline | ✅ Done |
| `contracts/` — BatchRegistry(V2/V3), QLSAVerifier(V4–V13/VFRI/VFRI2/VFRI3), CM31/QM31/MerkleVerifier | ✅ Done |
| `aggregator/` — Mempool, Batcher, AggregatorNode, rate limiting, HTTP API | ✅ Done |
| Tests — **210 Rust** (non-ignored) + **~249 Python** + **31 TS** + **Solidity suite** | ✅ Done |
| `sdk/` — Python SDK (Wallet, LocalClient, HttpClient, WitnessStatus) + JS SDK | ✅ Done |
| Phase 6 — Sepolia testnet: first batch finalized (4 tx, 3234-byte proof, 9.16 s) | ✅ Done |
| **V22** — All 7 ML-DSA circuits in 1 STARK + Merkle root Fiat-Shamir binding | ✅ Done |
| **V23** — V22 + RangeQBatch (288 cols) — az_hat ∈ [0,Q) closes AzFull soundness gap | ✅ Done |
| **QLSAVerifierVFRI2** — K-round FRI + constant last-layer check (on-chain FRI complete) | ✅ Done |
| **QLSAVerifierVFRI3** — Non-constant last-layer polynomial check (MVP-4 bounded-degree) | ✅ Done |
| **VFRI2 bridge** — `gen_poseidon2_vfri2_hints()` Rust+Python; generates VFRI2-compatible hints | ✅ Done |
| **VFRI3 real bridge** — `gen_poseidon2_vfri3_real()` real Poseidon2 OODS; end-to-end Solidity test | ✅ Done |
| **NttBatch VFRI3 bridge** — `gen_ntt_batch_vfri3_hints()` ML-DSA NTT arithmetic → VFRI3; generic `gen_vfri3_hints_from_cols()` | ✅ Done |
| **E2E contract stack** — BatchRegistryV3 + QLSAVerifierVFRI3 full on-chain flow test | ✅ Done |
| **Security hardening** — constant-time Merkle verify, X-Forwarded-For fix, input validation V22/V23, Solidity depth guards | ✅ Done |

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

- Verify `onchain_commitment` = Blake2s(proof[:32] ∥ c_tilde[:32])[:16]
- Store `merkle_root` in BatchRegistryV2 (nonce-ordered)
- Finalize batch

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
| On-chain FRI verifier — full multi-round FRI with OODS | Critical | ✅ Done (QLSAVerifierVFRI2/VFRI3, 2026-05-19) |
| FRI soundness — `N_FRI_QUERIES=3` default (22-bit) | High | ✅ Fixed (LOG_BLOWUP=6, N_FRI_QUERIES=20, POW_BITS=10 → 130-bit, 2026-05-19) |
| ML-DSA verification inside AIR circuit | Critical | ✅ Done (V21: 1 STARK proof, 2026-05-16) |
| Merkle root not a public input of the STARK proof | Critical | ✅ Done (V22: Fiat-Shamir binding, 2026-05-16) |
| AzFull multiplication soundness gap (az_hat not range-checked) | High | ✅ Closed (V23: RangeQBatch 288 cols, 2026-05-20) |
| M31 wrap-around soundness gap in multiplication | High | ✅ Closed (Q-range check AIR, 2026-05-14) |
| c_tilde not bound to STARK proof | High | ✅ Done (Fiat-Shamir mixing, 2026-05-14) |
| No replay protection on-chain | High | ✅ Done (`submitBatchWithNonces()`, BatchRegistryV2) |
| Non-constant-time Merkle root comparison | Medium | ✅ Fixed (`hmac.compare_digest`, 2026-05-20) |
| X-Forwarded-For spoofing in rate limiter | Medium | ✅ Fixed (take rightmost IP, 2026-05-20) |
| Rate limiter eviction thread-safety (KeyError race) | Medium | ✅ Fixed (`dict.pop` + evict both windows, 2026-05-20) |
| Missing k/l bounds check in combined STARK | Medium | ✅ Fixed (`_validate_mldsa65_inputs`, 2026-05-20) |
| Solidity MerkleVerifier uncapped depth (overflow at depth≥256) | Medium | ✅ Fixed (`depth > 32` guard, 2026-05-20) |
| CM31.fromBytes8LE no M31 range check | Medium | ✅ Fixed (`require(a < P && b < P)`, 2026-05-20) |
| treeDepth upper bound missing in V11/V12/V13 | Low | ✅ Fixed (`> 30` guard added, 2026-05-20) |
| API rate limiting | Medium | ✅ Done (100 tx/min, 20 batch ops/min per IP) |
| Private key zeroing in Python is best-effort | Medium | Open (Rust `wipe_bytes` via `zeroize`; Python-side copy unavoidable) |
| Hash AIR `H(a,b) = a³+b` not cryptographic | Low | ✅ Done (Poseidon2-over-M31, 2026-05-16) |
| Non-constant last FRI layer (bounded-degree check) | High | ✅ Done (QLSAVerifierVFRI3, 2026-05-19) |

For the full cryptography and security analysis, see `context.md`.

---

## Performance

| Metric | Value |
|--------|-------|
| Batch size | up to 3,000 tx |
| Proof size (hash chain STARK) | ~90–200 KB |
| On-chain verification | O(1) |
| Sepolia first batch (4 tx) | 3,234-byte proof, 9.16 s |
| V23 STARK columns | 3,505 (8 components, 1 FRI commitment) |
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
├── contracts/          # Solidity: BatchRegistry(V2), QLSAVerifier(V2/V3/Full/V4), CM31/QM31/MerkleVerifier
├── sdk/python/         # Python SDK: Wallet, LocalClient, HttpClient, WitnessStatus
├── sdk/js/             # TypeScript SDK: AggregatorClient
├── benchmarks/         # bench_core, bench_stark, bench_poly_circuits, bench_witnesses
├── testnet/            # e2e.py, deploy.sh, submit.py, monitor.py (Sepolia)
├── tests/              # ~243 Python tests (pytest)
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

---

## Contributing

Early-stage deep-tech research project.

Looking for contributors in: Cryptography, ZK / STARKs, Blockchain infrastructure.

---

## License

Apache 2.0

---

**Disclaimer:** QLSA is experimental research software. Do not use in production systems.
