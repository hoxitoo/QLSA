# QLSA — Post-Quantum Rollup Infrastructure

Aggregate thousands of post-quantum signatures into a single constant-size proof.

**O(1) on-chain verification. No trusted setup. Quantum-safe by design.**

---

> **⚠ NOT PRODUCTION READY — Research Prototype**
>
> This codebase is a **research prototype / testnet demonstrator**.
> It has **not** undergone an external cryptographic audit.
> Known architectural limitations include:
> - ML-DSA signature verification partially inside the STARK circuit (MVP-3+, in progress)
> - FRI blowup=4 targets ~60-bit soundness; production requires ≥8 (128-bit)
> - No full on-chain FRI verifier — Blake2s commitment binding only (MVP-4)
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

**Phase 6 complete** (Sepolia testnet live since 2026-05-05). **MVP-3+ in progress** (7 of ~10 AIR circuits implemented).

| Component | Status |
|-----------|--------|
| `core/` — ML-DSA keys, signing, Merkle tree, batch | Done |
| `stark_stwo/src/mldsa/` — Pure Rust ML-DSA-65 verifier (FIPS 204) | Done |
| `stark_stwo/` — Stwo Circle STARK prover (Rust) | Done |
| `stark_stwo/src/` — ML-DSA arithmetic AIR circuits (NTT, INTT, PolyMul, PolyAdd, NormCheck, UseHint, Q-range check) | 7/~10 Done |
| `stark/` — Python prover/verifier wrappers, witness pipeline | Done |
| `contracts/` — BatchRegistry, BatchRegistryV2 (nonce registry), QLSAVerifier, V2, V3, QLSAVerifierFull | Done |
| `aggregator/` — Mempool, Batcher, AggregatorNode, rate limiting, HTTP API | Done |
| `tests/` — **243 Python tests + 181 Rust tests**, all passing | Done |
| `sdk/` — Python SDK (Wallet, LocalClient, HttpClient, WitnessStatus) + JS SDK | Done |
| Phase 6 — Sepolia testnet: first batch finalized (4 tx, 3234-byte proof, 9.16 s) | Done |

---

## Architecture

### Layer 1 — Signing

- ML-DSA-65 (FIPS 204)
- Address = `SHA3-256(pubkey)`

### Layer 2 — Aggregation (off-chain)

- Collect transactions (mempool → batcher)
- Verify ML-DSA-65 signatures (pure Rust FIPS 204 verifier)
- Build Merkle tree with SHA3-512 → `merkle_root`
- Generate Stwo Circle STARK proof → `stark_proof` + `onchain_commitment`
- Optional: prove ML-DSA arithmetic witness (MVP-3+ pipeline)

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

**Active AIR circuits (MVP-3+):**

| Circuit | Columns | Rows | Proves |
|---------|--------:|-----:|--------|
| NTT | 512+ | 256 | Forward NTT is correct |
| INTT | 512+ | 256 | Inverse NTT + fingerprint binding |
| PolyMul | — | 256 | Coefficient-wise multiply mod Q |
| PolyAdd | — | 256 | Coefficient-wise add mod Q |
| NormCheck | 3 | 256 | norm[i] = min(z[i], Q−z[i]) |
| UseHint | — | 256 | UseHint(h, r) = w1 |
| Q-range check | 48 | 256 | v ∈ [0, Q) via 23-bit decomposition |
| Az-full (AzProofV3) | — | 256×K | Full matrix-vector product A·z |

**c_tilde binding:** The FIPS 204 challenge c̃ is mixed into the Az-full Fiat-Shamir channel before the first trace commitment. This makes FRI query positions depend on c̃ — tampered challenge bytes cause verification to fail.

### Infrastructure

- Python 3.10+
- `liboqs-python==0.14.1`
- Solidity + Hardhat (OpenZeppelin v5)
- Deployed on Ethereum Sepolia testnet

---

## Security Notes

| Issue | Severity | Status |
|-------|----------|--------|
| ML-DSA verification partially inside AIR circuit | Critical | 🔄 In progress (MVP-3+, 7 circuits) |
| `QLSAVerifierFull` — Blake2s binding, not full FRI verifier | Critical | Partial (MVP-4 for full FRI) |
| Merkle root is not a public input of the STARK proof | Critical | Open (MVP-3+) |
| FRI blowup=4 → ~60-bit soundness (needs ≥8 for mainnet) | High | Partial |
| M31 wrap-around soundness gap in multiplication | High | ✅ Closed (Q-range check AIR, 2026-05-14) |
| c_tilde not bound to STARK proof | High | ✅ Done (Fiat-Shamir mixing, 2026-05-14) |
| No replay protection on-chain | High | ✅ Done (`submitBatchWithNonces()`, BatchRegistryV2) |
| API rate limiting | Medium | ✅ Done (100 tx/min, 20 batch ops/min per IP) |
| Private key zeroing in Python is best-effort | Medium | Open (needs Rust wrapper, MVP-4) |
| Hash AIR `H(a,b) = a³+b` not cryptographic | Low | Accepted for prototype |

For the full cryptography and security analysis, see `context.md`.

---

## Performance

| Metric | Value |
|--------|-------|
| Batch size | up to 3,000 tx |
| Proof size (hash chain STARK) | ~90–200 KB |
| On-chain verification | O(1) |
| Sepolia first batch (4 tx) | 3,234-byte proof, 9.16 s |
| ML-DSA batch verify (Rust FIPS 204, 4 sigs) | ~seconds |
| Prover time (MVP-3+ full witness, 49 sub-proofs) | ~53 s (dev build) |

Benchmarks: `/benchmarks/bench_core.py`, `bench_stark.py`, `bench_poly_circuits.py`, `bench_witnesses.py`.

---

## Repository Structure

```text
QLSA/
├── core/               # ML-DSA keys, signing, Merkle tree, batch
├── stark/              # Python prover/verifier wrappers, witness pipeline
├── stark_stwo/         # Stwo Circle STARK prover (Rust), ML-DSA arithmetic circuits
├── aggregator/         # Mempool, Batcher, AggregatorNode, HTTP API
├── contracts/          # Solidity: BatchRegistry(V2), QLSAVerifier(V2/V3/Full), Blake2s.sol
├── sdk/python/         # Python SDK: Wallet, LocalClient, HttpClient, WitnessStatus
├── sdk/js/             # TypeScript SDK: AggregatorClient
├── benchmarks/         # bench_core, bench_stark, bench_poly_circuits, bench_witnesses
├── testnet/            # e2e.py, deploy.sh, submit.py, monitor.py (Sepolia)
├── tests/              # 243 Python tests (pytest)
├── context.md          # Technical decisions and architecture log
└── README.md
```

---

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | ML-DSA keys, signing, Merkle tree, batch | ✅ Done |
| Phase 2 | Stwo Circle STARK prover (hash chain AIR) | ✅ Done |
| Phase 3 | Solidity contracts (BatchRegistry + verifier) | ✅ Done |
| Phase 3+ | M31 library + QLSAVerifierV2 + FRI blowup 4x | ✅ Done |
| Phase 3++ | Blake2s.sol + QLSAVerifierV3 + QLSAVerifierFull | ✅ Done |
| Phase 4 | Aggregator: Mempool, Batcher, AggregatorNode | ✅ Done |
| Phase 5 | SDK: Python + JavaScript + HTTP API | ✅ Done |
| MVP-3 | ML-DSA batch verifier (Rust FIPS 204) + STARK bridge | ✅ Done |
| **Phase 6** | **Testnet deployment — Sepolia, first batch 2026-05-05** | ✅ Done |
| **MVP-3+** | ML-DSA verification natively inside AIR circuit | 🔄 In progress (7/~10 circuits) |
| MVP-4 | Full on-chain FRI verifier, blowup≥8, RPO256 | ⏳ Future |

---

## Risks & Mitigations

### 1. ML-DSA inside STARK (main research challenge)

ML-DSA operations (NTT, rejection sampling, modular arithmetic) are expensive in AIR.
Proof size grows with the number of sub-proofs.

**Mitigation:**
- 7 circuits already proven (NTT, INTT, PolyMul, PolyAdd, NormCheck, UseHint, Q-range check)
- Full witness pipeline operational: `prove_mldsa_sig_witness_py` → `WitnessStatus`
- Remaining: UseHint integration, Merkle root as public input, full circuit composition

### 2. Aggregator trust model

Off-chain signature verification introduces trust in the aggregator until MVP-3+ is complete.

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
- Full on-chain FRI verifier (MVP-4, ~5K lines of Solidity)
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
