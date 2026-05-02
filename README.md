# QLSA — Post-Quantum Rollup Infrastructure

Aggregate thousands of post-quantum signatures into a single constant-size proof.

**O(1) on-chain verification. No trusted setup. Quantum-safe by design.**

---

> **⚠ NOT PRODUCTION READY — Research Prototype**
>
> This codebase is a **research prototype / testnet-ready demonstrator**.
> It has **not** undergone an external cryptographic audit.
> Known architectural limitations include:
> - ML-DSA signature verification happens off-chain, not inside the STARK circuit
> - The Merkle AIR lacks inter-node continuity constraints (lookup arguments not yet implemented)
> - LOG_BLOWUP = 4 targets ~120-bit FRI security; production parameters require formal review
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

**MVP-3 complete** (May 2026).

| Component | Status |
|-----------|--------|
| `core/` — ML-DSA keys, signing, Merkle tree, batch | Done |
| `stark_stwo/src/mldsa/` — Pure Rust ML-DSA-65 verifier (FIPS 204, 61 Rust tests) | Done |
| `stark_stwo/` — Stwo Circle STARK prover (Rust) + ML-DSA batch bridge | Done |
| `stark/` — Python prover/verifier wrappers (`prove_mldsa_batch`) | Done |
| `contracts/` — BatchRegistry, QLSAVerifier, QLSAVerifierV2, QLSAVerifierV3, QLSAVerifierFull | Done (Blake2s binding verifier) |
| `aggregator/` — Mempool, Batcher, AggregatorNode | Done |
| `tests/` — 135 Python tests + 61 Rust tests, all passing | Done |
| `sdk/` — Python SDK + JS SDK + HTTP API | Done |

> **Note:** `QLSAVerifier.sol` is a stub that always returns `true`. `QLSAVerifierFull` binds proof to commitment via Blake2s (commitment = Blake2s(proof[0:32])[:8]) but is not a full FRI verifier. Do not deploy to mainnet until the full on-chain STARK verifier (MVP-3+) is implemented.

---

## Architecture

### Layer 1 — Signing

- ML-DSA-65 (FIPS 204)
- Address = `SHA3-256(pubkey)`

### Layer 2 — Aggregation (off-chain)

- Collect transactions
- Verify ML-DSA-65 signatures (pure Rust FIPS 204 verifier — no liboqs)
- Build Merkle tree with SHA3-512 → `merkle_root`
- Generate Stwo Circle STARK proof → `stark_proof` + `stark_commitment`

### Layer 3 — Verification (on-chain)

- Verify STARK proof at constant cost
- Store `merkle_root` in BatchRegistry
- Finalize batch

---

## Tech Stack

### Cryptographic Core

- **ML-DSA-65** — FIPS 204 (liboqs-python 0.14.1)
- **SHA3-512** — Merkle hashing
- **SHA3-256** — address scheme

### STARK Layer

| Stage | Stack | Status |
|-------|-------|--------|
| Prototype | Stwo 2.2.0 (Circle STARK, Rust nightly-2025-07-01) | Active |
| Legacy | Winterfell v0.13.1 | Archived |

The current AIR circuit proves a hash chain `H(a,b) = a³ + b` over M31 (prototype).
This is **not a cryptographically secure hash**. The production circuit will use RPO256
and prove ML-DSA signature correctness directly inside the STARK (MVP-3).

### Infrastructure

- Python 3.10+
- `liboqs-python==0.14.1`
- Solidity + Hardhat (OpenZeppelin v5)
- Target L2: Polygon zkEVM / Starknet

---

## Security Notes

QLSA is experimental research software. Several known limitations exist that must
be resolved before any production or testnet deployment:

| Issue | Severity | Status |
|-------|----------|--------|
| ML-DSA verification happens outside the AIR circuit | Critical | Partial ✅ (Rust FIPS 204, prove_mldsa_batch) |
| `QLSAVerifierFull` is not a full FRI on-chain verifier | Critical | Partial (Blake2s binding only) |
| Merkle root is not a public input of the STARK proof | Critical | Open (MVP-3+) |
| M31 commitment is 32 bits — not cryptographically binding | High | Open |
| No replay protection on-chain (nonce registry missing) | High | Open |
| FRI blowup factor = 4 → ~60-bit soundness (needs 8+) | Medium | Partial |
| Private key zeroing in Python is best-effort, not guaranteed | Medium | Open |

For the full cryptography and security analysis, see `context.md`.

---

## Performance Targets

| Metric | Target |
|--------|--------|
| Batch size | 3,000 tx |
| Proof size | 90–200 KB |
| On-chain verification | O(1) |
| Prover time (current prototype, hash chain) | seconds to minutes |
| ML-DSA batch verify time (Rust FIPS 204, 4 sigs) | ~seconds |
| Prover time (MVP-3+, ML-DSA in AIR) | TBD |

Benchmarks are published in `/benchmarks/` as development progresses.

---

## Repository Structure

```text
QLSA/
├── core/               # Cryptographic kernel (ML-DSA, Merkle, batch)
├── stark/              # Python prover/verifier wrappers (subprocess)
├── stark_stwo/         # Stwo Circle STARK prover (Rust)
├── aggregator/         # Mempool, Batcher, AggregatorNode
├── contracts/          # Solidity contracts (Hardhat + OpenZeppelin v5)
├── benchmarks/         # Performance benchmarks
├── tests/              # 135 tests (pytest) + 61 Rust tests
├── docs/               # Architecture docs
├── context.md          # Technical context and decisions log
└── README.md
```

---

## Risks & Mitigations

### 1. ML-DSA inside STARK (main research challenge)

ML-DSA operations (NTT, rejection sampling, modular arithmetic) are expensive in AIR.
Proof size may grow significantly versus the current hash-chain prototype.

**Mitigation:**
- ML-DSA signature verification stays outside STARK in current MVP
- Benchmark AIR feasibility before full integration
- Evaluate proof aggregation (recursive STARK) as fallback

### 2. Aggregator trust model

Off-chain signature verification introduces trust in the aggregator until MVP-3.

**Planned mitigation:**
- Fraud proofs
- Permissionless aggregators

### 3. Adoption timeline

PQ adoption is inevitable, but gradual.

**Focus areas:** CBDCs, government systems, long-term archival infrastructure.

---

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | ML-DSA keys, signing, Merkle tree, batch | Done |
| Phase 2 | Stwo Circle STARK prover (hash chain AIR) | Done |
| Phase 3 | Solidity contracts (BatchRegistry + stub verifier) | Done |
| Phase 4 | Aggregator: Mempool, Batcher, Node | Done |
| Phase 5 | SDK: Python + JavaScript + HTTP API | Done |
| Phase 3+ | M31 field library + QLSAVerifierV2 + FRI blowup 4x | Done |
| Phase 3++ | Blake2s-256 library + QLSAVerifierV3 (MIN_PROOF_LENGTH=700) | Done |
| QLSAVerifierFull | Blake2s FRI root binding: proof[:32] → commitment | Done |
| MVP-3 | ML-DSA batch verifier (Rust FIPS 204) + STARK bridge | Done |
| MVP-3+ | ML-DSA verification natively inside AIR circuit | Research |
| Phase 6 | Testnet deployment (Polygon zkEVM / Starknet) | Next |

---

## Economics (Draft)

- Users pay a fee for batch inclusion
- Aggregators receive rewards proportional to gas saved vs naive verification
- Future: fraud-proof penalties, decentralized aggregator market

---

## Future Extensions

- Threshold signatures (`t-of-n`)
- Multi-party aggregation
- Full zk aggregation (ML-DSA in AIR)
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
