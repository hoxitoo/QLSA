# QLSA — Post-Quantum Rollup Infrastructure

Aggregate thousands of post-quantum signatures into a single constant-size proof.

**O(1) on-chain verification. No trusted setup. Quantum-safe by design.**

---

## ⚡ The Problem

Post-quantum cryptography is inevitable — but it breaks blockchain scalability.

| Signature | Size | 3000 tx block |
|----------|------:|--------------:|
| ECDSA (current) | ~70 bytes | ~220 KB ✅ |
| ML-DSA-65 (FIPS 204) | ~2,420 bytes | ~7.2 MB ❌ |

A direct migration causes **~30–40x overhead per block**, collapsing throughput.

> The bottleneck is not cryptography — it is infrastructure.

---

## 💡 The Solution

QLSA is **not a new signature scheme**.

It is a **post-quantum aggregation layer** that makes PQ signatures usable at scale.

### Core idea

- Aggregate **N** ML-DSA signatures
- Produce **1 STARK proof** of constant size

---

## ✅ Properties

- O(1) on-chain verification
- No trusted setup (FRI-based STARK)
- Post-quantum secure (lattice + hash)
- Deployable as L2 (no hard fork required)
- Crypto-agile (algorithm versioning supported)

---

## 🏗 Architecture

### Layer 1 — Signing

- ML-DSA-65 (FIPS 204)
- Address = `SHA3-256(pubkey)`
- Standard wallet UX

### Layer 2 — Aggregation (off-chain)

- Collect transactions
- Verify ML-DSA signatures
- Build Merkle tree with `SHA3-512`
- Generate STARK proof

### Layer 3 — Verification (on-chain)

- Verify STARK proof at constant cost
- Store `merkle_root`
- Finalize batch

---

## 🏗 Architecture

### Layer 1 — Signing

- ML-DSA-65 (FIPS 204)
- Address = `SHA3-256(pubkey)`
- Standard wallet UX

### Layer 2 — Aggregation (off-chain)

- Collect transactions
- Verify ML-DSA signatures
- Build Merkle tree with `SHA3-512`
- Generate STARK proof

### Layer 3 — Verification (on-chain)

- Verify STARK proof at constant cost
- Store `merkle_root`
- Finalize batch

---

👉 Deliver working system fast, expand later.

---

🔬 Tech Stack (2026)

### Cryptographic Core

- **ML-DSA-65** — FIPS 204
- **SHA3-512** — Merkle hashing
- **SHA3-256** — address scheme

### STARK Layer

| Stage | Stack | Notes |
|------|------|------|
| Prototype | Winterfell v0.13.1 | Not perfect zero-knowledge |
| Production | Stwo (Circle STARK) | High-performance, no trusted setup |

### Infrastructure

- Python 3.10+
- `liboqs-python >= 0.14.0`
- Solidity + Hardhat
- Target L2: Polygon zkEVM / Starknet

---

## 📊 Performance Targets

| Metric | Target |
|------|--------|
| Batch size | 3,000 tx |
| Proof size | 90–200 KB |
| On-chain verification | O(1) |
| Prover time (MVP-2) | seconds to minutes |
| Prover time (MVP-3) | TBD |

> Benchmarks will be published in `/benchmarks/` as development progresses.

---

## ⚠️ Key Risks & Mitigations

### 1. ML-DSA inside STARK (main risk)

ML-DSA operations such as NTT and modular arithmetic are expensive in AIR.  
Proof size may grow significantly.

**Mitigation:**
- Keep ML-DSA outside STARK in MVP
- Benchmark feasibility before full integration

### 2. Aggregator trust model

Off-chain verification introduces trust in the aggregator.

**Planned mitigation:**
- Fraud proofs
- Permissionless aggregators

### 3. Adoption timeline

PQ adoption is inevitable, but gradual.

**Focus areas:**
- CBDCs
- Government systems
- Long-term archival infrastructure

---

## 💰 Economics (Draft)

- Users pay a fee for batch inclusion
- Aggregators receive rewards
- Incentives are based on gas saved versus naive verification

### Future

- Fraud-proof penalties
- Decentralized aggregator market

---

## 🧩 Future Extensions

- Threshold signatures (`t-of-n`)
- Multi-party aggregation
- Full zk aggregation (ML-DSA in AIR)
- Native PQ rollup chain

---

## 🗺 Roadmap

### Phase 1 — Core
- ML-DSA keys
- Signing
- Verification
- Merkle tree

### Phase 2 — STARK (prototype)
- Merkle inside STARK
- Benchmarks

### Phase 3 — Smart Contracts
- On-chain verifier
- Batch registry

### Phase 4 — Aggregator Node
- Mempool
- Batching logic

### Phase 5 — SDK
- Python SDK
- JavaScript SDK

### Phase 6 — Testnet
- Polygon zkEVM / Starknet deployment

---

## 📂 Repository Structure

```text
qlsa/
├── core/
├── aggregator/
├── stark/
├── contracts/
├── sdk/
├── benchmarks/
├── docs/
├── tests/
└── CONTEXT.md

---

📌 Current Status

Phase: 1 — Core
In progress: "core/keys.py"
Next: "core/signing.py"
---

🧠 Why Now

NIST finalized PQC standards (FIPS 203–205)
Quantum threat: “harvest now, decrypt later”
STARK infrastructure matured (Stwo, 2025)
PQ migration window is open — but narrowing
---

🤝 Contributing

Early-stage deep-tech project.

Looking for contributors in:

Cryptography
ZK / STARKs
Blockchain infrastructure
---

📜 License

Apache 2.0

---

⚠️ Disclaimer

QLSA is experimental research software.
Do not use in production systems.