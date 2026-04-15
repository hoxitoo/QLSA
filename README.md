QLSA — Post-Quantum Rollup Infrastructure

Aggregate thousands of post-quantum signatures into a single constant-size proof.
O(1) on-chain verification. No trusted setup. Quantum-safe by design.

---

⚡ The Problem

Post-quantum cryptography is inevitable — but it breaks blockchain scalability.

Signature| Size| 3000 tx block
ECDSA (current)| ~70 bytes| ~220 KB ✅
ML-DSA-65 (FIPS 204)| ~2 420 bytes| ~7.2 MB ❌

A direct migration causes ×30–40 overhead per block, collapsing throughput.

«The bottleneck is not cryptography — it is infrastructure.»

---

💡 The Solution

QLSA is not a new signature scheme.

It is a post-quantum aggregation layer that makes PQ signatures usable at scale.

Core idea:

Aggregate "N" ML-DSA signatures
Produce 1 STARK proof (constant size)
---

✅ Properties

O(1) on-chain verification
No trusted setup (FRI-based STARK)
Post-quantum secure (lattice + hash)
Deployable as L2 (no hard fork required)
Crypto-agile (algorithm versioning supported)
---

🏗 Architecture

Layer 1 — Signing

ML-DSA-65 (FIPS 204)
Address = "SHA3-256(pubkey)"
Standard wallet UX
---

Layer 2 — Aggregation (off-chain)

Collect transactions
Verify ML-DSA signatures
Build Merkle tree ("SHA3-512")
Generate STARK proof
---

Layer 3 — Verification (on-chain)

Verify STARK proof (constant cost)
Store "merkle_root"
Finalize batch
---

🧠 Key Design Decisions

Public inputs = Merkle roots only
→ keeps verification truly O(1)

Heavy computation is off-chain
→ scalable by design

Protocol not tied to specific prover
→ crypto-agile architecture

---

🚧 MVP Strategy

Full ML-DSA inside STARK is high-risk.

QLSA follows a staged rollout:

Phase| STARK proves| ML-DSA inside STARK
MVP-1| Core crypto only| ❌
MVP-2| Merkle correctness| ❌
MVP-3| ML-DSA verification| ✅ (research)

👉 Deliver working system fast, expand later.

---

🔬 Tech Stack (2026)

Cryptographic Core

ML-DSA-65 — FIPS 204
SHA3-512 — Merkle hashing
SHA3-256 — address scheme
---

STARK Layer

Stage| Stack| Notes
Prototype| Winterfell v0.13.1| ⚠️ Not perfect ZK
Production| Stwo (Circle STARK)| High-performance, no trusted setup

---

Infrastructure

Python 3.10+
liboqs-python ≥ 0.14.0
Solidity + Hardhat
Target: Polygon zkEVM / Starknet
---

📊 Performance Targets

Metric| Target
Batch size| 3000 tx
Proof size| 90–200 KB
Verification| O(1)
Prover time (MVP-2)| seconds–minutes
Prover time (MVP-3)| TBD

---

⚠️ Key Risks & Mitigations

ML-DSA inside STARK (main risk)

Expensive operations (NTT, modular arithmetic)
Proof size may increase significantly
Mitigation:

Keep ML-DSA outside STARK in MVP
Benchmark before integration
---

Aggregator trust model

Off-chain verification introduces trust

Mitigation (planned):

Fraud proofs
Permissionless aggregators
---

Adoption timeline

PQ adoption is inevitable but gradual (3–7 years)

Focus:

Early adopters (CBDCs, gov systems, long-term storage)
---

💰 Economics (Draft)

Users pay fee for batch inclusion
Aggregators receive rewards
Incentive = gas saved vs naive verification
Future:

Fraud proof penalties
Decentralized aggregator market
---

🧩 Future Extensions

Threshold signatures (t-of-n)
Multi-party aggregation
Full zk aggregation (ML-DSA in AIR)
Native PQ rollup chain
---

🗺 Roadmap

Phase 1 — Core

ML-DSA keys, signing, verification
Merkle tree
Phase 2 — STARK (prototype)

Merkle inside STARK
Benchmarks
Phase 3 — Smart Contracts

On-chain verifier
Batch registry
Phase 4 — Aggregator Node

Mempool + batching
Phase 5 — SDK

Python + JS
Phase 6 — Testnet

Polygon zkEVM / Starknet
---

📂 Repository Structure

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