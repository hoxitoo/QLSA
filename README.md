# QLSA
Quantum-Layered Signature Aggregation — post-quantum signature aggregation protocol for next-generation blockchain infrastructure.


The Problem
Current blockchain networks rely on ECDSA and Schnorr signatures — both vulnerable to quantum attacks via Shor's algorithm. As quantum computing scales, billions of dollars in on-chain assets face existential risk.
Existing post-quantum proposals either:

Sacrifice signature aggregation (making multi-party protocols impractical)
Introduce unacceptable latency for real-time consensus
Lack native Layer-1 integration paths

No production-ready solution exists today.

✅ What QLSA Does

QLSA is a novel signature protocol that combines lattice-based cryptography with layered threshold aggregation — enabling: 

| Feature | QLSA | ECDSA | Naive PQC |
|---|---|---|---|
| Quantum-resistant | ✅ | ❌ | ✅ |
| Signature aggregation | ✅ | ✅ | ❌ |
| Threshold (t-of-n) | ✅ | Partial | ❌ |
| L1-compatible design | ✅ | ✅ | ❌ |


The core innovation: layered aggregation trees that compress n lattice-based signatures into a single constant-size proof, preserving threshold semantics.

Technical Overview
Cryptographic foundation:

CRYSTALS-Dilithium (NIST PQC Round 3 winner) via liboqs
Layered Merkle-style aggregation over lattice signatures
Threshold scheme: any t of n signers can produce valid aggregate

Stack:
<pre> ```text Python 3.11+
├── liboqs-python        # NIST PQC primitives
├── cryptography         # Key management
├── hashlib / hmac       # Merkle construction
└── pytest               # Test suite
Architecture:
qlsa/
├── core/
│   ├── keygen.py        # Dilithium keypair generation
│   ├── sign.py          # Individual signing
│   ├── aggregate.py     # Layered aggregation logic
│   └── verify.py        # Aggregate proof verification
├── threshold/
│   ├── coordinator.py   # t-of-n orchestration
│   └── shares.py        # Secret sharing scheme
├── benchmarks/          # Performance profiling
└── tests/               # Unit + integration tests ``` </pre>

Roadmap
Phase 0 — Research & Design

 Literature review: NIST PQC finalists
 Protocol specification
 Architecture design

Phase 1 — Core Implementation (current)

 Environment setup (liboqs, Python bindings)
 Key generation module
 Basic sign/verify pipeline
 Layered aggregation prototype

Phase 2 — Threshold Protocol

 t-of-n coordinator
 Secret sharing integration
 Multi-party test vectors

Phase 3 — Benchmarks & Whitepaper

 Performance vs ECDSA / Schnorr
 Formal security analysis
 Published whitepaper

Phase 4 — L1 Integration Prototype

 EVM-compatible verifier contract
 Testnet deployment

Research Context
  QLSA builds on:

  CRYSTALS-Dilithium — NIST FIPS 204 standard (2024)
  Boneh & Shacham threshold signature constructions
  STARK-based aggregation techniques adapted for lattice settings

This work is aligned with NIST's Post-Quantum Cryptography Standardization initiative and addresses the "harvest now, decrypt later" threat model increasingly relevant to long-lived blockchain assets.

Why We're Seeking AI Research Credits
  We're using large language models as a force multiplier for:

  Formal verification assistance — reasoning about security proofs
  Code review — catching subtle cryptographic implementation bugs
  Research synthesis — navigating NIST PQC literature efficiently
  Documentation — generating rigorous technical specifications

This is active, technical research — not a demo project.

Author
Independent researcher focused on post-quantum blockchain infrastructure.
Open to collaboration, feedback and research partnerships.

License
MIT — open research, open future.

QLSA is pre-production research software. Do not use in production systems.
