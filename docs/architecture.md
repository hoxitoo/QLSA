# QLSA — Architecture

> ⚠️ **STALE SNAPSHOT (pre-MVP-4).** This document describes an earlier
> architecture iteration (QLSAVerifierV3, FRI blowup ×4). The current
> production state is documented in `context.md` and `README.md`:
> V23 STARK pipeline, QLSAVerifierVFRI9, BatchRegistryV5, blowup ×64 /
> 130-bit soundness. Kept for historical reference only.

## Problem

Post-quantum signatures (ML-DSA-65, FIPS 204) are ~35× larger than ECDSA.
A 3000-tx block grows from ~220 KB to ~7.2 MB — breaking L1 throughput.

## Solution: Aggregation via Circle STARK

```
N signed transactions  →  1 STARK proof (~90–200 KB)  →  O(1) on-chain verification
```

---

## Data Flow

```
 ┌─────────────────────────────────────────────────────────────────────────┐
 │  WALLET (off-chain)                                                      │
 │                                                                          │
 │  ML-DSA-65 keypair  →  sign(tx.to_bytes())  →  signed Transaction       │
 └────────────────────────────┬────────────────────────────────────────────┘
                              │ HTTP POST /transactions
                              ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │  AGGREGATOR NODE (off-chain)                                             │
 │                                                                          │
 │  Mempool (FIFO, thread-safe, max 3000 tx)                                │
 │       │                                                                  │
 │       │ drain(max_batch_size)                                            │
 │       ▼                                                                  │
 │  1. Verify all ML-DSA signatures (Python / liboqs)                       │
 │  2. Build SHA3-512 Merkle tree  →  merkle_root (64 bytes)               │
 │  3. Split merkle_root (64 bytes) into 8 × u64 M31 leaves                 │
 │  4. Run Stwo Circle STARK prover  →  stark_proof + stark_commitment      │
 └────────────────────────────┬────────────────────────────────────────────┘
                              │ BatchResult
                              ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │  SMART CONTRACTS (on-chain)                                              │
 │                                                                          │
 │  BatchRegistry.submitBatch(merkleRoot, starkCommitment, starkProof)      │
 │       │                                                                  │
 │       │ IQLSAVerifier.verify(proof, commitment)                          │
 │       ▼                                                                  │
 │  QLSAVerifierV3  →  M31 range check + MIN_PROOF_LENGTH=700 + Blake2s    │
 │  (QLSAVerifierFull → full FRI decommitment + OODS + constraint check)   │
 │       │                                                                  │
 │       │ finalizedBatches[merkleRoot] = true                             │
 │       └──  emit BatchFinalized(merkleRoot, commitment, timestamp)        │
 └─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Map

| Layer | Component | Location | Status |
|-------|-----------|----------|--------|
| Signing | ML-DSA-65 keygen, sign, verify | `core/keys.py`, `core/signing.py` | Done |
| Transaction | Dataclass, hash, serialization | `core/transaction.py` | Done |
| Merkle | SHA3-512 tree, proof, verify | `core/merkle.py` | Done |
| Batch | Aggregate + verify N txs | `core/batch.py` | Done |
| STARK Prover | Stwo Circle STARK (Rust) | `stark_stwo/` | Done |
| STARK Python API | Subprocess wrapper | `stark/prover.py`, `stark/verifier.py` | Done |
| Mempool | Thread-safe FIFO queue | `aggregator/mempool.py` | Done |
| Batcher | Drain + prove | `aggregator/batcher.py` | Done |
| Node | Orchestrator | `aggregator/node.py` | Done |
| HTTP API | FastAPI server | `aggregator/api.py` | Done |
| Contracts | BatchRegistry + Verifier | `contracts/src/` | Done (structural) |
| M31 Library | On-chain field arithmetic | `contracts/src/verifier/M31.sol` | Done |
| Blake2s Library | On-chain Blake2s-256 (RFC 7693) | `contracts/src/verifier/Blake2s.sol` | Done (Phase 3++) |
| QLSAVerifierV3 | Structural verifier (MIN_PROOF_LENGTH=700) | `contracts/src/QLSAVerifierV3.sol` | Done (Phase 3++) |
| Python SDK | Wallet, Builder, Client | `sdk/python/qlsa/` | Done |
| JS SDK | AggregatorClient (TS) | `sdk/js/src/` | Done |

---

## STARK Circuit (Current — Phase 2+)

```
Leaves (M31):  merkle_root split into 8 × u64, each reduced mod (2^31 - 1)
               — binds the STARK proof directly to the on-chain Merkle root

AIR constraint:  h[i+1] = h[i]³ + leaf[i+1]   (H(a,b) = a³+b over M31)

Commitment:  h[n-2]  (last non-padding row, 4 bytes, M31 field element)
```

**Limitations (MVP-3 targets):**
- Does NOT prove ML-DSA signature correctness inside the circuit
- H(a,b) = a³+b is a prototype hash — not cryptographically secure in isolation
- Production upgrade: replace with Poseidon2 over M31

---

## STARK Circuit (Target — MVP-3)

```
Public inputs:  merkle_root (SHA3-512, 64 bytes)

Witness:  N signed transactions + N ML-DSA public keys + N ML-DSA signatures

AIR constraints:
  1. Each ML-DSA-65 signature verifies against the corresponding public key and tx_hash
     (requires NTT over Z_q, rejection sampling approximation, or IVC)
  2. Each tx_hash is correctly placed as a Merkle tree leaf
  3. The Merkle tree root matches the committed merkle_root
```

---

## On-Chain Verifier Roadmap

| Version | What it checks | Status |
|---------|---------------|--------|
| `QLSAVerifier` (stub) | proof.length ≥ 64, commitment ≠ 0 | Done |
| `QLSAVerifierV2` | + M31 range, + trailing zero bytes | Done (Phase 3+) |
| `QLSAVerifierV3` | + MIN_PROOF_LENGTH=700, trivial-proof guard, keccak binding, Blake2s imported | Done (Phase 3++) |
| `QLSAVerifierFull` | + Blake2s FRI root binding (commitment = Blake2s(proof[0:32])[:8]) | Done |
| `QLSAVerifierFinalFull` | + ML-DSA constraint satisfaction | MVP-3 |

---

## Security Properties

| Property | Current State | Target |
|----------|--------------|--------|
| ML-DSA signature validity | Verified off-chain (Python) | In STARK (MVP-3) |
| Merkle tree integrity | SHA3-512, Merkle root fed as STARK leaves | Full Merkle-in-STARK (MVP-3) |
| STARK soundness (FRI blowup) | 4× (~60-bit) | ≥8× (~90-bit) for production |
| On-chain binding | Structural (M31 range) | Full FRI (Phase 3++) |
| Replay protection | `BatchAlreadyFinalized` on-chain | Done |
| Key zeroing | Best-effort (`wipe_key`) | Rust `SecureZeroingMemory` (future) |

---

## Key Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Signature scheme | ML-DSA-65 (FIPS 204) | 2420-byte signatures |
| Merkle hash | SHA3-512 | 64-byte root |
| Address scheme | SHA3-256(pubkey) | 32-byte / 64-char hex |
| STARK field | M31 (2³¹−1) | Mersenne prime |
| STARK hash (prototype) | H(a,b) = a³+b | NOT cryptographically secure |
| FRI blowup | 4× (log=2) | ~60-bit soundness |
| Max batch size | 3000 tx | Enforced in Python + Rust |
| Proof size target | 90–200 KB | Constant regardless of N |
| Target L2 | Polygon zkEVM / Starknet | TBD at Phase 6 |
