"""
QLSA STARK layer — Stwo Circle STARK backend (Phase 2+).

The STARK proves:
  "The SHA3-512 Merkle root of this batch, split into 8 × u64 chunks,
   produces hash-chain commitment C under H(a,b) = a³+b over M31."

This cryptographically binds the on-chain Merkle root to the STARK commitment.

NOTE: H(a,b) = a³+b is a prototype algebraic hash — not cryptographically
secure in isolation. Production upgrade: replace with Poseidon2 over M31.

Usage:
    from stark.prover import prove_batch
    from stark.verifier import verify_batch_proof
"""
