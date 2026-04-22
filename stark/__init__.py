"""
QLSA STARK layer — Phase 2 prototype.

The STARK proves:
  "I know N leaf values such that their hash-chain commitment equals C"
using a prototype algebraic hash H(a, b) = a^3 + b over a 64-bit prime field.

NOTE: The prototype hash is NOT cryptographically secure.
Production will replace it with Rescue Prime (RPO256) via Stwo.

Usage:
    from stark.prover import prove_batch
    from stark.verifier import verify_batch_proof
"""
