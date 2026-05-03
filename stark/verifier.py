"""
Python interface to the qlsa_stark_stwo native extension — verify side.

Install the extension once before use:
    cd stark_stwo && maturin develop --features python --release
"""

from __future__ import annotations

import qlsa_stark_stwo as _ext


def verify_batch_proof(proof: bytes, commitment: str, log_size: int) -> bool:
    """
    Verify a Circle STARK proof (Stwo 2.2.0) for the given batch.

    Args:
        proof:      Raw proof bytes (from ProofResult.proof).
        commitment: 32-char hex commitment string (from ProofResult.commitment).
        log_size:   log₂(trace length) (from ProofResult.log_size).

    Returns:
        True if the proof is valid, False otherwise.
    """
    return _ext.verify(proof, commitment, log_size)
