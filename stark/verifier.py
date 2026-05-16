"""
Python interface to the qlsa_stark_stwo native extension — verify side.

Install the extension once before use:
    cd stark_stwo && maturin develop --features python --release
"""

from __future__ import annotations

try:
    import qlsa_stark_stwo as _ext
    _HAVE_EXT = True
except ImportError:
    _ext = None
    _HAVE_EXT = False


def verify_batch_proof(
    proof: bytes,
    commitment: str,
    log_size: int,
    merkle_root: bytes | None = None,
) -> bool:
    """
    Verify a Poseidon2 STARK proof for the given batch.

    Args:
        proof:       Raw proof bytes (from ProofResult.proof).
        commitment:  32-char hex commitment string (from ProofResult.commitment).
        log_size:    log₂(trace length) (from ProofResult.log_size).
        merkle_root: Optional SHA3-512 Merkle root bytes.  Must match the root
                     used during proving; otherwise verification fails.

    Returns:
        True if the proof is valid, False otherwise.
    """
    if not _HAVE_EXT:
        raise RuntimeError(
            "qlsa_stark_stwo extension required for verify_p2. "
            "Install with: cd stark_stwo && maturin develop --features python --release"
        )
    return bool(_ext.verify_p2(proof, commitment, log_size, merkle_root))


def verify_batch_poseidon2_proof(
    proof: bytes,
    commitment: str,
    log_size: int,
    seed: bytes | None = None,
) -> bool:
    """Alias for verify_batch_proof — both now use Poseidon2-over-M31 internally."""
    return verify_batch_proof(proof, commitment, log_size, merkle_root=seed)


def verify_batch_merkle_proof(
    proof: bytes,
    commitment: str,
    log_size: int,
    seed: bytes | None = None,
) -> bool:
    """Verify a Poseidon2 Merkle-tree STARK proof (prove_batch_merkle output).

    `seed` must match the batch Merkle root passed to prove_batch_merkle —
    it was mixed into the Fiat-Shamir transcript and must be replayed here.
    """
    if not _HAVE_EXT:
        raise RuntimeError(
            "qlsa_stark_stwo extension required for verify_merkle. "
            "Install with: cd stark_stwo && maturin develop --features python --release"
        )
    return bool(_ext.verify_merkle(proof, commitment, log_size, seed))
