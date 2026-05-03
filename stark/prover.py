"""
Python interface to the qlsa_stark_stwo native extension (PyO3).

Install the extension once before use:
    cd stark_stwo && maturin develop --features python --release

The extension exposes prove/verify pairs for three circuits:
  prove / verify           — hash-chain (MVP-2)
  prove_p2 / verify_p2    — Poseidon2 hash-chain (MVP-3)
  prove_merkle / verify_merkle — Poseidon2 Merkle tree (MVP-3+)
  prove_mldsa              — ML-DSA-65 batch verification
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field

import qlsa_stark_stwo as _ext

from core.batch import Batch

logger = logging.getLogger(__name__)


@dataclass
class ProofResult:
    proof: bytes             # raw proof bytes (serialised Stwo StarkProof)
    commitment: str          # 32-char hex (16 bytes, 128-bit) — for Rust verifier
    log_size: int            # log₂(trace length) — required by the Rust verifier
    onchain_commitment: str = field(default="")
    # onchain_commitment: 32-char hex (16 bytes, 128-bit) = Blake2s(proof[0:32] ∥ merkle_root[:32])[:16]
    # Use this as the commitment when submitting to QLSAVerifierBound / BatchRegistryV2.
    # The Merkle root binding ensures the proof cannot be replayed against a different batch.


def prove_batch(batch: Batch) -> ProofResult:
    """
    Generate a hash-chain STARK proof for the batch.

    Converts the SHA3-512 Merkle root to 8 × u64 leaves (little-endian),
    then calls the Rust prover.

    Raises RuntimeError if the extension is not installed or the prover fails.
    """
    leaves = _txs_to_leaves(batch)
    result = _call_prover(leaves, merkle_root=batch.merkle_root)
    batch.stark_commitment = result.commitment
    batch.stark_log_size = result.log_size
    return result


def _txs_to_leaves(batch: Batch) -> list[int]:
    # Feed the 64-byte SHA3-512 Merkle root as 8 × u64 leaves (little-endian).
    root: bytes = batch.merkle_root  # 64 bytes
    return [int.from_bytes(root[i : i + 8], "little") for i in range(0, 64, 8)]


def _call_prover(leaves: list[int], merkle_root: bytes | None = None) -> ProofResult:
    try:
        proof_bytes, commitment, log_size = _ext.prove(leaves)
    except Exception as exc:
        raise RuntimeError(f"qlsa-stark-stwo prove failed: {exc}") from exc

    if len(commitment) != 32:
        raise RuntimeError(
            f"qlsa-stark-stwo prove returned unexpected commitment length "
            f"({len(commitment)} chars, expected 32)"
        )
    if len(proof_bytes) < 32:
        raise RuntimeError(
            f"qlsa-stark-stwo prove returned proof shorter than 32 bytes "
            f"({len(proof_bytes)} bytes) — cannot compute on-chain commitment"
        )

    binding_input = proof_bytes[:32]
    if merkle_root is not None:
        binding_input = binding_input + merkle_root[:32]
    onchain_commitment = hashlib.blake2s(binding_input).digest()[:16].hex()

    return ProofResult(
        proof=proof_bytes,
        commitment=commitment,
        log_size=log_size,
        onchain_commitment=onchain_commitment,
    )


# ─── Poseidon2 hash-chain STARK (MVP-3+) ─────────────────────────────────────

@dataclass
class Poseidon2ProofResult(ProofResult):
    """ProofResult whose commitment is a Poseidon2-over-M31 hash of the leaves."""


def prove_batch_poseidon2(batch: Batch) -> Poseidon2ProofResult:
    """
    Generate a Poseidon2-over-M31 STARK proof for the batch.

    The `onchain_commitment` binding formula is unchanged:
      Blake2s(proof[0:32] ∥ merkle_root[:32])[:16]

    Raises RuntimeError if the extension is not installed or the prover fails.
    """
    leaves = _txs_to_leaves(batch)
    result = _call_prover_p2(leaves, merkle_root=batch.merkle_root)
    batch.stark_commitment = result.commitment
    batch.stark_log_size = result.log_size
    return result


def _call_prover_p2(
    leaves: list[int], merkle_root: bytes | None = None
) -> Poseidon2ProofResult:
    try:
        proof_bytes, commitment, log_size = _ext.prove_p2(leaves)
    except Exception as exc:
        raise RuntimeError(f"qlsa-stark-stwo prove_p2 failed: {exc}") from exc

    if len(proof_bytes) < 32:
        raise RuntimeError(
            f"qlsa-stark-stwo prove_p2 returned proof shorter than 32 bytes "
            f"({len(proof_bytes)} bytes)"
        )

    binding_input = proof_bytes[:32]
    if merkle_root is not None:
        binding_input = binding_input + merkle_root[:32]
    onchain_commitment = hashlib.blake2s(binding_input).digest()[:16].hex()

    return Poseidon2ProofResult(
        proof=proof_bytes,
        commitment=commitment,
        log_size=log_size,
        onchain_commitment=onchain_commitment,
    )


# ─── ML-DSA batch verification + STARK proof ─────────────────────────────────

@dataclass
class MldsaBatchResult(ProofResult):
    verified: int = 0  # number of valid signatures included in proof
    rejected: int = 0  # number of invalid signatures skipped


def prove_mldsa_batch(
    entries: list[tuple[bytes, bytes, bytes]],
) -> MldsaBatchResult:
    """
    Verify N ML-DSA-65 signatures in Rust and generate a STARK proof.

    Each entry is (pk_bytes, msg_bytes, sig_bytes).
    Invalid signatures are silently skipped; at least one must be valid.

    Returns a MldsaBatchResult with the STARK proof and verification counts.
    """
    try:
        proof_bytes, commitment, log_size, verified, rejected = _ext.prove_mldsa(entries)
    except Exception as exc:
        raise RuntimeError(f"qlsa-stark-stwo mldsa_batch failed: {exc}") from exc

    onchain_commitment = hashlib.blake2s(proof_bytes[:32]).digest()[:16].hex()

    return MldsaBatchResult(
        proof=proof_bytes,
        commitment=commitment,
        log_size=log_size,
        onchain_commitment=onchain_commitment,
        verified=verified,
        rejected=rejected,
    )


# ─── Poseidon2 Merkle-tree STARK ─────────────────────────────────────────────

@dataclass
class MerkleProofResult(ProofResult):
    """ProofResult whose commitment is a Poseidon2 Merkle root (M31 hex)."""


def prove_batch_merkle(batch: Batch) -> MerkleProofResult:
    """
    Generate a Poseidon2 Merkle-tree STARK proof for the batch.

    The `onchain_commitment` binding formula is unchanged:
      Blake2s(proof[0:32] ∥ merkle_root[:32])[:16]

    Raises RuntimeError if the extension is not installed or the prover fails.
    """
    leaves = _txs_to_leaves(batch)
    result = _call_prover_merkle(leaves, merkle_root=batch.merkle_root)
    batch.stark_commitment = result.commitment
    batch.stark_log_size = result.log_size
    return result


def _call_prover_merkle(
    leaves: list[int], merkle_root: bytes | None = None
) -> MerkleProofResult:
    if merkle_root is None:
        import warnings
        warnings.warn(
            "_call_prover_merkle called without merkle_root: on-chain commitment "
            "will not be bound to any batch Merkle root.",
            stacklevel=3,
        )

    try:
        proof_bytes, commitment, log_size = _ext.prove_merkle(leaves)
    except Exception as exc:
        raise RuntimeError(f"qlsa-stark-stwo merkle_prove failed: {exc}") from exc

    if len(commitment) != 32:
        raise RuntimeError(
            f"qlsa-stark-stwo merkle_prove returned unexpected commitment length "
            f"({len(commitment)} chars, expected 32)"
        )
    if len(proof_bytes) < 32:
        raise RuntimeError(
            f"qlsa-stark-stwo merkle_prove returned proof shorter than 32 bytes "
            f"({len(proof_bytes)} bytes)"
        )

    binding_input = proof_bytes[:32]
    if merkle_root is not None:
        binding_input = binding_input + merkle_root[:32]
    onchain_commitment = hashlib.blake2s(binding_input).digest()[:16].hex()

    return MerkleProofResult(
        proof=proof_bytes,
        commitment=commitment,
        log_size=log_size,
        onchain_commitment=onchain_commitment,
    )
