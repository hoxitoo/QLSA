"""
Python wrapper around the qlsa-stark-stwo Rust binary — prove side.

The binary is expected at:
  stark_stwo/target/release/qlsa-stark-stwo   (relative to repo root)

Build it with:
  cd stark_stwo && cargo +nightly-2025-07-01 build --release
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from core.batch import Batch


BINARY = Path(__file__).parent.parent / "stark_stwo" / "target" / "release" / "qlsa-stark-stwo"


@dataclass
class ProofResult:
    proof: bytes             # raw proof bytes (serialised Stwo StarkProof)
    commitment: str          # 8-char little-endian hex (4 bytes, M31) — for Rust verifier
    log_size: int            # log₂(trace length) — required by the Rust verifier
    onchain_commitment: str = field(default="")
    # onchain_commitment: 16-char hex (8 bytes) = Blake2s(proof[0:32] ∥ merkle_root[:32])[:8]
    # Use this as the commitment when submitting to QLSAVerifierBound / BatchRegistryV2.
    # The Merkle root binding ensures the proof cannot be replayed against a different batch.


def binary_available() -> bool:
    return BINARY.exists() and BINARY.is_file()


def prove_batch(batch: Batch) -> ProofResult:
    """
    Generate a STARK proof for the batch.

    Converts the SHA3-512 Merkle root to 8 × u64 leaves (little-endian),
    then runs the Rust prover.

    The `onchain_commitment` is bound to the Merkle root:
      Blake2s(proof[0:32] ∥ merkle_root[:32])[:8]
    This matches QLSAVerifierBound / BatchRegistryV2 on-chain.

    Raises RuntimeError if the binary is not built or the prover fails.
    """
    if not binary_available():
        raise RuntimeError(
            f"STARK binary not found at {BINARY}. "
            "Build it with: cd stark_stwo && cargo +nightly-2025-07-01 build --release"
        )

    leaves = _txs_to_leaves(batch)
    result = _call_prover(leaves, merkle_root=batch.merkle_root)

    batch.stark_commitment = result.commitment
    batch.stark_log_size = result.log_size
    return result


def _txs_to_leaves(batch: Batch) -> list[int]:
    # Feed the 64-byte SHA3-512 Merkle root as 8 × u64 leaves (little-endian).
    # This binds the STARK proof directly to the Merkle root stored on-chain:
    # the proof's commitment = hash_chain(root_chunk_0, ..., root_chunk_7).
    root: bytes = batch.merkle_root  # 64 bytes
    return [int.from_bytes(root[i : i + 8], "little") for i in range(0, 64, 8)]


def _call_prover(leaves: list[int], merkle_root: bytes | None = None) -> ProofResult:
    payload = json.dumps({"leaves": leaves})

    try:
        proc = subprocess.run(
            [str(BINARY), "prove"],
            input=payload.encode(),
            capture_output=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("qlsa-stark-stwo prove timed out after 300 s")

    if proc.returncode != 0:
        stderr = proc.stderr.decode(errors="replace")
        raise RuntimeError(
            f"qlsa-stark-stwo prove failed (exit {proc.returncode}):\n{stderr}"
        )

    try:
        out = json.loads(proc.stdout.decode(errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"qlsa-stark-stwo prove returned invalid JSON: {exc}") from exc

    try:
        proof_bytes = base64.b64decode(out["proof"])
        commitment = str(out["commitment"])
        log_size = int(out["log_size"])
    except (KeyError, ValueError) as exc:
        raise RuntimeError(f"qlsa-stark-stwo prove output missing field: {exc}") from exc

    if len(commitment) != 8:
        raise RuntimeError(
            f"qlsa-stark-stwo prove returned unexpected commitment length "
            f"({len(commitment)} chars, expected 8)"
        )

    if len(proof_bytes) < 32:
        raise RuntimeError(
            f"qlsa-stark-stwo prove returned proof shorter than 32 bytes "
            f"({len(proof_bytes)} bytes) — cannot compute on-chain commitment"
        )

    # Compute on-chain commitment for QLSAVerifierBound / BatchRegistryV2:
    # Blake2s(proof[0:32] ∥ merkle_root[:32])[:8] — binds proof to Merkle root.
    # Falls back to Blake2s(proof[0:32])[:8] when merkle_root is not provided
    # (legacy path for QLSAVerifierFull compatibility).
    binding_input = proof_bytes[:32]
    if merkle_root is not None:
        binding_input = binding_input + merkle_root[:32]
    onchain_commitment = hashlib.blake2s(binding_input).digest()[:8].hex()

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

    Uses the same 8 × u64 leaf encoding as prove_batch, but the hash chain
    inside the STARK uses a cryptographically secure Poseidon2 permutation
    (6 full rounds, α=5, MDS [[3,1],[1,3]] over M31) instead of the
    prototype H(a,b) = a³+b.

    The `onchain_commitment` binding formula is unchanged:
      Blake2s(proof[0:32] ∥ merkle_root[:32])[:8]

    Raises RuntimeError if the binary is not built or the prover fails.
    """
    if not binary_available():
        raise RuntimeError(
            f"STARK binary not found at {BINARY}. "
            "Build it with: cd stark_stwo && cargo +nightly-2025-07-01 build --release"
        )

    leaves = _txs_to_leaves(batch)
    result = _call_prover_p2(leaves, merkle_root=batch.merkle_root)

    batch.stark_commitment = result.commitment
    batch.stark_log_size = result.log_size
    return result


def _call_prover_p2(
    leaves: list[int], merkle_root: bytes | None = None
) -> Poseidon2ProofResult:
    """Call the `prove_p2` command on the Rust binary."""
    payload = json.dumps({"leaves": leaves})

    try:
        proc = subprocess.run(
            [str(BINARY), "prove_p2"],
            input=payload.encode(),
            capture_output=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("qlsa-stark-stwo prove_p2 timed out after 300 s")

    if proc.returncode != 0:
        stderr = proc.stderr.decode(errors="replace")
        raise RuntimeError(
            f"qlsa-stark-stwo prove_p2 failed (exit {proc.returncode}):\n{stderr}"
        )

    try:
        out = json.loads(proc.stdout.decode(errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"qlsa-stark-stwo prove_p2 returned invalid JSON: {exc}"
        ) from exc

    try:
        proof_bytes = base64.b64decode(out["proof"])
        commitment = str(out["commitment"])
        log_size = int(out["log_size"])
    except (KeyError, ValueError) as exc:
        raise RuntimeError(
            f"qlsa-stark-stwo prove_p2 output missing field: {exc}"
        ) from exc

    if len(proof_bytes) < 32:
        raise RuntimeError(
            f"qlsa-stark-stwo prove_p2 returned proof shorter than 32 bytes "
            f"({len(proof_bytes)} bytes)"
        )

    binding_input = proof_bytes[:32]
    if merkle_root is not None:
        binding_input = binding_input + merkle_root[:32]
    onchain_commitment = hashlib.blake2s(binding_input).digest()[:8].hex()

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
    if not binary_available():
        raise RuntimeError(
            f"STARK binary not found at {BINARY}. "
            "Build it with: cd stark_stwo && cargo +nightly-2025-07-01 build --release"
        )

    payload = json.dumps({
        "entries": [
            {
                "pk":  base64.b64encode(pk).decode(),
                "msg": base64.b64encode(msg).decode(),
                "sig": base64.b64encode(sig).decode(),
            }
            for pk, msg, sig in entries
        ]
    })

    try:
        proc = subprocess.run(
            [str(BINARY), "mldsa_batch"],
            input=payload.encode(),
            capture_output=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("qlsa-stark-stwo mldsa_batch timed out after 300 s")

    if proc.returncode != 0:
        stderr = proc.stderr.decode(errors="replace")
        raise RuntimeError(
            f"qlsa-stark-stwo mldsa_batch failed (exit {proc.returncode}):\n{stderr}"
        )

    try:
        out = json.loads(proc.stdout.decode(errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"qlsa-stark-stwo mldsa_batch returned invalid JSON: {exc}") from exc

    proof_bytes = base64.b64decode(out["proof"])
    onchain_commitment = hashlib.blake2s(proof_bytes[:32]).digest()[:8].hex()

    return MldsaBatchResult(
        proof=proof_bytes,
        commitment=str(out["commitment"]),
        log_size=int(out["log_size"]),
        onchain_commitment=onchain_commitment,
        verified=int(out["verified"]),
        rejected=int(out["rejected"]),
    )
