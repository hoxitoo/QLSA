"""
Python wrapper around the qlsa-stark-stwo Rust binary — verify side.
"""

from __future__ import annotations

import base64
import json
import subprocess

from stark.prover import BINARY, binary_available


def verify_batch_proof(proof: bytes, commitment: str, log_size: int) -> bool:
    """
    Verify a Circle STARK proof (Stwo 2.2.0) for the given batch.

    Args:
        proof:      Raw proof bytes (from ProofResult.proof).
        commitment: Hex commitment string (from ProofResult.commitment).
        log_size:   log₂(trace length) (from ProofResult.log_size).

    Returns:
        True if the proof is valid, False otherwise.

    Raises:
        RuntimeError if the binary is not built or crashes unexpectedly.
    """
    if not binary_available():
        raise RuntimeError(
            f"STARK binary not found at {BINARY}. "
            "Build it with: cd stark_stwo && cargo +nightly-2025-07-01 build --release"
        )

    payload = json.dumps({
        "proof":      base64.b64encode(proof).decode("ascii"),
        "commitment": commitment,
        "log_size":   log_size,
    })

    try:
        proc = subprocess.run(
            [str(BINARY), "verify"],
            input=payload.encode(),
            capture_output=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("qlsa-stark-stwo verify timed out after 120 s")

    if proc.returncode != 0:
        stderr = proc.stderr.decode(errors="replace")
        raise RuntimeError(
            f"qlsa-stark-stwo verify failed (exit {proc.returncode}):\n{stderr}"
        )

    try:
        out = json.loads(proc.stdout.decode(errors="replace"))
        return bool(out["valid"])
    except (json.JSONDecodeError, KeyError) as exc:
        raise RuntimeError(f"qlsa-stark-stwo verify returned invalid JSON: {exc}") from exc
