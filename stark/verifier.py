"""
Python wrapper around the qlsa-stark Rust binary — verify side.
"""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

from stark.prover import BINARY, binary_available


def verify_batch_proof(proof: bytes, commitment: str) -> bool:
    """
    Verify a STARK proof for the given batch commitment.

    Args:
        proof:      Raw proof bytes (from ProofResult.proof).
        commitment: Hex commitment string (from ProofResult.commitment).

    Returns:
        True if the proof is valid, False otherwise.

    Raises:
        RuntimeError if the binary is not built or crashes unexpectedly.
    """
    if not binary_available():
        raise RuntimeError(
            f"STARK binary not found at {BINARY}. "
            "Build it with: cd stark && cargo build --release"
        )

    payload = json.dumps({
        "proof":      base64.b64encode(proof).decode("ascii"),
        "commitment": commitment,
    })

    proc = subprocess.run(
        [str(BINARY), "verify"],
        input=payload.encode(),
        capture_output=True,
        timeout=120,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"qlsa-stark verify failed (exit {proc.returncode}):\n"
            f"{proc.stderr.decode()}"
        )

    out = json.loads(proc.stdout.decode())
    return bool(out["valid"])
