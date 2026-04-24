"""
Python wrapper around the qlsa-stark-stwo Rust binary — prove side.

The binary is expected at:
  stark_stwo/target/release/qlsa-stark-stwo   (relative to repo root)

Build it with:
  cd stark_stwo && cargo +nightly-2025-07-01 build --release
"""

from __future__ import annotations

import base64
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from core.batch import Batch


BINARY = Path(__file__).parent.parent / "stark_stwo" / "target" / "release" / "qlsa-stark-stwo"


@dataclass
class ProofResult:
    proof: bytes       # raw proof bytes (serialised Stwo StarkProof)
    commitment: str    # 8-char little-endian hex (4 bytes, M31 field element)
    log_size: int      # log₂(trace length) — required by the verifier


def binary_available() -> bool:
    return BINARY.exists() and BINARY.is_file()


def prove_batch(batch: Batch) -> ProofResult:
    """
    Generate a STARK proof for the batch.

    Converts each transaction's SHA3-256 tx_hash to a 64-bit leaf value
    (first 8 bytes, little-endian), then runs the Rust prover.

    Raises RuntimeError if the binary is not built or the prover fails.
    """
    if not binary_available():
        raise RuntimeError(
            f"STARK binary not found at {BINARY}. "
            "Build it with: cd stark_stwo && cargo +nightly-2025-07-01 build --release"
        )

    leaves = _txs_to_leaves(batch)
    result = _call_prover(leaves)

    batch.stark_commitment = result.commitment
    batch.stark_log_size = result.log_size
    return result


def _txs_to_leaves(batch: Batch) -> list[int]:
    leaves = []
    for tx in batch.transactions:
        h = tx.tx_hash()           # 32-byte SHA3-256
        leaf = int.from_bytes(h[:8], "little")
        leaves.append(leaf)
    return leaves


def _call_prover(leaves: list[int]) -> ProofResult:
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

    return ProofResult(proof=proof_bytes, commitment=commitment, log_size=log_size)
