"""
Python wrapper around the qlsa-stark Rust binary — prove side.

The binary is expected at:
  stark/target/release/qlsa-stark   (relative to repo root)

Build it with:
  cd stark && cargo build --release
"""

from __future__ import annotations

import base64
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from core.batch import Batch


BINARY = Path(__file__).parent / "target" / "release" / "qlsa-stark"


@dataclass
class ProofResult:
    proof: bytes       # raw proof bytes (serialised Winterfell StarkProof)
    commitment: str    # hex-encoded field element (16 hex chars)


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
            "Build it with: cd stark && cargo build --release"
        )

    leaves = _txs_to_leaves(batch)
    result = _call_prover(leaves)

    batch.stark_commitment = result.commitment
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

    proc = subprocess.run(
        [str(BINARY), "prove"],
        input=payload.encode(),
        capture_output=True,
        timeout=300,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"qlsa-stark prove failed (exit {proc.returncode}):\n"
            f"{proc.stderr.decode()}"
        )

    out = json.loads(proc.stdout.decode())
    proof_bytes = base64.b64decode(out["proof"])
    return ProofResult(proof=proof_bytes, commitment=out["commitment"])
