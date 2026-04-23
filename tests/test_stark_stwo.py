"""
Additional Stwo Circle STARK tests exercising edge-cases and the CLI directly.

Skipped automatically when the binary is not compiled. Build with:
    cd stark_stwo && cargo +nightly-2025-07-01 build --release
"""

from __future__ import annotations

import base64
import json
import subprocess

import pytest

from stark.prover import BINARY, binary_available

needs_binary = pytest.mark.skipif(
    not binary_available(),
    reason="qlsa-stark-stwo not built",
)


def _prove(leaves: list[int]) -> dict:
    proc = subprocess.run(
        [str(BINARY), "prove"],
        input=json.dumps({"leaves": leaves}).encode(),
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout)


def _verify(proof: str, commitment: str, log_size: int) -> bool:
    proc = subprocess.run(
        [str(BINARY), "verify"],
        input=json.dumps({"proof": proof, "commitment": commitment, "log_size": log_size}).encode(),
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout)["valid"]


# ──────────────────────────────────────────────────────────────────────────────
# CLI smoke tests
# ──────────────────────────────────────────────────────────────────────────────

@needs_binary
def test_prove_output_schema():
    out = _prove([1, 2, 3, 4])
    assert "proof" in out
    assert "commitment" in out
    assert "log_size" in out
    assert len(out["commitment"]) == 8
    assert out["log_size"] >= 3
    base64.b64decode(out["proof"])  # must be valid base64


@needs_binary
def test_prove_verify_roundtrip_small():
    out = _prove([1, 2, 3, 4, 5, 6, 7, 8])
    assert _verify(out["proof"], out["commitment"], out["log_size"])


@needs_binary
def test_prove_verify_roundtrip_single_leaf():
    out = _prove([42])
    assert _verify(out["proof"], out["commitment"], out["log_size"])


@needs_binary
def test_prove_verify_roundtrip_large_values():
    leaves = [2**63 - 1, 2**32, 0, 1]
    out = _prove(leaves)
    assert _verify(out["proof"], out["commitment"], out["log_size"])


@needs_binary
def test_commitment_is_8_hex_chars():
    out = _prove([10, 20, 30])
    assert len(out["commitment"]) == 8
    int(out["commitment"], 16)  # must be valid hex


@needs_binary
def test_tampered_proof_fails_verify():
    out = _prove([1, 2, 3, 4])
    raw = bytearray(base64.b64decode(out["proof"]))
    raw[8] ^= 0xFF
    bad_proof = base64.b64encode(bytes(raw)).decode()
    assert not _verify(bad_proof, out["commitment"], out["log_size"])


@needs_binary
def test_wrong_log_size_fails_verify():
    out = _prove([1, 2, 3, 4])
    wrong_log = out["log_size"] + 1
    # Verification should either return False or error — both are acceptable.
    proc = subprocess.run(
        [str(BINARY), "verify"],
        input=json.dumps({
            "proof": out["proof"],
            "commitment": out["commitment"],
            "log_size": wrong_log,
        }).encode(),
        capture_output=True,
        timeout=60,
    )
    # Either non-zero exit or valid=False
    if proc.returncode == 0:
        assert not json.loads(proc.stdout)["valid"]


@needs_binary
def test_log_size_grows_with_more_leaves():
    out_small = _prove([1, 2, 3, 4])
    out_large = _prove(list(range(1, 33)))  # 32 leaves → larger trace
    assert out_large["log_size"] >= out_small["log_size"]


@needs_binary
def test_different_leaves_give_different_commitments():
    out_a = _prove([1, 2, 3, 4])
    out_b = _prove([5, 6, 7, 8])
    assert out_a["commitment"] != out_b["commitment"]
