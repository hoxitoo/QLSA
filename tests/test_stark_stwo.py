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


# ──────────────────────────────────────────────────────────────────────────────
# prove_p2 / verify_p2 CLI tests (Poseidon2 sponge hash chain)
# ──────────────────────────────────────────────────────────────────────────────

def _prove_p2(leaves: list[int]) -> dict:
    proc = subprocess.run(
        [str(BINARY), "prove_p2"],
        input=json.dumps({"leaves": leaves}).encode(),
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout)


def _verify_p2(proof: str, commitment: str, log_size: int) -> bool:
    proc = subprocess.run(
        [str(BINARY), "verify_p2"],
        input=json.dumps({"proof": proof, "commitment": commitment, "log_size": log_size}).encode(),
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout)["valid"]


@needs_binary
def test_prove_p2_output_schema():
    out = _prove_p2([1, 2, 3, 4])
    assert "proof" in out
    assert "commitment" in out
    assert "log_size" in out
    assert len(out["commitment"]) == 8
    base64.b64decode(out["proof"])


@needs_binary
def test_prove_p2_verify_p2_roundtrip():
    out = _prove_p2([1, 2, 3, 4, 5, 6, 7, 8])
    assert _verify_p2(out["proof"], out["commitment"], out["log_size"])


@needs_binary
def test_prove_p2_tampered_proof_fails():
    out = _prove_p2([1, 2, 3, 4])
    raw = bytearray(base64.b64decode(out["proof"]))
    raw[20] ^= 0xFF
    bad_proof = base64.b64encode(bytes(raw)).decode()
    assert not _verify_p2(bad_proof, out["commitment"], out["log_size"])


@needs_binary
def test_prove_p2_different_leaves_different_commitments():
    out_a = _prove_p2([1, 2, 3, 4])
    out_b = _prove_p2([5, 6, 7, 8])
    assert out_a["commitment"] != out_b["commitment"]


# ──────────────────────────────────────────────────────────────────────────────
# merkle_prove / merkle_verify CLI tests (Poseidon2 Merkle tree)
# ──────────────────────────────────────────────────────────────────────────────

def _merkle_prove(leaves: list[int]) -> dict:
    proc = subprocess.run(
        [str(BINARY), "merkle_prove"],
        input=json.dumps({"leaves": leaves}).encode(),
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout)


def _merkle_verify(proof: str, commitment: str, log_size: int) -> bool:
    proc = subprocess.run(
        [str(BINARY), "merkle_verify"],
        input=json.dumps({"proof": proof, "commitment": commitment, "log_size": log_size}).encode(),
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout)["valid"]


@needs_binary
def test_merkle_prove_output_schema():
    out = _merkle_prove([1, 2, 3, 4])
    assert "proof" in out
    assert "commitment" in out
    assert "log_size" in out
    assert len(out["commitment"]) == 8
    int(out["commitment"], 16)  # must be valid hex
    base64.b64decode(out["proof"])  # must be valid base64


@needs_binary
def test_merkle_prove_verify_roundtrip_two_leaves():
    out = _merkle_prove([10, 20])
    assert _merkle_verify(out["proof"], out["commitment"], out["log_size"])


@needs_binary
def test_merkle_prove_verify_roundtrip_four_leaves():
    out = _merkle_prove([1, 2, 3, 4])
    assert _merkle_verify(out["proof"], out["commitment"], out["log_size"])


@needs_binary
def test_merkle_prove_verify_roundtrip_eight_leaves():
    out = _merkle_prove([1, 2, 3, 4, 5, 6, 7, 8])
    assert _merkle_verify(out["proof"], out["commitment"], out["log_size"])


@needs_binary
def test_merkle_tampered_proof_fails():
    out = _merkle_prove([1, 2, 3, 4])
    raw = bytearray(base64.b64decode(out["proof"]))
    raw[20] ^= 0xFF
    bad_proof = base64.b64encode(bytes(raw)).decode()
    assert not _merkle_verify(bad_proof, out["commitment"], out["log_size"])


@needs_binary
def test_merkle_different_leaves_different_commitments():
    out_a = _merkle_prove([1, 2, 3, 4])
    out_b = _merkle_prove([1, 2, 3, 5])
    assert out_a["commitment"] != out_b["commitment"]


@needs_binary
def test_merkle_log_size_grows_with_leaves():
    out_small = _merkle_prove([1, 2])
    out_large = _merkle_prove([1, 2, 3, 4, 5, 6, 7, 8])
    assert out_large["log_size"] >= out_small["log_size"]


# ── Negative security tests ───────────────────────────────────────────────────

@needs_binary
def test_merkle_empty_leaves_rejected():
    proc = subprocess.run(
        [str(BINARY), "merkle_prove"],
        input=json.dumps({"leaves": []}).encode(),
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode != 0, "empty leaves should be rejected"


@needs_binary
def test_merkle_out_of_bounds_log_size_rejected():
    out = _merkle_prove([1, 2, 3, 4])
    proc = subprocess.run(
        [str(BINARY), "merkle_verify"],
        input=json.dumps({
            "proof": out["proof"],
            "commitment": out["commitment"],
            "log_size": 100,  # absurdly large — should error
        }).encode(),
        capture_output=True,
        timeout=60,
    )
    # Must error (non-zero exit) OR return valid=False
    if proc.returncode == 0:
        assert not json.loads(proc.stdout)["valid"]


@needs_binary
def test_merkle_zero_log_size_rejected():
    out = _merkle_prove([1, 2])
    proc = subprocess.run(
        [str(BINARY), "merkle_verify"],
        input=json.dumps({
            "proof": out["proof"],
            "commitment": out["commitment"],
            "log_size": 0,
        }).encode(),
        capture_output=True,
        timeout=60,
    )
    # Must error (non-zero exit) OR return valid=False
    if proc.returncode == 0:
        assert not json.loads(proc.stdout)["valid"]


@needs_binary
def test_merkle_wrong_log_size_fails():
    out = _merkle_prove([1, 2, 3, 4])
    wrong_log = out["log_size"] + 1
    proc = subprocess.run(
        [str(BINARY), "merkle_verify"],
        input=json.dumps({
            "proof": out["proof"],
            "commitment": out["commitment"],
            "log_size": wrong_log,
        }).encode(),
        capture_output=True,
        timeout=60,
    )
    if proc.returncode == 0:
        assert not json.loads(proc.stdout)["valid"]
