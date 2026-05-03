"""
Stwo Circle STARK tests using the PyO3 native extension.

Skipped automatically when the module is not installed. Install with:
    cd stark_stwo && maturin develop --features python --release
"""

from __future__ import annotations

import pytest

try:
    import qlsa_stark_stwo as _ext
    _HAVE_EXT = True
except ImportError:
    _HAVE_EXT = False

needs_ext = pytest.mark.skipif(
    not _HAVE_EXT,
    reason="qlsa_stark_stwo not installed — run: cd stark_stwo && maturin develop --features python",
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _prove(leaves: list[int]) -> dict:
    proof, commitment, log_size = _ext.prove(leaves)
    return {"proof": proof, "commitment": commitment, "log_size": log_size}


def _verify(proof: bytes, commitment: str, log_size: int) -> bool:
    return _ext.verify(proof, commitment, log_size)


def _prove_p2(leaves: list[int]) -> dict:
    proof, commitment, log_size = _ext.prove_p2(leaves)
    return {"proof": proof, "commitment": commitment, "log_size": log_size}


def _verify_p2(proof: bytes, commitment: str, log_size: int) -> bool:
    return _ext.verify_p2(proof, commitment, log_size)


def _prove_merkle(leaves: list[int]) -> dict:
    proof, commitment, log_size = _ext.prove_merkle(leaves)
    return {"proof": proof, "commitment": commitment, "log_size": log_size}


def _verify_merkle(proof: bytes, commitment: str, log_size: int) -> bool:
    return _ext.verify_merkle(proof, commitment, log_size)


# ─── Hash-chain prove / verify ────────────────────────────────────────────────

@needs_ext
def test_prove_output_schema():
    out = _prove([1, 2, 3, 4])
    assert isinstance(out["proof"], bytes)
    assert len(out["proof"]) > 0
    assert len(out["commitment"]) == 32
    int(out["commitment"], 16)  # must be valid hex
    assert out["log_size"] >= 3


@needs_ext
def test_prove_verify_roundtrip_small():
    out = _prove([1, 2, 3, 4, 5, 6, 7, 8])
    assert _verify(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_prove_verify_roundtrip_single_leaf():
    out = _prove([42])
    assert _verify(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_prove_verify_roundtrip_large_values():
    out = _prove([2**63 - 1, 2**32, 0, 1])
    assert _verify(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_commitment_is_128bit_hex():
    out = _prove([10, 20, 30])
    assert len(out["commitment"]) == 32
    int(out["commitment"], 16)


@needs_ext
def test_tampered_proof_fails_verify():
    out = _prove([1, 2, 3, 4])
    raw = bytearray(out["proof"])
    raw[8] ^= 0xFF
    assert not _verify(bytes(raw), out["commitment"], out["log_size"])


@needs_ext
def test_wrong_log_size_fails_verify():
    out = _prove([1, 2, 3, 4])
    # Out-of-range log_size — verify returns False (errors are silenced to False).
    assert not _verify(out["proof"], out["commitment"], out["log_size"] + 1)


@needs_ext
def test_log_size_grows_with_more_leaves():
    out_small = _prove([1, 2, 3, 4])
    out_large = _prove(list(range(1, 33)))
    assert out_large["log_size"] >= out_small["log_size"]


@needs_ext
def test_different_leaves_give_different_commitments():
    out_a = _prove([1, 2, 3, 4])
    out_b = _prove([5, 6, 7, 8])
    assert out_a["commitment"] != out_b["commitment"]


# ─── prove_p2 / verify_p2 (Poseidon2 sponge hash chain) ─────────────────────

@needs_ext
def test_prove_p2_output_schema():
    out = _prove_p2([1, 2, 3, 4])
    assert isinstance(out["proof"], bytes)
    assert len(out["proof"]) > 0
    assert len(out["commitment"]) == 32


@needs_ext
def test_prove_p2_verify_p2_roundtrip():
    out = _prove_p2([1, 2, 3, 4, 5, 6, 7, 8])
    assert _verify_p2(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_prove_p2_tampered_proof_fails():
    out = _prove_p2([1, 2, 3, 4])
    raw = bytearray(out["proof"])
    raw[20] ^= 0xFF
    assert not _verify_p2(bytes(raw), out["commitment"], out["log_size"])


@needs_ext
def test_prove_p2_different_leaves_different_commitments():
    out_a = _prove_p2([1, 2, 3, 4])
    out_b = _prove_p2([5, 6, 7, 8])
    assert out_a["commitment"] != out_b["commitment"]


# ─── prove_merkle / verify_merkle (Poseidon2 Merkle tree) ────────────────────

@needs_ext
def test_merkle_prove_output_schema():
    out = _prove_merkle([1, 2, 3, 4])
    assert isinstance(out["proof"], bytes)
    assert len(out["proof"]) > 0
    assert len(out["commitment"]) == 32
    int(out["commitment"], 16)


@needs_ext
def test_merkle_prove_verify_roundtrip_two_leaves():
    out = _prove_merkle([10, 20])
    assert _verify_merkle(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_merkle_prove_verify_roundtrip_four_leaves():
    out = _prove_merkle([1, 2, 3, 4])
    assert _verify_merkle(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_merkle_prove_verify_roundtrip_eight_leaves():
    out = _prove_merkle([1, 2, 3, 4, 5, 6, 7, 8])
    assert _verify_merkle(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_merkle_tampered_proof_fails():
    out = _prove_merkle([1, 2, 3, 4])
    raw = bytearray(out["proof"])
    raw[20] ^= 0xFF
    assert not _verify_merkle(bytes(raw), out["commitment"], out["log_size"])


@needs_ext
def test_merkle_different_leaves_different_commitments():
    out_a = _prove_merkle([1, 2, 3, 4])
    out_b = _prove_merkle([1, 2, 3, 5])
    assert out_a["commitment"] != out_b["commitment"]


@needs_ext
def test_merkle_log_size_grows_with_leaves():
    out_small = _prove_merkle([1, 2])
    out_large = _prove_merkle([1, 2, 3, 4, 5, 6, 7, 8])
    assert out_large["log_size"] >= out_small["log_size"]


# ─── Negative security tests ──────────────────────────────────────────────────

@needs_ext
def test_merkle_empty_leaves_rejected():
    with pytest.raises(Exception):
        _ext.prove_merkle([])


@needs_ext
def test_merkle_out_of_bounds_log_size_rejected():
    out = _prove_merkle([1, 2, 3, 4])
    # Absurdly large log_size — verify returns False (silenced error).
    assert not _verify_merkle(out["proof"], out["commitment"], 100)


@needs_ext
def test_merkle_zero_log_size_rejected():
    out = _prove_merkle([1, 2])
    assert not _verify_merkle(out["proof"], out["commitment"], 0)


@needs_ext
def test_merkle_wrong_log_size_fails():
    out = _prove_merkle([1, 2, 3, 4])
    assert not _verify_merkle(out["proof"], out["commitment"], out["log_size"] + 1)
