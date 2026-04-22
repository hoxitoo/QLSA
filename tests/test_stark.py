"""
STARK layer integration tests.

Tests that require the Rust binary are automatically skipped when the binary
has not been compiled yet. Build it with:

    cd stark && cargo build --release
"""

from __future__ import annotations

import pytest

from stark.prover import BINARY, ProofResult, binary_available, _txs_to_leaves
from stark.verifier import verify_batch_proof

# Helper: skip all tests if binary not present
needs_binary = pytest.mark.skipif(
    not binary_available(),
    reason="qlsa-stark binary not built — run: cd stark && cargo build --release",
)

# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

def _make_signed_batch(n: int):
    """Return a signed Batch with n transactions."""
    from core.batch import create_batch
    from core.keys import derive_address, generate_keypair, wipe_key
    from core.signing import sign
    from core.transaction import Transaction

    pub, priv = generate_keypair()
    addr = derive_address(pub)
    txs = []
    for i in range(n):
        tx = Transaction(
            sender=addr,
            recipient="d" * 64,
            amount=i + 1,
            nonce=i,
            public_key=pub,
        )
        tx.signature = sign(tx.to_bytes(), priv)
        txs.append(tx)
    wipe_key(priv)
    return create_batch(txs)


# ──────────────────────────────────────────────────────────────────────────────
# Tests that do NOT require the binary
# ──────────────────────────────────────────────────────────────────────────────

def test_binary_path_is_configured():
    assert BINARY.name == "qlsa-stark"
    assert "stark" in str(BINARY)


def test_txs_to_leaves_length():
    batch = _make_signed_batch(4)
    leaves = _txs_to_leaves(batch)
    assert len(leaves) == 4


def test_txs_to_leaves_are_u64():
    batch = _make_signed_batch(3)
    leaves = _txs_to_leaves(batch)
    for leaf in leaves:
        assert 0 <= leaf < 2**64


def test_txs_to_leaves_are_deterministic():
    batch = _make_signed_batch(2)
    l1 = _txs_to_leaves(batch)
    l2 = _txs_to_leaves(batch)
    assert l1 == l2


# ──────────────────────────────────────────────────────────────────────────────
# Tests that require the compiled Rust binary
# ──────────────────────────────────────────────────────────────────────────────

@needs_binary
def test_prove_returns_proof_result():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)
    assert isinstance(result, ProofResult)
    assert len(result.proof) > 0
    assert len(result.commitment) == 16  # 8 bytes as hex


@needs_binary
def test_prove_sets_batch_stark_commitment():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    assert batch.stark_commitment is None
    prove_batch(batch)
    assert batch.stark_commitment is not None
    assert len(batch.stark_commitment) == 16


@needs_binary
def test_verify_valid_proof():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)
    assert verify_batch_proof(result.proof, result.commitment) is True


@needs_binary
def test_verify_tampered_commitment_fails():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)
    bad_commitment = "ff" * 8  # wrong commitment
    assert verify_batch_proof(result.proof, bad_commitment) is False


@needs_binary
def test_verify_tampered_proof_fails():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)
    bad_proof = bytearray(result.proof)
    bad_proof[10] ^= 0xFF  # flip bits
    assert verify_batch_proof(bytes(bad_proof), result.commitment) is False


@needs_binary
def test_commitment_is_deterministic():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    r1 = prove_batch(batch)
    r2 = prove_batch(batch)
    assert r1.commitment == r2.commitment


@needs_binary
def test_different_batches_have_different_commitments():
    from stark.prover import prove_batch
    b1 = _make_signed_batch(4)
    b2 = _make_signed_batch(4)
    r1 = prove_batch(b1)
    r2 = prove_batch(b2)
    assert r1.commitment != r2.commitment
