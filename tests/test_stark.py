"""
STARK layer integration tests (Stwo Circle STARK backend).

Tests that require the Rust binary are automatically skipped when the binary
has not been compiled yet. Build it with:

    cd stark_stwo && cargo +nightly-2025-07-01 build --release
"""

from __future__ import annotations

import pytest

from stark.prover import BINARY, ProofResult, binary_available, _txs_to_leaves
from stark.verifier import verify_batch_proof

# Helper: skip all tests if binary not present
needs_binary = pytest.mark.skipif(
    not binary_available(),
    reason="qlsa-stark-stwo binary not built — run: cd stark_stwo && cargo +nightly-2025-07-01 build --release",
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
    assert BINARY.name == "qlsa-stark-stwo"
    assert "stark_stwo" in str(BINARY)


def test_txs_to_leaves_always_8():
    # Merkle root is always 64 bytes → 8 × u64 chunks regardless of batch size.
    for n in (1, 4, 16):
        leaves = _txs_to_leaves(_make_signed_batch(n))
        assert len(leaves) == 8


def test_txs_to_leaves_are_u64():
    leaves = _txs_to_leaves(_make_signed_batch(3))
    for leaf in leaves:
        assert 0 <= leaf < 2**64


def test_txs_to_leaves_are_deterministic():
    batch = _make_signed_batch(2)
    assert _txs_to_leaves(batch) == _txs_to_leaves(batch)


def test_txs_to_leaves_encodes_merkle_root():
    # Reconstruct leaves manually and verify they match the Merkle root bytes.
    batch = _make_signed_batch(4)
    leaves = _txs_to_leaves(batch)
    root = batch.merkle_root  # 64 bytes
    expected = [int.from_bytes(root[i : i + 8], "little") for i in range(0, 64, 8)]
    assert leaves == expected


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
    assert len(result.commitment) == 8  # 4 bytes M31 as 8 hex chars
    assert result.log_size >= 3         # minimum trace log size
    assert len(result.onchain_commitment) == 16  # 8 bytes as 16 hex chars


@needs_binary
def test_onchain_commitment_bound_to_merkle_root():
    """onchain_commitment = Blake2s(proof[:32] || merkle_root[:32])[:8]
    matches QLSAVerifierBound / BatchRegistryV2 commitment scheme."""
    import hashlib
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)

    expected = hashlib.blake2s(
        result.proof[:32] + batch.merkle_root[:32]
    ).digest()[:8].hex()
    assert result.onchain_commitment == expected


@needs_binary
def test_onchain_commitment_differs_for_different_batches():
    """Each batch has a unique onchain_commitment — no replay possible."""
    from stark.prover import prove_batch
    b1 = _make_signed_batch(4)
    b2 = _make_signed_batch(4)
    r1 = prove_batch(b1)
    r2 = prove_batch(b2)
    assert r1.onchain_commitment != r2.onchain_commitment


@needs_binary
def test_prove_sets_batch_stark_fields():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    assert batch.stark_commitment is None
    assert batch.stark_log_size is None
    prove_batch(batch)
    assert batch.stark_commitment is not None
    assert len(batch.stark_commitment) == 8
    assert batch.stark_log_size is not None
    assert batch.stark_log_size >= 3


@needs_binary
def test_verify_valid_proof():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)
    assert verify_batch_proof(result.proof, result.commitment, result.log_size) is True


@needs_binary
def test_verify_tampered_proof_fails():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)
    bad_proof = bytearray(result.proof)
    bad_proof[10] ^= 0xFF  # flip bits
    assert verify_batch_proof(bytes(bad_proof), result.commitment, result.log_size) is False


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


# ─── ML-DSA batch via Rust verifier ──────────────────────────────────────────

def _mldsa_entries(n: int) -> list[tuple[bytes, bytes, bytes]]:
    """Generate n real ML-DSA-65 (pk, msg, sig) triples via liboqs."""
    import oqs
    entries = []
    for i in range(n):
        alg = oqs.Signature("ML-DSA-65")
        pk = alg.generate_keypair()
        msg = f"transaction payload {i}".encode()
        sig = alg.sign(msg)
        entries.append((pk, msg, sig))
    return entries


@needs_binary
def test_prove_mldsa_batch_returns_result():
    from stark.prover import prove_mldsa_batch, MldsaBatchResult
    entries = _mldsa_entries(2)
    result = prove_mldsa_batch(entries)
    assert isinstance(result, MldsaBatchResult)
    assert result.verified == 2
    assert result.rejected == 0
    assert len(result.proof) > 0


@needs_binary
def test_prove_mldsa_batch_rejects_invalid_sig():
    from stark.prover import prove_mldsa_batch
    entries = _mldsa_entries(2)
    # Corrupt the second signature
    bad_sig = bytearray(entries[1][2])
    bad_sig[10] ^= 0xFF
    entries[1] = (entries[1][0], entries[1][1], bytes(bad_sig))
    result = prove_mldsa_batch(entries)
    assert result.verified == 1
    assert result.rejected == 1


@needs_binary
def test_prove_mldsa_batch_verify_proof():
    from stark.prover import prove_mldsa_batch
    entries = _mldsa_entries(2)
    result = prove_mldsa_batch(entries)
    assert verify_batch_proof(result.proof, result.commitment, result.log_size) is True
