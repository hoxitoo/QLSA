"""
STARK layer integration tests (Stwo Circle STARK backend).

Tests that require the PyO3 extension are automatically skipped when the module
is not installed. Install it with:

    cd stark_stwo && maturin develop --features python --release
"""

from __future__ import annotations

import pytest

from stark.prover import ProofResult, _txs_to_leaves
from stark.verifier import (
    verify_batch_proof,
    verify_batch_merkle_proof,
    verify_batch_poseidon2_proof,
)

try:
    import qlsa_stark_stwo as _ext
    _HAVE_EXT = True
except ImportError:
    _HAVE_EXT = False

needs_ext = pytest.mark.skipif(
    not _HAVE_EXT,
    reason="qlsa_stark_stwo not installed — run: cd stark_stwo && maturin develop --features python",
)

try:
    import oqs.oqs as _oqs_check
    _HAVE_OQS = hasattr(_oqs_check, "Signature")
except ImportError:
    _HAVE_OQS = False

needs_oqs = pytest.mark.skipif(
    not _HAVE_OQS,
    reason="liboqs not available — install liboqs-python with liboqs C library",
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


def _make_synthetic_batch():
    """Batch with a deterministic 64-byte Merkle root — no oqs required."""
    import hashlib
    from core.batch import Batch
    root = hashlib.sha3_512(b"synthetic-test-batch").digest()  # always 64 bytes
    return Batch(transactions=[], merkle_root=root)


# ──────────────────────────────────────────────────────────────────────────────
# Tests that do NOT require the extension or oqs
# ──────────────────────────────────────────────────────────────────────────────

def test_txs_to_leaves_always_8():
    # Merkle root is always 64 bytes → always 8 × u64 leaves, regardless of batch content.
    leaves = _txs_to_leaves(_make_synthetic_batch())
    assert len(leaves) == 8


def test_txs_to_leaves_are_u64():
    leaves = _txs_to_leaves(_make_synthetic_batch())
    for leaf in leaves:
        assert 0 <= leaf < 2**64


def test_txs_to_leaves_are_deterministic():
    batch = _make_synthetic_batch()
    assert _txs_to_leaves(batch) == _txs_to_leaves(batch)


def test_txs_to_leaves_encodes_merkle_root():
    batch = _make_synthetic_batch()
    leaves = _txs_to_leaves(batch)
    root = batch.merkle_root  # 64 bytes
    expected = [int.from_bytes(root[i : i + 8], "little") for i in range(0, 64, 8)]
    assert leaves == expected


# ──────────────────────────────────────────────────────────────────────────────
# Tests that require the compiled PyO3 extension
# ──────────────────────────────────────────────────────────────────────────────

@needs_ext
@needs_oqs
def test_prove_returns_proof_result():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)
    assert isinstance(result, ProofResult)
    assert len(result.proof) > 0
    assert len(result.commitment) == 32        # 128-bit = 32 hex chars
    assert result.log_size >= 3
    assert len(result.onchain_commitment) == 32  # Blake2s 16 bytes = 32 hex chars


@needs_ext
@needs_oqs
def test_onchain_commitment_bound_to_merkle_root():
    """onchain_commitment = Blake2s(proof[:32] || merkle_root[:32])[:16]
    matches QLSAVerifierBound / BatchRegistryV2 commitment scheme."""
    import hashlib
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)

    expected = hashlib.blake2s(
        result.proof[:32] + batch.merkle_root[:32]
    ).digest()[:16].hex()
    assert result.onchain_commitment == expected


@needs_ext
@needs_oqs
def test_onchain_commitment_differs_for_different_batches():
    """Each batch has a unique onchain_commitment — no replay possible."""
    from stark.prover import prove_batch
    b1 = _make_signed_batch(4)
    b2 = _make_signed_batch(4)
    r1 = prove_batch(b1)
    r2 = prove_batch(b2)
    assert r1.onchain_commitment != r2.onchain_commitment


@needs_ext
@needs_oqs
def test_prove_sets_batch_stark_fields():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    assert batch.stark_commitment is None
    assert batch.stark_log_size is None
    prove_batch(batch)
    assert batch.stark_commitment is not None
    assert len(batch.stark_commitment) == 32  # 128-bit commitment
    assert batch.stark_log_size is not None
    assert batch.stark_log_size >= 3


@needs_ext
@needs_oqs
def test_verify_valid_proof():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)
    # Merkle root is now a Fiat-Shamir public input — must pass the same root.
    assert verify_batch_proof(result.proof, result.commitment, result.log_size,
                              merkle_root=batch.merkle_root) is True


@needs_ext
@needs_oqs
def test_verify_wrong_merkle_root_fails():
    """Proof generated for one batch must not verify with a different Merkle root."""
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)
    wrong_root = bytes([b ^ 0xFF for b in batch.merkle_root])
    assert verify_batch_proof(result.proof, result.commitment, result.log_size,
                              merkle_root=wrong_root) is False


@needs_ext
@needs_oqs
def test_verify_tampered_proof_fails():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    result = prove_batch(batch)
    bad_proof = bytearray(result.proof)
    bad_proof[10] ^= 0xFF
    assert verify_batch_proof(bytes(bad_proof), result.commitment, result.log_size,
                              merkle_root=batch.merkle_root) is False


@needs_ext
@needs_oqs
def test_commitment_is_deterministic():
    from stark.prover import prove_batch
    batch = _make_signed_batch(4)
    r1 = prove_batch(batch)
    r2 = prove_batch(batch)
    assert r1.commitment == r2.commitment


@needs_ext
@needs_oqs
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
    import oqs.oqs as oqs
    entries = []
    for i in range(n):
        alg = oqs.Signature("ML-DSA-65")
        pk = alg.generate_keypair()
        msg = f"transaction payload {i}".encode()
        sig = alg.sign(msg)
        entries.append((pk, msg, sig))
    return entries


@needs_ext
@needs_oqs
def test_prove_mldsa_batch_returns_result():
    from stark.prover import prove_mldsa_batch, MldsaBatchResult
    entries = _mldsa_entries(2)
    result = prove_mldsa_batch(entries)
    assert isinstance(result, MldsaBatchResult)
    assert result.verified == 2
    assert result.rejected == 0
    assert len(result.proof) > 0


@needs_ext
@needs_oqs
def test_prove_mldsa_batch_rejects_invalid_sig():
    from stark.prover import prove_mldsa_batch
    entries = _mldsa_entries(2)
    bad_sig = bytearray(entries[1][2])
    bad_sig[10] ^= 0xFF
    entries[1] = (entries[1][0], entries[1][1], bytes(bad_sig))
    result = prove_mldsa_batch(entries)
    assert result.verified == 1
    assert result.rejected == 1


@needs_ext
@needs_oqs
def test_prove_mldsa_batch_verify_proof():
    from stark.prover import prove_mldsa_batch
    entries = _mldsa_entries(2)
    result = prove_mldsa_batch(entries)
    assert verify_batch_proof(result.proof, result.commitment, result.log_size) is True


# ─── prove_batch_poseidon2 ────────────────────────────────────────────────────

@needs_ext
@needs_oqs
def test_prove_batch_poseidon2_returns_result():
    from stark.prover import prove_batch_poseidon2, Poseidon2ProofResult
    batch = _make_signed_batch(4)
    result = prove_batch_poseidon2(batch)
    assert isinstance(result, Poseidon2ProofResult)
    assert len(result.proof) > 0
    assert len(result.commitment) == 32
    assert result.log_size >= 3
    assert len(result.onchain_commitment) == 32


@needs_ext
@needs_oqs
def test_prove_batch_poseidon2_verify_roundtrip():
    from stark.prover import prove_batch_poseidon2
    batch = _make_signed_batch(4)
    result = prove_batch_poseidon2(batch)
    assert verify_batch_poseidon2_proof(
        result.proof, result.commitment, result.log_size,
        seed=batch.merkle_root,
    ) is True


@needs_ext
@needs_oqs
def test_prove_batch_poseidon2_onchain_commitment_binding():
    """onchain_commitment = Blake2s(proof[:32] ‖ merkle_root[:32])[:16]."""
    import hashlib
    from stark.prover import prove_batch_poseidon2
    batch = _make_signed_batch(4)
    result = prove_batch_poseidon2(batch)
    expected = hashlib.blake2s(result.proof[:32] + batch.merkle_root[:32]).digest()[:16].hex()
    assert result.onchain_commitment == expected


# ─── prove_batch_merkle ───────────────────────────────────────────────────────

@needs_ext
@needs_oqs
def test_prove_batch_merkle_returns_result():
    from stark.prover import prove_batch_merkle, MerkleProofResult
    batch = _make_signed_batch(4)
    result = prove_batch_merkle(batch)
    assert isinstance(result, MerkleProofResult)
    assert len(result.proof) > 0
    assert len(result.commitment) == 32
    assert result.log_size >= 3
    assert len(result.onchain_commitment) == 32


@needs_ext
@needs_oqs
def test_prove_batch_merkle_verify_roundtrip():
    from stark.prover import prove_batch_merkle
    batch = _make_signed_batch(4)
    result = prove_batch_merkle(batch)
    assert verify_batch_merkle_proof(
        result.proof, result.commitment, result.log_size,
        seed=batch.merkle_root,
    ) is True


@needs_ext
@needs_oqs
def test_prove_batch_merkle_onchain_commitment_binding():
    """onchain_commitment = Blake2s(proof[:32] ‖ merkle_root[:32])[:16]."""
    import hashlib
    from stark.prover import prove_batch_merkle
    batch = _make_signed_batch(4)
    result = prove_batch_merkle(batch)
    expected = hashlib.blake2s(result.proof[:32] + batch.merkle_root[:32]).digest()[:16].hex()
    assert result.onchain_commitment == expected


@needs_ext
@needs_oqs
def test_prove_batch_merkle_different_batches_different_commitments():
    from stark.prover import prove_batch_merkle
    b1 = _make_signed_batch(4)
    b2 = _make_signed_batch(4)
    r1 = prove_batch_merkle(b1)
    r2 = prove_batch_merkle(b2)
    assert r1.commitment != r2.commitment
