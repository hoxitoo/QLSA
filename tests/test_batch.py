import pytest

from core.batch import (
    MAX_BATCH_SIZE,
    Batch,
    BatchSizeError,
    InvalidSignatureError,
    create_batch,
)
from core.keys import derive_address, generate_keypair, wipe_key
from core.signing import sign
from core.transaction import Transaction


def _make_signed_tx(nonce: int = 0) -> tuple[Transaction, bytearray]:
    pub, priv = generate_keypair()
    sender = derive_address(pub)
    recipient = "c" * 64
    tx = Transaction(
        sender=sender,
        recipient=recipient,
        amount=1,
        nonce=nonce,
        public_key=pub,
    )
    tx.signature = sign(tx.to_bytes(), priv)
    return tx, priv


def _make_batch_txs(n: int) -> tuple[list[Transaction], list[bytearray]]:
    txs, privs = zip(*[_make_signed_tx(nonce=i) for i in range(n)])
    return list(txs), list(privs)


def _wipe_all(privs: list[bytearray]) -> None:
    for p in privs:
        wipe_key(p)


def test_create_batch_returns_batch():
    txs, privs = _make_batch_txs(3)
    batch = create_batch(txs)
    _wipe_all(privs)
    assert isinstance(batch, Batch)
    assert len(batch.merkle_root) == 64  # SHA3-512
    assert len(batch.transactions) == 3


def test_batch_merkle_root_is_deterministic():
    txs, privs = _make_batch_txs(4)
    root1 = create_batch(txs).merkle_root
    root2 = create_batch(txs).merkle_root
    _wipe_all(privs)
    assert root1 == root2


def test_batch_root_changes_if_tx_changes():
    txs, privs = _make_batch_txs(4)
    root1 = create_batch(txs).merkle_root

    # Replace first transaction with a different one
    new_tx, new_priv = _make_signed_tx(nonce=99)
    txs[0] = new_tx
    root2 = create_batch(txs).merkle_root

    _wipe_all(privs)
    wipe_key(new_priv)
    assert root1 != root2


def test_batch_id_is_unique():
    txs1, privs1 = _make_batch_txs(2)
    txs2, privs2 = _make_batch_txs(2)
    b1 = create_batch(txs1)
    b2 = create_batch(txs2)
    _wipe_all(privs1)
    _wipe_all(privs2)
    assert b1.batch_id != b2.batch_id


def test_unsigned_transaction_raises():
    pub, priv = generate_keypair()
    wipe_key(priv)
    tx = Transaction(
        sender=derive_address(pub),
        recipient="d" * 64,
        amount=1,
        nonce=0,
        public_key=pub,
    )
    with pytest.raises(InvalidSignatureError, match="unsigned"):
        create_batch([tx])


def test_invalid_signature_raises():
    tx, priv = _make_signed_tx()
    wipe_key(priv)
    tx.signature = b"\x00" * len(tx.signature)  # corrupt signature
    with pytest.raises(InvalidSignatureError, match="Invalid signature"):
        create_batch([tx])


def test_empty_batch_raises():
    with pytest.raises(BatchSizeError):
        create_batch([])


def test_batch_too_large_raises(monkeypatch):
    # Build just enough to trigger the limit without generating MAX_BATCH_SIZE keys.
    # Use monkeypatch for proper teardown even if the assertion fails.
    txs, privs = _make_batch_txs(2)
    _wipe_all(privs)
    import core.batch as batch_mod
    monkeypatch.setattr(batch_mod, "MAX_BATCH_SIZE", 1)
    with pytest.raises(BatchSizeError, match="maximum"):
        create_batch(txs)


def test_merkle_root_onchain_is_32_bytes():
    txs, privs = _make_batch_txs(2)
    batch = create_batch(txs)
    _wipe_all(privs)
    onchain = batch.merkle_root_onchain()
    assert isinstance(onchain, bytes)
    assert len(onchain) == 32
    assert onchain == batch.merkle_root[:32]


