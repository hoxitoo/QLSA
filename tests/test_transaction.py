import pytest

from core.keys import derive_address, generate_keypair, wipe_key
from core.transaction import Transaction


def _make_tx(amount: int = 100, nonce: int = 0) -> tuple[Transaction, bytes, bytearray]:
    pub, priv = generate_keypair()
    sender = derive_address(pub)
    recipient = "a" * 64  # dummy valid hex address
    tx = Transaction(
        sender=sender,
        recipient=recipient,
        amount=amount,
        nonce=nonce,
        public_key=pub,
    )
    return tx, pub, priv


def test_transaction_to_bytes_is_deterministic():
    tx, _, priv = _make_tx()
    wipe_key(priv)
    assert tx.to_bytes() == tx.to_bytes()


def test_transaction_to_bytes_changes_with_amount():
    tx1, _, priv1 = _make_tx(amount=100)
    tx2, _, priv2 = _make_tx(amount=200)
    wipe_key(priv1)
    wipe_key(priv2)
    assert tx1.to_bytes() != tx2.to_bytes()


def test_tx_hash_is_32_bytes():
    tx, _, priv = _make_tx()
    wipe_key(priv)
    h = tx.tx_hash()
    assert isinstance(h, bytes)
    assert len(h) == 32


def test_tx_hash_is_deterministic():
    tx, _, priv = _make_tx()
    wipe_key(priv)
    assert tx.tx_hash() == tx.tx_hash()


def test_tx_hash_changes_with_nonce():
    pub, priv = generate_keypair()
    addr = derive_address(pub)
    wipe_key(priv)
    tx1 = Transaction(sender=addr, recipient="b" * 64, amount=1, nonce=0, public_key=pub)
    tx2 = Transaction(sender=addr, recipient="b" * 64, amount=1, nonce=1, public_key=pub)
    assert tx1.tx_hash() != tx2.tx_hash()


def test_negative_amount_raises():
    pub, priv = generate_keypair()
    wipe_key(priv)
    with pytest.raises(ValueError, match="positive"):
        Transaction(sender="a" * 64, recipient="b" * 64, amount=-1, nonce=0, public_key=pub)


def test_zero_amount_raises():
    pub, priv = generate_keypair()
    wipe_key(priv)
    with pytest.raises(ValueError, match="positive"):
        Transaction(sender="a" * 64, recipient="b" * 64, amount=0, nonce=0, public_key=pub)


def test_negative_nonce_raises():
    pub, priv = generate_keypair()
    wipe_key(priv)
    with pytest.raises(ValueError, match="non-negative"):
        Transaction(sender="a" * 64, recipient="b" * 64, amount=1, nonce=-1, public_key=pub)


def test_invalid_sender_raises():
    pub, priv = generate_keypair()
    wipe_key(priv)
    with pytest.raises(ValueError, match="sender"):
        Transaction(sender="not-an-address", recipient="b" * 64, amount=1, nonce=0, public_key=pub)


def test_amount_at_uint64_max_is_valid():
    pub, priv = generate_keypair()
    wipe_key(priv)
    tx = Transaction(
        sender="a" * 64,
        recipient="b" * 64,
        amount=(1 << 64) - 1,
        nonce=0,
        public_key=pub,
    )
    assert tx.amount == (1 << 64) - 1


def test_amount_exceeds_uint64_raises():
    pub, priv = generate_keypair()
    wipe_key(priv)
    with pytest.raises(ValueError, match="uint64"):
        Transaction(sender="a" * 64, recipient="b" * 64, amount=1 << 64, nonce=0, public_key=pub)


def test_nonce_at_uint64_max_is_valid():
    pub, priv = generate_keypair()
    wipe_key(priv)
    tx = Transaction(
        sender="a" * 64,
        recipient="b" * 64,
        amount=1,
        nonce=(1 << 64) - 1,
        public_key=pub,
    )
    assert tx.nonce == (1 << 64) - 1


def test_nonce_exceeds_uint64_raises():
    pub, priv = generate_keypair()
    wipe_key(priv)
    with pytest.raises(ValueError, match="uint64"):
        Transaction(sender="a" * 64, recipient="b" * 64, amount=1, nonce=1 << 64, public_key=pub)


def test_invalid_recipient_raises():
    pub, priv = generate_keypair()
    wipe_key(priv)
    with pytest.raises(ValueError, match="recipient"):
        Transaction(sender="a" * 64, recipient="not-an-address", amount=1, nonce=0, public_key=pub)


def test_recipient_wrong_length_raises():
    pub, priv = generate_keypair()
    wipe_key(priv)
    with pytest.raises(ValueError, match="recipient"):
        Transaction(sender="a" * 64, recipient="ab" * 10, amount=1, nonce=0, public_key=pub)


def test_invalid_pubkey_size_raises():
    pub, priv = generate_keypair()
    addr = derive_address(pub)
    wipe_key(priv)
    with pytest.raises(ValueError, match="ML-DSA"):
        Transaction(sender=addr, recipient="b" * 64, amount=1, nonce=0, public_key=b"\x01" * 10)

