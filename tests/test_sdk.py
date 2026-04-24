import pytest

from core.keys import derive_address, generate_keypair, wipe_key
from core.transaction import Transaction
from sdk.python.qlsa import (
    BatchStatus,
    LocalClient,
    NodeStats,
    SubmitResult,
    TransactionBuilder,
    Wallet,
)


# ── Wallet ────────────────────────────────────────────────────────────────────

def test_wallet_generate_returns_wallet():
    with Wallet.generate() as w:
        assert len(w.address) == 64
        assert isinstance(w.public_key, bytes)
        assert len(w.public_key) > 0
        assert isinstance(w._private_key, bytearray)
        assert len(w._private_key) > 0


def test_wallet_wipe_zeroes_key():
    wallet = Wallet.generate()
    wallet.wipe()
    assert all(b == 0 for b in wallet._private_key)


def test_wallet_context_manager_wipes_on_exit():
    with Wallet.generate() as wallet:
        pass
    assert all(b == 0 for b in wallet._private_key)


def test_wallet_context_manager_wipes_on_exception():
    try:
        with Wallet.generate() as wallet:
            raise RuntimeError("test error")
    except RuntimeError:
        pass
    assert all(b == 0 for b in wallet._private_key)


def test_wallet_sign_transaction_produces_signature():
    with Wallet.generate() as wallet:
        tx = Transaction(
            sender=wallet.address,
            recipient="a" * 64,
            amount=1,
            nonce=0,
            public_key=wallet.public_key,
        )
        signed = wallet.sign_transaction(tx)
    assert signed.signature is not None
    assert len(signed.signature) > 0


# ── TransactionBuilder ────────────────────────────────────────────────────────

def test_builder_produces_signed_transaction():
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet)
        tx = builder.build(recipient="b" * 64, amount=100, nonce=0)
    assert tx.signature is not None
    assert tx.sender == wallet.address
    assert tx.recipient == "b" * 64
    assert tx.amount == 100
    assert tx.nonce == 0


def test_builder_multiple_transactions():
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet)
        txs = [builder.build(recipient="c" * 64, amount=i, nonce=i) for i in range(5)]
    assert all(tx.signature is not None for tx in txs)
    assert [tx.nonce for tx in txs] == list(range(5))


# ── LocalClient.submit ────────────────────────────────────────────────────────

def test_local_client_submit_signed_tx():
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="d" * 64, amount=10, nonce=0)
        client = LocalClient()
        result = client.submit(tx)
    assert isinstance(result, SubmitResult)
    assert result.accepted is True
    assert result.error is None
    assert result.mempool_size == 1


def test_local_client_submit_increments_mempool():
    client = LocalClient()
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet)
        for i in range(3):
            r = client.submit(builder.build(recipient="e" * 64, amount=1, nonce=i))
            assert r.mempool_size == i + 1


def test_local_client_submit_unsigned_tx_rejected():
    pub, priv = generate_keypair()
    wipe_key(priv)
    tx = Transaction(
        sender=derive_address(pub),
        recipient="f" * 64,
        amount=1,
        nonce=0,
        public_key=pub,
    )
    client = LocalClient()
    result = client.submit(tx)
    assert result.accepted is False
    assert result.error is not None


# ── LocalClient.flush / run_cycle ─────────────────────────────────────────────

def test_local_client_flush_empty_returns_none():
    client = LocalClient()
    assert client.flush() is None


def test_local_client_flush_creates_batch():
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="ab" * 32, amount=5, nonce=0)
        client = LocalClient()
        client.submit(tx)
        status = client.flush()
    assert isinstance(status, BatchStatus)
    assert status.tx_count == 1
    assert len(status.merkle_root) == 128   # SHA3-512 → 64 bytes → 128 hex chars
    assert status.batch_id != ""
    assert isinstance(status.is_proven, bool)


def test_local_client_flush_drains_mempool():
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet)
        client = LocalClient()
        for i in range(3):
            client.submit(builder.build(recipient="cd" * 32, amount=1, nonce=i))
        assert client.stats().pending == 3
        status = client.flush()
    assert status is not None
    assert status.tx_count == 3
    assert client.stats().pending == 0


def test_local_client_run_cycle_respects_min_batch_size():
    from aggregator.node import AggregatorNode

    node = AggregatorNode(min_batch_size=5)
    client = LocalClient(node=node)
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="ef" * 32, amount=1, nonce=0)
        client.submit(tx)
    assert client.run_cycle() is None   # only 1 tx, min is 5


def test_local_client_run_cycle_batches_when_ready():
    from aggregator.node import AggregatorNode

    node = AggregatorNode(min_batch_size=2)
    client = LocalClient(node=node)
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet)
        client.submit(builder.build(recipient="01" * 32, amount=1, nonce=0))
        client.submit(builder.build(recipient="01" * 32, amount=2, nonce=1))
    status = client.run_cycle()
    assert status is not None
    assert status.tx_count == 2


# ── LocalClient.stats ─────────────────────────────────────────────────────────

def test_local_client_stats_tracks_submissions():
    client = LocalClient()
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet)
        for i in range(3):
            client.submit(builder.build(recipient="23" * 32, amount=1, nonce=i))
        client.flush()
    stats = client.stats()
    assert isinstance(stats, NodeStats)
    assert stats.transactions_received == 3
    assert stats.transactions_batched == 3
    assert stats.batches_created == 1
    assert stats.pending == 0


def test_local_client_stats_initial_state():
    client = LocalClient()
    stats = client.stats()
    assert stats.transactions_received == 0
    assert stats.batches_created == 0
    assert stats.pending == 0
