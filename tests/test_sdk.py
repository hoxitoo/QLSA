import httpx
import pytest

from core.keys import derive_address, generate_keypair, wipe_key
from core.transaction import Transaction
from sdk.python.qlsa import (
    BatchStatus,
    LocalClient,
    NodeConfig,
    NodeStats,
    SubmitResult,
    TransactionBuilder,
    Wallet,
    WitnessStatus,
)
from sdk.python.qlsa.client import HttpClient


# ── HttpClient helpers ────────────────────────────────────────────────────────

@pytest.fixture()
def http_client():
    """HttpClient wired to the in-process FastAPI app via TestClient.

    starlette.testclient.TestClient is itself an httpx.Client, so it can be
    injected directly as the _client transport — no real TCP socket needed.
    The TestClient is used as a context manager so the FastAPI lifespan
    (which sets app.state.node) runs before any request.
    Rate-limit windows are cleared per-test to prevent cross-test accumulation.
    """
    from starlette.testclient import TestClient
    from aggregator.api import app
    import aggregator.api as api_mod
    with api_mod._rate_lock:
        api_mod._tx_windows.clear()
        api_mod._batch_windows.clear()
        api_mod._read_windows.clear()
    with TestClient(app, base_url="http://test") as tc:
        yield HttpClient("http://test", _client=tc)


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
        txs = [builder.build(recipient="c" * 64, amount=i + 1, nonce=i) for i in range(5)]
    assert all(tx.signature is not None for tx in txs)
    assert [tx.nonce for tx in txs] == list(range(5))


def test_wallet_public_key_hex_is_hex_string():
    with Wallet.generate() as wallet:
        assert isinstance(wallet.public_key_hex, str)
        assert all(c in "0123456789abcdef" for c in wallet.public_key_hex)
        assert wallet.public_key_hex == wallet.public_key.hex()


def test_builder_auto_nonce_increments():
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet)
        txs = [builder.build(recipient="f" * 64, amount=1) for _ in range(4)]
    assert [tx.nonce for tx in txs] == [0, 1, 2, 3]
    assert builder.next_nonce == 4


def test_builder_auto_nonce_start_nonce():
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet, start_nonce=10)
        tx0 = builder.build(recipient="aa" * 32, amount=1)
        tx1 = builder.build(recipient="bb" * 32, amount=1)
    assert tx0.nonce == 10
    assert tx1.nonce == 11
    assert builder.next_nonce == 12


def test_builder_explicit_nonce_does_not_advance_counter():
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet)
        builder.build(recipient="cc" * 32, amount=1)  # nonce=0, counter → 1
        tx = builder.build(recipient="dd" * 32, amount=1, nonce=99)
    assert tx.nonce == 99
    assert builder.next_nonce == 1  # counter unchanged by explicit nonce


def test_builder_mixed_auto_and_explicit_nonce():
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet)
        t0 = builder.build(recipient="11" * 32, amount=1)          # auto → 0
        t1 = builder.build(recipient="22" * 32, amount=1, nonce=5)  # explicit 5
        t2 = builder.build(recipient="33" * 32, amount=1)          # auto → 1
    assert [t0.nonce, t1.nonce, t2.nonce] == [0, 5, 1]


# ── LocalClient.health ────────────────────────────────────────────────────────

def test_local_client_health_returns_true():
    assert LocalClient().health() is True


def test_local_client_history_empty_initially():
    assert LocalClient().history() == []


def test_local_client_history_accumulates_batches():
    client = LocalClient()
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet)
        client.submit(builder.build(recipient="11" * 32, amount=1))
        client.flush()
        client.submit(builder.build(recipient="22" * 32, amount=1))
        client.flush()
    history = client.history()
    assert len(history) == 2
    assert all(isinstance(b, BatchStatus) for b in history)
    assert history[0].batch_id != history[1].batch_id


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


def test_local_client_stats_fri_fields():
    client = LocalClient()
    stats = client.stats()
    assert isinstance(stats.n_fri_queries, int) and stats.n_fri_queries >= 1
    assert stats.fri_security_bits == 6 * stats.n_fri_queries + 10


def test_local_client_node_config_returns_config():
    client = LocalClient()
    cfg = client.node_config()
    assert isinstance(cfg, NodeConfig)
    assert cfg.n_fri_queries >= 1
    assert cfg.fri_security_bits == 6 * cfg.n_fri_queries + 10
    assert cfg.min_batch_size >= 1
    assert cfg.max_batch_size >= cfg.min_batch_size
    assert cfg.mempool_capacity >= cfg.max_batch_size


def test_local_client_node_config_custom_params():
    from aggregator.node import AggregatorNode
    node = AggregatorNode(min_batch_size=5, max_batch_size=100,
                          mempool_capacity=500, n_fri_queries=3)
    client = LocalClient(node=node)
    cfg = client.node_config()
    assert cfg.n_fri_queries == 3
    assert cfg.fri_security_bits == 28
    assert cfg.min_batch_size == 5
    assert cfg.max_batch_size == 100
    assert cfg.mempool_capacity == 500


def test_local_client_get_batch_returns_status():
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="cd" * 32, amount=1, nonce=0)
        client = LocalClient()
        client.submit(tx)
        status = client.flush()
    assert status is not None
    found = client.get_batch(status.batch_id)
    assert found is not None
    assert found.batch_id == status.batch_id
    assert found.tx_count == status.tx_count
    assert found.is_proven == status.is_proven


def test_local_client_get_batch_unknown_returns_none():
    client = LocalClient()
    assert client.get_batch("nonexistent-batch-id") is None


# ── BatchStatus witness fields ────────────────────────────────────────────────

def test_batch_status_has_witness_false_by_default():
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="ab" * 32, amount=5, nonce=0)
        client = LocalClient()
        client.submit(tx)
        status = client.flush()
    assert status is not None
    assert status.has_witness is False
    assert status.witness_commitment is None
    assert status.has_vfri7 is False
    assert status.vfri7_commitment_log10 is None
    assert status.vfri7_commitment_log8 is None


def test_batch_status_prove_witnesses_param_accepted():
    """flush(prove_witnesses=True) completes without error regardless of PyO3 ext."""
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="ab" * 32, amount=5, nonce=0)
        client = LocalClient()
        client.submit(tx)
        status = client.flush(prove_witnesses=True)
    assert status is not None
    assert isinstance(status.has_witness, bool)
    assert isinstance(status.has_vfri7, bool)


def test_run_cycle_prove_witnesses_param_accepted():
    from aggregator.node import AggregatorNode

    node = AggregatorNode(min_batch_size=1)
    client = LocalClient(node=node)
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="cd" * 32, amount=1, nonce=0)
        client.submit(tx)
    status = client.run_cycle(prove_witnesses=True)
    assert status is not None
    assert isinstance(status.has_witness, bool)


# ── LocalClient.prove_witness ─────────────────────────────────────────────────

def test_prove_witness_unsigned_tx_returns_no_witness():
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
    ws = client.prove_witness(tx)
    assert isinstance(ws, WitnessStatus)
    assert ws.has_witness is False


def test_prove_witness_signed_tx_returns_witness_status():
    """Returns WitnessStatus; has_witness may be False if PyO3 ext is not installed."""
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="ab" * 32, amount=1, nonce=0)
        client = LocalClient()
        ws = client.prove_witness(tx)
    assert isinstance(ws, WitnessStatus)
    assert isinstance(ws.has_witness, bool)
    assert isinstance(ws.max_norms, list)
    if ws.has_witness:
        # VFRI7 cross-bound path: onchain_commitment aliases vfri7_commitment_log10
        assert ws.onchain_commitment is not None
        assert len(ws.onchain_commitment) == 32
        int(ws.onchain_commitment, 16)  # valid hex
        assert ws.has_vfri7 is True
        assert ws.vfri7_commitment_log10 == ws.onchain_commitment
        assert ws.vfri7_commitment_log8 is not None
        assert len(ws.vfri7_commitment_log8) == 32
        # c_tilde_hex is legacy V3/V4 only; VFRI7 path does not populate it
        assert ws.c_tilde_hex is None
        # FRI security fields
        assert ws.n_fri_queries >= 1
        assert ws.fri_security_bits == 6 * ws.n_fri_queries + 10


# ── HttpClient ────────────────────────────────────────────────────────────────

def test_http_client_health(http_client: HttpClient):
    assert http_client.health() is True


def test_http_client_stats_initial_state(http_client: HttpClient):
    stats = http_client.stats()
    assert isinstance(stats, NodeStats)
    assert stats.transactions_received == 0
    assert stats.pending == 0
    assert stats.batches_created == 0


def test_http_client_submit_signed_tx(http_client: HttpClient):
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="d" * 64, amount=10, nonce=0)
        result = http_client.submit(tx)
    assert isinstance(result, SubmitResult)
    assert result.accepted is True
    assert result.error is None
    assert result.mempool_size == 1


def test_http_client_submit_unsigned_tx_rejected(http_client: HttpClient):
    pub, priv = generate_keypair()
    wipe_key(priv)
    tx = Transaction(
        sender=derive_address(pub),
        recipient="f" * 64,
        amount=1,
        nonce=0,
        public_key=pub,
    )
    result = http_client.submit(tx)
    assert result.accepted is False
    assert result.error is not None


def test_http_client_flush_empty_returns_none(http_client: HttpClient):
    assert http_client.flush() is None


def test_http_client_flush_creates_batch(http_client: HttpClient):
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="ab" * 32, amount=5, nonce=0)
        http_client.submit(tx)
        status = http_client.flush()
    assert isinstance(status, BatchStatus)
    assert status.tx_count == 1
    assert len(status.merkle_root) == 128
    assert status.batch_id != ""
    assert isinstance(status.is_proven, bool)


def test_http_client_run_cycle_empty_returns_none(http_client: HttpClient):
    assert http_client.run_cycle() is None


def test_http_client_run_cycle_prove_witnesses_param_accepted(http_client: HttpClient):
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="ef" * 32, amount=1, nonce=0)
        http_client.submit(tx)
    status = http_client.run_cycle(prove_witnesses=True)
    assert status is not None
    assert isinstance(status.has_witness, bool)
    assert isinstance(status.has_vfri7, bool)


def test_http_client_flush_prove_witnesses_param_accepted(http_client: HttpClient):
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="ab" * 32, amount=5, nonce=0)
        http_client.submit(tx)
    status = http_client.flush(prove_witnesses=True)
    assert status is not None
    assert isinstance(status.has_witness, bool)
    assert isinstance(status.has_vfri7, bool)


def test_http_client_get_batch_returns_status(http_client: HttpClient):
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="cd" * 32, amount=1, nonce=0)
        http_client.submit(tx)
        flushed = http_client.flush()
    assert flushed is not None
    found = http_client.get_batch(flushed.batch_id)
    assert found is not None
    assert found.batch_id == flushed.batch_id
    assert found.tx_count == flushed.tx_count


def test_http_client_get_batch_unknown_returns_none(http_client: HttpClient):
    import uuid
    assert http_client.get_batch(str(uuid.uuid4())) is None


def test_http_client_stats_tracks_submissions(http_client: HttpClient):
    with Wallet.generate() as wallet:
        builder = TransactionBuilder(wallet)
        for i in range(3):
            http_client.submit(builder.build(recipient="23" * 32, amount=1, nonce=i))
        http_client.flush()
    stats = http_client.stats()
    assert stats.transactions_received == 3
    assert stats.transactions_batched == 3
    assert stats.batches_created == 1
    assert stats.pending == 0


def test_http_client_prove_witness_unsigned_returns_no_witness(http_client: HttpClient):
    pub, priv = generate_keypair()
    wipe_key(priv)
    tx = Transaction(
        sender=derive_address(pub),
        recipient="f" * 64,
        amount=1,
        nonce=0,
        public_key=pub,
    )
    ws = http_client.prove_witness(tx)
    assert isinstance(ws, WitnessStatus)
    assert ws.has_witness is False


def test_http_client_node_config(http_client: HttpClient):
    cfg = http_client.node_config()
    assert isinstance(cfg, NodeConfig)
    assert cfg.n_fri_queries >= 1
    assert cfg.fri_security_bits == 6 * cfg.n_fri_queries + 10
    assert cfg.min_batch_size >= 1
    assert cfg.max_batch_size >= cfg.min_batch_size
    assert cfg.mempool_capacity >= cfg.max_batch_size
    assert isinstance(cfg.version, str) and len(cfg.version) > 0


def test_http_client_run_cycle_prove_witnesses_param_accepted(http_client: HttpClient):
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="ef" * 32, amount=1, nonce=0)
        http_client.submit(tx)
    status = http_client.run_cycle(prove_witnesses=True)
    assert status is not None
    assert isinstance(status.has_witness, bool)
    assert isinstance(status.has_vfri7, bool)


def test_http_client_flush_prove_witnesses_param_accepted(http_client: HttpClient):
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="ab" * 32, amount=5, nonce=0)
        http_client.submit(tx)
    status = http_client.flush(prove_witnesses=True)
    assert status is not None
    assert isinstance(status.has_witness, bool)
    assert isinstance(status.has_vfri7, bool)


# ── LocalClient.get_witness_status ───────────────────────────────────────────

def test_local_client_get_witness_status_unknown_batch_returns_none():
    client = LocalClient()
    assert client.get_witness_status("00000000-0000-0000-0000-000000000000") is None


def test_local_client_get_witness_status_no_witness():
    client = LocalClient()
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="cc" * 32, amount=1, nonce=0)
        client.submit(tx)
    batch = client.flush(prove_witnesses=False)
    assert batch is not None
    ws = client.get_witness_status(batch.batch_id)
    assert isinstance(ws, WitnessStatus)
    assert ws.has_witness is False
    assert ws.n_fri_queries >= 1


# ── HttpClient.get_witness_status ────────────────────────────────────────────

def test_http_client_context_manager_closes_connection(http_client: HttpClient):
    with http_client:
        assert http_client.health() is True
    assert http_client._owned_client is None  # close() was called


def test_http_client_get_witness_status_unknown_returns_none(http_client: HttpClient):
    result = http_client.get_witness_status("00000000-0000-0000-0000-000000000000")
    assert result is None


def test_http_client_get_witness_status_no_witness(http_client: HttpClient):
    with Wallet.generate() as wallet:
        tx = TransactionBuilder(wallet).build(recipient="dd" * 32, amount=2, nonce=0)
        http_client.submit(tx)
    batch = http_client.flush(prove_witnesses=False)
    assert batch is not None
    ws = http_client.get_witness_status(batch.batch_id)
    assert isinstance(ws, WitnessStatus)
    assert ws.has_witness is False
    assert ws.n_fri_queries >= 1
    assert ws.fri_security_bits == 6 * ws.n_fri_queries + 10
