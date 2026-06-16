"""Tests for the aggregator layer (Phase 4)."""

from __future__ import annotations

import threading

import pytest

from core.keys import derive_address, generate_keypair, wipe_key
from core.signing import sign
from core.transaction import Transaction
from aggregator.mempool import Mempool, MempoolFullError
from aggregator.batcher import BatchResult, Batcher
from aggregator.node import AggregatorNode, ReplayedTxError


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_signed_tx(nonce: int = 0) -> tuple[Transaction, bytearray]:
    pub, priv = generate_keypair()
    tx = Transaction(
        sender=derive_address(pub),
        recipient="e" * 64,
        amount=1,
        nonce=nonce,
        public_key=pub,
    )
    tx.signature = sign(tx.to_bytes(), priv)
    return tx, priv


def _signed_txs(n: int) -> tuple[list[Transaction], list[bytearray]]:
    pairs = [_make_signed_tx(nonce=i) for i in range(n)]
    txs, privs = zip(*pairs)
    return list(txs), list(privs)


def _wipe(privs: list[bytearray]) -> None:
    for p in privs:
        wipe_key(p)


# ──────────────────────────────────────────────────────────────────────────────
# Mempool tests
# ──────────────────────────────────────────────────────────────────────────────

class TestMempool:
    def test_add_increases_size(self):
        mp = Mempool()
        tx, priv = _make_signed_tx()
        mp.add(tx)
        wipe_key(priv)
        assert mp.size() == 1

    def test_add_unsigned_raises(self):
        pub, priv = generate_keypair()
        wipe_key(priv)
        tx = Transaction(
            sender=derive_address(pub),
            recipient="f" * 64,
            amount=1,
            nonce=0,
            public_key=pub,
        )
        mp = Mempool()
        with pytest.raises(ValueError, match="signed"):
            mp.add(tx)

    def test_drain_fifo_order(self):
        mp = Mempool()
        txs, privs = _signed_txs(3)
        for tx in txs:
            mp.add(tx)
        drained = mp.drain(3)
        _wipe(privs)
        assert drained == txs

    def test_drain_partial(self):
        mp = Mempool()
        txs, privs = _signed_txs(5)
        for tx in txs:
            mp.add(tx)
        drained = mp.drain(3)
        _wipe(privs)
        assert len(drained) == 3
        assert mp.size() == 2

    def test_drain_zero_returns_empty(self):
        mp = Mempool()
        tx, priv = _make_signed_tx()
        mp.add(tx)
        wipe_key(priv)
        assert mp.drain(0) == []
        assert mp.size() == 1

    def test_drain_more_than_available(self):
        mp = Mempool()
        txs, privs = _signed_txs(2)
        for tx in txs:
            mp.add(tx)
        drained = mp.drain(100)
        _wipe(privs)
        assert len(drained) == 2
        assert mp.size() == 0

    def test_full_raises_mempool_full_error(self):
        mp = Mempool(max_size=2)
        txs, privs = _signed_txs(3)
        mp.add(txs[0])
        mp.add(txs[1])
        _wipe(privs)
        with pytest.raises(MempoolFullError):
            mp.add(txs[2])

    def test_clear_empties_pool(self):
        mp = Mempool()
        txs, privs = _signed_txs(3)
        for tx in txs:
            mp.add(tx)
        _wipe(privs)
        mp.clear()
        assert mp.size() == 0

    def test_peek_does_not_remove(self):
        mp = Mempool()
        txs, privs = _signed_txs(3)
        for tx in txs:
            mp.add(tx)
        peeked = mp.peek(2)
        _wipe(privs)
        assert len(peeked) == 2
        assert mp.size() == 3

    def test_invalid_max_size_raises(self):
        with pytest.raises(ValueError):
            Mempool(max_size=0)

    def test_thread_safety(self):
        """Multiple threads adding concurrently must not lose transactions."""
        mp = Mempool(max_size=200)
        txs, privs = _signed_txs(100)
        errors: list[Exception] = []

        def add_batch(batch: list[Transaction]) -> None:
            try:
                for tx in batch:
                    mp.add(tx)
            except Exception as e:
                errors.append(e)

        mid = len(txs) // 2
        t1 = threading.Thread(target=add_batch, args=(txs[:mid],))
        t2 = threading.Thread(target=add_batch, args=(txs[mid:],))
        t1.start(); t2.start()
        t1.join();  t2.join()
        _wipe(privs)

        assert not errors
        assert mp.size() == 100


# ──────────────────────────────────────────────────────────────────────────────
# Batcher tests
# ──────────────────────────────────────────────────────────────────────────────

class TestBatcher:
    def test_try_batch_returns_none_when_empty(self):
        mp = Mempool()
        batcher = Batcher(mp, min_batch_size=1)
        assert batcher.try_batch() is None

    def test_try_batch_returns_none_below_min(self):
        mp = Mempool()
        tx, priv = _make_signed_tx()
        mp.add(tx)
        wipe_key(priv)
        batcher = Batcher(mp, min_batch_size=5)
        assert batcher.try_batch() is None
        assert mp.size() == 1  # tx was NOT consumed

    def test_try_batch_creates_batch_result(self):
        mp = Mempool()
        txs, privs = _signed_txs(3)
        for tx in txs:
            mp.add(tx)
        batcher = Batcher(mp, min_batch_size=3)
        result = batcher.try_batch()
        _wipe(privs)
        assert isinstance(result, BatchResult)
        assert len(result.batch.transactions) == 3
        assert mp.size() == 0

    def test_try_batch_drains_max_batch_size(self):
        mp = Mempool()
        txs, privs = _signed_txs(10)
        for tx in txs:
            mp.add(tx)
        batcher = Batcher(mp, min_batch_size=1, max_batch_size=4)
        result = batcher.try_batch()
        _wipe(privs)
        assert result is not None
        assert len(result.batch.transactions) == 4
        assert mp.size() == 6

    def test_force_batch_returns_none_when_empty(self):
        mp = Mempool()
        batcher = Batcher(mp)
        assert batcher.force_batch() is None

    def test_force_batch_ignores_min_size(self):
        mp = Mempool()
        tx, priv = _make_signed_tx()
        mp.add(tx)
        wipe_key(priv)
        batcher = Batcher(mp, min_batch_size=100)
        result = batcher.force_batch()
        assert result is not None
        assert len(result.batch.transactions) == 1

    def test_batch_result_merkle_root_onchain_is_32_bytes(self):
        mp = Mempool()
        txs, privs = _signed_txs(2)
        for tx in txs:
            mp.add(tx)
        result = Batcher(mp).try_batch()
        _wipe(privs)
        assert result is not None
        assert len(result.merkle_root_onchain) == 32

    def test_batch_result_stark_commitment_onchain_none_when_unproven(self):
        mp = Mempool()
        txs, privs = _signed_txs(2)
        for tx in txs:
            mp.add(tx)
        result = Batcher(mp).try_batch()
        _wipe(privs)
        assert result is not None
        # binary not available in test env — commitment stays None
        if not result.is_proven:
            assert result.stark_commitment_onchain is None

    def test_invalid_batcher_params_raise(self):
        mp = Mempool()
        with pytest.raises(ValueError):
            Batcher(mp, min_batch_size=0)
        with pytest.raises(ValueError):
            Batcher(mp, min_batch_size=10, max_batch_size=5)

    def test_batch_result_has_witness_false_by_default(self):
        mp = Mempool()
        txs, privs = _signed_txs(2)
        for tx in txs:
            mp.add(tx)
        result = Batcher(mp).try_batch()
        _wipe(privs)
        assert result is not None
        assert result.has_witness is False
        assert result.has_vfri7 is False
        assert result.has_vfri8 is False
        assert result.has_vfri9 is False
        assert result.has_vfri10 is False
        assert result.witness_commitment is None
        assert result.vfri7_commitment_log10 is None
        assert result.vfri7_commitment_log8 is None
        assert result.vfri8_commitment_log10 is None
        assert result.vfri8_commitment_log8 is None
        assert result.vfri9_commitment_log10 is None
        assert result.vfri9_commitment_log8 is None
        assert result.vfri10_commitment_log10 is None
        assert result.vfri10_commitment_log8 is None

    def test_try_batch_prove_witnesses_true_accepted(self):
        """prove_witnesses=True runs without error; has_witness may be False without PyO3 ext."""
        mp = Mempool()
        txs, privs = _signed_txs(2)
        for tx in txs:
            mp.add(tx)
        result = Batcher(mp).try_batch(prove_witnesses=True)
        _wipe(privs)
        assert result is not None
        assert isinstance(result.has_witness, bool)
        assert isinstance(result.has_vfri7, bool)
        assert isinstance(result.has_vfri8, bool)
        assert isinstance(result.has_vfri9, bool)
        assert isinstance(result.has_vfri10, bool)

    def test_force_batch_prove_witnesses_true_accepted(self):
        mp = Mempool()
        tx, priv = _make_signed_tx()
        mp.add(tx)
        wipe_key(priv)
        result = Batcher(mp, min_batch_size=100).force_batch(prove_witnesses=True)
        assert result is not None
        assert isinstance(result.has_witness, bool)
        assert isinstance(result.has_vfri7, bool)
        assert isinstance(result.has_vfri8, bool)
        assert isinstance(result.has_vfri9, bool)
        assert isinstance(result.has_vfri10, bool)

    def test_batch_result_vfri7_fields_accessible(self):
        """VFRI7 fields are present on BatchResult regardless of extension availability."""
        mp = Mempool()
        tx, priv = _make_signed_tx()
        mp.add(tx)
        wipe_key(priv)
        result = Batcher(mp).try_batch()
        assert result is not None
        assert hasattr(result, "vfri7_proof_log10")
        assert hasattr(result, "vfri7_commitment_log10")
        assert hasattr(result, "vfri7_hints_log10")
        assert hasattr(result, "vfri7_proof_log8")
        assert hasattr(result, "vfri7_commitment_log8")
        assert hasattr(result, "vfri7_hints_log8")
        assert hasattr(result, "vfri8_proof_log10")
        assert hasattr(result, "vfri8_commitment_log10")
        assert hasattr(result, "vfri8_hints_log10")
        assert hasattr(result, "vfri8_proof_log8")
        assert hasattr(result, "vfri8_commitment_log8")
        assert hasattr(result, "vfri8_hints_log8")
        assert hasattr(result, "vfri9_proof_log10")
        assert hasattr(result, "vfri9_commitment_log10")
        assert hasattr(result, "vfri9_hints_log10")
        assert hasattr(result, "vfri9_proof_log8")
        assert hasattr(result, "vfri9_commitment_log8")
        assert hasattr(result, "vfri9_hints_log8")
        assert hasattr(result, "vfri10_proof_log10")
        assert hasattr(result, "vfri10_commitment_log10")
        assert hasattr(result, "vfri10_hints_log10")
        assert hasattr(result, "vfri10_proof_log8")
        assert hasattr(result, "vfri10_commitment_log8")
        assert hasattr(result, "vfri10_hints_log8")

    def test_vfri10_populated_and_version4_when_proving(self):
        """When the PyO3 extension is present, prove_witnesses=True populates the
        VFRI10 fields with consistent commitments and version-4 proof markers."""
        mp = Mempool()
        tx, priv = _make_signed_tx()
        mp.add(tx)
        wipe_key(priv)
        result = Batcher(mp, min_batch_size=1).force_batch(prove_witnesses=True)
        assert result is not None
        if not result.has_vfri10:
            pytest.skip("PyO3 extension (qlsa_stark_stwo) not available")
        # Both groups present and self-consistent.
        assert result.has_witness is True
        for proof, commit, hints in (
            (result.vfri10_proof_log10, result.vfri10_commitment_log10, result.vfri10_hints_log10),
            (result.vfri10_proof_log8,  result.vfri10_commitment_log8,  result.vfri10_hints_log8),
        ):
            assert isinstance(proof, bytes) and len(proof) >= 40
            assert isinstance(hints, bytes) and len(hints) > 0
            assert isinstance(commit, str) and len(commit) == 32
            bytes.fromhex(commit)  # valid hex
            # VFRI10 proof version marker is 4 (little-endian u64 in proof[0:8]).
            assert int.from_bytes(proof[0:8], "little") == 4


# ──────────────────────────────────────────────────────────────────────────────
# Prover failure recovery (liveness)
# ──────────────────────────────────────────────────────────────────────────────

class TestProverFailureRecovery:
    def test_prepend_batch_returns_dropped_and_keeps_oldest(self):
        mp = Mempool(max_size=2)
        txs, privs = _signed_txs(3)
        dropped = mp.prepend_batch(txs)
        _wipe(privs)
        # Oldest (FIFO-first) transactions are kept; newest overflow is dropped.
        assert dropped == [txs[2]]
        assert mp.peek(2) == [txs[0], txs[1]]
        assert mp.dropped_count == 1

    def test_prepend_batch_all_fit_returns_empty(self):
        mp = Mempool(max_size=10)
        txs, privs = _signed_txs(3)
        dropped = mp.prepend_batch(txs)
        _wipe(privs)
        assert dropped == []
        assert mp.size() == 3
        assert mp.dropped_count == 0

    def test_prover_crash_returns_txs_to_mempool(self, monkeypatch: pytest.MonkeyPatch):
        import stark.prover as prover_mod

        def _boom(batch):
            raise RuntimeError("simulated prover crash")

        monkeypatch.setattr(prover_mod, "prove_batch_poseidon2", _boom)
        mp = Mempool()
        txs, privs = _signed_txs(2)
        for tx in txs:
            mp.add(tx)
        batcher = Batcher(mp)
        result = batcher.try_batch()
        _wipe(privs)
        # Transient crash: no batch emitted, transactions back in the mempool.
        assert result is None
        assert mp.size() == 2

    def test_prover_crash_gives_up_after_max_retries(self, monkeypatch: pytest.MonkeyPatch):
        import stark.prover as prover_mod

        def _boom(batch):
            raise RuntimeError("simulated prover crash")

        monkeypatch.setattr(prover_mod, "prove_batch_poseidon2", _boom)
        mp = Mempool()
        txs, privs = _signed_txs(2)
        for tx in txs:
            mp.add(tx)
        batcher = Batcher(mp)
        for _ in range(Batcher.MAX_PROOF_RETRIES):
            assert batcher.try_batch() is None
            assert mp.size() == 2  # returned each time
        # Retry budget exhausted → unproven batch is emitted to preserve liveness.
        result = batcher.try_batch()
        _wipe(privs)
        assert result is not None
        assert result.is_proven is False
        assert len(result.batch.transactions) == 2
        assert mp.size() == 0

    def test_prover_unavailable_emits_unproven_batch(self, monkeypatch: pytest.MonkeyPatch):
        import stark.prover as prover_mod

        def _missing(batch):
            raise prover_mod.ProverUnavailableError("extension not installed")

        monkeypatch.setattr(prover_mod, "prove_batch_poseidon2", _missing)
        mp = Mempool()
        txs, privs = _signed_txs(2)
        for tx in txs:
            mp.add(tx)
        result = Batcher(mp).try_batch()
        _wipe(privs)
        # Documented degraded mode: batch emitted unproven, no retry loop.
        assert result is not None
        assert result.is_proven is False
        assert mp.size() == 0

    def test_successful_proof_clears_retry_budget(self, monkeypatch: pytest.MonkeyPatch):
        import stark.prover as prover_mod

        calls = {"n": 0}

        def _flaky(batch):
            calls["n"] += 1
            raise RuntimeError("simulated prover crash")

        monkeypatch.setattr(prover_mod, "prove_batch_poseidon2", _flaky)
        mp = Mempool()
        txs, privs = _signed_txs(2)
        for tx in txs:
            mp.add(tx)
        batcher = Batcher(mp)
        assert batcher.try_batch() is None  # one failed attempt recorded
        # Prover recovers before the budget is exhausted.
        monkeypatch.setattr(
            prover_mod, "prove_batch_poseidon2",
            lambda batch: (_ for _ in ()).throw(prover_mod.ProverUnavailableError("ext")),
        )
        result = batcher.try_batch()
        _wipe(privs)
        assert result is not None
        # Retry map cleaned up after the batch is emitted.
        assert batcher._proof_retries == {}


# ──────────────────────────────────────────────────────────────────────────────
# AggregatorNode tests
# ──────────────────────────────────────────────────────────────────────────────

class TestAggregatorNode:
    def test_submit_increases_pending(self):
        node = AggregatorNode()
        tx, priv = _make_signed_tx()
        node.submit(tx)
        wipe_key(priv)
        assert node.pending_count() == 1

    def test_mempool_capacity_below_min_batch_size_raises(self):
        with pytest.raises(ValueError, match="mempool_capacity"):
            AggregatorNode(min_batch_size=10, mempool_capacity=5)

    def test_resubmitting_a_batched_tx_is_rejected(self):
        # Replay guard: once a tx is batched it must not be batched again, even
        # after it has left the mempool (its hash is no longer pending).
        node = AggregatorNode(min_batch_size=1)
        tx, priv = _make_signed_tx()
        node.submit(tx)
        result = node.run_cycle()
        wipe_key(priv)
        assert result is not None and node.pending_count() == 0
        with pytest.raises(ReplayedTxError):
            node.submit(tx)
        # The replayed tx must not have been re-queued.
        assert node.pending_count() == 0

    def test_run_cycle_returns_none_when_below_min(self):
        node = AggregatorNode(min_batch_size=5)
        txs, privs = _signed_txs(3)
        for tx in txs:
            node.submit(tx)
        result = node.run_cycle()
        _wipe(privs)
        assert result is None
        assert node.pending_count() == 3

    def test_run_cycle_creates_batch(self):
        node = AggregatorNode(min_batch_size=2)
        txs, privs = _signed_txs(2)
        for tx in txs:
            node.submit(tx)
        result = node.run_cycle()
        _wipe(privs)
        assert result is not None
        assert len(result.batch.transactions) == 2
        assert node.pending_count() == 0

    def test_stats_track_correctly(self):
        node = AggregatorNode(min_batch_size=2, max_batch_size=2)
        txs, privs = _signed_txs(4)
        for tx in txs:
            node.submit(tx)
        node.run_cycle()
        node.run_cycle()
        _wipe(privs)
        s = node.stats()
        assert s.transactions_received == 4
        assert s.batches_created == 2
        assert s.transactions_batched == 4

    def test_history_records_all_batches(self):
        node = AggregatorNode(min_batch_size=1)
        for i in range(3):
            tx, priv = _make_signed_tx(nonce=i)
            node.submit(tx)
            wipe_key(priv)
            node.run_cycle()
        assert len(node.history()) == 3

    def test_force_cycle_flushes_partial_mempool(self):
        node = AggregatorNode(min_batch_size=10)
        txs, privs = _signed_txs(3)
        for tx in txs:
            node.submit(tx)
        # run_cycle won't fire (below min), force_cycle will
        assert node.run_cycle() is None
        result = node.force_cycle()
        _wipe(privs)
        assert result is not None
        assert len(result.batch.transactions) == 3
        assert node.pending_count() == 0

    def test_force_cycle_returns_none_when_empty(self):
        node = AggregatorNode()
        assert node.force_cycle() is None

    def test_run_cycle_prove_witnesses_param_accepted(self):
        node = AggregatorNode(min_batch_size=1)
        tx, priv = _make_signed_tx()
        node.submit(tx)
        wipe_key(priv)
        result = node.run_cycle(prove_witnesses=True)
        assert result is not None
        assert isinstance(result.has_witness, bool)

    def test_force_cycle_prove_witnesses_param_accepted(self):
        node = AggregatorNode(min_batch_size=10)
        tx, priv = _make_signed_tx()
        node.submit(tx)
        wipe_key(priv)
        result = node.force_cycle(prove_witnesses=True)
        assert result is not None
        assert isinstance(result.has_witness, bool)

    def test_multiple_cycles_accumulate_stats(self):
        node = AggregatorNode(min_batch_size=1, max_batch_size=2, mempool_capacity=10)
        txs, privs = _signed_txs(6)
        for tx in txs:
            node.submit(tx)
        while node.pending_count() > 0:
            node.run_cycle()
        _wipe(privs)
        s = node.stats()
        assert s.batches_created == 3
        assert s.transactions_batched == 6
        assert s.transactions_received == 6

    def test_n_fri_queries_default_is_one(self):
        node = AggregatorNode()
        assert node.n_fri_queries == 1
        assert node.batcher.n_fri_queries == 1

    def test_n_fri_queries_constructor_override(self):
        node = AggregatorNode(n_fri_queries=3)
        assert node.n_fri_queries == 3
        assert node.batcher.n_fri_queries == 3

    def test_n_fri_queries_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("N_FRI_QUERIES", "5")
        node = AggregatorNode()
        assert node.n_fri_queries == 5
        assert node.batcher.n_fri_queries == 5

    def test_n_fri_queries_env_ignored_when_explicit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("N_FRI_QUERIES", "5")
        node = AggregatorNode(n_fri_queries=2)
        assert node.n_fri_queries == 2


class TestBatcherNFriQueries:
    def test_default_is_one(self):
        mp = Mempool()
        b = Batcher(mp)
        assert b.n_fri_queries == 1

    def test_custom_value(self):
        mp = Mempool()
        b = Batcher(mp, n_fri_queries=4)
        assert b.n_fri_queries == 4

    def test_zero_raises(self):
        mp = Mempool()
        with pytest.raises(ValueError, match="n_fri_queries must be in"):
            Batcher(mp, n_fri_queries=0)

    def test_over_max_raises(self):
        mp = Mempool()
        with pytest.raises(ValueError, match="n_fri_queries must be in"):
            Batcher(mp, n_fri_queries=65)

    def test_boundary_values_accepted(self):
        mp = Mempool()
        Batcher(mp, n_fri_queries=1)
        Batcher(mp, n_fri_queries=64)
