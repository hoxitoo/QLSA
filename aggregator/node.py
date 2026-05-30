from __future__ import annotations

import logging
import os
import threading
from collections import deque
from dataclasses import dataclass, field

from core.transaction import Transaction
from aggregator.batcher import BatchResult, Batcher
from aggregator.mempool import Mempool

logger = logging.getLogger(__name__)


@dataclass
class NodeStats:
    transactions_received: int = 0
    transactions_batched: int = 0
    batches_created: int = 0
    proofs_generated: int = 0


class AggregatorNode:
    """Top-level orchestrator for the QLSA aggregation protocol.

    Lifecycle:
        1. Wallets call submit() with signed transactions.
        2. Caller triggers run_cycle() periodically (timer, block event, etc.).
        3. run_cycle() drains the mempool → create_batch → STARK prove.
        4. Caller submits BatchResult to the on-chain BatchRegistry.

    Example::

        node = AggregatorNode(min_batch_size=10)
        for tx in signed_txs:
            node.submit(tx)
        result = node.run_cycle()
        if result and result.is_proven:
            # call BatchRegistry.submitBatch(
            #     result.merkle_root_onchain,
            #     result.stark_commitment_onchain,
            #     result.proof,
            # )
    """

    def __init__(
        self,
        min_batch_size: int = 1,
        max_batch_size: int = 3000,
        mempool_capacity: int = 3000,
        n_fri_queries: int | None = None,
    ) -> None:
        # Allow override from env (e.g. N_FRI_QUERIES=3 for 28-bit on-chain soundness).
        # Default 1 is gas-safe for testnet; production target is 20 (requires gas optimisation).
        if n_fri_queries is None:
            raw = os.environ.get("N_FRI_QUERIES", "1")
            try:
                n_fri_queries = int(raw)
            except ValueError as exc:
                raise ValueError(
                    f"N_FRI_QUERIES must be an integer, got {raw!r}"
                ) from exc
            if not (1 <= n_fri_queries <= 64):
                raise ValueError(
                    f"N_FRI_QUERIES must be in [1, 64], got {n_fri_queries}"
                )
        self.mempool = Mempool(max_size=mempool_capacity)
        self.batcher = Batcher(
            self.mempool,
            min_batch_size=min_batch_size,
            max_batch_size=max_batch_size,
            n_fri_queries=n_fri_queries,
        )
        self.n_fri_queries = n_fri_queries
        self._stats = NodeStats()
        self._history: deque[BatchResult] = deque(maxlen=self._MAX_HISTORY)
        self._batch_index: dict[str, BatchResult] = {}
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def submit(self, tx: Transaction) -> None:
        """Accept a signed transaction into the mempool."""
        self.mempool.add(tx)
        with self._lock:
            self._stats.transactions_received += 1
        logger.debug("tx accepted: %s (mempool=%d)", tx.tx_hash().hex()[:16], self.mempool.size())

    def run_cycle(self, prove_witnesses: bool = False) -> BatchResult | None:
        """Attempt to create and prove a batch from pending transactions.

        Returns a BatchResult when a batch is created, None when the mempool
        has fewer transactions than min_batch_size.
        """
        result = self.batcher.try_batch(prove_witnesses=prove_witnesses)
        if result is not None:
            self._record(result)
        return result

    def force_cycle(self, prove_witnesses: bool = False) -> BatchResult | None:
        """Force a batch from whatever is in the mempool (≥ 1 tx).

        Useful for flushing at shutdown or when a deadline is reached.
        Returns None only if the mempool is completely empty.
        """
        result = self.batcher.force_batch(prove_witnesses=prove_witnesses)
        if result is not None:
            self._record(result)
        return result

    def pending_count(self) -> int:
        return self.mempool.size()

    def stats(self) -> NodeStats:
        with self._lock:
            return NodeStats(
                transactions_received=self._stats.transactions_received,
                transactions_batched=self._stats.transactions_batched,
                batches_created=self._stats.batches_created,
                proofs_generated=self._stats.proofs_generated,
            )

    def history(self) -> list[BatchResult]:
        """Return a snapshot of all BatchResults produced so far (ordered oldest→newest)."""
        with self._lock:
            return list(self._history)

    def get_batch(self, batch_id: str) -> BatchResult | None:
        """O(1) lookup of a BatchResult by batch_id. Returns None if not found."""
        with self._lock:
            return self._batch_index.get(batch_id)

    # ── Internal ─────────────────────────────────────────────────────────────

    # Keep at most this many BatchResults in memory; oldest are evicted first.
    _MAX_HISTORY = 1000

    def _record(self, result: BatchResult) -> None:
        n = len(result.batch.transactions)
        with self._lock:
            self._stats.batches_created += 1
            self._stats.transactions_batched += n
            if result.is_proven:
                self._stats.proofs_generated += 1
            # When the deque is at capacity the oldest entry will be evicted on
            # append — remove it from the index first to keep them in sync.
            if len(self._history) == self._MAX_HISTORY:
                evicted = self._history[0]
                self._batch_index.pop(evicted.batch.batch_id, None)
            self._history.append(result)
            self._batch_index[result.batch.batch_id] = result
        logger.info(
            "batch created: id=%s txs=%d proven=%s",
            result.batch.batch_id[:8],
            n,
            result.is_proven,
        )
