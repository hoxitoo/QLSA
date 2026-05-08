from __future__ import annotations

import logging
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
    ) -> None:
        self.mempool = Mempool(max_size=mempool_capacity)
        self.batcher = Batcher(
            self.mempool,
            min_batch_size=min_batch_size,
            max_batch_size=max_batch_size,
        )
        self._stats = NodeStats()
        self._history: list[BatchResult] = []

    # ── Public API ────────────────────────────────────────────────────────────

    def submit(self, tx: Transaction) -> None:
        """Accept a signed transaction into the mempool."""
        self.mempool.add(tx)
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
        return NodeStats(
            transactions_received=self._stats.transactions_received,
            transactions_batched=self._stats.transactions_batched,
            batches_created=self._stats.batches_created,
            proofs_generated=self._stats.proofs_generated,
        )

    def history(self) -> list[BatchResult]:
        """Return a snapshot of all BatchResults produced so far."""
        return list(self._history)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _record(self, result: BatchResult) -> None:
        n = len(result.batch.transactions)
        self._stats.batches_created += 1
        self._stats.transactions_batched += n
        if result.is_proven:
            self._stats.proofs_generated += 1
        self._history.append(result)
        logger.info(
            "batch created: id=%s txs=%d proven=%s",
            result.batch.batch_id[:8],
            n,
            result.is_proven,
        )
