from __future__ import annotations

import logging
import os
import threading
from collections import deque
from dataclasses import dataclass, field

from core.transaction import Transaction
from aggregator.batcher import BatchResult, Batcher
from aggregator.mempool import DuplicateTxError, Mempool

logger = logging.getLogger(__name__)


class ReplayedTxError(Exception):
    """Raised when a transaction that was already batched is re-submitted.

    Off-chain defence-in-depth: the on-chain BatchRegistry enforces strictly
    increasing per-sender nonces, but the mempool's hash-dedup only covers
    *pending* transactions.  Once a tx is batched and drained from the mempool
    its hash leaves the pending set, so an identical tx could be re-submitted
    and batched a second time.  The node rejects any tx whose hash is still in
    the retained batch history (bounded to _MAX_HISTORY batches).
    """


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
        # A mempool smaller than min_batch_size can never satisfy try_batch —
        # the node would silently produce no batches forever.
        if mempool_capacity < min_batch_size:
            raise ValueError(
                f"mempool_capacity ({mempool_capacity}) must be >= "
                f"min_batch_size ({min_batch_size})"
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
        self._tx_to_batch: dict[str, str] = {}  # tx_hash_hex → batch_id
        self._sender_txs: dict[str, deque[str]] = {}  # sender_hex → deque[tx_hash_hex]
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def submit(self, tx: Transaction) -> None:
        """Accept a signed transaction into the mempool.

        Raises DuplicateTxError if the tx is already pending, ReplayedTxError if
        it was already batched within the retained history, and the usual
        MempoolFullError / ValueError from the mempool.
        """
        tx_hash_hex = tx.tx_hash().hex()
        # Replay guard: reject re-submission of an already-batched transaction.
        # The tx is not in the mempool yet, so it cannot race a concurrent drain.
        with self._lock:
            if tx_hash_hex in self._tx_to_batch:
                raise ReplayedTxError(
                    f"transaction {tx_hash_hex[:16]}… was already batched"
                )
        self.mempool.add(tx)
        with self._lock:
            self._stats.transactions_received += 1
        logger.debug("tx accepted: %s (mempool=%d)", tx_hash_hex[:16], self.mempool.size())

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

    def get_transaction_batch(self, tx_hash_hex: str) -> str | None:
        """Return the batch_id that contains this tx, or None if not found in history."""
        with self._lock:
            return self._tx_to_batch.get(tx_hash_hex)

    def get_sender_transactions(self, sender_hex: str, limit: int = 100) -> list[str]:
        """Return batched tx_hashes for *sender_hex*, newest-first, up to *limit*.

        Thread-safe.  Returns an empty list if the sender has no recorded batched
        transactions.
        """
        with self._lock:
            dq = self._sender_txs.get(sender_hex, deque())
            return list(reversed(dq))[:limit]

    # ── Internal ─────────────────────────────────────────────────────────────

    # Keep at most this many BatchResults in memory; oldest are evicted first.
    _MAX_HISTORY = 1000
    # Per-sender tx_hash ring buffer size.
    _MAX_SENDER_HISTORY: int = 500

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
                for tx in evicted.batch.transactions:
                    tx_hex = tx.tx_hash().hex()
                    self._tx_to_batch.pop(tx_hex, None)
                    sender = tx.sender
                    if sender in self._sender_txs:
                        sq = self._sender_txs[sender]
                        try:
                            sq.remove(tx_hex)
                        except ValueError:
                            pass
                        if not sq:
                            del self._sender_txs[sender]
            self._history.append(result)
            self._batch_index[result.batch.batch_id] = result
            for tx in result.batch.transactions:
                tx_hash_hex = tx.tx_hash().hex()
                self._tx_to_batch[tx_hash_hex] = result.batch.batch_id
                sender = tx.sender
                if sender not in self._sender_txs:
                    self._sender_txs[sender] = deque(maxlen=self._MAX_SENDER_HISTORY)
                self._sender_txs[sender].append(tx_hash_hex)
        logger.info(
            "batch created: id=%s txs=%d proven=%s",
            result.batch.batch_id[:8],
            n,
            result.is_proven,
        )
