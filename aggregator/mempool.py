from __future__ import annotations

import logging
import threading
from collections import deque

from core.transaction import Transaction

logger = logging.getLogger(__name__)


MAX_MEMPOOL_SIZE = 3000


class MempoolFullError(Exception):
    """Raised when the mempool has reached its capacity."""


class DuplicateTxError(Exception):
    """Raised when a transaction with the same hash is already in the mempool."""


class Mempool:
    """Thread-safe FIFO pool of pending signed transactions."""

    def __init__(self, max_size: int = MAX_MEMPOOL_SIZE) -> None:
        if max_size < 1:
            raise ValueError("max_size must be at least 1")
        self.max_size = max_size
        self._txs: deque[Transaction] = deque()
        self._tx_hashes: set[str] = set()
        self._dropped_total = 0
        self._lock = threading.Lock()

    def add(self, tx: Transaction) -> None:
        """Enqueue a signed transaction.

        Raises ValueError if the transaction is unsigned.
        Raises MempoolFullError if the pool is at capacity.
        """
        if tx.signature is None:
            raise ValueError("Transaction must be signed before adding to mempool")
        tx_hash = tx.tx_hash().hex()
        with self._lock:
            if tx_hash in self._tx_hashes:
                raise DuplicateTxError(
                    f"transaction {tx_hash[:16]}… is already in the mempool"
                )
            if len(self._txs) >= self.max_size:
                raise MempoolFullError(
                    f"Mempool is full ({self.max_size} transactions)"
                )
            self._txs.append(tx)
            self._tx_hashes.add(tx_hash)

    def drain(self, n: int) -> list[Transaction]:
        """Remove and return up to *n* transactions (FIFO order)."""
        if n < 1:
            return []
        with self._lock:
            count = min(n, len(self._txs))
            txs = [self._txs.popleft() for _ in range(count)]
            for tx in txs:
                self._tx_hashes.discard(tx.tx_hash().hex())
            return txs

    def drain_if_ready(self, min_n: int, max_n: int) -> list[Transaction]:
        """Atomically drain up to *max_n* txs only if at least *min_n* are present.

        Returns an empty list (without draining) when fewer than *min_n* are pending.
        Eliminates the TOCTOU race between size() + drain() across two lock acquisitions.
        """
        if min_n < 1:
            raise ValueError("min_n must be at least 1")
        with self._lock:
            if len(self._txs) < min_n:
                return []
            count = min(max_n, len(self._txs))
            txs = [self._txs.popleft() for _ in range(count)]
            for tx in txs:
                self._tx_hashes.discard(tx.tx_hash().hex())
            return txs

    def prepend_batch(self, txs: list[Transaction]) -> list[Transaction]:
        """Re-insert transactions at the front of the queue (FIFO recovery).

        Used by the batcher to return valid transactions that could not be batched
        (e.g. batch creation or proving failed) so they are included in the next
        cycle.  Preserves the original FIFO order; when capacity is insufficient
        the OLDEST transactions are kept and the newest overflow is dropped.

        Returns the list of dropped transactions (empty when all fit) so the
        caller can persist, retry, or report them instead of losing them silently.
        """
        with self._lock:
            fit = self.max_size - len(self._txs)
            if fit < 0:
                fit = 0
            kept, dropped = txs[:fit], txs[fit:]
            for tx in reversed(kept):
                self._txs.appendleft(tx)
                self._tx_hashes.add(tx.tx_hash().hex())
            self._dropped_total += len(dropped)
        if dropped:
            logger.warning(
                "prepend_batch: dropped %d tx(s) — mempool full (capacity=%d)",
                len(dropped), self.max_size,
            )
        return dropped

    @property
    def dropped_count(self) -> int:
        """Total transactions dropped by prepend_batch overflow since startup."""
        with self._lock:
            return self._dropped_total

    def peek(self, n: int) -> list[Transaction]:
        """Return up to *n* transactions without removing them."""
        if n < 1:
            return []
        with self._lock:
            return list(self._txs)[:n]

    def peek_hashes(self, n: int) -> list[str]:
        """Return up to *n* pending tx hashes (FIFO order) without removing them."""
        if n < 1:
            return []
        with self._lock:
            return [tx.tx_hash().hex() for tx in list(self._txs)[:n]]

    def size(self) -> int:
        with self._lock:
            return len(self._txs)

    def contains(self, tx_hash_hex: str) -> bool:
        """Return True if a transaction with this hash is currently pending."""
        with self._lock:
            return tx_hash_hex in self._tx_hashes

    def get_pending_by_sender(self, sender_hex: str) -> list[str]:
        """Return tx_hashes (FIFO order, oldest-first) for pending txs from *sender_hex*.

        Performs a linear scan of the mempool deque.  Thread-safe.
        """
        with self._lock:
            return [
                tx.tx_hash().hex()
                for tx in self._txs
                if tx.sender == sender_hex
            ]

    def clear(self) -> None:
        with self._lock:
            self._txs.clear()
            self._tx_hashes.clear()
