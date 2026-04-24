from __future__ import annotations

import threading
from collections import deque

from core.transaction import Transaction


MAX_MEMPOOL_SIZE = 3000


class MempoolFullError(Exception):
    """Raised when the mempool has reached its capacity."""


class Mempool:
    """Thread-safe FIFO pool of pending signed transactions."""

    def __init__(self, max_size: int = MAX_MEMPOOL_SIZE) -> None:
        if max_size < 1:
            raise ValueError("max_size must be at least 1")
        self.max_size = max_size
        self._txs: deque[Transaction] = deque()
        self._lock = threading.Lock()

    def add(self, tx: Transaction) -> None:
        """Enqueue a signed transaction.

        Raises ValueError if the transaction is unsigned.
        Raises MempoolFullError if the pool is at capacity.
        """
        if tx.signature is None:
            raise ValueError("Transaction must be signed before adding to mempool")
        with self._lock:
            if len(self._txs) >= self.max_size:
                raise MempoolFullError(
                    f"Mempool is full ({self.max_size} transactions)"
                )
            self._txs.append(tx)

    def drain(self, n: int) -> list[Transaction]:
        """Remove and return up to *n* transactions (FIFO order)."""
        if n < 1:
            return []
        with self._lock:
            count = min(n, len(self._txs))
            return [self._txs.popleft() for _ in range(count)]

    def peek(self, n: int) -> list[Transaction]:
        """Return up to *n* transactions without removing them."""
        if n < 1:
            return []
        with self._lock:
            return list(self._txs)[:n]

    def size(self) -> int:
        with self._lock:
            return len(self._txs)

    def clear(self) -> None:
        with self._lock:
            self._txs.clear()
