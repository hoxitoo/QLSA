from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.batch import Batch, create_batch
from core.keys import DEFAULT_ALGORITHM
from aggregator.mempool import Mempool


@dataclass
class BatchResult:
    """Output of a single batch cycle."""

    batch: Batch

    # Populated when the Rust binary is available; None otherwise.
    proof: bytes | None = field(default=None, repr=False)
    commitment: str | None = None       # 8 hex chars (4-byte M31 field element)

    # Convenience properties for Solidity submission
    @property
    def merkle_root_onchain(self) -> bytes:
        """First 32 bytes of SHA3-512 Merkle root — use as bytes32 in Solidity."""
        return self.batch.merkle_root[:32]

    @property
    def stark_commitment_onchain(self) -> bytes | None:
        """Raw 8 bytes of the STARK commitment — use as bytes8 in Solidity."""
        if self.commitment is None:
            return None
        return bytes.fromhex(self.commitment)

    @property
    def is_proven(self) -> bool:
        return self.proof is not None and self.commitment is not None


class Batcher:
    """Creates batches from a Mempool and optionally generates STARK proofs."""

    def __init__(
        self,
        mempool: Mempool,
        min_batch_size: int = 1,
        max_batch_size: int = 3000,
        algorithm: str = DEFAULT_ALGORITHM,
    ) -> None:
        if min_batch_size < 1:
            raise ValueError("min_batch_size must be at least 1")
        if max_batch_size < min_batch_size:
            raise ValueError("max_batch_size must be >= min_batch_size")
        self.mempool = mempool
        self.min_batch_size = min_batch_size
        self.max_batch_size = max_batch_size
        self.algorithm = algorithm

    def try_batch(self) -> BatchResult | None:
        """Create a batch if the mempool has enough transactions.

        Returns None if fewer than min_batch_size transactions are pending.
        Drains up to max_batch_size transactions on success.
        """
        if self.mempool.size() < self.min_batch_size:
            return None

        txs = self.mempool.drain(self.max_batch_size)
        if not txs:
            return None

        batch = create_batch(txs, algorithm=self.algorithm)
        return self._try_prove(batch)

    def force_batch(self) -> BatchResult | None:
        """Drain whatever is in the mempool (≥1 tx) and create a batch.

        Returns None if the mempool is empty.
        """
        if self.mempool.size() == 0:
            return None

        txs = self.mempool.drain(self.max_batch_size)
        batch = create_batch(txs, algorithm=self.algorithm)
        return self._try_prove(batch)

    # ──────────────────────────────────────────────────────────────────────────

    def _try_prove(self, batch: Batch) -> BatchResult:
        """Run the STARK prover if the binary is available; skip gracefully."""
        try:
            from stark.prover import binary_available, prove_batch
            if binary_available():
                pr = prove_batch(batch)
                return BatchResult(
                    batch=batch,
                    proof=pr.proof,
                    commitment=pr.commitment,
                )
        except Exception as exc:
            logging.warning("STARK proving skipped due to error: %s", exc)
        return BatchResult(batch=batch)
