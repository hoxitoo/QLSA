from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.batch import Batch, InvalidSignatureError, BatchSizeError, create_batch
from core.keys import DEFAULT_ALGORITHM
from core.transaction import Transaction
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
        """Raw bytes of the STARK commitment — use as bytes8 in Solidity.

        BatchRegistryV2 accepts bytes8 (8 bytes).  The Stwo prover returns
        an 8-char hex string (4 bytes); we left-pad with zeros to produce
        exactly 8 bytes so the contract receives a well-formed bytes8.
        """
        if self.commitment is None:
            return None
        raw = bytes.fromhex(self.commitment)
        if len(raw) == 8:
            return raw
        if len(raw) == 4:
            return raw + b"\x00" * 4
        raise ValueError(f"commitment must be 4 or 8 bytes, got {len(raw)}")

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
        Transactions with invalid signatures are dropped with a warning;
        remaining valid transactions are returned to the mempool front so they
        are included in the next batch cycle.
        """
        if self.mempool.size() < self.min_batch_size:
            return None

        txs = self.mempool.drain(self.max_batch_size)
        if not txs:
            return None

        return self._create_and_prove(txs)

    def force_batch(self) -> BatchResult | None:
        """Drain whatever is in the mempool (≥1 tx) and create a batch.

        Returns None if the mempool is empty.
        Transactions with invalid signatures are dropped with a warning;
        remaining valid transactions are returned to the mempool front so they
        are included in the next batch cycle.
        """
        txs = self.mempool.drain(self.max_batch_size)
        # Guard against TOCTOU: another thread may have drained the mempool
        # between a size() check and this drain call.
        if not txs:
            return None
        return self._create_and_prove(txs)

    # ──────────────────────────────────────────────────────────────────────────

    def _create_and_prove(self, txs: list[Transaction]) -> BatchResult | None:
        """Filter invalid-signature transactions, build a valid batch, and prove.

        Invalid transactions are logged and discarded.  Valid transactions that
        couldn't form a batch (e.g. all were invalid) return the remaining valid
        ones to the mempool so they are not lost.
        """
        from core.signing import verify as sig_verify
        valid_txs = []
        for tx in txs:
            if tx.signature is None:
                logging.warning("batcher: dropping unsigned tx %s", tx.tx_hash().hex()[:16])
                continue
            if sig_verify(tx.to_bytes(), tx.signature, tx.public_key, self.algorithm):
                valid_txs.append(tx)
            else:
                logging.warning("batcher: dropping tx with invalid signature %s", tx.tx_hash().hex()[:16])

        if not valid_txs:
            return None

        try:
            batch = create_batch(valid_txs, algorithm=self.algorithm)
        except (InvalidSignatureError, BatchSizeError) as exc:
            logging.error("batcher: create_batch failed after pre-filter: %s", exc)
            return None

        return self._try_prove(batch)

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
        except RuntimeError as exc:
            # Expected: binary not built, prover timeout, or serialization failure.
            logging.warning("STARK proving skipped: %s", exc)
        except Exception as exc:
            # Unexpected: log at error level so it's not silently swallowed.
            logging.error("Unexpected error during STARK proving: %s", exc, exc_info=True)
        return BatchResult(batch=batch)
