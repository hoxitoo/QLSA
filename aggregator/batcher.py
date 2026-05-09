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

    # Populated when the PyO3 extension is available; None otherwise.
    proof: bytes | None = field(default=None, repr=False)
    commitment: str | None = None  # 32 hex chars (16-byte 128-bit Scheme-B commitment)

    # ML-DSA arithmetic witness proof for the first transaction (MVP-3+).
    # Populated when prove_witnesses=True is passed to Batcher; None otherwise.
    witness_bundle:       bytes | None = field(default=None, repr=False)
    witness_commitment:   str | None = None  # 32-char hex — Blake2s binding
    witness_max_norms:    list[int] | None = None  # L=5 ‖z[j]‖_∞ values
    witness_c_tilde_hex:  str | None = None  # 96-char hex (48-byte ML-DSA-65 c̃)

    # Convenience properties for Solidity submission
    @property
    def merkle_root_onchain(self) -> bytes:
        """First 32 bytes of SHA3-512 Merkle root — use as bytes32 in Solidity."""
        return self.batch.merkle_root[:32]

    @property
    def stark_commitment_onchain(self) -> bytes | None:
        """Raw 16 bytes of the STARK commitment — use as bytes16 in Solidity.

        BatchRegistryV2 accepts bytes16 (16 bytes).  The Stwo prover returns
        a 32-char hex string (16 bytes); this property decodes it directly.
        """
        if self.commitment is None:
            return None
        raw = bytes.fromhex(self.commitment)
        if len(raw) != 16:
            raise ValueError(
                f"commitment must be 16 bytes (32 hex chars), got {len(raw)} bytes. "
                "Ensure the Rust qlsa_stark_stwo extension is up to date."
            )
        return raw

    @property
    def is_proven(self) -> bool:
        return self.proof is not None and self.commitment is not None

    @property
    def has_witness(self) -> bool:
        return self.witness_bundle is not None

    @property
    def witness_norm_bound_ok(self) -> bool:
        """True when all ‖z[j]‖_∞ are within the ML-DSA-65 NORM_BOUND (524 092)."""
        if self.witness_max_norms is None:
            return False
        from stark.prover import NORM_BOUND
        return all(mn < NORM_BOUND for mn in self.witness_max_norms)


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

    def try_batch(self, prove_witnesses: bool = False) -> BatchResult | None:
        """Create a batch if the mempool has enough transactions.

        Returns None if fewer than min_batch_size transactions are pending.
        Drains up to max_batch_size transactions on success.
        Transactions with invalid signatures are dropped with a warning;
        remaining valid transactions are returned to the mempool front so they
        are included in the next batch cycle.

        If prove_witnesses=True, also generates an ML-DSA arithmetic witness
        proof for the first transaction (MVP-3+, requires PyO3 extension).
        """
        if self.mempool.size() < self.min_batch_size:
            return None

        txs = self.mempool.drain(self.max_batch_size)
        if not txs:
            return None

        return self._create_and_prove(txs, prove_witnesses=prove_witnesses)

    def force_batch(self, prove_witnesses: bool = False) -> BatchResult | None:
        """Drain whatever is in the mempool (≥1 tx) and create a batch.

        Returns None if the mempool is empty.
        Transactions with invalid signatures are dropped with a warning;
        remaining valid transactions are returned to the mempool front so they
        are included in the next batch cycle.

        If prove_witnesses=True, also generates an ML-DSA arithmetic witness
        proof for the first transaction (MVP-3+).
        """
        txs = self.mempool.drain(self.max_batch_size)
        # Guard against TOCTOU: another thread may have drained the mempool
        # between a size() check and this drain call.
        if not txs:
            return None
        return self._create_and_prove(txs, prove_witnesses=prove_witnesses)

    # ──────────────────────────────────────────────────────────────────────────

    def _create_and_prove(self, txs: list[Transaction], prove_witnesses: bool = False) -> BatchResult | None:
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

        return self._try_prove(batch, prove_witnesses=prove_witnesses)

    def _try_prove(self, batch: Batch, prove_witnesses: bool = False) -> BatchResult:
        """Run the STARK prover; optionally add an ML-DSA witness proof for tx[0]."""
        result = BatchResult(batch=batch)
        try:
            from stark.prover import prove_batch
            pr = prove_batch(batch)
            result.proof = pr.proof
            result.commitment = pr.commitment
        except RuntimeError as exc:
            logging.warning("STARK proving skipped: %s", exc)
        except Exception as exc:
            logging.error("Unexpected error during STARK proving: %s", exc, exc_info=True)

        if prove_witnesses and batch.transactions:
            tx0 = batch.transactions[0]
            if tx0.signature is not None and tx0.public_key is not None:
                try:
                    from stark.prover import prove_mldsa_sig_witness_stark
                    wr = prove_mldsa_sig_witness_stark(
                        pk=tx0.public_key,
                        msg=tx0.to_bytes(),
                        sig=tx0.signature,
                    )
                    result.witness_bundle      = wr.proof_bundle
                    result.witness_commitment  = wr.onchain_commitment
                    result.witness_max_norms   = wr.max_norms
                    result.witness_c_tilde_hex = wr.c_tilde_hex
                except RuntimeError as exc:
                    logging.warning("ML-DSA witness proof skipped: %s", exc)
                except Exception as exc:
                    logging.error("Unexpected error during witness proving: %s", exc, exc_info=True)

        return result
