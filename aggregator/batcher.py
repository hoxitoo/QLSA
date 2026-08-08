from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

from core.batch import Batch, InvalidSignatureError, BatchSizeError, create_batch
from core.keys import DEFAULT_ALGORITHM
from core.transaction import Transaction
from aggregator.mempool import Mempool
# Re-exported: these were defined here, and callers import them from here.
from stark.prover import WitnessGroup as GroupProof, WitnessProof


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

    # Cross-bound ML-DSA V23 witness proofs for tx[0], keyed by protocol name
    # ("vfri7".."vfri11").  Populated when prove_witnesses=True and the PyO3
    # extension is available.
    #
    # This replaced four hand-enumerated blocks of six fields each. That shape is
    # why the aggregator fell behind the deployed stack: adding VFRI11 meant
    # editing six fields in four layers, so it simply was not done, and the
    # aggregator's proofs silently stopped being submittable to the default
    # registry. The per-protocol `vfriN_*` attributes below are kept as read-only
    # views over this dict so existing callers (API, SDKs) keep working.
    witness_proofs: dict[str, WitnessProof] = field(default_factory=dict, repr=False)

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

    def witness_for(self, protocol: str) -> WitnessProof | None:
        """The witness proof generated under `protocol`, or None."""
        return self.witness_proofs.get(protocol)

    def has_protocol(self, protocol: str) -> bool:
        return protocol in self.witness_proofs

    @property
    def witness_protocols(self) -> list[str]:
        """Protocols for which a witness proof was generated, in insertion order."""
        return list(self.witness_proofs)

    # ── Deprecated per-protocol views ─────────────────────────────────────────
    # Kept so aggregator/api.py and both SDKs keep working unchanged. Prefer
    # `witness_proofs` / `witness_for(protocol)`; these cannot express a protocol
    # added after they were written, which is exactly how VFRI11 got missed.

    @property
    def has_vfri7(self) -> bool:
        return self.has_protocol("vfri7")

    @property
    def has_vfri8(self) -> bool:
        return self.has_protocol("vfri8")

    @property
    def has_vfri9(self) -> bool:
        return self.has_protocol("vfri9")

    @property
    def has_vfri10(self) -> bool:
        return self.has_protocol("vfri10")

    @property
    def has_vfri11(self) -> bool:
        return self.has_protocol("vfri11")

    @property
    def vfri7_proof_log10(self) -> bytes | None:
        w = self.witness_proofs.get("vfri7")
        return w.log10.proof if w else None

    @property
    def vfri7_commitment_log10(self) -> str | None:
        w = self.witness_proofs.get("vfri7")
        return w.log10.commitment if w else None

    @property
    def vfri7_hints_log10(self) -> bytes | None:
        w = self.witness_proofs.get("vfri7")
        return w.log10.hints if w else None

    @property
    def vfri7_proof_log8(self) -> bytes | None:
        w = self.witness_proofs.get("vfri7")
        return w.log8.proof if w else None

    @property
    def vfri7_commitment_log8(self) -> str | None:
        w = self.witness_proofs.get("vfri7")
        return w.log8.commitment if w else None

    @property
    def vfri7_hints_log8(self) -> bytes | None:
        w = self.witness_proofs.get("vfri7")
        return w.log8.hints if w else None

    @property
    def vfri8_proof_log10(self) -> bytes | None:
        w = self.witness_proofs.get("vfri8")
        return w.log10.proof if w else None

    @property
    def vfri8_commitment_log10(self) -> str | None:
        w = self.witness_proofs.get("vfri8")
        return w.log10.commitment if w else None

    @property
    def vfri8_hints_log10(self) -> bytes | None:
        w = self.witness_proofs.get("vfri8")
        return w.log10.hints if w else None

    @property
    def vfri8_proof_log8(self) -> bytes | None:
        w = self.witness_proofs.get("vfri8")
        return w.log8.proof if w else None

    @property
    def vfri8_commitment_log8(self) -> str | None:
        w = self.witness_proofs.get("vfri8")
        return w.log8.commitment if w else None

    @property
    def vfri8_hints_log8(self) -> bytes | None:
        w = self.witness_proofs.get("vfri8")
        return w.log8.hints if w else None

    @property
    def vfri9_proof_log10(self) -> bytes | None:
        w = self.witness_proofs.get("vfri9")
        return w.log10.proof if w else None

    @property
    def vfri9_commitment_log10(self) -> str | None:
        w = self.witness_proofs.get("vfri9")
        return w.log10.commitment if w else None

    @property
    def vfri9_hints_log10(self) -> bytes | None:
        w = self.witness_proofs.get("vfri9")
        return w.log10.hints if w else None

    @property
    def vfri9_proof_log8(self) -> bytes | None:
        w = self.witness_proofs.get("vfri9")
        return w.log8.proof if w else None

    @property
    def vfri9_commitment_log8(self) -> str | None:
        w = self.witness_proofs.get("vfri9")
        return w.log8.commitment if w else None

    @property
    def vfri9_hints_log8(self) -> bytes | None:
        w = self.witness_proofs.get("vfri9")
        return w.log8.hints if w else None

    @property
    def vfri10_proof_log10(self) -> bytes | None:
        w = self.witness_proofs.get("vfri10")
        return w.log10.proof if w else None

    @property
    def vfri10_commitment_log10(self) -> str | None:
        w = self.witness_proofs.get("vfri10")
        return w.log10.commitment if w else None

    @property
    def vfri10_hints_log10(self) -> bytes | None:
        w = self.witness_proofs.get("vfri10")
        return w.log10.hints if w else None

    @property
    def vfri10_proof_log8(self) -> bytes | None:
        w = self.witness_proofs.get("vfri10")
        return w.log8.proof if w else None

    @property
    def vfri10_commitment_log8(self) -> str | None:
        w = self.witness_proofs.get("vfri10")
        return w.log8.commitment if w else None

    @property
    def vfri10_hints_log8(self) -> bytes | None:
        w = self.witness_proofs.get("vfri10")
        return w.log8.hints if w else None

    @property
    def vfri11_proof_log10(self) -> bytes | None:
        w = self.witness_proofs.get("vfri11")
        return w.log10.proof if w else None

    @property
    def vfri11_commitment_log10(self) -> str | None:
        w = self.witness_proofs.get("vfri11")
        return w.log10.commitment if w else None

    @property
    def vfri11_hints_log10(self) -> bytes | None:
        w = self.witness_proofs.get("vfri11")
        return w.log10.hints if w else None

    @property
    def vfri11_proof_log8(self) -> bytes | None:
        w = self.witness_proofs.get("vfri11")
        return w.log8.proof if w else None

    @property
    def vfri11_commitment_log8(self) -> str | None:
        w = self.witness_proofs.get("vfri11")
        return w.log8.commitment if w else None

    @property
    def vfri11_hints_log8(self) -> bytes | None:
        w = self.witness_proofs.get("vfri11")
        return w.log8.hints if w else None

    @property
    def has_witness(self) -> bool:
        return self.witness_bundle is not None or bool(self.witness_proofs)

    @property
    def witness_norm_bound_ok(self) -> bool:
        """True when all ‖z[j]‖_∞ are within the ML-DSA-65 NORM_BOUND (524 092)."""
        if self.witness_max_norms is None:
            return False
        from stark.prover import NORM_BOUND
        return all(mn < NORM_BOUND for mn in self.witness_max_norms)


class Batcher:
    """Creates batches from a Mempool and optionally generates STARK proofs."""

    # When the prover fails unexpectedly (not "extension missing"), the batch's
    # transactions are returned to the mempool and proving is retried on the
    # next cycle, up to this many times per batch (keyed by Merkle root).
    # After the budget is exhausted the batch is emitted unproven so that a
    # persistently broken prover cannot stall the pipeline forever.
    MAX_PROOF_RETRIES = 3

    # Fold rounds for VFRI10 witness proofs.  BatchRegistryV6 verifies each V23
    # trace group in its own tx; num_folds=6 keeps each Poseidon2 t=4 verify()
    # within the ~16.7M per-tx gas cap (num_folds=3 overruns the LOG=10 group).
    VFRI10_NUM_FOLDS = 6

    def __init__(
        self,
        mempool: Mempool,
        min_batch_size: int = 1,
        max_batch_size: int = 3000,
        algorithm: str = DEFAULT_ALGORITHM,
        n_fri_queries: int | None = None,
        witness_protocols: tuple[str, ...] | None = None,
    ) -> None:
        if min_batch_size < 1:
            raise ValueError("min_batch_size must be at least 1")
        if max_batch_size < min_batch_size:
            raise ValueError("max_batch_size must be >= min_batch_size")
        # None means "each protocol's own default" — 1 for the direct
        # protocols, 20 for `recursive`. A single shared default would hand the
        # recursive route 16-bit soundness at more gas than direct verification.
        if n_fri_queries is not None and (n_fri_queries < 1 or n_fri_queries > 64):
            raise ValueError(f"n_fri_queries must be in [1, 64], got {n_fri_queries}")
        from stark.prover import DEFAULT_WITNESS_PROTOCOL, WITNESS_PROTOCOLS
        # Default to the protocol the DEPLOYED default stack accepts, not to
        # "all of them": only one can be submitted to any given registry, and
        # generating the rest costs a full proof each for nothing.
        self.witness_protocols: tuple[str, ...] = (
            witness_protocols if witness_protocols is not None
            else (DEFAULT_WITNESS_PROTOCOL,)
        )
        unknown = [p for p in self.witness_protocols if p not in WITNESS_PROTOCOLS]
        if unknown:
            raise ValueError(
                f"unknown witness protocol(s): {unknown}; "
                f"supported: {sorted(WITNESS_PROTOCOLS)}"
            )
        self.mempool = mempool
        self.min_batch_size = min_batch_size
        self.max_batch_size = max_batch_size
        self.algorithm = algorithm
        self.n_fri_queries = n_fri_queries
        self._proof_retries: dict[bytes, int] = {}
        self._retry_lock = threading.Lock()
        # Security level: log_blowup(6) × n_fri_queries + pow_bits(10)
        # n=1 → 16 bits (demo/testnet), n=3 → 28 bits, n=20 → 130 bits (but ~300M gas).

    def _prove_witnesses(self, result: "BatchResult", tx0: Any) -> None:
        """Generate the configured witness protocols for tx[0].

        One loop over `self.witness_protocols`, where there used to be four
        near-identical blocks — one per protocol, each duplicating the same
        error handling. That duplication is why VFRI11 was never added: the cost
        of a new protocol was six fields in four layers rather than one name.

        Generating every protocol unconditionally, as the old code did, also cost
        four proofs where at most one is submittable — the others cannot be
        accepted by any single deployed registry, since each verifier derives its
        own FRI query indices from its own hash backend.
        """
        from stark.prover import prove_mldsa_sig_for_protocol

        for protocol in self.witness_protocols:
            try:
                vr = prove_mldsa_sig_for_protocol(
                    protocol,
                    pk=tx0.public_key,
                    msg=tx0.to_bytes(),
                    sig=tx0.signature,
                    batch_merkle_root=result.merkle_root_onchain,
                    n_queries=self.n_fri_queries,   # None → the protocol's default
                )
            except KeyError:
                # An unknown name is a configuration error, not a runtime one:
                # silently producing no proof is how this layer drifted before.
                raise
            except (RuntimeError, ImportError) as exc:
                logger.warning("%s witness proof skipped: %s", protocol, exc)
                continue
            except ValueError as exc:
                logger.warning(
                    "ML-DSA signature invalid for %s proving: %s", protocol, exc)
                continue
            except Exception as exc:
                logger.error(
                    "Unexpected error during %s proving: %s", protocol, exc,
                    exc_info=True)
                continue

            result.witness_proofs[protocol] = vr
            if result.witness_commitment is None:
                result.witness_commitment = vr.log10.commitment

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
        txs = self.mempool.drain_if_ready(self.min_batch_size, self.max_batch_size)
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
                logger.warning("batcher: dropping unsigned tx %s", tx.tx_hash().hex()[:16])
                continue
            if sig_verify(tx.to_bytes(), tx.signature, tx.public_key, self.algorithm):
                valid_txs.append(tx)
            else:
                logger.warning("batcher: dropping tx with invalid signature %s", tx.tx_hash().hex()[:16])

        if not valid_txs:
            return None

        try:
            batch = create_batch(valid_txs, algorithm=self.algorithm)
        except (InvalidSignatureError, BatchSizeError) as exc:
            logger.error("batcher: create_batch failed after pre-filter: %s", exc)
            # Return valid transactions to front of mempool so they are not lost.
            self.mempool.prepend_batch(valid_txs)
            return None

        result, prover_crashed = self._try_prove(batch, prove_witnesses=prove_witnesses)

        if prover_crashed:
            # Transient prover failure (NOT "extension missing"): return the
            # transactions to the mempool and retry on the next cycle, up to
            # MAX_PROOF_RETRIES per batch.  After that, emit unproven to keep
            # the pipeline live.
            root = batch.merkle_root
            with self._retry_lock:
                # Bound the retry map — stale roots accumulate only on repeated
                # failures with changing batch composition.
                if len(self._proof_retries) > 256:
                    self._proof_retries.clear()
                attempts = self._proof_retries.get(root, 0) + 1
                self._proof_retries[root] = attempts
            if attempts <= self.MAX_PROOF_RETRIES:
                logger.warning(
                    "batcher: prover failed (attempt %d/%d) — returning %d tx(s) "
                    "to mempool for retry",
                    attempts, self.MAX_PROOF_RETRIES, len(valid_txs),
                )
                self.mempool.prepend_batch(valid_txs)
                return None
            logger.error(
                "batcher: prover failed %d times for batch %s — emitting unproven batch",
                attempts, batch.batch_id[:8],
            )

        with self._retry_lock:
            self._proof_retries.pop(batch.merkle_root, None)
        return result

    def _try_prove(
        self, batch: Batch, prove_witnesses: bool = False
    ) -> tuple[BatchResult, bool]:
        """Run the STARK prover; optionally add an ML-DSA witness proof for tx[0].

        Returns (result, prover_crashed).  prover_crashed is True only when the
        prover raised unexpectedly — not when the PyO3 extension is missing,
        which is the documented unproven degraded mode.
        """
        result = BatchResult(batch=batch)
        prover_crashed = False
        try:
            from stark.prover import ProverUnavailableError, prove_batch_poseidon2 as prove_batch
            pr = prove_batch(batch)
            result.proof = pr.proof
            result.commitment = pr.commitment
        except ProverUnavailableError as exc:
            logger.warning("STARK proving skipped: %s", exc)
        except Exception as exc:
            logger.error("Unexpected error during STARK proving: %s", exc, exc_info=True)
            prover_crashed = True

        if prove_witnesses and batch.transactions:
            tx0 = batch.transactions[0]
            if tx0.signature is not None and tx0.public_key is not None:
                self._prove_witnesses(result, tx0)

        return result, prover_crashed
