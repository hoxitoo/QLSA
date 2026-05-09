from __future__ import annotations

from typing import TYPE_CHECKING

from core.transaction import Transaction
from aggregator.mempool import MempoolFullError
from aggregator.node import AggregatorNode
from .models import BatchStatus, NodeStats, SubmitResult, WitnessStatus

if TYPE_CHECKING:
    from aggregator.batcher import BatchResult


def _batch_status(result: BatchResult) -> BatchStatus:
    return BatchStatus(
        batch_id=result.batch.batch_id,
        tx_count=len(result.batch.transactions),
        merkle_root=result.batch.merkle_root.hex(),
        is_proven=result.is_proven,
        stark_commitment=result.commitment,
        has_witness=result.has_witness,
        witness_commitment=result.witness_commitment,
    )


def _prove_witness_local(tx: Transaction) -> WitnessStatus:
    """Prove an ML-DSA-65 witness for a single transaction (pure local, no mempool)."""
    if tx.signature is None or tx.public_key is None:
        return WitnessStatus(has_witness=False)
    try:
        from stark.prover import prove_mldsa_sig_witness_stark
        wr = prove_mldsa_sig_witness_stark(
            pk=tx.public_key,
            msg=tx.to_bytes(),
            sig=tx.signature,
        )
        return WitnessStatus(
            has_witness=True,
            onchain_commitment=wr.onchain_commitment,
            c_tilde_hex=wr.c_tilde_hex,
            max_norms=wr.max_norms,
        )
    except (RuntimeError, ImportError):
        return WitnessStatus(has_witness=False)


class LocalClient:
    """SDK client backed by an in-process AggregatorNode.

    Suitable for testing, scripts, and single-process deployments.

    Example::

        client = LocalClient()
        result = client.submit(signed_tx)
        status = client.flush()
    """

    def __init__(self, node: AggregatorNode | None = None) -> None:
        self._node = node or AggregatorNode()

    def submit(self, tx: Transaction) -> SubmitResult:
        """Add a signed transaction to the mempool."""
        try:
            self._node.submit(tx)
            return SubmitResult(accepted=True, mempool_size=self._node.pending_count())
        except (ValueError, MempoolFullError) as exc:
            return SubmitResult(
                accepted=False,
                error=str(exc),
                mempool_size=self._node.pending_count(),
            )

    def run_cycle(self, prove_witnesses: bool = False) -> BatchStatus | None:
        """Try to create a batch (respects min_batch_size). Returns None if too few txs."""
        result = self._node.run_cycle(prove_witnesses=prove_witnesses)
        return _batch_status(result) if result is not None else None

    def flush(self, prove_witnesses: bool = False) -> BatchStatus | None:
        """Force a batch from whatever is in the mempool. Returns None if empty."""
        result = self._node.force_cycle(prove_witnesses=prove_witnesses)
        return _batch_status(result) if result is not None else None

    def prove_witness(self, tx: Transaction) -> WitnessStatus:
        """Generate an ML-DSA-65 arithmetic witness STARK proof for a single transaction.

        Does not touch the mempool — purely a local proving operation.
        Requires the PyO3 extension (qlsa_stark_stwo). Returns WitnessStatus
        with has_witness=False if the extension is not available or the
        transaction is unsigned.
        """
        return _prove_witness_local(tx)

    def stats(self) -> NodeStats:
        s = self._node.stats()
        return NodeStats(
            transactions_received=s.transactions_received,
            transactions_batched=s.transactions_batched,
            batches_created=s.batches_created,
            proofs_generated=s.proofs_generated,
            pending=self._node.pending_count(),
        )


class HttpClient:
    """SDK client that talks to a remote QLSA aggregator over HTTP.

    Requires ``httpx`` (install via ``pip install httpx``).

    Example::

        client = HttpClient("http://localhost:8000")
        result = client.submit(signed_tx)
    """

    def __init__(self, base_url: str, timeout: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def _httpx(self):
        try:
            import httpx
            return httpx
        except ImportError as exc:
            raise ImportError("httpx is required for HttpClient: pip install httpx") from exc

    def submit(self, tx: Transaction) -> SubmitResult:
        if tx.signature is None:
            return SubmitResult(accepted=False, error="transaction is unsigned")
        httpx = self._httpx()
        payload = {
            "sender": tx.sender,
            "recipient": tx.recipient,
            "amount": tx.amount,
            "nonce": tx.nonce,
            "public_key": tx.public_key.hex(),
            "signature": tx.signature.hex(),
        }
        resp = httpx.post(
            f"{self._base_url}/transactions", json=payload, timeout=self._timeout
        )
        resp.raise_for_status()
        data = resp.json()
        return SubmitResult(
            accepted=data["accepted"],
            error=data.get("error"),
            mempool_size=data.get("mempool_size", 0),
        )

    def run_cycle(self) -> BatchStatus | None:
        httpx = self._httpx()
        resp = httpx.post(f"{self._base_url}/batch/run", timeout=self._timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "no_batch":
            return None
        try:
            return BatchStatus(
                batch_id=data["batch_id"],
                tx_count=data["tx_count"],
                merkle_root=data["merkle_root"],
                is_proven=data["is_proven"],
                stark_commitment=data.get("stark_commitment"),
                has_witness=data.get("has_witness", False),
                witness_commitment=data.get("witness_commitment"),
            )
        except KeyError as exc:
            raise RuntimeError(
                f"Aggregator /batch/run response missing field: {exc}. Got: {list(data)}"
            ) from exc

    def flush(self) -> BatchStatus | None:
        httpx = self._httpx()
        resp = httpx.post(f"{self._base_url}/batch/flush", timeout=self._timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "empty":
            return None
        try:
            return BatchStatus(
                batch_id=data["batch_id"],
                tx_count=data["tx_count"],
                merkle_root=data["merkle_root"],
                is_proven=data["is_proven"],
                stark_commitment=data.get("stark_commitment"),
                has_witness=data.get("has_witness", False),
                witness_commitment=data.get("witness_commitment"),
            )
        except KeyError as exc:
            raise RuntimeError(
                f"Aggregator /batch/flush response missing field: {exc}. Got: {list(data)}"
            ) from exc

    def prove_witness(self, tx: Transaction) -> WitnessStatus:
        """Generate an ML-DSA-65 arithmetic witness STARK proof for a single transaction.

        Runs locally (does not call the remote aggregator). Requires the PyO3
        extension (qlsa_stark_stwo). Returns WitnessStatus with has_witness=False
        if the extension is unavailable or the transaction is unsigned.
        """
        return _prove_witness_local(tx)

    def stats(self) -> NodeStats:
        httpx = self._httpx()
        resp = httpx.get(f"{self._base_url}/stats", timeout=self._timeout)
        resp.raise_for_status()
        data = resp.json()
        return NodeStats(
            transactions_received=data["transactions_received"],
            transactions_batched=data["transactions_batched"],
            batches_created=data["batches_created"],
            proofs_generated=data["proofs_generated"],
            pending=data["pending"],
        )

    def health(self) -> bool:
        httpx = self._httpx()
        try:
            resp = httpx.get(f"{self._base_url}/health", timeout=self._timeout)
            return resp.is_success
        except (httpx.TransportError, httpx.TimeoutException):
            # Expected: server is down, unreachable, or timed out.
            return False
