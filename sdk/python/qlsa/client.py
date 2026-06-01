from __future__ import annotations

from typing import TYPE_CHECKING, Any

from core.transaction import Transaction
from aggregator.mempool import MempoolFullError
from aggregator.node import AggregatorNode
from .models import BatchStatus, NodeConfig, NodeStats, SubmitResult, WitnessStatus

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
        has_vfri7=result.has_vfri7,
        vfri7_commitment_log10=result.vfri7_commitment_log10,
        vfri7_commitment_log8=result.vfri7_commitment_log8,
    )


def _prove_witness_local(tx: Transaction, n_fri_queries: int = 1) -> WitnessStatus:
    """Prove a VFRI7 cross-bound V23 ML-DSA witness for a single transaction (local, no mempool).

    Uses a zero batch_merkle_root (bytes(32)) since this is a standalone per-tx operation
    with no associated batch context.  The resulting commitment is therefore bound to the
    all-zeros root, not a real batch; suitable for capability testing and SDK demos.
    """
    if tx.signature is None or tx.public_key is None:
        return WitnessStatus(has_witness=False, has_vfri7=False)
    try:
        from stark.prover import prove_mldsa_sig_vfri7_stark
        vr = prove_mldsa_sig_vfri7_stark(
            pk=tx.public_key,
            msg=tx.to_bytes(),
            sig=tx.signature,
            batch_merkle_root=bytes(32),  # standalone: no real batch root available
            n_queries=n_fri_queries,
        )
        return WitnessStatus(
            has_witness=True,
            onchain_commitment=vr.log10_commitment,  # backward-compat alias
            has_vfri7=True,
            vfri7_commitment_log10=vr.log10_commitment,
            vfri7_commitment_log8=vr.log8_commitment,
            n_fri_queries=n_fri_queries,
            fri_security_bits=6 * n_fri_queries + 10,
        )
    except (RuntimeError, ImportError, ValueError):
        return WitnessStatus(has_witness=False, has_vfri7=False)


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
        """Generate a VFRI7 cross-bound V23 ML-DSA-65 witness proof for a single transaction.

        Does not touch the mempool — purely a local proving operation.
        Requires the PyO3 extension (qlsa_stark_stwo). Returns WitnessStatus
        with has_witness=False if the extension is not available or the
        transaction is unsigned.
        """
        return _prove_witness_local(tx, n_fri_queries=self._node.n_fri_queries)

    def get_batch(self, batch_id: str) -> BatchStatus | None:
        """Return the BatchStatus for a given batch_id, or None if not found."""
        for result in self._node.history():
            if result.batch.batch_id == batch_id:
                return _batch_status(result)
        return None

    def stats(self) -> NodeStats:
        s = self._node.stats()
        n = self._node.n_fri_queries
        return NodeStats(
            transactions_received=s.transactions_received,
            transactions_batched=s.transactions_batched,
            batches_created=s.batches_created,
            proofs_generated=s.proofs_generated,
            pending=self._node.pending_count(),
            n_fri_queries=n,
            fri_security_bits=6 * n + 10,
        )

    def node_config(self) -> NodeConfig:
        """Return static node configuration (security level, batch size limits)."""
        n = self._node.n_fri_queries
        return NodeConfig(
            n_fri_queries=n,
            fri_security_bits=6 * n + 10,
            min_batch_size=self._node.batcher.min_batch_size,
            max_batch_size=self._node.batcher.max_batch_size,
            mempool_capacity=self._node.mempool.max_size,
        )


class HttpClient:
    """SDK client that talks to a remote QLSA aggregator over HTTP.

    Requires ``httpx`` (install via ``pip install httpx``).

    Example::

        client = HttpClient("http://localhost:8000")
        result = client.submit(signed_tx)

    For testing, pass an ``httpx.Client`` with an ASGI transport::

        import httpx
        from aggregator.api import app
        transport = httpx.ASGITransport(app=app)
        http = httpx.Client(transport=transport, base_url="http://test")
        client = HttpClient("http://test", _client=http)
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        *,
        _client: Any = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._client: Any = _client  # injected httpx.Client (for testing / custom transports)

    def _get_client(self) -> Any:
        """Return the httpx.Client to use, creating a default one if not injected."""
        if self._client is not None:
            return self._client
        try:
            import httpx
            return httpx.Client(timeout=self._timeout)
        except ImportError as exc:
            raise ImportError("httpx is required for HttpClient: pip install httpx") from exc

    def submit(self, tx: Transaction) -> SubmitResult:
        if tx.signature is None:
            return SubmitResult(accepted=False, error="transaction is unsigned")
        client = self._get_client()
        payload = {
            "sender": tx.sender,
            "recipient": tx.recipient,
            "amount": tx.amount,
            "nonce": tx.nonce,
            "public_key": tx.public_key.hex(),
            "signature": tx.signature.hex(),
        }
        resp = client.post(f"{self._base_url}/transactions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        try:
            return SubmitResult(
                accepted=data["accepted"],
                error=data.get("error"),
                mempool_size=data.get("mempool_size", 0),
            )
        except KeyError as exc:
            raise RuntimeError(
                f"Aggregator /transactions response missing field: {exc}. Got: {list(data)}"
            ) from exc

    def run_cycle(self) -> BatchStatus | None:
        client = self._get_client()
        resp = client.post(f"{self._base_url}/batch/run")
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "no_batch":
            return None
        try:
            return self._parse_batch_status(data)
        except KeyError as exc:
            raise RuntimeError(
                f"Aggregator /batch/run response missing field: {exc}. Got: {list(data)}"
            ) from exc

    def flush(self) -> BatchStatus | None:
        client = self._get_client()
        resp = client.post(f"{self._base_url}/batch/flush")
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "empty":
            return None
        try:
            return self._parse_batch_status(data)
        except KeyError as exc:
            raise RuntimeError(
                f"Aggregator /batch/flush response missing field: {exc}. Got: {list(data)}"
            ) from exc

    def get_batch(self, batch_id: str) -> BatchStatus | None:
        """Return the BatchStatus for a given batch_id, or None if not found (HTTP 404)."""
        client = self._get_client()
        resp = client.get(f"{self._base_url}/batch/{batch_id}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return self._parse_batch_status(resp.json())

    def prove_witness(self, tx: Transaction, n_fri_queries: int = 1) -> WitnessStatus:
        """Generate an ML-DSA-65 arithmetic witness STARK proof for a single transaction.

        Runs locally (does not call the remote aggregator). Requires the PyO3
        extension (qlsa_stark_stwo). Returns WitnessStatus with has_witness=False
        if the extension is unavailable or the transaction is unsigned.
        """
        return _prove_witness_local(tx, n_fri_queries=n_fri_queries)

    def stats(self) -> NodeStats:
        client = self._get_client()
        resp = client.get(f"{self._base_url}/stats")
        resp.raise_for_status()
        data = resp.json()
        return NodeStats(
            transactions_received=data["transactions_received"],
            transactions_batched=data["transactions_batched"],
            batches_created=data["batches_created"],
            proofs_generated=data["proofs_generated"],
            pending=data["pending"],
            n_fri_queries=data.get("n_fri_queries", 1),
            fri_security_bits=data.get("fri_security_bits", 16),
        )

    def node_config(self) -> NodeConfig:
        """Return static node configuration (security level, batch size limits)."""
        client = self._get_client()
        resp = client.get(f"{self._base_url}/node/config")
        resp.raise_for_status()
        data = resp.json()
        return NodeConfig(
            n_fri_queries=data["n_fri_queries"],
            fri_security_bits=data["fri_security_bits"],
            min_batch_size=data["min_batch_size"],
            max_batch_size=data["max_batch_size"],
            mempool_capacity=data["mempool_capacity"],
            version=data.get("version", "0.1.0"),
        )

    def health(self) -> bool:
        try:
            client = self._get_client()
            resp = client.get(f"{self._base_url}/health")
            return bool(resp.is_success)
        except Exception:
            return False

    @staticmethod
    def _parse_batch_status(data: dict[str, Any]) -> BatchStatus:
        return BatchStatus(
            batch_id=data["batch_id"],
            tx_count=data["tx_count"],
            merkle_root=data["merkle_root"],
            is_proven=data["is_proven"],
            stark_commitment=data.get("stark_commitment"),
            has_witness=data.get("has_witness", False),
            witness_commitment=data.get("witness_commitment"),
            has_vfri7=data.get("has_vfri7", False),
            vfri7_commitment_log10=data.get("vfri7_commitment_log10"),
            vfri7_commitment_log8=data.get("vfri7_commitment_log8"),
        )
