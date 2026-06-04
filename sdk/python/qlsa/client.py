from __future__ import annotations

from types import TracebackType
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

    def history(self, limit: int | None = None) -> list[BatchStatus]:
        """Return BatchStatus objects produced by this node (oldest → newest).

        If *limit* is given, return only the last *limit* entries (still
        ordered oldest → newest within that slice).
        """
        results = [_batch_status(r) for r in self._node.history()]
        if limit is not None:
            return results[-limit:]
        return results

    def get_batch(self, batch_id: str) -> BatchStatus | None:
        """Return the BatchStatus for a given batch_id, or None if not found."""
        for result in self._node.history():
            if result.batch.batch_id == batch_id:
                return _batch_status(result)
        return None

    def get_witness_status(self, batch_id: str) -> WitnessStatus | None:
        """Return the WitnessStatus for a given batch_id, or None if not found."""
        result = self._node.get_batch(batch_id)
        if result is None:
            return None
        n = self._node.n_fri_queries
        if not result.has_witness:
            return WitnessStatus(
                has_witness=False,
                has_vfri7=False,
                n_fri_queries=n,
                fri_security_bits=6 * n + 10,
            )
        return WitnessStatus(
            has_witness=True,
            onchain_commitment=result.witness_commitment,
            c_tilde_hex=result.witness_c_tilde_hex,
            max_norms=result.witness_max_norms or [],
            has_vfri7=result.has_vfri7,
            vfri7_commitment_log10=result.vfri7_commitment_log10,
            vfri7_commitment_log8=result.vfri7_commitment_log8,
            n_fri_queries=n,
            fri_security_bits=6 * n + 10,
        )

    def health(self) -> bool:
        """Always True for an in-process node — included for API parity with HttpClient."""
        return True

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

    Use as a context manager to ensure the connection pool is closed::

        with HttpClient("http://localhost:8000") as client:
            result = client.submit(signed_tx)

    Or call ``close()`` explicitly when done::

        client = HttpClient("http://localhost:8000")
        try:
            result = client.submit(signed_tx)
        finally:
            client.close()

    For testing, inject an ``httpx.Client`` or ``starlette.testclient.TestClient``::

        from starlette.testclient import TestClient
        from aggregator.api import app
        with TestClient(app, base_url="http://test") as tc:
            client = HttpClient("http://test", _client=tc)
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
        self._client: Any = _client  # injected client (tests / custom transports)
        self._owned_client: Any = None  # lazily created; closed by close() / __exit__

    def close(self) -> None:
        """Close the underlying HTTP connection pool (if owned by this client)."""
        if self._owned_client is not None:
            self._owned_client.close()
            self._owned_client = None

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def _get_client(self) -> Any:
        """Return the httpx.Client to use.

        If a client was injected at construction time it is returned as-is.
        Otherwise a single httpx.Client is created lazily and reused across
        all requests (connection pooling), then closed by close() / __exit__.
        """
        if self._client is not None:
            return self._client
        if self._owned_client is None:
            try:
                import httpx
                self._owned_client = httpx.Client(timeout=self._timeout)
            except ImportError as exc:
                raise ImportError("httpx is required for HttpClient: pip install httpx") from exc
        return self._owned_client

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
        data = self._decode_json(resp, "/transactions")
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

    def run_cycle(self, prove_witnesses: bool = False) -> BatchStatus | None:
        client = self._get_client()
        params = {"prove_witnesses": "true"} if prove_witnesses else {}
        resp = client.post(f"{self._base_url}/batch/run", params=params)
        resp.raise_for_status()
        data = self._decode_json(resp, "/batch/run")
        if data.get("status") == "no_batch":
            return None
        try:
            return self._parse_batch_status(data)
        except KeyError as exc:
            raise RuntimeError(
                f"Aggregator /batch/run response missing field: {exc}. Got: {list(data)}"
            ) from exc

    def flush(self, prove_witnesses: bool = False) -> BatchStatus | None:
        client = self._get_client()
        params = {"prove_witnesses": "true"} if prove_witnesses else {}
        resp = client.post(f"{self._base_url}/batch/flush", params=params)
        resp.raise_for_status()
        data = self._decode_json(resp, "/batch/flush")
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
        return self._parse_batch_status(self._decode_json(resp, f"/batch/{batch_id}"))

    def get_witness_status(self, batch_id: str) -> WitnessStatus | None:
        """Return the WitnessStatus for a batch, or None if not found (HTTP 404)."""
        client = self._get_client()
        resp = client.get(f"{self._base_url}/batch/{batch_id}/witness")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = self._decode_json(resp, f"/batch/{batch_id}/witness")
        if not data.get("has_witness", False):
            return WitnessStatus(
                has_witness=False,
                has_vfri7=False,
                n_fri_queries=data.get("n_fri_queries", 0),
                fri_security_bits=data.get("fri_security_bits", 0),
            )
        return WitnessStatus(
            has_witness=True,
            onchain_commitment=data.get("onchain_commitment"),
            c_tilde_hex=data.get("c_tilde_hex"),
            max_norms=data.get("max_norms") or [],
            has_vfri7=data.get("has_vfri7", False),
            vfri7_commitment_log10=data.get("vfri7_commitment_log10"),
            vfri7_commitment_log8=data.get("vfri7_commitment_log8"),
            n_fri_queries=data.get("n_fri_queries", 0),
            fri_security_bits=data.get("fri_security_bits", 0),
        )

    def prove_witness(self, tx: Transaction, n_fri_queries: int = 1) -> WitnessStatus:
        """Generate an ML-DSA-65 arithmetic witness STARK proof for a single transaction.

        Runs locally (does not call the remote aggregator). Requires the PyO3
        extension (qlsa_stark_stwo). Returns WitnessStatus with has_witness=False
        if the extension is unavailable or the transaction is unsigned.
        """
        return _prove_witness_local(tx, n_fri_queries=n_fri_queries)

    def history(self, limit: int = 50) -> list[BatchStatus]:
        """Return recent batches from the aggregator (newest first).

        ``limit`` caps the number returned (1–200). Raises ``ValueError`` for
        out-of-range values; the server enforces the same bound and returns
        HTTP 422 for values outside [1, 200].
        """
        if not 1 <= limit <= 200:
            raise ValueError(f"limit must be between 1 and 200, got {limit}")
        client = self._get_client()
        resp = client.get(f"{self._base_url}/batches", params={"limit": limit})
        resp.raise_for_status()
        data = self._decode_json(resp, "/batches")
        return [self._parse_batch_status(b) for b in data.get("batches", [])]

    def wait_for_batch(
        self,
        batch_id: str,
        *,
        timeout: float = 60.0,
        poll_interval: float = 2.0,
    ) -> BatchStatus:
        """Poll ``GET /batch/{id}`` until the batch appears or timeout is reached.

        Returns the ``BatchStatus`` as soon as the batch is found.
        Raises ``TimeoutError`` if the batch is not found within *timeout* seconds.
        Re-raises any non-404 HTTP error immediately so callers detect outages.

        Typical use: call ``flush()`` on a remote node and then poll for the
        resulting batch when you need to wait for proof generation to finish.
        """
        import time
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        deadline = time.monotonic() + timeout
        while True:
            status = self.get_batch(batch_id)
            if status is not None:
                return status
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Batch {batch_id!r} not found after {timeout:.1f} s"
                )
            time.sleep(min(poll_interval, remaining))

    def stats(self) -> NodeStats:
        client = self._get_client()
        resp = client.get(f"{self._base_url}/stats")
        resp.raise_for_status()
        data = self._decode_json(resp, "/stats")
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
        data = self._decode_json(resp, "/node/config")
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
    def _decode_json(resp: Any, endpoint: str) -> Any:
        """Decode a response body as JSON, raising RuntimeError on parse failure.

        Protects callers from json.JSONDecodeError when a proxy or gateway
        returns an HTML error page with a 2xx-but-wrong-content-type response
        (rare but observable behind nginx/cloudflare during restarts).
        """
        import json as _json
        try:
            return resp.json()
        except _json.JSONDecodeError as exc:
            preview = resp.text[:200].replace("\n", " ")
            raise RuntimeError(
                f"Aggregator {endpoint} returned non-JSON body: {preview!r}"
            ) from exc

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
