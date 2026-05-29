from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from starlette.middleware.base import BaseHTTPMiddleware

from aggregator.mempool import MempoolFullError
from aggregator.node import AggregatorNode
from core.keys import derive_address
from core.signing import verify as sig_verify
from core.transaction import Transaction


# ── Rate-limit configuration ──────────────────────────────────────────────────
# Sliding-window counters keyed by client IP.  No external dependencies.

_TX_LIMIT = 100          # max POST /transactions per IP per minute
_BATCH_LIMIT = 20        # max POST /batch/* per IP per minute
_WINDOW_SECS = 60.0
_EVICT_EVERY = 500       # evict stale entries every N calls to avoid unbounded growth

# {ip: deque[timestamp]}  — one deque per IP per bucket
_tx_windows: dict[str, deque[float]] = {}
_batch_windows: dict[str, deque[float]] = {}
_rate_lock = threading.Lock()
_rate_call_count = 0

# IPs that route through trusted reverse proxies (read X-Forwarded-For).
_TRUSTED_PROXIES: frozenset[str] = frozenset({"127.0.0.1", "::1"})


def _get_client_ip(request: Request) -> str:
    """Return the real client IP, honouring X-Forwarded-For behind trusted proxies.

    When the immediate peer is a trusted proxy we read X-Forwarded-For and take
    the *rightmost* (last) entry — that is the IP the trusted proxy itself appended
    and therefore cannot be spoofed by the client.  Taking the first entry would
    allow an attacker to inject an arbitrary IP before the proxy sees the request.
    """
    host = request.client.host if request.client else "unknown"
    if host in _TRUSTED_PROXIES:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            if parts:
                return parts[-1]
    return host


def _evict_stale(windows: dict[str, deque[float]], cutoff: float) -> None:
    """Remove entries whose last timestamp is older than *cutoff*."""
    stale = [ip for ip, dq in windows.items() if not dq or dq[-1] < cutoff]
    for ip in stale:
        windows.pop(ip, None)  # pop avoids KeyError on concurrent eviction


def _check_rate(windows: dict[str, deque[float]], ip: str, limit: int) -> bool:
    """Return True if the request is allowed, False if the limit is exceeded."""
    global _rate_call_count
    now = time.monotonic()
    cutoff = now - _WINDOW_SECS
    with _rate_lock:
        _rate_call_count += 1
        if _rate_call_count >= _EVICT_EVERY:
            # Evict both window dicts so neither grows unboundedly.
            _evict_stale(_tx_windows, cutoff)
            _evict_stale(_batch_windows, cutoff)
            _rate_call_count = 0
        dq = windows.setdefault(ip, deque())
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


class _RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Any:
        ip = _get_client_ip(request)
        path = request.url.path
        method = request.method

        if method == "POST" and path == "/transactions":
            if not _check_rate(_tx_windows, ip, _TX_LIMIT):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "rate limit exceeded: max 100 transaction submissions per minute"},
                )
        elif method == "POST" and (path.startswith("/batch/")):
            if not _check_rate(_batch_windows, ip, _BATCH_LIMIT):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "rate limit exceeded: max 20 batch operations per minute"},
                )

        return await call_next(request)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.node = AggregatorNode()
    yield


app = FastAPI(title="QLSA Aggregator", version="0.1.0", lifespan=_lifespan)
app.add_middleware(_RateLimitMiddleware)


# ── Request / Response models ─────────────────────────────────────────────────

class TxPayload(BaseModel):
    sender: str
    recipient: str
    amount: int
    nonce: int
    public_key: str   # hex
    signature: str    # hex

    @field_validator("sender", "recipient")
    @classmethod
    def must_be_address(cls, v: str) -> str:
        if len(v) != 64:
            raise ValueError("must be a 64-character hex string (SHA3-256 address)")
        try:
            bytes.fromhex(v)
        except ValueError as exc:
            raise ValueError("must be a valid hex string") from exc
        return v.lower()

    @field_validator("public_key")
    @classmethod
    def must_be_valid_pubkey(cls, v: str) -> str:
        try:
            b = bytes.fromhex(v)
        except ValueError as exc:
            raise ValueError("must be a valid hex string") from exc
        # FIPS 204 ML-DSA public key sizes: 44→1312, 65→1952, 87→2592 bytes
        if len(b) not in {1312, 1952, 2592}:
            raise ValueError(
                f"public_key length {len(b)} B is not a valid ML-DSA key size "
                "(expected 1312, 1952, or 2592 bytes)"
            )
        return v

    @field_validator("signature")
    @classmethod
    def must_be_valid_signature(cls, v: str) -> str:
        try:
            b = bytes.fromhex(v)
        except ValueError as exc:
            raise ValueError("must be a valid hex string") from exc
        # FIPS 204 ML-DSA signature sizes: 44→2420, 65→3309, 87→4627 bytes
        if len(b) not in {2420, 3309, 4627}:
            raise ValueError(
                f"signature length {len(b)} B is not a valid ML-DSA signature size "
                "(expected 2420, 3309, or 4627 bytes)"
            )
        return v

    @field_validator("amount", "nonce")
    @classmethod
    def must_be_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("must be non-negative")
        if v > (1 << 64) - 1:
            raise ValueError("must fit in uint64")
        return v

    @field_validator("amount")
    @classmethod
    def amount_must_be_positive(cls, v: int) -> int:
        if v == 0:
            raise ValueError("amount must be positive (non-zero)")
        return v


class SubmitResponse(BaseModel):
    accepted: bool
    mempool_size: int
    error: str | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/stats")
def stats(request: Request) -> dict[str, Any]:
    node: AggregatorNode = request.app.state.node
    s = node.stats()
    n = node.n_fri_queries
    return {
        "transactions_received": s.transactions_received,
        "transactions_batched": s.transactions_batched,
        "batches_created": s.batches_created,
        "proofs_generated": s.proofs_generated,
        "pending": node.pending_count(),
        "n_fri_queries": n,
        "fri_security_bits": 6 * n + 10,  # log_blowup(6) × n + pow_bits(10)
    }


@app.post("/transactions", response_model=SubmitResponse)
def submit_transaction(payload: TxPayload, request: Request) -> SubmitResponse:
    node: AggregatorNode = request.app.state.node
    try:
        pub_key = bytes.fromhex(payload.public_key)
        sig_bytes = bytes.fromhex(payload.signature)
        tx = Transaction(
            sender=payload.sender,
            recipient=payload.recipient,
            amount=payload.amount,
            nonce=payload.nonce,
            public_key=pub_key,
        )
        # Verify signature at ingestion time — prevents mempool flooding with
        # invalid transactions that would cause batch creation to fail later.
        if not sig_verify(tx.to_bytes(), sig_bytes, pub_key):
            return SubmitResponse(
                accepted=False,
                mempool_size=node.pending_count(),
                error="invalid signature",
            )
        if payload.sender != derive_address(pub_key):
            return SubmitResponse(
                accepted=False,
                mempool_size=node.pending_count(),
                error="sender does not match public key",
            )
        tx.signature = sig_bytes
        node.submit(tx)
        return SubmitResponse(accepted=True, mempool_size=node.pending_count())
    except (ValueError, MempoolFullError) as exc:
        return SubmitResponse(
            accepted=False, mempool_size=node.pending_count(), error=str(exc)
        )


@app.post("/batch/run")
def batch_run(
    request: Request,
    prove_witnesses: bool = Query(default=False),
) -> dict[str, Any]:
    node: AggregatorNode = request.app.state.node
    result = node.run_cycle(prove_witnesses=prove_witnesses)
    if result is None:
        return {"status": "no_batch", "reason": "insufficient transactions in mempool"}
    return {
        "status": "ok",
        "batch_id": result.batch.batch_id,
        "tx_count": len(result.batch.transactions),
        "merkle_root": result.batch.merkle_root.hex(),
        "is_proven": result.is_proven,
        "stark_commitment": result.commitment,
        "has_witness": result.has_witness,
        "witness_commitment": result.witness_commitment,
        "has_vfri7": result.has_vfri7,
        "vfri7_commitment_log10": result.vfri7_commitment_log10,
        "vfri7_commitment_log8": result.vfri7_commitment_log8,
    }


@app.get("/batch/{batch_id}/witness")
def batch_witness(batch_id: str, request: Request) -> dict[str, Any]:
    """Return witness proof metadata for a previously created batch.

    Returns 404 if the batch_id is unknown to this node.
    Returns has_witness=false if the batch exists but was created without
    prove_witnesses=true.
    """
    node: AggregatorNode = request.app.state.node
    for result in node.history():
        if result.batch.batch_id == batch_id:
            n = node.n_fri_queries
            if not result.has_witness:
                return {
                    "batch_id": batch_id, "has_witness": False, "has_vfri7": False,
                    "n_fri_queries": n, "fri_security_bits": 6 * n + 10,
                }
            return {
                "batch_id": batch_id,
                "has_witness": True,
                "onchain_commitment": result.witness_commitment,
                "c_tilde_hex": result.witness_c_tilde_hex,
                "max_norms": result.witness_max_norms,
                "has_vfri7": result.has_vfri7,
                "vfri7_commitment_log10": result.vfri7_commitment_log10,
                "vfri7_commitment_log8": result.vfri7_commitment_log8,
                "n_fri_queries": n,
                "fri_security_bits": 6 * n + 10,
            }
    raise HTTPException(status_code=404, detail=f"batch {batch_id!r} not found")

@app.post("/batch/flush")
def batch_flush(
    request: Request,
    prove_witnesses: bool = Query(default=False),
) -> dict[str, Any]:
    node: AggregatorNode = request.app.state.node
    result = node.force_cycle(prove_witnesses=prove_witnesses)
    if result is None:
        return {"status": "empty"}
    return {
        "status": "ok",
        "batch_id": result.batch.batch_id,
        "tx_count": len(result.batch.transactions),
        "merkle_root": result.batch.merkle_root.hex(),
        "is_proven": result.is_proven,
        "stark_commitment": result.commitment,
        "has_witness": result.has_witness,
        "witness_commitment": result.witness_commitment,
        "has_vfri7": result.has_vfri7,
        "vfri7_commitment_log10": result.vfri7_commitment_log10,
        "vfri7_commitment_log8": result.vfri7_commitment_log8,
    }
