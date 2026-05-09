from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, field_validator

from aggregator.mempool import MempoolFullError
from aggregator.node import AggregatorNode
from core.signing import verify as sig_verify
from core.transaction import Transaction


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.node = AggregatorNode()
    yield


app = FastAPI(title="QLSA Aggregator", version="0.1.0", lifespan=_lifespan)


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

    @field_validator("public_key", "signature")
    @classmethod
    def must_be_hex(cls, v: str) -> str:
        try:
            bytes.fromhex(v)
        except ValueError as exc:
            raise ValueError("must be a valid hex string") from exc
        return v

    @field_validator("amount", "nonce")
    @classmethod
    def must_be_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("must be non-negative")
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
    return {
        "transactions_received": s.transactions_received,
        "transactions_batched": s.transactions_batched,
        "batches_created": s.batches_created,
        "proofs_generated": s.proofs_generated,
        "pending": node.pending_count(),
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
            if not result.has_witness:
                return {"batch_id": batch_id, "has_witness": False}
            return {
                "batch_id": batch_id,
                "has_witness": True,
                "onchain_commitment": result.witness_commitment,
                "c_tilde_hex": result.witness_c_tilde_hex,
                "max_norms": result.witness_max_norms,
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
    }
