from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from pydantic import BaseModel, field_validator

from aggregator.mempool import MempoolFullError
from aggregator.node import AggregatorNode
from core.transaction import Transaction


@asynccontextmanager
async def _lifespan(app: FastAPI):
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
        tx = Transaction(
            sender=payload.sender,
            recipient=payload.recipient,
            amount=payload.amount,
            nonce=payload.nonce,
            public_key=bytes.fromhex(payload.public_key),
        )
        tx.signature = bytes.fromhex(payload.signature)
        node.submit(tx)
        return SubmitResponse(accepted=True, mempool_size=node.pending_count())
    except (ValueError, MempoolFullError) as exc:
        return SubmitResponse(
            accepted=False, mempool_size=node.pending_count(), error=str(exc)
        )


@app.post("/batch/run")
def batch_run(request: Request) -> dict[str, Any]:
    node: AggregatorNode = request.app.state.node
    result = node.run_cycle()
    if result is None:
        return {"status": "no_batch", "reason": "insufficient transactions in mempool"}
    return {
        "status": "ok",
        "batch_id": result.batch.batch_id,
        "tx_count": len(result.batch.transactions),
        "merkle_root": result.batch.merkle_root.hex(),
        "is_proven": result.is_proven,
        "stark_commitment": result.commitment,
    }


@app.post("/batch/flush")
def batch_flush(request: Request) -> dict[str, Any]:
    node: AggregatorNode = request.app.state.node
    result = node.force_cycle()
    if result is None:
        return {"status": "empty"}
    return {
        "status": "ok",
        "batch_id": result.batch.batch_id,
        "tx_count": len(result.batch.transactions),
        "merkle_root": result.batch.merkle_root.hex(),
        "is_proven": result.is_proven,
        "stark_commitment": result.commitment,
    }
