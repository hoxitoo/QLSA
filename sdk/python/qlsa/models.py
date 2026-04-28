from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SubmitResult:
    accepted: bool
    error: str | None = None
    mempool_size: int = 0


@dataclass
class BatchStatus:
    batch_id: str
    tx_count: int
    merkle_root: str       # hex string (128 chars for SHA3-512)
    is_proven: bool
    stark_commitment: str | None = None


@dataclass
class NodeStats:
    transactions_received: int
    transactions_batched: int
    batches_created: int
    proofs_generated: int
    pending: int
