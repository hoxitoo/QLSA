from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SubmitResult:
    accepted: bool
    error: str | None = None
    mempool_size: int = 0


@dataclass
class WitnessStatus:
    """Result of an ML-DSA-65 arithmetic witness STARK proof."""

    has_witness: bool
    onchain_commitment: str | None = None  # 32-char hex (16-byte Blake2s binding)
    c_tilde_hex: str | None = None         # 96-char hex (48-byte ML-DSA-65 LAMBDA_BYTES)
    max_norms: list[int] = field(default_factory=list)


@dataclass
class BatchStatus:
    batch_id: str
    tx_count: int
    merkle_root: str       # hex string (128 chars for SHA3-512)
    is_proven: bool
    stark_commitment: str | None = None
    has_witness: bool = False
    witness_commitment: str | None = None  # 32-char hex (16-byte binding for tx[0])
    # VFRI7 cross-bound ML-DSA V23 proofs (MVP-5)
    has_vfri7: bool = False
    vfri7_commitment_log10: str | None = None  # 32-char hex
    vfri7_commitment_log8:  str | None = None  # 32-char hex


@dataclass
class NodeStats:
    transactions_received: int
    transactions_batched: int
    batches_created: int
    proofs_generated: int
    pending: int
