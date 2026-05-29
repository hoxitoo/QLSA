from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SubmitResult:
    accepted: bool
    error: str | None = None
    mempool_size: int = 0


@dataclass
class WitnessStatus:
    """Result of an ML-DSA-65 arithmetic witness STARK proof (VFRI7)."""

    has_witness: bool
    # Legacy V3/V4 fields (kept for backward compatibility; None when VFRI7 is used).
    onchain_commitment: str | None = None  # 32-char hex — mapped to vfri7_commitment_log10
    c_tilde_hex: str | None = None         # 96-char hex — not available in VFRI7 path
    max_norms: list[int] = field(default_factory=list)
    # VFRI7 cross-bound fields (MVP-5)
    has_vfri7: bool = False
    vfri7_commitment_log10: str | None = None  # 32-char hex
    vfri7_commitment_log8:  str | None = None  # 32-char hex
    n_fri_queries: int = 0  # FRI queries used; 0 = extension not available


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
    n_fri_queries: int = 1          # configured FRI queries per proof group
    fri_security_bits: int = 16     # 6 × n_fri_queries + 10
