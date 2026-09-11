"""ARCHIVED — NOT IMPORTED, NOT COLLECTED BY pytest.

Removed by the Ф1 narrowing; restored here from stark/prover.py@f2020d9 so the code
stays visible in the repository rather than only in git history.
To bring an item back, paste it into stark/prover.py and re-run the suite.
"""

@dataclass
class MldsaV23VFRI7HintResult:
    proof:       bytes
    commitment:  str    # Blake2s(proof[:32]‖bound_merkle_root)[:16]
    query_hints: bytes  # ABI-encoded for QLSAVerifierVFRI7.verify(queryHints)
    n_cols:      int
    n_queries:   int

def gen_mldsa_v23_vfri7_hints(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds: int | None = None,
) -> MldsaV23VFRI7HintResult:
    """Generate VFRI7-compatible hints for V23's LOG=10 group (1298 cols).

    VFRI7 adds mixRoot(batch_merkle_root) into the Fiat-Shamir transcript
    immediately before drawQueries, binding FRI query indices to the external
    batch context (MVP-5 Priority 2).

    Args:
        z, c, t1, a_hat:   ML-DSA witness (L=5 / K=6 polynomials, 256 coeffs each).
        batch_merkle_root: 32-byte batch Merkle root (or cross-bound root from
                           gen_mldsa_v23_vfri7_cross_bound_hints).
        n_queries:         Number of FRI queries (default 1).
        num_folds:         Fold rounds (default: automatic).

    Returns:
        MldsaV23VFRI7HintResult with proof, commitment, query_hints, n_cols=1298.
    """
    _require_ext("gen_mldsa_v23_vfri7_hints_py")
    try:
        proof, commitment, query_hints = _ext.gen_mldsa_v23_vfri7_hints_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri7_hints failed: {exc}") from exc
    return MldsaV23VFRI7HintResult(
        proof=bytes(proof),
        commitment=commitment,
        query_hints=bytes(query_hints),
        n_cols=1298,
        n_queries=n_queries,
    )

@dataclass
class MldsaV23VFRI7Log8HintResult:
    proof:       bytes
    commitment:  str
    query_hints: bytes
    n_cols:      int    # 2206
    n_queries:   int

def gen_mldsa_v23_vfri7_hints_log8(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    hints: list[list[bool]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds: int | None = None,
) -> MldsaV23VFRI7Log8HintResult:
    """Generate VFRI7-compatible hints for V23's LOG=8 group (2206 cols).

    Args:
        hints:             K=6 UseHint bool arrays (each 256 bools).
        Other args:        Same as gen_mldsa_v23_vfri7_hints.

    Returns:
        MldsaV23VFRI7Log8HintResult with proof, commitment, query_hints, n_cols=2206.
    """
    _require_ext("gen_mldsa_v23_vfri7_hints_log8_py")
    try:
        proof, commitment, query_hints = _ext.gen_mldsa_v23_vfri7_hints_log8_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            [list(h) for h in hints],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri7_hints_log8 failed: {exc}") from exc
    return MldsaV23VFRI7Log8HintResult(
        proof=bytes(proof),
        commitment=commitment,
        query_hints=bytes(query_hints),
        n_cols=2206,
        n_queries=n_queries,
    )

@dataclass
class FullV23VFRI7CrossBoundHintResult:
    """Cross-bound VFRI7 hints for the full V23 trace (MVP-5 Priority 2).

    Each proof's FRI query indices depend on the other proof's trace commitment:
      bound_root_10 = keccak256(batch_merkle_root ‖ proof8[8:40])
      bound_root_8  = keccak256(batch_merkle_root ‖ proof10[8:40])

    An adversary mixing LOG=10 and LOG=8 proofs from different ML-DSA witnesses
    gets mismatched query indices and fails on-chain Merkle verification.

    BatchRegistryV4 reconstructs the bound roots on-chain from the proof bytes
    and passes them to QLSAVerifierVFRI7.verify().
    """

    log10_proof: bytes
    log10_commitment: str   # Blake2s(proof10[:32] ‖ bound_root_10)[:16]
    log10_query_hints: bytes

    log8_proof: bytes
    log8_commitment: str    # Blake2s(proof8[:32] ‖ bound_root_8)[:16]
    log8_query_hints: bytes

    batch_merkle_root: bytes
    n_queries: int

def gen_mldsa_v23_vfri7_cross_bound_hints(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    hints: list[list[bool]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds_log10: int | None = None,
    num_folds_log8: int | None = None,
) -> FullV23VFRI7CrossBoundHintResult:
    """Generate cross-bound VFRI7 hints for both LOG groups (MVP-5 Priority 2).

    Two-pass generation:
      Pass 1: generate with batch_merkle_root to extract trace roots.
      Pass 2: regenerate with cross-bound roots derived from the other group's
              trace root, so each proof's FRI query indices depend on the
              other proof's committed trace.

    Args:
        z, c, t1, a_hat:   ML-DSA witness.
        hints:             K=6 UseHint bool arrays.
        batch_merkle_root: 32-byte batch Merkle root (from SHA3-512 Merkle tree).
        n_queries:         FRI queries per group (default 1).
        num_folds_log10:   Fold rounds for LOG=10 (default: automatic).
        num_folds_log8:    Fold rounds for LOG=8 (default: automatic).

    Returns:
        FullV23VFRI7CrossBoundHintResult with both proof triples.
    """
    _require_ext("gen_mldsa_v23_vfri7_cross_bound_hints_py")
    if num_folds_log10 is not None and num_folds_log8 is not None and num_folds_log10 != num_folds_log8:
        raise ValueError(
            f"num_folds_log10={num_folds_log10} and num_folds_log8={num_folds_log8} differ; "
            "the Rust bridge uses the same fold count for both groups — pass only num_folds_log10."
        )
    # The Rust bridge uses one fold count for both LOG groups.
    # num_folds_log8 is accepted for API symmetry; use it when log10 is unset.
    num_folds = num_folds_log10 if num_folds_log10 is not None else num_folds_log8
    try:
        (proof10, commit10, hints10,
         proof8, commit8, hints8) = _ext.gen_mldsa_v23_vfri7_cross_bound_hints_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            [list(h) for h in hints],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri7_cross_bound_hints failed: {exc}") from exc
    return FullV23VFRI7CrossBoundHintResult(
        log10_proof=bytes(proof10),
        log10_commitment=commit10,
        log10_query_hints=bytes(hints10),
        log8_proof=bytes(proof8),
        log8_commitment=commit8,
        log8_query_hints=bytes(hints8),
        batch_merkle_root=batch_merkle_root,
        n_queries=n_queries,
    )

def prove_mldsa_sig_vfri7_stark(
    pk: bytes,
    msg: bytes,
    sig: bytes,
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds_log10: int | None = None,
    num_folds_log8: int | None = None,
) -> FullV23VFRI7CrossBoundHintResult:
    """Generate cross-bound VFRI7 hints from a real ML-DSA-65 signature.

    Decodes the signature to extract the arithmetic witness (z, c, t1, a_hat,
    hints), then runs gen_mldsa_v23_vfri7_cross_bound_hints for both LOG=10 and
    LOG=8 trace groups with the given batch_merkle_root.

    Args:
        pk:                ML-DSA-65 public key bytes (1952 bytes).
        msg:               Signed message bytes.
        sig:               ML-DSA-65 signature bytes (3309 bytes).
        batch_merkle_root: 32-byte batch Merkle root for Fiat-Shamir binding.
        n_queries:         FRI queries per group (default 1).
        num_folds_log10:   Fold rounds for LOG=10 group (default: automatic).
        num_folds_log8:    Fold rounds for LOG=8 group (default: automatic).

    Returns:
        FullV23VFRI7CrossBoundHintResult with cross-bound proofs for both groups.

    Raises:
        ValueError: if the signature fails ML-DSA-65 verification.
        RuntimeError: if the extension is not installed or proof generation fails.
    """
    _require_ext("extract_mldsa_witness_py")
    try:
        z_raw, c_raw, t1_raw, a_hat_raw, hints_raw = _ext.extract_mldsa_witness_py(
            bytes(pk), bytes(msg), bytes(sig),
        )
    except Exception as exc:
        raise ValueError(f"extract_mldsa_witness_py failed: {exc}") from exc

    z     = [list(p) for p in z_raw]
    c     = list(c_raw)
    t1    = [list(p) for p in t1_raw]
    a_hat = [list(p) for p in a_hat_raw]
    hints = [list(h) for h in hints_raw]

    return gen_mldsa_v23_vfri7_cross_bound_hints(
        z, c, t1, a_hat, hints,
        batch_merkle_root,
        n_queries=n_queries,
        num_folds_log10=num_folds_log10,
        num_folds_log8=num_folds_log8,
    )


# ── VFRI8: Poseidon2 trace commitment ────────────────────────────────────────

@dataclass
class MldsaV23VFRI8HintResult:
    proof:       bytes
    commitment:  str
    query_hints: bytes
    n_cols:      int    # 1298
    n_queries:   int

def gen_mldsa_v23_vfri8_hints(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds: int | None = None,
) -> MldsaV23VFRI8HintResult:
    """Generate VFRI8 hints for V23's LOG=10 group (1298 cols, NttBatch+InttBatch).

    VFRI8 = VFRI7 with Poseidon2 replacing Blake2s for Merkle hashing and the
    Fiat-Shamir channel.  Gas: ~400K for Merkle proofs vs ~160M for Blake2s.

    Args:
        z, c, t1, a_hat:   ML-DSA witness (L=5/K=6 polynomials, 256 coeffs each).
        batch_merkle_root: 32-byte batch Merkle root.
        n_queries:         FRI queries (default 1; use 20 for 130-bit soundness).
        num_folds:         Fold rounds (default: automatic = tree_depth - 1 = 9).

    Returns:
        MldsaV23VFRI8HintResult with proof, commitment, query_hints, n_cols=1298.
    """
    _require_ext("gen_mldsa_v23_vfri8_hints_py")
    try:
        proof, commitment, query_hints = _ext.gen_mldsa_v23_vfri8_hints_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri8_hints failed: {exc}") from exc
    return MldsaV23VFRI8HintResult(
        proof=bytes(proof),
        commitment=commitment,
        query_hints=bytes(query_hints),
        n_cols=1298,
        n_queries=n_queries,
    )

@dataclass
class MldsaV23VFRI8Log8HintResult:
    proof:       bytes
    commitment:  str
    query_hints: bytes
    n_cols:      int    # 2206
    n_queries:   int

def gen_mldsa_v23_vfri8_hints_log8(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    hints: list[list[bool]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds: int | None = None,
) -> MldsaV23VFRI8Log8HintResult:
    """Generate VFRI8 hints for V23's LOG=8 group (2206 cols).

    Args:
        hints:   K=6 UseHint bool arrays (each 256 bools).
        Other:   Same as gen_mldsa_v23_vfri8_hints.

    Returns:
        MldsaV23VFRI8Log8HintResult with proof, commitment, query_hints, n_cols=2206.
    """
    _require_ext("gen_mldsa_v23_vfri8_hints_log8_py")
    try:
        proof, commitment, query_hints = _ext.gen_mldsa_v23_vfri8_hints_log8_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            [list(h) for h in hints],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri8_hints_log8 failed: {exc}") from exc
    return MldsaV23VFRI8Log8HintResult(
        proof=bytes(proof),
        commitment=commitment,
        query_hints=bytes(query_hints),
        n_cols=2206,
        n_queries=n_queries,
    )

@dataclass
class FullV23VFRI8CrossBoundHintResult:
    """Cross-bound VFRI8 hints for the full V23 trace.

    Identical semantics to FullV23VFRI7CrossBoundHintResult but uses Poseidon2
    for Merkle hashing and the Fiat-Shamir channel instead of Blake2s.
    """

    log10_proof: bytes
    log10_commitment: str
    log10_query_hints: bytes

    log8_proof: bytes
    log8_commitment: str
    log8_query_hints: bytes

    batch_merkle_root: bytes
    n_queries: int

def gen_mldsa_v23_vfri8_cross_bound_hints(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    hints: list[list[bool]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds_log10: int | None = None,
    num_folds_log8: int | None = None,
) -> FullV23VFRI8CrossBoundHintResult:
    """Generate cross-bound VFRI8 hints for both LOG groups.

    Two-pass cross-proof binding using Poseidon2 backends:
      bound_root_10 = keccak256(batch_merkle_root ‖ proof8[8:40])
      bound_root_8  = keccak256(batch_merkle_root ‖ proof10[8:40])

    Args:
        z, c, t1, a_hat:   ML-DSA witness.
        hints:             K=6 UseHint bool arrays.
        batch_merkle_root: 32-byte batch Merkle root.
        n_queries:         FRI queries per group (default 1; use 20 for production).
        num_folds_log10:   Fold rounds for LOG=10 (default: automatic).
        num_folds_log8:    Fold rounds for LOG=8 (default: automatic).

    Returns:
        FullV23VFRI8CrossBoundHintResult with both proof triples.
    """
    _require_ext("gen_mldsa_v23_vfri8_cross_bound_hints_py")
    if num_folds_log10 is not None and num_folds_log8 is not None and num_folds_log10 != num_folds_log8:
        raise ValueError(
            f"num_folds_log10={num_folds_log10} and num_folds_log8={num_folds_log8} differ; "
            "the Rust bridge uses the same fold count for both groups."
        )
    num_folds = num_folds_log10 if num_folds_log10 is not None else num_folds_log8
    try:
        (proof10, commit10, hints10,
         proof8, commit8, hints8) = _ext.gen_mldsa_v23_vfri8_cross_bound_hints_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            [list(h) for h in hints],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri8_cross_bound_hints failed: {exc}") from exc
    return FullV23VFRI8CrossBoundHintResult(
        log10_proof=bytes(proof10),
        log10_commitment=commit10,
        log10_query_hints=bytes(hints10),
        log8_proof=bytes(proof8),
        log8_commitment=commit8,
        log8_query_hints=bytes(hints8),
        batch_merkle_root=batch_merkle_root,
        n_queries=n_queries,
    )

def prove_mldsa_sig_vfri8_stark(
    pk: bytes,
    msg: bytes,
    sig: bytes,
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds_log10: int | None = None,
    num_folds_log8: int | None = None,
) -> FullV23VFRI8CrossBoundHintResult:
    """Generate cross-bound VFRI8 hints from a real ML-DSA-65 signature.

    Decodes the signature to extract the arithmetic witness (z, c, t1, a_hat,
    hints), then runs gen_mldsa_v23_vfri8_cross_bound_hints for both LOG=10 and
    LOG=8 trace groups with the given batch_merkle_root.

    Args:
        pk:                ML-DSA-65 public key bytes (1952 bytes).
        msg:               Signed message bytes.
        sig:               ML-DSA-65 signature bytes (3309 bytes).
        batch_merkle_root: 32-byte batch Merkle root for Fiat-Shamir binding.
        n_queries:         FRI queries per group (default 1).
        num_folds_log10:   Fold rounds for LOG=10 group (default: automatic).
        num_folds_log8:    Fold rounds for LOG=8 group (default: automatic).

    Returns:
        FullV23VFRI8CrossBoundHintResult with cross-bound Poseidon2 proofs for both groups.

    Raises:
        ValueError: if the signature fails ML-DSA-65 verification.
        RuntimeError: if the extension is not installed or proof generation fails.
    """
    _require_ext("extract_mldsa_witness_py")
    try:
        z_raw, c_raw, t1_raw, a_hat_raw, hints_raw = _ext.extract_mldsa_witness_py(
            bytes(pk), bytes(msg), bytes(sig),
        )
    except Exception as exc:
        raise ValueError(f"extract_mldsa_witness_py failed: {exc}") from exc

    z     = [list(p) for p in z_raw]
    c     = list(c_raw)
    t1    = [list(p) for p in t1_raw]
    a_hat = [list(p) for p in a_hat_raw]
    hints = [list(h) for h in hints_raw]

    return gen_mldsa_v23_vfri8_cross_bound_hints(
        z, c, t1, a_hat, hints,
        batch_merkle_root,
        n_queries=n_queries,
        num_folds_log10=num_folds_log10,
        num_folds_log8=num_folds_log8,
    )


# ── VFRI9: last-layer FRI check + wide Poseidon2 nodes ───────────────────────

@dataclass
class MldsaV23VFRI9HintResult:
    proof:       bytes
    commitment:  str
    query_hints: bytes
    n_cols:      int    # 1298
    n_queries:   int

def gen_mldsa_v23_vfri9_hints(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds: int | None = None,
) -> MldsaV23VFRI9HintResult:
    """Generate VFRI9 hints for V23's LOG=10 group (1298 cols, NttBatch+InttBatch).

    VFRI9 = VFRI8 with three security upgrades:
      1. Last-layer FRI bounded-degree check (closes the VFRI5..8 soundness gap).
      2. Wide (62-bit) Poseidon2 Merkle nodes — node collision 2^15.5 → 2^31.
      3. Full-root Fiat-Shamir absorption (all 32 bytes of trace/batch roots).

    Args:
        z, c, t1, a_hat:   ML-DSA witness (L=5/K=6 polynomials, 256 coeffs each).
        batch_merkle_root: 32-byte batch Merkle root.
        n_queries:         FRI queries (default 1; use 20 for 130-bit soundness).
        num_folds:         Fold rounds (default: automatic = tree_depth - 1 = 9).

    Returns:
        MldsaV23VFRI9HintResult with proof, commitment, query_hints, n_cols=1298.
    """
    _require_ext("gen_mldsa_v23_vfri9_hints_py")
    try:
        proof, commitment, query_hints = _ext.gen_mldsa_v23_vfri9_hints_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri9_hints failed: {exc}") from exc
    return MldsaV23VFRI9HintResult(
        proof=bytes(proof),
        commitment=commitment,
        query_hints=bytes(query_hints),
        n_cols=1298,
        n_queries=n_queries,
    )

@dataclass
class MldsaV23VFRI9Log8HintResult:
    proof:       bytes
    commitment:  str
    query_hints: bytes
    n_cols:      int    # 2206
    n_queries:   int

def gen_mldsa_v23_vfri9_hints_log8(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    hints: list[list[bool]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds: int | None = None,
) -> MldsaV23VFRI9Log8HintResult:
    """Generate VFRI9 hints for V23's LOG=8 group (2206 cols).

    Args:
        hints:   K=6 UseHint bool arrays (each 256 bools).
        Other:   Same as gen_mldsa_v23_vfri9_hints.

    Returns:
        MldsaV23VFRI9Log8HintResult with proof, commitment, query_hints, n_cols=2206.
    """
    _require_ext("gen_mldsa_v23_vfri9_hints_log8_py")
    try:
        proof, commitment, query_hints = _ext.gen_mldsa_v23_vfri9_hints_log8_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            [list(h) for h in hints],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri9_hints_log8 failed: {exc}") from exc
    return MldsaV23VFRI9Log8HintResult(
        proof=bytes(proof),
        commitment=commitment,
        query_hints=bytes(query_hints),
        n_cols=2206,
        n_queries=n_queries,
    )

@dataclass
class FullV23VFRI9CrossBoundHintResult:
    """Cross-bound VFRI9 hints for the full V23 trace.

    Identical semantics to FullV23VFRI8CrossBoundHintResult but with wide
    Poseidon2 nodes, full-root Fiat-Shamir absorption, and last-layer
    evaluations included in the query hints.
    """

    log10_proof: bytes
    log10_commitment: str
    log10_query_hints: bytes

    log8_proof: bytes
    log8_commitment: str
    log8_query_hints: bytes

    batch_merkle_root: bytes
    n_queries: int

def gen_mldsa_v23_vfri9_cross_bound_hints(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    hints: list[list[bool]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds_log10: int | None = None,
    num_folds_log8: int | None = None,
) -> FullV23VFRI9CrossBoundHintResult:
    """Generate cross-bound VFRI9 hints for both LOG groups.

    Two-pass cross-proof binding (same as VFRI8):
      bound_root_10 = keccak256(batch_merkle_root ‖ proof8[8:40])
      bound_root_8  = keccak256(batch_merkle_root ‖ proof10[8:40])

    Args:
        z, c, t1, a_hat:   ML-DSA witness.
        hints:             K=6 UseHint bool arrays.
        batch_merkle_root: 32-byte batch Merkle root.
        n_queries:         FRI queries per group (default 1; use 20 for production).
        num_folds_log10:   Fold rounds for LOG=10 (default: automatic).
        num_folds_log8:    Fold rounds for LOG=8 (default: automatic).

    Returns:
        FullV23VFRI9CrossBoundHintResult with both proof triples.
    """
    _require_ext("gen_mldsa_v23_vfri9_cross_bound_hints_py")
    if num_folds_log10 is not None and num_folds_log8 is not None and num_folds_log10 != num_folds_log8:
        raise ValueError(
            f"num_folds_log10={num_folds_log10} and num_folds_log8={num_folds_log8} differ; "
            "the Rust bridge uses the same fold count for both groups."
        )
    num_folds = num_folds_log10 if num_folds_log10 is not None else num_folds_log8
    try:
        (proof10, commit10, hints10,
         proof8, commit8, hints8) = _ext.gen_mldsa_v23_vfri9_cross_bound_hints_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            [list(h) for h in hints],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri9_cross_bound_hints failed: {exc}") from exc
    return FullV23VFRI9CrossBoundHintResult(
        log10_proof=bytes(proof10),
        log10_commitment=commit10,
        log10_query_hints=bytes(hints10),
        log8_proof=bytes(proof8),
        log8_commitment=commit8,
        log8_query_hints=bytes(hints8),
        batch_merkle_root=batch_merkle_root,
        n_queries=n_queries,
    )

def prove_mldsa_sig_vfri9_stark(
    pk: bytes,
    msg: bytes,
    sig: bytes,
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds_log10: int | None = None,
    num_folds_log8: int | None = None,
) -> FullV23VFRI9CrossBoundHintResult:
    """Generate cross-bound VFRI9 hints from a real ML-DSA-65 signature.

    Decodes the signature to extract the arithmetic witness (z, c, t1, a_hat,
    hints), then runs gen_mldsa_v23_vfri9_cross_bound_hints for both LOG=10 and
    LOG=8 trace groups with the given batch_merkle_root.

    Args:
        pk:                ML-DSA-65 public key bytes (1952 bytes).
        msg:               Signed message bytes.
        sig:               ML-DSA-65 signature bytes (3309 bytes).
        batch_merkle_root: 32-byte batch Merkle root for Fiat-Shamir binding.
        n_queries:         FRI queries per group (default 1).
        num_folds_log10:   Fold rounds for LOG=10 group (default: automatic).
        num_folds_log8:    Fold rounds for LOG=8 group (default: automatic).

    Returns:
        FullV23VFRI9CrossBoundHintResult with cross-bound proofs for both groups.

    Raises:
        ValueError: if the signature fails ML-DSA-65 verification.
        RuntimeError: if the extension is not installed or proof generation fails.
    """
    _require_ext("extract_mldsa_witness_py")
    try:
        z_raw, c_raw, t1_raw, a_hat_raw, hints_raw = _ext.extract_mldsa_witness_py(
            bytes(pk), bytes(msg), bytes(sig),
        )
    except Exception as exc:
        raise ValueError(f"extract_mldsa_witness_py failed: {exc}") from exc

    z     = [list(p) for p in z_raw]
    c     = list(c_raw)
    t1    = [list(p) for p in t1_raw]
    a_hat = [list(p) for p in a_hat_raw]
    hints = [list(h) for h in hints_raw]

    return gen_mldsa_v23_vfri9_cross_bound_hints(
        z, c, t1, a_hat, hints,
        batch_merkle_root,
        n_queries=n_queries,
        num_folds_log10=num_folds_log10,
        num_folds_log8=num_folds_log8,
    )


# ── VFRI10: VFRI9 protocol on the Poseidon2 t=4 hash backend ─────────────────

@dataclass
class MldsaV23VFRI10HintResult:
    proof:       bytes
    commitment:  str
    query_hints: bytes
    n_cols:      int    # 1298
    n_queries:   int

def gen_mldsa_v23_vfri10_hints(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds: int | None = None,
) -> MldsaV23VFRI10HintResult:
    """Generate VFRI10 hints for V23's LOG=10 group (1298 cols, NttBatch+InttBatch).

    VFRI10 = VFRI9 protocol on the Poseidon2 t=4 hash backend (t=4 wide Merkle +
    t=4 Fiat-Shamir channel).  Same queryHints ABI, last-layer FRI check, and
    full-root absorption as VFRI9; only the permutation widens (t=2 → t=4),
    lifting the node/transcript collision wall above the t=2 ceiling (~2^31).

    Args:
        z, c, t1, a_hat:   ML-DSA witness (L=5/K=6 polynomials, 256 coeffs each).
        batch_merkle_root: 32-byte batch Merkle root.
        n_queries:         FRI queries (default 1; use 20 for 130-bit soundness).
        num_folds:         Fold rounds (default: automatic = tree_depth - 1 = 9).

    Returns:
        MldsaV23VFRI10HintResult with proof, commitment, query_hints, n_cols=1298.
    """
    _require_ext("gen_mldsa_v23_vfri10_hints_py")
    try:
        proof, commitment, query_hints = _ext.gen_mldsa_v23_vfri10_hints_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri10_hints failed: {exc}") from exc
    return MldsaV23VFRI10HintResult(
        proof=bytes(proof),
        commitment=commitment,
        query_hints=bytes(query_hints),
        n_cols=1298,
        n_queries=n_queries,
    )

@dataclass
class MldsaV23VFRI10Log8HintResult:
    proof:       bytes
    commitment:  str
    query_hints: bytes
    n_cols:      int    # 2206
    n_queries:   int

def gen_mldsa_v23_vfri10_hints_log8(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    hints: list[list[bool]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds: int | None = None,
) -> MldsaV23VFRI10Log8HintResult:
    """Generate VFRI10 hints for V23's LOG=8 group (2206 cols).

    Args:
        hints:   K=6 UseHint bool arrays (each 256 bools).
        Other:   Same as gen_mldsa_v23_vfri10_hints.

    Returns:
        MldsaV23VFRI10Log8HintResult with proof, commitment, query_hints, n_cols=2206.
    """
    _require_ext("gen_mldsa_v23_vfri10_hints_log8_py")
    try:
        proof, commitment, query_hints = _ext.gen_mldsa_v23_vfri10_hints_log8_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            [list(h) for h in hints],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri10_hints_log8 failed: {exc}") from exc
    return MldsaV23VFRI10Log8HintResult(
        proof=bytes(proof),
        commitment=commitment,
        query_hints=bytes(query_hints),
        n_cols=2206,
        n_queries=n_queries,
    )

@dataclass
class FullV23VFRI10CrossBoundHintResult:
    """Cross-bound VFRI10 hints for the full V23 trace.

    Identical semantics to FullV23VFRI9CrossBoundHintResult but with the
    Poseidon2 t=4 hash backend (t=4 wide Merkle + t=4 Fiat-Shamir channel).
    """

    log10_proof: bytes
    log10_commitment: str
    log10_query_hints: bytes

    log8_proof: bytes
    log8_commitment: str
    log8_query_hints: bytes

    batch_merkle_root: bytes
    n_queries: int

def gen_mldsa_v23_vfri10_cross_bound_hints(
    z: list[list[int]],
    c: list[int],
    t1: list[list[int]],
    a_hat: list[list[int]],
    hints: list[list[bool]],
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds_log10: int | None = None,
    num_folds_log8: int | None = None,
) -> FullV23VFRI10CrossBoundHintResult:
    """Generate cross-bound VFRI10 hints for both LOG groups.

    Two-pass cross-proof binding (same as VFRI9):
      bound_root_10 = keccak256(batch_merkle_root ‖ proof8[8:40])
      bound_root_8  = keccak256(batch_merkle_root ‖ proof10[8:40])

    Args:
        z, c, t1, a_hat:   ML-DSA witness.
        hints:             K=6 UseHint bool arrays.
        batch_merkle_root: 32-byte batch Merkle root.
        n_queries:         FRI queries per group (default 1; use 20 for production).
        num_folds_log10:   Fold rounds for LOG=10 (default: automatic).
        num_folds_log8:    Fold rounds for LOG=8 (default: automatic).

    Returns:
        FullV23VFRI10CrossBoundHintResult with both proof triples.
    """
    _require_ext("gen_mldsa_v23_vfri10_cross_bound_hints_py")
    if num_folds_log10 is not None and num_folds_log8 is not None and num_folds_log10 != num_folds_log8:
        raise ValueError(
            f"num_folds_log10={num_folds_log10} and num_folds_log8={num_folds_log8} differ; "
            "the Rust bridge uses the same fold count for both groups."
        )
    num_folds = num_folds_log10 if num_folds_log10 is not None else num_folds_log8
    try:
        (proof10, commit10, hints10,
         proof8, commit8, hints8) = _ext.gen_mldsa_v23_vfri10_cross_bound_hints_py(
            [list(p) for p in z],
            list(c),
            [list(p) for p in t1],
            [list(p) for p in a_hat],
            [list(h) for h in hints],
            list(batch_merkle_root),
            n_queries,
            num_folds,
        )
    except Exception as exc:
        raise RuntimeError(f"gen_mldsa_v23_vfri10_cross_bound_hints failed: {exc}") from exc
    return FullV23VFRI10CrossBoundHintResult(
        log10_proof=bytes(proof10),
        log10_commitment=commit10,
        log10_query_hints=bytes(hints10),
        log8_proof=bytes(proof8),
        log8_commitment=commit8,
        log8_query_hints=bytes(hints8),
        batch_merkle_root=batch_merkle_root,
        n_queries=n_queries,
    )

def prove_mldsa_sig_vfri10_stark(
    pk: bytes,
    msg: bytes,
    sig: bytes,
    batch_merkle_root: bytes,
    n_queries: int = 1,
    num_folds_log10: int | None = None,
    num_folds_log8: int | None = None,
) -> FullV23VFRI10CrossBoundHintResult:
    """Generate cross-bound VFRI10 hints from a real ML-DSA-65 signature.

    Decodes the signature to extract the arithmetic witness (z, c, t1, a_hat,
    hints), then runs gen_mldsa_v23_vfri10_cross_bound_hints for both LOG=10 and
    LOG=8 trace groups with the given batch_merkle_root.

    Args:
        pk:                ML-DSA-65 public key bytes (1952 bytes).
        msg:               Signed message bytes.
        sig:               ML-DSA-65 signature bytes (3309 bytes).
        batch_merkle_root: 32-byte batch Merkle root for Fiat-Shamir binding.
        n_queries:         FRI queries per group (default 1).
        num_folds_log10:   Fold rounds for LOG=10 group (default: automatic).
        num_folds_log8:    Fold rounds for LOG=8 group (default: automatic).

    Returns:
        FullV23VFRI10CrossBoundHintResult with cross-bound proofs for both groups.

    Raises:
        ValueError: if the signature fails ML-DSA-65 verification.
        RuntimeError: if the extension is not installed or proof generation fails.
    """
    _require_ext("extract_mldsa_witness_py")
    try:
        z_raw, c_raw, t1_raw, a_hat_raw, hints_raw = _ext.extract_mldsa_witness_py(
            bytes(pk), bytes(msg), bytes(sig),
        )
    except Exception as exc:
        raise ValueError(f"extract_mldsa_witness_py failed: {exc}") from exc

    z     = [list(p) for p in z_raw]
    c     = list(c_raw)
    t1    = [list(p) for p in t1_raw]
    a_hat = [list(p) for p in a_hat_raw]
    hints = [list(h) for h in hints_raw]

    return gen_mldsa_v23_vfri10_cross_bound_hints(
        z, c, t1, a_hat, hints,
        batch_merkle_root,
        n_queries=n_queries,
        num_folds_log10=num_folds_log10,
        num_folds_log8=num_folds_log8,
    )


# ── VFRI11 (VFRI10 protocol on the Poseidon2 t=8 hash backend) ────────────────
