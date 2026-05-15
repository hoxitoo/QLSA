"""
Python interface to the qlsa_stark_stwo native extension (PyO3).

Install the extension once before use:
    cd stark_stwo && maturin develop --features python --release

The extension exposes prove/verify pairs for three circuits:
  prove / verify           — hash-chain (MVP-2)
  prove_p2 / verify_p2    — Poseidon2 hash-chain (MVP-3)
  prove_merkle / verify_merkle — Poseidon2 Merkle tree (MVP-3+)
  prove_mldsa              — ML-DSA-65 batch verification
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field

try:
    import qlsa_stark_stwo as _ext
    _HAVE_EXT = True
except ImportError:
    _ext = None
    _HAVE_EXT = False

from core.batch import Batch


def _require_ext(fn_name: str) -> None:
    if not _HAVE_EXT:
        raise RuntimeError(
            f"qlsa_stark_stwo extension required for {fn_name}. "
            "Install with: cd stark_stwo && maturin develop --features python --release"
        )

logger = logging.getLogger(__name__)

# ML-DSA-65: γ₁ − β = 524 288 − 196
NORM_BOUND: int = 524_092


@dataclass
class ProofResult:
    proof: bytes             # raw proof bytes (serialised Stwo StarkProof)
    commitment: str          # 32-char hex (16 bytes, 128-bit) — for Rust verifier
    log_size: int            # log₂(trace length) — required by the Rust verifier
    onchain_commitment: str = field(default="")
    # onchain_commitment: 32-char hex (16 bytes, 128-bit) = Blake2s(proof[0:32] ∥ merkle_root[:32])[:16]
    # Use this as the commitment when submitting to QLSAVerifierBound / BatchRegistryV2.
    # The Merkle root binding ensures the proof cannot be replayed against a different batch.


def prove_batch(batch: Batch) -> ProofResult:
    """
    Generate a hash-chain STARK proof for the batch.

    Converts the SHA3-512 Merkle root to 8 × u64 leaves (little-endian),
    then calls the Rust prover.

    Raises RuntimeError if the extension is not installed or the prover fails.
    """
    leaves = _txs_to_leaves(batch)
    result = _call_prover(leaves, merkle_root=batch.merkle_root)
    batch.stark_commitment = result.commitment
    batch.stark_log_size = result.log_size
    return result


def _txs_to_leaves(batch: Batch) -> list[int]:
    # Feed the 64-byte SHA3-512 Merkle root as 8 × u64 leaves (little-endian).
    root: bytes = batch.merkle_root  # 64 bytes
    return [int.from_bytes(root[i : i + 8], "little") for i in range(0, 64, 8)]


def _call_prover(leaves: list[int], merkle_root: bytes | None = None) -> ProofResult:
    _require_ext("prove")
    try:
        # Pass the Merkle root as a Fiat-Shamir seed so the STARK proof is
        # cryptographically bound to this specific batch root.
        proof_bytes, commitment, log_size = _ext.prove(leaves, merkle_root=merkle_root)
    except Exception as exc:
        raise RuntimeError(f"qlsa-stark-stwo prove failed: {exc}") from exc

    if len(commitment) != 32:
        raise RuntimeError(
            f"qlsa-stark-stwo prove returned unexpected commitment length "
            f"({len(commitment)} chars, expected 32)"
        )
    if len(proof_bytes) < 32:
        raise RuntimeError(
            f"qlsa-stark-stwo prove returned proof shorter than 32 bytes "
            f"({len(proof_bytes)} bytes) — cannot compute on-chain commitment"
        )

    binding_input = proof_bytes[:32]
    if merkle_root is not None:
        binding_input = binding_input + merkle_root[:32]
    onchain_commitment = hashlib.blake2s(binding_input).digest()[:16].hex()

    return ProofResult(
        proof=proof_bytes,
        commitment=commitment,
        log_size=log_size,
        onchain_commitment=onchain_commitment,
    )


# ─── Poseidon2 hash-chain STARK (MVP-3+) ─────────────────────────────────────

@dataclass
class Poseidon2ProofResult(ProofResult):
    """ProofResult whose commitment is a Poseidon2-over-M31 hash of the leaves."""


def prove_batch_poseidon2(batch: Batch) -> Poseidon2ProofResult:
    """
    Generate a Poseidon2-over-M31 STARK proof for the batch.

    The `onchain_commitment` binding formula is unchanged:
      Blake2s(proof[0:32] ∥ merkle_root[:32])[:16]

    Raises RuntimeError if the extension is not installed or the prover fails.
    """
    leaves = _txs_to_leaves(batch)
    result = _call_prover_p2(leaves, merkle_root=batch.merkle_root)
    batch.stark_commitment = result.commitment
    batch.stark_log_size = result.log_size
    return result


def _call_prover_p2(
    leaves: list[int], merkle_root: bytes | None = None
) -> Poseidon2ProofResult:
    _require_ext("prove_p2")
    try:
        proof_bytes, commitment, log_size = _ext.prove_p2(leaves, merkle_root)
    except Exception as exc:
        raise RuntimeError(f"qlsa-stark-stwo prove_p2 failed: {exc}") from exc

    if len(proof_bytes) < 32:
        raise RuntimeError(
            f"qlsa-stark-stwo prove_p2 returned proof shorter than 32 bytes "
            f"({len(proof_bytes)} bytes)"
        )

    binding_input = proof_bytes[:32]
    if merkle_root is not None:
        binding_input = binding_input + merkle_root[:32]
    onchain_commitment = hashlib.blake2s(binding_input).digest()[:16].hex()

    return Poseidon2ProofResult(
        proof=proof_bytes,
        commitment=commitment,
        log_size=log_size,
        onchain_commitment=onchain_commitment,
    )


# ─── Polynomial circuit STARK provers (MVP-3+) ────────────────────────────────
#
# Lower-level provers for individual polynomial operations.
# Each function corresponds directly to a Rust STARK circuit.
# All operate on lists of 256 integers in [0, Q) where Q = 8_380_417.


@dataclass
class PolyProofResult:
    """Result of a single-polynomial circuit STARK proof."""
    proof: bytes
    commitment: str  # 32-char hex, Scheme-B (4 M31 words)
    output: list[int]  # 256 output coefficients


@dataclass
class NormCheckResult:
    """Result of a norm-check STARK proof."""
    proof: bytes
    commitment: str
    norm: list[int]   # absolute centered values
    max_norm: int     # ||z||_∞ — caller asserts < γ₁ − β = 524 092


@dataclass
class UseHintResult:
    """Result of a UseHint STARK proof."""
    proof: bytes
    commitment: str
    w1: list[int]  # UseHint output: high bits in [0, m) where m=16


def prove_poly_sub_stark(
    a: list[int],
    b: list[int],
) -> PolyProofResult:
    """
    Prove c[i] = (a[i] − b[i]) mod Q for all 256 coefficients.

    Uses the poly_add AIR with negated b.  Both a and b must be 256-element
    lists of integers in [0, Q).
    """
    _require_ext("prove_poly_sub_py")
    try:
        proof_bytes, commitment, diff = _ext.prove_poly_sub_py(a, b)
    except Exception as exc:
        raise RuntimeError(f"prove_poly_sub_py failed: {exc}") from exc
    return PolyProofResult(proof=proof_bytes, commitment=commitment, output=diff)


def verify_poly_sub_stark(result: PolyProofResult) -> bool:
    """Verify a polynomial-subtraction proof."""
    _require_ext("verify_poly_sub_py")
    return bool(_ext.verify_poly_sub_py(result.proof, result.commitment))


def prove_norm_check_stark(z: list[int]) -> NormCheckResult:
    """
    Prove norm[i] = min(z[i], Q − z[i]) for all 256 coefficients.

    `z` must be a 256-element list of integers in [0, Q).
    Returns norm polynomial and max_norm (||z||_∞).
    Caller checks: max_norm < 524 092  (γ₁ − β for ML-DSA-65).
    """
    _require_ext("prove_norm_check_py")
    try:
        proof_bytes, commitment, norm, max_norm = _ext.prove_norm_check_py(z)
    except Exception as exc:
        raise RuntimeError(f"prove_norm_check_py failed: {exc}") from exc
    return NormCheckResult(proof=proof_bytes, commitment=commitment,
                           norm=norm, max_norm=max_norm)


def verify_norm_check_stark(result: NormCheckResult) -> bool:
    """Verify a norm-check proof."""
    _require_ext("verify_norm_check_py")
    return bool(_ext.verify_norm_check_py(result.proof, result.commitment))


def prove_use_hint_stark(r: list[int], h_bits: list[bool]) -> UseHintResult:
    """
    Prove UseHint(h_bits[i], r[i]) = w1[i] for all 256 coefficients.

    `r` must be 256 ints in [0, Q).  `h_bits` must be 256 bools.
    Returns w1 ∈ [0, 16) — the high-bits output used in the ML-DSA hash check.
    """
    _require_ext("prove_use_hint_py")
    try:
        proof_bytes, commitment, w1 = _ext.prove_use_hint_py(r, h_bits)
    except Exception as exc:
        raise RuntimeError(f"prove_use_hint_py failed: {exc}") from exc
    return UseHintResult(proof=proof_bytes, commitment=commitment, w1=w1)


def verify_use_hint_stark(result: UseHintResult) -> bool:
    """Verify a UseHint proof."""
    _require_ext("verify_use_hint_py")
    return bool(_ext.verify_use_hint_py(result.proof, result.commitment))


# ─── ML-DSA full arithmetic witness pipeline (MVP-3+) ────────────────────────

@dataclass
class MldsaWitnessResult:
    """
    Result of the full ML-DSA.Verify arithmetic witness pipeline (V3).

    proof_bundle       — bincode-serialized VerifyMldsaProofV3 (49 sub-proofs).
                         Includes Az-full, Ct1, NormCheck, UseHint, HintWeight proofs.
                         Pass to verify_mldsa_witness_stark.
    max_norms          — L values, ||z[j]||_∞; each must be < NORM_BOUND (524 092).
    w1_prime           — K rows × N coefficients; UseHint output for hash comparison.
    onchain_commitment — 32-char hex (16 bytes): Blake2s(bundle[:32] ∥ c_tilde[:32])[:16].
                         Binds the proof to this specific signature's challenge seed.
                         Use this as the commitment when publishing to QLSAVerifierBound.
    c_tilde_hex        — Hex-encoded c_tilde (48 bytes = LAMBDA_BYTES for ML-DSA-65).
                         Lets the caller re-derive Hash(μ ∥ w1_encode(w1_prime)) == c_tilde.
    hint_weight_total  — Σᵢ ||h[i]||₁ (total hint weight; caller asserts ≤ ω=55).
                         The corresponding STARK proof is included in proof_bundle.
    """
    proof_bundle:       bytes
    max_norms:          list[int]        # L entries
    w1_prime:           list[list[int]]  # K × N
    onchain_commitment: str = field(default="")  # 32-char hex
    c_tilde_hex:        str = field(default="")  # 96-char hex for ML-DSA-65
    hint_weight_total:  int = field(default=0)


def prove_mldsa_witness_stark(
    a_hat:   list[list[int]],       # K*L flat list, each 256 ints, NTT-domain
    z:       list[list[int]],       # L polynomials (signature)
    c:       list[int],             # 256-int challenge polynomial
    t1:      list[list[int]],       # K polynomials (public key)
    hints:   list[list[bool]],      # K × 256 hint bits
    k:       int,                   # rows (must be 6 for ML-DSA-65)
    l:       int,                   # columns (must be 5 for ML-DSA-65)
    c_tilde: bytes | None = None,   # FIPS 204 signature challenge (48 bytes); binds proof to (pk, msg)
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V3 pipeline, 49 sub-proofs):
      Az-full  →  c·t₁  →  poly_sub  →  norm_check  →  UseHint  →  HintWeight

    Requires k=6, l=5 (ML-DSA-65). All coefficients must be in [0, Q=8_380_417).

    c_tilde, if provided, is mixed into the Az-full Fiat-Shamir channel as a STARK
    public input, binding the proof to the specific FIPS 204 signing challenge.

    Returns MldsaWitnessResult with the V3 serialized proof bundle,
    ||z||_∞ norms for each of the L signature polynomials,
    and the UseHint output w1_prime (K × 256) for hash comparison.

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v3_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v3_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v3_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V3 pipeline)."""
    _require_ext("verify_mldsa_witness_v3_py")
    return bool(_ext.verify_mldsa_witness_v3_py(result.proof_bundle))


def prove_mldsa_witness_stark_v4(
    a_hat:   list[list[int]],
    z:       list[list[int]],
    c:       list[int],
    t1:      list[list[int]],
    hints:   list[list[bool]],
    k:       int,
    l:       int,
    c_tilde: bytes | None = None,
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V4 pipeline, 50 sub-proofs):
      Az-full  →  c·t₁ (Ct1-full AIR)  →  poly_sub  →  norm_check  →  UseHint  →  HintWeight

    Identical to prove_mldsa_witness_stark (V3) but uses the compact 295-column
    Ct1-full STARK instead of K individual PolyMul proofs, saving 5 sub-proofs.

    Requires k=6, l=5 (ML-DSA-65). All coefficients must be in [0, Q=8_380_417).
    c_tilde (48 bytes for ML-DSA-65) is mixed into both Az-full and Ct1-full
    Fiat-Shamir channels, binding both proofs to the specific challenge.

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v4_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v4_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v4_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark_v4(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V4 pipeline)."""
    _require_ext("verify_mldsa_witness_v4_py")
    return bool(_ext.verify_mldsa_witness_v4_py(result.proof_bundle))


def prove_mldsa_witness_stark_v5(
    a_hat:   list[list[int]],
    z:       list[list[int]],
    c:       list[int],
    t1:      list[list[int]],
    hints:   list[list[bool]],
    k:       int,
    l:       int,
    c_tilde: bytes | None = None,
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V5 pipeline, 45 sub-proofs):
      Az-full  →  Ct1-full  →  WPrime-full  →  norm_check  →  UseHint  →  HintWeight

    Identical to V4 but replaces K individual poly_sub proofs with the compact
    24-column WPrime-full STARK, saving 5 more sub-proofs (total: 45 vs 50).

    Requires k=6, l=5 (ML-DSA-65). All coefficients must be in [0, Q=8_380_417).

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v5_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v5_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v5_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark_v5(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V5 pipeline)."""
    _require_ext("verify_mldsa_witness_v5_py")
    return bool(_ext.verify_mldsa_witness_v5_py(result.proof_bundle))


def prove_mldsa_witness_stark_v8(
    a_hat:   list[list[int]],
    z:       list[list[int]],
    c:       list[int],
    t1:      list[list[int]],
    hints:   list[list[bool]],
    k:       int,
    l:       int,
    c_tilde: bytes | None = None,
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V8 pipeline, 31 sub-proofs):
      Az-full (range-Q batch)  →  Ct1-full  →  WPrime-full  →  NormCheck-batch
      →  UseHint-batch  →  HintWeight

    Replaces K individual range-Q proofs with one compact 288-column RangeQ-batch
    STARK inside AzProofV4, saving K-1=5 more sub-proofs (total: 31 vs 36 in V7).

    Requires k=6, l=5 (ML-DSA-65). All coefficients must be in [0, Q=8_380_417).

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v8_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v8_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v8_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark_v8(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V8 pipeline)."""
    _require_ext("verify_mldsa_witness_v8_py")
    return bool(_ext.verify_mldsa_witness_v8_py(result.proof_bundle))


def prove_mldsa_witness_stark_v6(
    a_hat:   list[list[int]],
    z:       list[list[int]],
    c:       list[int],
    t1:      list[list[int]],
    hints:   list[list[bool]],
    k:       int,
    l:       int,
    c_tilde: bytes | None = None,
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V6 pipeline, 41 sub-proofs):
      Az-full  →  Ct1-full  →  WPrime-full  →  NormCheck-batch  →  UseHint  →  HintWeight

    Replaces L individual NormCheck proofs with one compact 15-column NormCheck-batch
    STARK, saving L-1=4 more sub-proofs (total: 41 vs 45 in V5).

    Requires k=6, l=5 (ML-DSA-65). All coefficients must be in [0, Q=8_380_417).

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v6_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v6_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v6_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark_v6(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V6 pipeline)."""
    _require_ext("verify_mldsa_witness_v6_py")
    return bool(_ext.verify_mldsa_witness_v6_py(result.proof_bundle))


def prove_mldsa_witness_stark_v7(
    a_hat:   list[list[int]],
    z:       list[list[int]],
    c:       list[int],
    t1:      list[list[int]],
    hints:   list[list[bool]],
    k:       int,
    l:       int,
    c_tilde: bytes | None = None,
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V7 pipeline, 36 sub-proofs):
      Az-full  →  Ct1-full  →  WPrime-full  →  NormCheck-batch  →  UseHint-batch  →  HintWeight

    Replaces K individual UseHint proofs with one compact 60-column UseHint-batch
    STARK, saving K-1=5 more sub-proofs (total: 36 vs 41 in V6).
    This is the most compact witness pipeline currently implemented.

    Requires k=6, l=5 (ML-DSA-65). All coefficients must be in [0, Q=8_380_417).

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v7_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v7_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v7_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark_v7(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V7 pipeline)."""
    _require_ext("verify_mldsa_witness_v7_py")
    return bool(_ext.verify_mldsa_witness_v7_py(result.proof_bundle))


def prove_mldsa_witness_stark_v9(
    a_hat:   list[list[int]],
    z:       list[list[int]],
    c:       list[int],
    t1:      list[list[int]],
    hints:   list[list[bool]],
    k:       int,
    l:       int,
    c_tilde: bytes | None = None,
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V9 pipeline, 26 sub-proofs):
      Az-full (INTT-batch + range-Q-batch)  →  Ct1ProofV2  →  WPrime-full
      →  NormCheck-batch  →  UseHint-batch  →  HintWeight

    Replaces K individual INTT proofs inside AzProofV4 with one compact 325-column
    INTT-batch STARK, saving K-1=5 more sub-proofs (total: 26 vs 31 in V8).

    Requires k=6, l=5 (ML-DSA-65). All coefficients must be in [0, Q=8_380_417).

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v9_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v9_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v9_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark_v9(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V9 pipeline)."""
    _require_ext("verify_mldsa_witness_v9_py")
    return bool(_ext.verify_mldsa_witness_v9_py(result.proof_bundle))


def prove_mldsa_witness_stark_v10(
    a_hat:   list[list[int]],
    z:       list[list[int]],
    c:       list[int],
    t1:      list[list[int]],
    hints:   list[list[bool]],
    k:       int,
    l:       int,
    c_tilde: bytes | None = None,
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V10 pipeline, 16 sub-proofs):
      Az-full (INTT-batch + range-Q-batch)  →  Ct1ProofV3 (NTT-t1-batch + INTT-ct1-batch)
      →  WPrime-full  →  NormCheck-batch  →  UseHint-batch  →  HintWeight

    Replaces K individual NTT(t1) proofs and K individual INTT(ct1) proofs with
    two compact 325-column batch STARKs, saving 10 more sub-proofs (total: 16 vs 26 in V9).
    This is the most compact witness pipeline currently implemented.

    Requires k=6, l=5 (ML-DSA-65). All coefficients must be in [0, Q=8_380_417).

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v10_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v10_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v10_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark_v10(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V10 pipeline)."""
    _require_ext("verify_mldsa_witness_v10_py")
    return bool(_ext.verify_mldsa_witness_v10_py(result.proof_bundle))


def prove_mldsa_witness_stark_v11(
    a_hat:   list[list[int]],
    z:       list[list[int]],
    c:       list[int],
    t1:      list[list[int]],
    hints:   list[list[bool]],
    k:       int,
    l:       int,
    c_tilde: bytes | None = None,
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V11 pipeline, 12 sub-proofs):
      AzProofV6 (NTT-z-batch + Az-full + INTT-batch + range-Q-batch)
      →  Ct1ProofV3 (NTT-t1-batch + Ct1-full + INTT-ct1-batch)
      →  WPrime-full  →  NormCheck-batch  →  UseHint-batch  →  HintWeight

    Replaces L=5 individual NTT(z) proofs with one compact 271-column batch STARK,
    saving 4 more sub-proofs (total: 12 vs 16 in V10).

    Requires k=6, l=5 (ML-DSA-65). All coefficients must be in [0, Q=8_380_417).

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v11_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v11_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v11_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark_v11(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V11 pipeline)."""
    _require_ext("verify_mldsa_witness_v11_py")
    return bool(_ext.verify_mldsa_witness_v11_py(result.proof_bundle))


def prove_mldsa_witness_stark_v12(
    a_hat:   list[list[int]],
    z:       list[list[int]],
    c:       list[int],
    t1:      list[list[int]],
    hints:   list[list[bool]],
    k:       int,
    l:       int,
    c_tilde: bytes | None = None,
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V12 pipeline, 10 sub-proofs):
      AllNttProof (batch NTT for z+c+t1 = 12 polys)
      →  AzProofV7 (Az-full + INTT-az-batch + range-Q-batch)
      →  Ct1ProofV4 (Ct1-full + INTT-ct1-batch)
      →  WPrime-full  →  NormCheck-batch  →  UseHint-batch  →  HintWeight

    Merges NTT-z-batch (L=5) + NTT-c (1) + NTT-t1-batch (K=6) into one
    combined 12-poly batch NTT, saving 2 more sub-proofs (total: 10 vs 12 in V11).

    Requires k=6, l=5 (ML-DSA-65). All coefficients must be in [0, Q=8_380_417).

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v12_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v12_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v12_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark_v12(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V12 pipeline)."""
    _require_ext("verify_mldsa_witness_v12_py")
    return bool(_ext.verify_mldsa_witness_v12_py(result.proof_bundle))


def prove_mldsa_witness_stark_v13(
    a_hat:   list[list[int]],
    z:       list[list[int]],
    c:       list[int],
    t1:      list[list[int]],
    hints:   list[list[bool]],
    k:       int,
    l:       int,
    c_tilde: bytes | None = None,
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V13 pipeline, 9 sub-proofs):
      AllNttProof (12-poly NTT) + AzProofV8 (Az-full) + Ct1ProofV5 (Ct1-full)
      + CombinedInttBatch (2K=12-poly INTT + range-Q)
      + WPrime + NormBatch + UseHintBatch + HintWeight

    Merges the K=6 az INTT and K=6 ct1 INTT into one 2K=12-poly batch,
    saving 1 sub-proof vs V12 (total: 9).

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v13_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v13_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v13_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark_v13(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V13 pipeline)."""
    _require_ext("verify_mldsa_witness_v13_py")
    return bool(_ext.verify_mldsa_witness_v13_py(result.proof_bundle))


def prove_mldsa_witness_stark_v14(
    a_hat:   list[list[int]],
    z:       list[list[int]],
    c:       list[int],
    t1:      list[list[int]],
    hints:   list[list[bool]],
    k:       int,
    l:       int,
    c_tilde: bytes | None = None,
) -> MldsaWitnessResult:
    """
    Prove the full ML-DSA.Verify arithmetic witness (V14 pipeline, 8 sub-proofs):
      AllNttProof (12-poly NTT) + AzProofV8 (Az-full) + Ct1ProofV5 (Ct1-full)
      + CombinedInttWPrimeBatch (2K=12-poly INTT + WPrime with input-output binding)
      + NormBatch + UseHintBatch + HintWeight

    Merges the INTT and WPrime steps into one CombinedInttWPrimeBatch,
    removing the separate range-Q proof, saving 1 sub-proof vs V13 (total: 8).

    Raises RuntimeError if the extension is not installed or any sub-proof fails.
    """
    _require_ext("prove_mldsa_witness_v14_py")
    try:
        bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v14_py(
            a_hat, z, c, t1, hints, k, l, c_tilde
        )
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_witness_v14_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        hint_weight_total=int(hw_total),
    )


def verify_mldsa_witness_stark_v14(result: MldsaWitnessResult) -> bool:
    """Verify all STARK sub-proofs in an MldsaWitnessResult (V14 pipeline)."""
    _require_ext("verify_mldsa_witness_v14_py")
    return bool(_ext.verify_mldsa_witness_v14_py(result.proof_bundle))


def verify_mldsa_hash_check(
    pk:     bytes,
    msg:    bytes,
    result: MldsaWitnessResult,
) -> bool:
    """
    Off-circuit ML-DSA.Verify hash step.

    Recomputes μ = SHAKE-256(SHAKE-256(pk) ∥ M') and
    c̃' = SHAKE-256(μ ∥ w1Encode(w1_prime)), then checks c̃' == c_tilde.

    Together with verify_mldsa_witness_stark, this completes the full logical
    chain of ML-DSA.Verify: arithmetic correctness (STARK) + hash binding.

    Returns True iff the hash check passes.
    """
    _require_ext("verify_mldsa_hash_check_py")
    return bool(_ext.verify_mldsa_hash_check_py(
        pk, msg, result.w1_prime, result.c_tilde_hex
    ))


def prove_mldsa_sig_witness_stark(
    pk:  bytes,
    msg: bytes,
    sig: bytes,
) -> MldsaWitnessResult:
    """
    End-to-end: decode an ML-DSA-65 signature and prove the full arithmetic
    witness pipeline (Az → c·t₁·2^d → poly_sub → norm_check → UseHint).

    Raises ValueError if the signature is invalid.
    Raises RuntimeError if the extension is not installed or a sub-proof fails.
    """
    _require_ext("prove_mldsa_sig_witness_py")
    try:
        bundle, max_norms, w1_prime, onchain_commitment, c_tilde_hex, hw_total = \
            _ext.prove_mldsa_sig_witness_py(pk, msg, sig)
    except Exception as exc:
        raise RuntimeError(f"prove_mldsa_sig_witness_py failed: {exc}") from exc
    return MldsaWitnessResult(
        proof_bundle=bytes(bundle),
        max_norms=list(max_norms),
        w1_prime=[list(row) for row in w1_prime],
        onchain_commitment=onchain_commitment,
        c_tilde_hex=c_tilde_hex,
        hint_weight_total=int(hw_total),
    )


# ─── ML-DSA batch verification + STARK proof ─────────────────────────────────

@dataclass
class MldsaBatchResult(ProofResult):
    verified: int = 0  # number of valid signatures included in proof
    rejected: int = 0  # number of invalid signatures skipped


def prove_mldsa_batch(
    entries: list[tuple[bytes, bytes, bytes]],
) -> MldsaBatchResult:
    """
    Verify N ML-DSA-65 signatures in Rust and generate a STARK proof.

    Each entry is (pk_bytes, msg_bytes, sig_bytes).
    Invalid signatures are silently skipped; at least one must be valid.

    Returns a MldsaBatchResult with the STARK proof and verification counts.
    """
    _require_ext("prove_mldsa")
    try:
        proof_bytes, commitment, log_size, verified, rejected = _ext.prove_mldsa(entries)
    except Exception as exc:
        raise RuntimeError(f"qlsa-stark-stwo mldsa_batch failed: {exc}") from exc

    onchain_commitment = hashlib.blake2s(proof_bytes[:32]).digest()[:16].hex()

    return MldsaBatchResult(
        proof=proof_bytes,
        commitment=commitment,
        log_size=log_size,
        onchain_commitment=onchain_commitment,
        verified=verified,
        rejected=rejected,
    )


# ─── Poseidon2 Merkle-tree STARK ─────────────────────────────────────────────

@dataclass
class MerkleProofResult(ProofResult):
    """ProofResult whose commitment is a Poseidon2 Merkle root (M31 hex)."""


def prove_batch_merkle(batch: Batch) -> MerkleProofResult:
    """
    Generate a Poseidon2 Merkle-tree STARK proof for the batch.

    The `onchain_commitment` binding formula is unchanged:
      Blake2s(proof[0:32] ∥ merkle_root[:32])[:16]

    Raises RuntimeError if the extension is not installed or the prover fails.
    """
    leaves = _txs_to_leaves(batch)
    result = _call_prover_merkle(leaves, merkle_root=batch.merkle_root)
    batch.stark_commitment = result.commitment
    batch.stark_log_size = result.log_size
    return result


def _call_prover_merkle(
    leaves: list[int], merkle_root: bytes | None = None
) -> MerkleProofResult:
    _require_ext("prove_merkle")
    if merkle_root is None:
        import warnings
        warnings.warn(
            "_call_prover_merkle called without merkle_root: on-chain commitment "
            "will not be bound to any batch Merkle root.",
            stacklevel=3,
        )

    try:
        proof_bytes, commitment, log_size = _ext.prove_merkle(leaves, merkle_root)
    except Exception as exc:
        raise RuntimeError(f"qlsa-stark-stwo merkle_prove failed: {exc}") from exc

    if len(commitment) != 32:
        raise RuntimeError(
            f"qlsa-stark-stwo merkle_prove returned unexpected commitment length "
            f"({len(commitment)} chars, expected 32)"
        )
    if len(proof_bytes) < 32:
        raise RuntimeError(
            f"qlsa-stark-stwo merkle_prove returned proof shorter than 32 bytes "
            f"({len(proof_bytes)} bytes)"
        )

    binding_input = proof_bytes[:32]
    if merkle_root is not None:
        binding_input = binding_input + merkle_root[:32]
    onchain_commitment = hashlib.blake2s(binding_input).digest()[:16].hex()

    return MerkleProofResult(
        proof=proof_bytes,
        commitment=commitment,
        log_size=log_size,
        onchain_commitment=onchain_commitment,
    )
