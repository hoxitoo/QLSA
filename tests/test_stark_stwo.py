"""
Stwo Circle STARK tests using the PyO3 native extension.

Skipped automatically when the module is not installed. Install with:
    cd stark_stwo && maturin develop --features python --release
"""

from __future__ import annotations

import pytest

try:
    import qlsa_stark_stwo as _ext
    _HAVE_EXT = True
except ImportError:
    _HAVE_EXT = False

needs_ext = pytest.mark.skipif(
    not _HAVE_EXT,
    reason="qlsa_stark_stwo not installed — run: cd stark_stwo && maturin develop --features python",
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _prove(leaves: list[int]) -> dict:
    proof, commitment, log_size = _ext.prove(leaves)
    return {"proof": proof, "commitment": commitment, "log_size": log_size}


def _verify(proof: bytes, commitment: str, log_size: int) -> bool:
    return _ext.verify(proof, commitment, log_size)


def _prove_p2(leaves: list[int]) -> dict:
    proof, commitment, log_size = _ext.prove_p2(leaves)
    return {"proof": proof, "commitment": commitment, "log_size": log_size}


def _verify_p2(proof: bytes, commitment: str, log_size: int) -> bool:
    return _ext.verify_p2(proof, commitment, log_size)


def _prove_merkle(leaves: list[int]) -> dict:
    proof, commitment, log_size = _ext.prove_merkle(leaves)
    return {"proof": proof, "commitment": commitment, "log_size": log_size}


def _verify_merkle(proof: bytes, commitment: str, log_size: int) -> bool:
    return _ext.verify_merkle(proof, commitment, log_size)


# ─── Hash-chain prove / verify ────────────────────────────────────────────────

@needs_ext
def test_prove_output_schema():
    out = _prove([1, 2, 3, 4])
    assert isinstance(out["proof"], bytes)
    assert len(out["proof"]) > 0
    assert len(out["commitment"]) == 32
    int(out["commitment"], 16)  # must be valid hex
    assert out["log_size"] >= 3


@needs_ext
def test_prove_verify_roundtrip_small():
    out = _prove([1, 2, 3, 4, 5, 6, 7, 8])
    assert _verify(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_prove_verify_roundtrip_single_leaf():
    out = _prove([42])
    assert _verify(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_prove_verify_roundtrip_large_values():
    out = _prove([2**63 - 1, 2**32, 0, 1])
    assert _verify(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_commitment_is_128bit_hex():
    out = _prove([10, 20, 30])
    assert len(out["commitment"]) == 32
    int(out["commitment"], 16)


@needs_ext
def test_tampered_proof_fails_verify():
    out = _prove([1, 2, 3, 4])
    raw = bytearray(out["proof"])
    raw[8] ^= 0xFF
    assert not _verify(bytes(raw), out["commitment"], out["log_size"])


@needs_ext
def test_wrong_log_size_fails_verify():
    out = _prove([1, 2, 3, 4])
    # Out-of-range log_size — verify returns False (errors are silenced to False).
    assert not _verify(out["proof"], out["commitment"], out["log_size"] + 1)


@needs_ext
def test_log_size_grows_with_more_leaves():
    out_small = _prove([1, 2, 3, 4])
    out_large = _prove(list(range(1, 33)))
    assert out_large["log_size"] >= out_small["log_size"]


@needs_ext
def test_different_leaves_give_different_commitments():
    out_a = _prove([1, 2, 3, 4])
    out_b = _prove([5, 6, 7, 8])
    assert out_a["commitment"] != out_b["commitment"]


# ─── prove_p2 / verify_p2 (Poseidon2 sponge hash chain) ─────────────────────

@needs_ext
def test_prove_p2_output_schema():
    out = _prove_p2([1, 2, 3, 4])
    assert isinstance(out["proof"], bytes)
    assert len(out["proof"]) > 0
    assert len(out["commitment"]) == 32


@needs_ext
def test_prove_p2_verify_p2_roundtrip():
    out = _prove_p2([1, 2, 3, 4, 5, 6, 7, 8])
    assert _verify_p2(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_prove_p2_tampered_proof_fails():
    out = _prove_p2([1, 2, 3, 4])
    raw = bytearray(out["proof"])
    raw[20] ^= 0xFF
    assert not _verify_p2(bytes(raw), out["commitment"], out["log_size"])


@needs_ext
def test_prove_p2_different_leaves_different_commitments():
    out_a = _prove_p2([1, 2, 3, 4])
    out_b = _prove_p2([5, 6, 7, 8])
    assert out_a["commitment"] != out_b["commitment"]


# ─── prove_merkle / verify_merkle (Poseidon2 Merkle tree) ────────────────────

@needs_ext
def test_merkle_prove_output_schema():
    out = _prove_merkle([1, 2, 3, 4])
    assert isinstance(out["proof"], bytes)
    assert len(out["proof"]) > 0
    assert len(out["commitment"]) == 32
    int(out["commitment"], 16)


@needs_ext
def test_merkle_prove_verify_roundtrip_two_leaves():
    out = _prove_merkle([10, 20])
    assert _verify_merkle(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_merkle_prove_verify_roundtrip_four_leaves():
    out = _prove_merkle([1, 2, 3, 4])
    assert _verify_merkle(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_merkle_prove_verify_roundtrip_eight_leaves():
    out = _prove_merkle([1, 2, 3, 4, 5, 6, 7, 8])
    assert _verify_merkle(out["proof"], out["commitment"], out["log_size"])


@needs_ext
def test_merkle_tampered_proof_fails():
    out = _prove_merkle([1, 2, 3, 4])
    raw = bytearray(out["proof"])
    raw[20] ^= 0xFF
    assert not _verify_merkle(bytes(raw), out["commitment"], out["log_size"])


@needs_ext
def test_merkle_different_leaves_different_commitments():
    out_a = _prove_merkle([1, 2, 3, 4])
    out_b = _prove_merkle([1, 2, 3, 5])
    assert out_a["commitment"] != out_b["commitment"]


@needs_ext
def test_merkle_log_size_grows_with_leaves():
    out_small = _prove_merkle([1, 2])
    out_large = _prove_merkle([1, 2, 3, 4, 5, 6, 7, 8])
    assert out_large["log_size"] >= out_small["log_size"]


# ─── Negative security tests ──────────────────────────────────────────────────

@needs_ext
def test_merkle_empty_leaves_rejected():
    with pytest.raises(Exception):
        _ext.prove_merkle([])


@needs_ext
def test_merkle_out_of_bounds_log_size_rejected():
    out = _prove_merkle([1, 2, 3, 4])
    # Absurdly large log_size — verify returns False (silenced error).
    assert not _verify_merkle(out["proof"], out["commitment"], 100)


@needs_ext
def test_merkle_zero_log_size_rejected():
    out = _prove_merkle([1, 2])
    assert not _verify_merkle(out["proof"], out["commitment"], 0)


@needs_ext
def test_merkle_wrong_log_size_fails():
    out = _prove_merkle([1, 2, 3, 4])
    assert not _verify_merkle(out["proof"], out["commitment"], out["log_size"] + 1)


# ─── ML-DSA full arithmetic witness pipeline ──────────────────────────────────

Q = 8_380_417
N = 256
K = 2   # Use small k=2 l=1 for speed; proves same AIR as full k=6 l=5
L = 1


def _rand_poly(seed: int) -> list[int]:
    state = seed
    out = []
    for _ in range(N):
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFF_FFFF_FFFF_FFFF
        out.append((state >> 33) % Q)
    return out


def _zero_hints(k: int) -> list[list[bool]]:
    return [[False] * N for _ in range(k)]


@needs_ext
def test_mldsa_witness_prove_verify_roundtrip():
    """Full pipeline: Az → c·t₁ → sub → norm_check → UseHint proves and verifies."""
    from stark.prover import prove_mldsa_witness_stark, verify_mldsa_witness_stark

    a_hat = [_rand_poly(i) for i in range(K * L)]
    z     = [_rand_poly(100 + j) for j in range(L)]
    c     = _rand_poly(200)
    t1    = [_rand_poly(300 + i) for i in range(K)]
    hints = _zero_hints(K)

    result = prove_mldsa_witness_stark(a_hat, z, c, t1, hints, K, L)

    assert isinstance(result.proof_bundle, bytes)
    assert len(result.proof_bundle) > 0
    assert len(result.max_norms) == L
    assert len(result.w1_prime) == K
    for row in result.w1_prime:
        assert len(row) == N
    # max_norm is absolute centred value min(z, Q-z); for random z it may exceed
    # the ML-DSA norm bound — that is a caller-level check, not a STARK invariant.
    for mn in result.max_norms:
        assert 0 <= mn <= (Q - 1) // 2, f"max_norm {mn} out of centred range"

    assert verify_mldsa_witness_stark(result), "Witness proof did not verify"


@needs_ext
def test_mldsa_witness_tampered_bundle_fails():
    """Flipping a byte in the proof bundle must cause verification to fail."""
    from stark.prover import prove_mldsa_witness_stark, verify_mldsa_witness_stark, MldsaWitnessResult

    a_hat = [_rand_poly(i) for i in range(K * L)]
    z     = [_rand_poly(100 + j) for j in range(L)]
    c     = _rand_poly(200)
    t1    = [_rand_poly(300 + i) for i in range(K)]
    hints = _zero_hints(K)

    result = prove_mldsa_witness_stark(a_hat, z, c, t1, hints, K, L)

    tampered = bytearray(result.proof_bundle)
    tampered[len(tampered) // 2] ^= 0xFF
    bad = MldsaWitnessResult(
        proof_bundle=bytes(tampered),
        max_norms=result.max_norms,
        w1_prime=result.w1_prime,
    )
    assert not verify_mldsa_witness_stark(bad), "Tampered bundle should not verify"


@needs_ext
def test_mldsa_witness_wrong_input_size_raises():
    """a_hat with wrong poly size must raise ValueError."""
    with pytest.raises(Exception):
        _ext.prove_mldsa_witness_py(
            [[1, 2, 3]],  # wrong size — not 256
            [[0] * N], [0] * N, [[0] * N], [[False] * N], 1, 1,
        )


# ─── prove_mldsa_sig_witness — end-to-end with real oqs signature ─────────────

try:
    import oqs as _oqs
    _HAVE_OQS = True
except ImportError:
    _HAVE_OQS = False

needs_oqs = pytest.mark.skipif(
    not (_HAVE_EXT and _HAVE_OQS),
    reason="requires qlsa_stark_stwo + oqs",
)


@needs_oqs
def test_prove_mldsa_sig_witness_roundtrip():
    """Prove a real liboqs ML-DSA-65 signature through the full STARK pipeline."""
    from stark.prover import prove_mldsa_sig_witness_stark, verify_mldsa_witness_stark, NORM_BOUND

    alg = _oqs.Signature("ML-DSA-65")
    pk = alg.generate_keypair()
    msg = b"qlsa test message for witness proof"
    sig = alg.sign(msg)

    result = prove_mldsa_sig_witness_stark(pk, msg, sig)

    assert isinstance(result.proof_bundle, bytes)
    assert len(result.proof_bundle) > 0
    # L = 5 norm values (||z[j]||_∞); must be within ML-DSA bound.
    assert len(result.max_norms) == 5
    for mn in result.max_norms:
        assert 0 <= mn < NORM_BOUND, f"||z||_inf = {mn} >= NORM_BOUND {NORM_BOUND}"
    # K = 6 rows of UseHint output.
    assert len(result.w1_prime) == 6
    for row in result.w1_prime:
        assert len(row) == 256
        assert all(0 <= v < 16 for v in row), "w1 values must be in [0, m=16)"

    assert verify_mldsa_witness_stark(result), "Witness proof did not verify"


@needs_oqs
def test_prove_mldsa_sig_witness_rejects_invalid_sig():
    """Invalid signature must raise RuntimeError before attempting any proof."""
    from stark.prover import prove_mldsa_sig_witness_stark

    alg = _oqs.Signature("ML-DSA-65")
    pk = alg.generate_keypair()
    msg = b"original message"
    sig = alg.sign(msg)

    # Flip a byte to invalidate the signature.
    bad_sig = bytearray(sig)
    bad_sig[10] ^= 0xFF

    with pytest.raises(RuntimeError, match="failed"):
        prove_mldsa_sig_witness_stark(pk, msg, bytes(bad_sig))
