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

    # onchain_commitment is 32 hex chars (16 bytes).
    assert len(result.onchain_commitment) == 32
    int(result.onchain_commitment, 16)  # must be valid hex
    # c_tilde_hex is 96 hex chars (48 bytes = LAMBDA_BYTES for ML-DSA-65).
    assert len(result.c_tilde_hex) == 96
    int(result.c_tilde_hex, 16)

    # Two independent proofs of the same sig must produce the same c_tilde_hex.
    result2 = prove_mldsa_sig_witness_stark(pk, msg, sig)
    assert result2.c_tilde_hex == result.c_tilde_hex, "c_tilde must be deterministic"
    # But proof bundles may differ (randomised FRI) so onchain_commitments may too.


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


@needs_oqs
def test_mldsa_hash_check_passes_for_valid_sig():
    """verify_mldsa_hash_check must return True for a genuine witness result."""
    from stark.prover import prove_mldsa_sig_witness_stark, verify_mldsa_hash_check

    alg = _oqs.Signature("ML-DSA-65")
    pk = alg.generate_keypair()
    msg = b"hash check test"
    sig = alg.sign(msg)

    result = prove_mldsa_sig_witness_stark(pk, msg, sig)
    assert verify_mldsa_hash_check(pk, msg, result), \
        "Hash check must pass for a valid signature's witness result"


# ─── Az-row STARK (MVP-3+) ────────────────────────────────────────────────────

@needs_ext
def test_prove_az_row_output_schema():
    """prove_az_row_py returns (bytes, str, list[int]) with correct shapes."""
    a_row = [_rand_poly(j) for j in range(5)]
    z_hat = [_rand_poly(j + 10) for j in range(5)]

    proof, commitment, az_hat = _ext.prove_az_row_py(a_row, z_hat)

    assert isinstance(proof, bytes) and len(proof) > 0
    assert isinstance(commitment, str) and len(commitment) == 32  # 16-byte hex
    assert len(az_hat) == N
    assert all(0 <= c < Q for c in az_hat)


@needs_ext
def test_prove_az_row_verify_roundtrip():
    """prove → verify must succeed for honest witness."""
    a_row = [_rand_poly(j + 20) for j in range(5)]
    z_hat = [_rand_poly(j + 30) for j in range(5)]

    proof, commitment, _ = _ext.prove_az_row_py(a_row, z_hat)
    assert _ext.verify_az_row_py(proof, commitment, z_hat)


@needs_ext
def test_prove_az_row_correctness():
    """Output must equal the reference inner-product Σ_j a[j][p] * z[j][p] mod Q."""
    a_row = [_rand_poly(j + 40) for j in range(5)]
    z_hat = [_rand_poly(j + 50) for j in range(5)]

    _, _, az_hat = _ext.prove_az_row_py(a_row, z_hat)

    for p in range(N):
        expected = sum(a_row[j][p] * z_hat[j][p] for j in range(5)) % Q
        assert az_hat[p] == expected, f"mismatch at coefficient {p}"


@needs_ext
def test_prove_az_row_zero_z():
    """Inner product with z = 0 must produce the zero polynomial."""
    a_row = [_rand_poly(j + 60) for j in range(5)]
    z_zero = [[0] * N for _ in range(5)]

    _, _, az_hat = _ext.prove_az_row_py(a_row, z_zero)
    assert az_hat == [0] * N


@needs_ext
def test_prove_az_row_tampered_proof_fails():
    """Flipping a byte in the proof must cause verification to fail."""
    a_row = [_rand_poly(j + 70) for j in range(5)]
    z_hat = [_rand_poly(j + 80) for j in range(5)]

    proof, commitment, _ = _ext.prove_az_row_py(a_row, z_hat)
    tampered = bytearray(proof)
    tampered[len(tampered) // 2] ^= 0xFF
    assert not _ext.verify_az_row_py(bytes(tampered), commitment, z_hat)


@needs_ext
def test_prove_az_row_wrong_z_hat_fails():
    """Verifying with a different z_hat must fail (input fingerprint binding)."""
    a_row = [_rand_poly(j + 73) for j in range(5)]
    z_hat = [_rand_poly(j + 83) for j in range(5)]
    z_hat_other = [_rand_poly(j + 200) for j in range(5)]  # different values

    proof, commitment, _ = _ext.prove_az_row_py(a_row, z_hat)
    # Correct z_hat must pass.
    assert _ext.verify_az_row_py(proof, commitment, z_hat)
    # Wrong z_hat must fail (input fingerprint mismatch changes channel state).
    assert not _ext.verify_az_row_py(proof, commitment, z_hat_other)


@needs_ext
def test_prove_az_row_full_matrix():
    """Prove all K=6 output rows and verify each independently."""
    z_hat = [_rand_poly(j + 90) for j in range(5)]
    for i in range(6):
        a_row = [_rand_poly(i * 5 + j + 100) for j in range(5)]
        proof, commitment, az_hat = _ext.prove_az_row_py(a_row, z_hat)
        assert _ext.verify_az_row_py(proof, commitment, z_hat), f"row {i} failed verification"
        assert len(az_hat) == N


# ─── ML-DSA witness v2 pipeline (Az-row AIR — 53 sub-proofs vs 101) ──────────
# prove_verify_mldsa_v2 requires l = 5 (ML-DSA-65). Use k=1, l=5 for speed.

_K2 = 1   # rows for v2 tests
_L2 = 5   # cols for v2 tests (must equal ML-DSA-65 L)


@needs_ext
def test_prove_mldsa_witness_v2_output_schema():
    """prove_mldsa_witness_v2_py returns (bytes, list[int], list[list[int]])."""
    a_hat = [_rand_poly(i) for i in range(_K2 * _L2)]
    z     = [_rand_poly(100 + j) for j in range(_L2)]
    c     = _rand_poly(200)
    t1    = [_rand_poly(300 + i) for i in range(_K2)]
    hints = _zero_hints(_K2)

    bundle, max_norms, w1_prime = _ext.prove_mldsa_witness_v2_py(
        a_hat, z, c, t1, hints, _K2, _L2
    )

    assert isinstance(bundle, bytes) and len(bundle) > 0
    assert len(max_norms) == _L2
    assert len(w1_prime) == _K2
    for row in w1_prime:
        assert len(row) == N


@needs_ext
def test_prove_mldsa_witness_v2_verify_roundtrip():
    """prove_mldsa_witness_v2_py → verify_mldsa_witness_v2_py must succeed."""
    a_hat = [_rand_poly(i + 10) for i in range(_K2 * _L2)]
    z     = [_rand_poly(110 + j) for j in range(_L2)]
    c     = _rand_poly(210)
    t1    = [_rand_poly(310 + i) for i in range(_K2)]
    hints = _zero_hints(_K2)

    bundle, _, _ = _ext.prove_mldsa_witness_v2_py(a_hat, z, c, t1, hints, _K2, _L2)
    assert _ext.verify_mldsa_witness_v2_py(bundle)


@needs_ext
def test_prove_mldsa_witness_v2_tampered_bundle_fails():
    """Flipping a byte in the v2 bundle must cause verification to fail."""
    a_hat = [_rand_poly(i + 20) for i in range(_K2 * _L2)]
    z     = [_rand_poly(120 + j) for j in range(_L2)]
    c     = _rand_poly(220)
    t1    = [_rand_poly(320 + i) for i in range(_K2)]
    hints = _zero_hints(_K2)

    bundle, _, _ = _ext.prove_mldsa_witness_v2_py(a_hat, z, c, t1, hints, _K2, _L2)
    tampered = bytearray(bundle)
    tampered[len(tampered) // 2] ^= 0xFF
    assert not _ext.verify_mldsa_witness_v2_py(bytes(tampered))


@needs_ext
def test_prove_mldsa_witness_v2_matches_v1_w1_prime():
    """v2 and v1 pipelines must produce the same w1_prime for the same inputs."""
    a_hat = [_rand_poly(i + 30) for i in range(_K2 * _L2)]
    z     = [_rand_poly(130 + j) for j in range(_L2)]
    c     = _rand_poly(230)
    t1    = [_rand_poly(330 + i) for i in range(_K2)]
    hints = _zero_hints(_K2)

    _, _, w1_v1 = _ext.prove_mldsa_witness_py(a_hat, z, c, t1, hints, _K2, _L2)
    _, _, w1_v2 = _ext.prove_mldsa_witness_v2_py(a_hat, z, c, t1, hints, _K2, _L2)

    assert w1_v1 == w1_v2, "v1 and v2 pipelines must agree on w1_prime"


@needs_oqs
def test_mldsa_hash_check_fails_wrong_message():
    """Hash check must fail when msg is substituted for a different message."""
    from stark.prover import prove_mldsa_sig_witness_stark, verify_mldsa_hash_check

    alg = _oqs.Signature("ML-DSA-65")
    pk = alg.generate_keypair()
    msg = b"original"
    sig = alg.sign(msg)

    result = prove_mldsa_sig_witness_stark(pk, msg, sig)
    assert not verify_mldsa_hash_check(pk, b"different message", result), \
        "Hash check must fail when message is wrong"


# ─── Hint weight check STARK (MVP-3+) ────────────────────────────────────────

OMEGA = 55  # ML-DSA-65 hint weight bound


def _zero_hints_full() -> list:
    """All-zero hints for K=6, N=256."""
    return [[False] * N for _ in range(6)]


def _hints_with_count(count: int) -> list:
    """First `count` hint bits set to True, rest False."""
    h = [[False] * N for _ in range(6)]
    placed = 0
    for i in range(6):
        for j in range(N):
            if placed >= count:
                break
            h[i][j] = True
            placed += 1
        if placed >= count:
            break
    return h


@needs_ext
def test_prove_hint_weight_output_schema():
    """prove_hint_weight_py returns (bytes, str, int) with correct shapes."""
    hints = _zero_hints_full()
    proof, commitment, total = _ext.prove_hint_weight_py(hints)

    assert isinstance(proof, bytes) and len(proof) > 0
    assert isinstance(commitment, str) and len(commitment) == 32  # 16-byte hex
    assert total == 0


@needs_ext
def test_prove_hint_weight_zero_hints():
    """Zero hints → weight 0 → verify passes."""
    hints = _zero_hints_full()
    proof, commitment, total = _ext.prove_hint_weight_py(hints)
    assert total == 0
    assert _ext.verify_hint_weight_py(proof, commitment)


@needs_ext
def test_prove_hint_weight_counts_correctly():
    """Total weight matches the number of True bits in the hint vector."""
    for count in [1, 10, 55]:
        hints = _hints_with_count(count)
        proof, commitment, total = _ext.prove_hint_weight_py(hints)
        assert total == count, f"expected {count}, got {total}"
        assert _ext.verify_hint_weight_py(proof, commitment)


@needs_ext
def test_prove_hint_weight_verify_roundtrip():
    """Honest prove → verify must succeed."""
    hints = _hints_with_count(30)
    proof, commitment, total = _ext.prove_hint_weight_py(hints)
    assert total == 30
    assert _ext.verify_hint_weight_py(proof, commitment)


@needs_ext
def test_prove_hint_weight_tampered_proof_fails():
    """Flipping a byte in the proof must cause verification to fail."""
    hints = _hints_with_count(20)
    proof, commitment, _ = _ext.prove_hint_weight_py(hints)
    tampered = bytearray(proof)
    tampered[len(tampered) // 2] ^= 0xFF
    assert not _ext.verify_hint_weight_py(bytes(tampered), commitment)


@needs_ext
def test_prove_hint_weight_wrong_commitment_fails():
    """Wrong commitment hex must cause verification to fail."""
    hints = _hints_with_count(5)
    proof, commitment, _ = _ext.prove_hint_weight_py(hints)
    # Flip a hex digit.
    wrong = commitment[:30] + ("0" if commitment[30] != "0" else "1") + commitment[31:]
    assert not _ext.verify_hint_weight_py(proof, wrong)


@needs_ext
def test_prove_hint_weight_bounds_check():
    """The returned total_weight can be compared against OMEGA externally."""
    for count in [0, 55, 200]:
        hints = _hints_with_count(count)
        _, _, total = _ext.prove_hint_weight_py(hints)
        assert total == count
        within_bound = total <= OMEGA
        # This is the off-circuit check the verifier would perform.
        assert within_bound == (count <= OMEGA)
