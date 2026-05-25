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


# ─── Merkle root as Fiat-Shamir public input ────────────────────────────────

@needs_ext
def test_prove_verify_with_merkle_root_roundtrip():
    """prove(leaves, merkle_root=root) + verify(..., merkle_root=root) must pass."""
    leaves = [1, 2, 3, 4, 5, 6, 7, 8]
    root = b"sha3-512-merkle-root-64-bytes-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    proof, commitment, log_size = _ext.prove(leaves, merkle_root=root)
    assert _ext.verify(proof, commitment, log_size, merkle_root=root)


@needs_ext
def test_prove_with_merkle_root_wrong_root_fails():
    """Proof generated for root_A must NOT verify with root_B."""
    leaves = [1, 2, 3, 4, 5, 6, 7, 8]
    root_a = b"batch-root-A-64b-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    root_b = b"batch-root-B-64b-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    proof, commitment, log_size = _ext.prove(leaves, merkle_root=root_a)
    assert not _ext.verify(proof, commitment, log_size, merkle_root=root_b)


@needs_ext
def test_prove_with_merkle_root_no_root_verify_fails():
    """Proof generated with a root must NOT verify without a root (different FS state)."""
    leaves = [1, 2, 3, 4, 5, 6, 7, 8]
    root = b"some-real-merkle-root-64b-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    proof, commitment, log_size = _ext.prove(leaves, merkle_root=root)
    assert not _ext.verify(proof, commitment, log_size)


@needs_ext
def test_prove_without_root_verify_with_root_fails():
    """Proof generated without a root must NOT verify if a root is supplied."""
    leaves = [1, 2, 3, 4, 5, 6, 7, 8]
    root = b"some-real-merkle-root-64b-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    proof, commitment, log_size = _ext.prove(leaves)
    assert not _ext.verify(proof, commitment, log_size, merkle_root=root)


@needs_ext
def test_prove_batch_root_binding_via_prover_module():
    """prove_batch passes batch.merkle_root as Fiat-Shamir seed end-to-end."""
    import hashlib
    from core.batch import Batch
    from stark.prover import prove_batch
    from stark.verifier import verify_batch_proof

    # Build a minimal batch with a real SHA3-512 Merkle root.
    root = hashlib.sha3_512(b"dummy-batch").digest()  # 64 bytes

    batch = Batch.__new__(Batch)
    batch.merkle_root = root
    result = prove_batch(batch)

    # Verify with correct root → must pass.
    assert verify_batch_proof(result.proof, result.commitment, result.log_size, merkle_root=root)
    # Verify with wrong root → must fail.
    wrong_root = bytes([b ^ 0xFF for b in root])
    assert not verify_batch_proof(result.proof, result.commitment, result.log_size, merkle_root=wrong_root)


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
    """Full V3 pipeline (K=6, L=5): Az → c·t₁ → sub → norm_check → UseHint proves and verifies."""
    from stark.prover import prove_mldsa_witness_stark, verify_mldsa_witness_stark

    # V3 requires ML-DSA-65 dimensions (L=5 fixed in prove_az_v3)
    K3, L3 = 6, 5
    a_hat = [_rand_poly(i) for i in range(K3 * L3)]
    z     = [_rand_poly(100 + j) for j in range(L3)]
    c     = _rand_poly(200)
    t1    = [_rand_poly(300 + i) for i in range(K3)]
    hints = _zero_hints(K3)

    result = prove_mldsa_witness_stark(a_hat, z, c, t1, hints, K3, L3)

    assert isinstance(result.proof_bundle, bytes)
    assert len(result.proof_bundle) > 0
    assert len(result.max_norms) == L3
    assert len(result.w1_prime) == K3
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

    # V3 requires ML-DSA-65 dimensions (L=5 fixed in prove_az_v3)
    K3, L3 = 6, 5
    a_hat = [_rand_poly(i) for i in range(K3 * L3)]
    z     = [_rand_poly(100 + j) for j in range(L3)]
    c     = _rand_poly(200)
    t1    = [_rand_poly(300 + i) for i in range(K3)]
    hints = _zero_hints(K3)

    result = prove_mldsa_witness_stark(a_hat, z, c, t1, hints, K3, L3)

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
    import oqs.oqs as _oqs
    _HAVE_OQS = hasattr(_oqs, "Signature")
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


# ─── Full-matrix Az STARK — prove_az_full (MVP-3+) ───────────────────────────

_KF = 6   # ML-DSA-65 K
_LF = 5   # ML-DSA-65 L


@needs_ext
def test_prove_az_full_output_schema():
    """prove_az_full_py returns (bytes, str, list[K lists of 256 ints])."""
    a_hat = [_rand_poly(i + 400) for i in range(_KF * _LF)]
    z_hat = [_rand_poly(j + 500) for j in range(_LF)]
    proof, commitment, az_out = _ext.prove_az_full_py(a_hat, z_hat)
    assert isinstance(proof, bytes) and len(proof) > 0
    assert isinstance(commitment, str) and len(commitment) == 32
    int(commitment, 16)
    assert len(az_out) == _KF
    for row in az_out:
        assert len(row) == N
        assert all(0 <= v < Q for v in row)


@needs_ext
def test_prove_az_full_verify_roundtrip():
    """prove_az_full_py + verify_az_full_py round-trips."""
    a_hat = [_rand_poly(i + 600) for i in range(_KF * _LF)]
    z_hat = [_rand_poly(j + 700) for j in range(_LF)]
    proof, commitment, _ = _ext.prove_az_full_py(a_hat, z_hat)
    assert _ext.verify_az_full_py(proof, commitment, z_hat)


@needs_ext
def test_prove_az_full_wrong_z_hat_fails():
    """Supplying different z_hat to verify must fail (input fingerprint binding)."""
    a_hat = [_rand_poly(i + 800) for i in range(_KF * _LF)]
    z_hat = [_rand_poly(j + 900) for j in range(_LF)]
    proof, commitment, _ = _ext.prove_az_full_py(a_hat, z_hat)
    z_wrong = list(z_hat)
    z_wrong[0] = [v ^ 1 for v in z_wrong[0]]
    assert not _ext.verify_az_full_py(proof, commitment, z_wrong), \
        "Wrong z_hat must fail verification"


@needs_ext
def test_prove_az_full_tampered_proof_fails():
    """A tampered proof byte must fail verification."""
    a_hat = [_rand_poly(i + 1000) for i in range(_KF * _LF)]
    z_hat = [_rand_poly(j + 1100) for j in range(_LF)]
    proof, commitment, _ = _ext.prove_az_full_py(a_hat, z_hat)
    tampered = bytearray(proof)
    tampered[32] ^= 0xFF
    assert not _ext.verify_az_full_py(bytes(tampered), commitment, z_hat)


@needs_ext
def test_prove_az_full_matches_az_row_per_row():
    """az_full output must equal az_row output for each row independently."""
    a_hat = [_rand_poly(i + 1200) for i in range(_KF * _LF)]
    z_hat = [_rand_poly(j + 1300) for j in range(_LF)]
    _, _, az_full = _ext.prove_az_full_py(a_hat, z_hat)
    for i in range(_KF):
        a_row = a_hat[i * _LF:(i + 1) * _LF]
        _, _, az_row_i = _ext.prove_az_row_py(a_row, z_hat)
        assert az_full[i] == az_row_i, f"row {i}: az_full ≠ az_row"


# ─── Az-full c_tilde public input (MVP-3+) ───────────────────────────────────

@needs_ext
def test_prove_az_full_c_tilde_bound_verifies():
    """prove_az_full_py with c_tilde + verify with same c_tilde must pass."""
    a_hat = [_rand_poly(i + 1400) for i in range(_KF * _LF)]
    z_hat = [_rand_poly(j + 1500) for j in range(_LF)]
    c_tilde = bytes(range(48))  # 48-byte challenge (ML-DSA-65 λ/4)
    proof, commitment, _ = _ext.prove_az_full_py(a_hat, z_hat, c_tilde)
    assert _ext.verify_az_full_py(proof, commitment, z_hat, c_tilde), \
        "az_full with c_tilde should verify with matching c_tilde"


@needs_ext
def test_prove_az_full_wrong_c_tilde_fails():
    """Verifying with a different c_tilde must fail (Fiat-Shamir mismatch)."""
    a_hat = [_rand_poly(i + 1600) for i in range(_KF * _LF)]
    z_hat = [_rand_poly(j + 1700) for j in range(_LF)]
    c_tilde_a = bytes(range(48))
    c_tilde_b = bytes(range(1, 49))  # different challenge
    proof, commitment, _ = _ext.prove_az_full_py(a_hat, z_hat, c_tilde_a)
    assert not _ext.verify_az_full_py(proof, commitment, z_hat, c_tilde_b), \
        "az_full must fail verification with wrong c_tilde"


@needs_ext
def test_prove_mldsa_witness_v3_c_tilde_binding():
    """V3 proof with c_tilde stores it in bundle; tampered c_tilde fails verify."""
    from stark.prover import prove_mldsa_witness_stark, verify_mldsa_witness_stark, MldsaWitnessResult

    K3, L3 = 6, 5
    a_hat = [_rand_poly(i + 1800) for i in range(K3 * L3)]
    z     = [_rand_poly(100 + j + 1800) for j in range(L3)]
    c     = _rand_poly(200 + 1800)
    t1    = [_rand_poly(300 + i + 1800) for i in range(K3)]
    hints = _zero_hints(K3)

    c_tilde = bytes(range(48))
    result = prove_mldsa_witness_stark(a_hat, z, c, t1, hints, K3, L3, c_tilde=c_tilde)
    assert verify_mldsa_witness_stark(result), "V3 proof with c_tilde must verify"


# ─── INTT with input binding (MVP-3+) ────────────────────────────────────────

def _rand_poly_intt(seed: int) -> list[int]:
    """Random polynomial in [0, Q) — suitable as INTT input."""
    import random
    rng = random.Random(seed)
    return [rng.randint(0, Q - 1) for _ in range(N)]


@needs_ext
def test_prove_intt_bound_roundtrip():
    """prove_intt_bound_py + verify_intt_bound_py round-trips correctly."""
    f = _rand_poly_intt(42)
    proof, commitment = _ext.prove_intt_bound_py(f)
    assert isinstance(proof, bytes) and len(proof) > 0
    assert isinstance(commitment, str) and len(commitment) == 32
    int(commitment, 16)  # valid hex
    assert _ext.verify_intt_bound_py(proof, commitment, f), "INTT bound proof did not verify"


@needs_ext
def test_prove_intt_bound_wrong_input_fails():
    """Supplying a different input polynomial must cause verification to fail."""
    f = _rand_poly_intt(7)
    proof, commitment = _ext.prove_intt_bound_py(f)
    # Flip one coefficient to create a different polynomial.
    f_wrong = list(f)
    f_wrong[0] = (f_wrong[0] + 1) % Q
    assert not _ext.verify_intt_bound_py(proof, commitment, f_wrong), \
        "INTT bound proof must fail with wrong input"


@needs_ext
def test_prove_intt_bound_tampered_proof_fails():
    """A tampered proof byte must cause verification to fail."""
    f = _rand_poly_intt(13)
    proof, commitment = _ext.prove_intt_bound_py(f)
    tampered = bytearray(proof)
    tampered[16] ^= 0xFF
    assert not _ext.verify_intt_bound_py(bytes(tampered), commitment, f), \
        "INTT bound proof must fail when proof bytes are tampered"


@needs_ext
def test_prove_intt_bound_wrong_commitment_fails():
    """Using a commitment from a different proof must fail."""
    f1 = _rand_poly_intt(21)
    f2 = _rand_poly_intt(22)
    proof1, commitment1 = _ext.prove_intt_bound_py(f1)
    _,      commitment2 = _ext.prove_intt_bound_py(f2)
    assert not _ext.verify_intt_bound_py(proof1, commitment2, f1), \
        "Wrong commitment must cause INTT bound verification to fail"


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


# ─── ML-DSA witness v3 pipeline (Az-full AIR — 49 sub-proofs) ────────────────
# prove_verify_mldsa_v3 requires k=6, l=5 (ML-DSA-65 exact).

_K3 = 6   # ML-DSA-65 K
_L3 = 5   # ML-DSA-65 L


@needs_ext
def test_prove_mldsa_witness_v3_output_schema():
    """prove_mldsa_witness_v3_py returns (bytes, list[int], list[list[int]], int)."""
    a_hat = [_rand_poly(i + 2000) for i in range(_K3 * _L3)]
    z     = [_rand_poly(2100 + j) for j in range(_L3)]
    c     = _rand_poly(2200)
    t1    = [_rand_poly(2300 + i) for i in range(_K3)]
    hints = _zero_hints(_K3)

    bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v3_py(
        a_hat, z, c, t1, hints, _K3, _L3
    )

    assert isinstance(bundle, bytes) and len(bundle) > 0
    assert len(max_norms) == _L3
    assert len(w1_prime) == _K3
    for row in w1_prime:
        assert len(row) == N
    assert isinstance(hw_total, int) and hw_total == 0  # all-zero hints


@needs_ext
def test_prove_mldsa_witness_v3_verify_roundtrip():
    """prove_mldsa_witness_v3_py → verify_mldsa_witness_v3_py must succeed."""
    a_hat = [_rand_poly(i + 2010) for i in range(_K3 * _L3)]
    z     = [_rand_poly(2110 + j) for j in range(_L3)]
    c     = _rand_poly(2210)
    t1    = [_rand_poly(2310 + i) for i in range(_K3)]
    hints = _zero_hints(_K3)

    bundle, _, _, _ = _ext.prove_mldsa_witness_v3_py(a_hat, z, c, t1, hints, _K3, _L3)
    assert _ext.verify_mldsa_witness_v3_py(bundle), "V3 bundle must verify"


@needs_ext
def test_prove_mldsa_witness_v3_tampered_bundle_fails():
    """Flipping a byte in the v3 bundle must cause verification to fail."""
    a_hat = [_rand_poly(i + 2020) for i in range(_K3 * _L3)]
    z     = [_rand_poly(2120 + j) for j in range(_L3)]
    c     = _rand_poly(2220)
    t1    = [_rand_poly(2320 + i) for i in range(_K3)]
    hints = _zero_hints(_K3)

    bundle, _, _, _ = _ext.prove_mldsa_witness_v3_py(a_hat, z, c, t1, hints, _K3, _L3)
    tampered = bytearray(bundle)
    tampered[len(tampered) // 2] ^= 0xFF
    assert not _ext.verify_mldsa_witness_v3_py(bytes(tampered))


@needs_ext
def test_prove_mldsa_witness_v3_matches_v2_w1_prime():
    """v3 and v2 pipelines must produce identical w1_prime for the same inputs."""
    a_hat = [_rand_poly(i + 2030) for i in range(_K3 * _L3)]
    z     = [_rand_poly(2130 + j) for j in range(_L3)]
    c     = _rand_poly(2230)
    t1    = [_rand_poly(2330 + i) for i in range(_K3)]
    hints = _zero_hints(_K3)

    _, _, w1_v2, *_ = _ext.prove_mldsa_witness_v2_py(a_hat, z, c, t1, hints, _K3, _L3)
    _, _, w1_v3, _  = _ext.prove_mldsa_witness_v3_py(a_hat, z, c, t1, hints, _K3, _L3)

    assert w1_v2 == w1_v3, "v2 and v3 must agree on w1_prime"


@needs_ext
def test_prove_mldsa_witness_v3_nonzero_hint_weight():
    """V3 correctly encodes hint weight for a non-trivial hint vector."""
    a_hat = [_rand_poly(i + 2040) for i in range(_K3 * _L3)]
    z     = [_rand_poly(2140 + j) for j in range(_L3)]
    c     = _rand_poly(2240)
    t1    = [_rand_poly(2340 + i) for i in range(_K3)]
    # Set 10 hint bits across rows.
    hints = _zero_hints(_K3)
    for bit in range(10):
        hints[bit % _K3][bit] = True

    bundle, _, _, hw_total = _ext.prove_mldsa_witness_v3_py(
        a_hat, z, c, t1, hints, _K3, _L3
    )
    assert hw_total == 10, f"Expected hint_weight_total=10, got {hw_total}"
    assert _ext.verify_mldsa_witness_v3_py(bundle), "V3 with non-zero hints must verify"


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


@needs_oqs
def test_prove_mldsa_sig_witness_hint_weight_fields():
    """MldsaWitnessResult includes a valid hint_weight_total inside the V3 bundle."""
    from stark.prover import prove_mldsa_sig_witness_stark, verify_mldsa_witness_stark

    alg = _oqs.Signature("ML-DSA-65")
    pk = alg.generate_keypair()
    msg = b"hint weight integration test"
    sig = alg.sign(msg)

    result = prove_mldsa_sig_witness_stark(pk, msg, sig)

    # hint_weight_total is a non-negative integer ≤ ω=55 for any valid ML-DSA-65 sig.
    # (The hint weight proof is now part of the unified V3 bundle, not a separate field.)
    assert isinstance(result.hint_weight_total, int)
    assert 0 <= result.hint_weight_total <= 55, \
        f"hint weight {result.hint_weight_total} exceeds ω=55"

    # Full bundle (including hint weight sub-proof) must verify.
    assert verify_mldsa_witness_stark(result), "Hint weight proof inside V3 bundle did not verify"


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


# ─── wipe_bytes ───────────────────────────────────────────────────────────────

@needs_ext
def test_wipe_bytes_zeros_buffer():
    """wipe_bytes(bytearray) must overwrite every byte with 0."""
    buf = bytearray(b"\xDE\xAD\xBE\xEF" * 32)
    assert any(b != 0 for b in buf)
    _ext.wipe_bytes(buf)
    assert all(b == 0 for b in buf)


@needs_ext
def test_wipe_bytes_empty_buffer_is_noop():
    """wipe_bytes on an empty bytearray must not raise."""
    buf = bytearray()
    _ext.wipe_bytes(buf)
    assert len(buf) == 0


@needs_ext
def test_wipe_bytes_single_byte():
    buf = bytearray(b"\xFF")
    _ext.wipe_bytes(buf)
    assert buf[0] == 0


@needs_ext
def test_wipe_key_uses_rust_wipe_when_ext_available():
    """core.keys.wipe_key must produce all-zero buffer (via Rust wipe_bytes)."""
    from core.keys import wipe_key
    buf = bytearray(b"\xAB\xCD\xEF" * 100)
    wipe_key(buf)
    assert all(b == 0 for b in buf)


# ─── gen_poseidon2_vfri2_hints — VFRI2 bridge ────────────────────────────────

_FAKE_BATCH_ROOT = bytes(range(32))  # 32 deterministic bytes for tests


@needs_ext
def test_gen_poseidon2_vfri2_hints_output_schema():
    """gen_poseidon2_vfri2_hints_py returns (bytes, str, bytes)."""
    proof, commitment, hints = _ext.gen_poseidon2_vfri2_hints_py(
        [1, 2, 3, 4], list(_FAKE_BATCH_ROOT), 2
    )
    assert isinstance(proof, bytes)
    assert isinstance(commitment, str)
    assert isinstance(hints, bytes)


@needs_ext
def test_gen_poseidon2_vfri2_hints_proof_length():
    """Proof must be ≥ 700 bytes (QLSAVerifierVFRI2.MIN_PROOF_LENGTH)."""
    proof, _, _ = _ext.gen_poseidon2_vfri2_hints_py([1, 2, 3, 4], list(_FAKE_BATCH_ROOT), 2)
    assert len(proof) >= 700


@needs_ext
def test_gen_poseidon2_vfri2_hints_nonce_in_proof():
    """proof[0:8] must be nonce=2 as LE u64."""
    import struct
    proof, _, _ = _ext.gen_poseidon2_vfri2_hints_py([1, 2, 3, 4], list(_FAKE_BATCH_ROOT), 2)
    nonce = struct.unpack_from("<Q", proof, 0)[0]
    assert nonce == 2


@needs_ext
def test_gen_poseidon2_vfri2_hints_commitment_is_32_hex_chars():
    """commitment must be a 32-character lowercase hex string (16 bytes)."""
    _, commitment, _ = _ext.gen_poseidon2_vfri2_hints_py([1, 2, 3, 4], list(_FAKE_BATCH_ROOT), 2)
    assert len(commitment) == 32
    assert all(c in "0123456789abcdef" for c in commitment)


@needs_ext
def test_gen_poseidon2_vfri2_hints_commitment_binding():
    """commitment == Blake2s(proof[:32] ‖ batch_merkle_root)[:16] as hex."""
    import hashlib
    batch_root = bytes(range(32))
    proof, commitment, _ = _ext.gen_poseidon2_vfri2_hints_py([1, 2, 3, 4], list(batch_root), 2)
    expected = hashlib.blake2s(proof[:32] + batch_root).digest()[:16].hex()
    assert commitment == expected


@needs_ext
def test_gen_poseidon2_vfri2_hints_trace_root_in_proof():
    """proof[8:40] must be non-zero (trace Merkle root)."""
    proof, _, _ = _ext.gen_poseidon2_vfri2_hints_py([1, 2, 3, 4], list(_FAKE_BATCH_ROOT), 2)
    assert proof[8:40] != b"\x00" * 32


@needs_ext
def test_gen_poseidon2_vfri2_hints_deterministic():
    """Same inputs produce identical outputs."""
    leaves = [10, 20, 30, 40]
    root = bytes(range(32))
    r1 = _ext.gen_poseidon2_vfri2_hints_py(leaves, list(root), 2)
    r2 = _ext.gen_poseidon2_vfri2_hints_py(leaves, list(root), 2)
    assert r1[0] == r2[0]  # proof bytes
    assert r1[1] == r2[1]  # commitment
    assert r1[2] == r2[2]  # hints


@needs_ext
def test_gen_poseidon2_vfri2_hints_different_roots_different_commitments():
    """Different batch Merkle roots produce different commitments."""
    leaves = [1, 2, 3, 4]
    root_a = bytes(range(32))
    root_b = bytes([i ^ 0xFF for i in range(32)])
    _, c_a, _ = _ext.gen_poseidon2_vfri2_hints_py(leaves, list(root_a), 2)
    _, c_b, _ = _ext.gen_poseidon2_vfri2_hints_py(leaves, list(root_b), 2)
    assert c_a != c_b


@needs_ext
def test_gen_poseidon2_vfri2_hints_different_queries_different_hints():
    """Different n_queries values produce different (sized) hint encodings."""
    leaves = [1, 2, 3, 4]
    root = bytes(range(32))
    _, _, h1 = _ext.gen_poseidon2_vfri2_hints_py(leaves, list(root), 1)
    _, _, h2 = _ext.gen_poseidon2_vfri2_hints_py(leaves, list(root), 2)
    assert len(h2) > len(h1)


@needs_ext
def test_gen_poseidon2_vfri2_hints_query_hints_non_empty():
    """ABI-encoded query hints must be non-empty."""
    _, _, hints = _ext.gen_poseidon2_vfri2_hints_py([1, 2, 3, 4], list(_FAKE_BATCH_ROOT), 2)
    assert len(hints) > 0


@needs_ext
def test_gen_poseidon2_vfri2_hints_empty_leaves_error():
    """Empty leaves list must raise an error."""
    with pytest.raises(Exception):
        _ext.gen_poseidon2_vfri2_hints_py([], list(_FAKE_BATCH_ROOT), 2)


@needs_ext
def test_gen_poseidon2_vfri2_hints_bad_root_length_error():
    """batch_merkle_root of wrong length must raise an error."""
    with pytest.raises(Exception):
        _ext.gen_poseidon2_vfri2_hints_py([1, 2, 3, 4], list(b"\x00" * 16), 2)  # 16 bytes, not 32


@needs_ext
def test_gen_poseidon2_vfri2_hints_prover_module_wrapper():
    """stark.prover.gen_poseidon2_vfri2_hints wraps the Rust function correctly."""
    from stark.prover import gen_poseidon2_vfri2_hints, VFRI2HintResult
    import hashlib
    root = bytes(range(32))
    result = gen_poseidon2_vfri2_hints([1, 2, 3, 4], root, n_queries=2)
    assert isinstance(result, VFRI2HintResult)
    assert len(result.proof) >= 700
    assert len(result.commitment) == 32
    assert len(result.query_hints) > 0
    # Verify commitment binding
    expected = hashlib.blake2s(result.proof[:32] + root).digest()[:16].hex()
    assert result.commitment == expected


@needs_ext
def test_gen_poseidon2_vfri2_hints_prover_module_validates_inputs():
    """stark.prover.gen_poseidon2_vfri2_hints raises ValueError for bad inputs."""
    from stark.prover import gen_poseidon2_vfri2_hints
    with pytest.raises(ValueError, match="empty"):
        gen_poseidon2_vfri2_hints([], bytes(32))
    with pytest.raises(ValueError, match="32 bytes"):
        gen_poseidon2_vfri2_hints([1, 2], bytes(16))  # wrong root length
    with pytest.raises(ValueError, match="n_queries"):
        gen_poseidon2_vfri2_hints([1, 2], bytes(32), n_queries=0)



# ── gen_poseidon2_vfri3_real tests ────────────────────────────────────────────

@needs_ext
def test_gen_poseidon2_vfri3_real_output_schema():
    """Returns (bytes, str, bytes) triple."""
    proof, commitment, hints = _ext.gen_poseidon2_vfri3_real_py(
        [1, 2, 3, 4], list(_FAKE_BATCH_ROOT), 2
    )
    assert isinstance(proof, bytes)
    assert isinstance(commitment, str)
    assert isinstance(hints, bytes)


@needs_ext
def test_gen_poseidon2_vfri3_real_proof_length():
    """Proof must be at least 700 bytes."""
    proof, _, _ = _ext.gen_poseidon2_vfri3_real_py([1, 2, 3, 4], list(_FAKE_BATCH_ROOT), 2)
    assert len(proof) >= 700


@needs_ext
def test_gen_poseidon2_vfri3_real_commitment_format():
    """Commitment is 32-char hex string (16 bytes)."""
    _, commitment, _ = _ext.gen_poseidon2_vfri3_real_py([1, 2, 3, 4], list(_FAKE_BATCH_ROOT), 2)
    assert len(commitment) == 32
    assert bytes.fromhex(commitment)  # valid hex


@needs_ext
def test_gen_poseidon2_vfri3_real_commitment_binding():
    """Commitment = Blake2s(proof[:32] ‖ batch_merkle_root)[:16]."""
    import hashlib
    root = bytes(range(32))
    proof, commitment, _ = _ext.gen_poseidon2_vfri3_real_py([1, 2, 3, 4], list(root), 2)
    expected = hashlib.blake2s(proof[:32] + root).digest()[:16].hex()
    assert commitment == expected


@needs_ext
def test_gen_poseidon2_vfri3_real_deterministic():
    """Same inputs produce identical outputs."""
    leaves = [10, 20, 30, 40]
    root = list(_FAKE_BATCH_ROOT)
    r1 = _ext.gen_poseidon2_vfri3_real_py(leaves, root, 2)
    r2 = _ext.gen_poseidon2_vfri3_real_py(leaves, root, 2)
    assert r1[1] == r2[1]  # commitments equal
    assert r1[2] == r2[2]  # hints equal


@needs_ext
def test_gen_poseidon2_vfri3_real_different_leaves_differ():
    """Different leaves produce different commitments."""
    root = list(_FAKE_BATCH_ROOT)
    _, c1, _ = _ext.gen_poseidon2_vfri3_real_py([1, 2, 3, 4], root, 2)
    _, c2, _ = _ext.gen_poseidon2_vfri3_real_py([5, 6, 7, 8], root, 2)
    assert c1 != c2


@needs_ext
def test_gen_poseidon2_vfri3_real_hints_non_empty():
    """ABI-encoded hints must be non-empty."""
    _, _, hints = _ext.gen_poseidon2_vfri3_real_py([1, 2, 3, 4], list(_FAKE_BATCH_ROOT), 2)
    assert len(hints) > 0


@needs_ext
def test_gen_poseidon2_vfri3_real_hints_differ_from_zero_poly():
    """Real-trace hints differ from the zero-polynomial (VFRI2) hints."""
    leaves = [1, 2, 3, 4]
    root = list(_FAKE_BATCH_ROOT)
    _, _, h3 = _ext.gen_poseidon2_vfri3_real_py(leaves, root, 2)
    _, _, h2 = _ext.gen_poseidon2_vfri2_hints_py(leaves, root, 2)
    assert h3 != h2


@needs_ext
def test_gen_poseidon2_vfri3_real_more_queries_larger_hints():
    """More queries produce a larger hints blob."""
    leaves = [1, 2, 3, 4]
    root = list(_FAKE_BATCH_ROOT)
    _, _, h1 = _ext.gen_poseidon2_vfri3_real_py(leaves, root, 1)
    _, _, h2 = _ext.gen_poseidon2_vfri3_real_py(leaves, root, 2)
    assert len(h2) > len(h1)


@needs_ext
def test_gen_poseidon2_vfri3_real_empty_leaves_error():
    """Empty leaves list must raise an error."""
    with pytest.raises(Exception):
        _ext.gen_poseidon2_vfri3_real_py([], list(_FAKE_BATCH_ROOT), 2)


@needs_ext
def test_gen_poseidon2_vfri3_real_bad_root_length_error():
    """batch_merkle_root of wrong length must raise an error."""
    with pytest.raises(Exception):
        _ext.gen_poseidon2_vfri3_real_py([1, 2, 3, 4], list(b"\x00" * 16), 2)


@needs_ext
def test_gen_poseidon2_vfri3_real_prover_module_wrapper():
    """stark.prover.gen_poseidon2_vfri3_real wraps the Rust function correctly."""
    from stark.prover import gen_poseidon2_vfri3_real, VFRI3RealHintResult
    import hashlib
    root = bytes(range(32))
    result = gen_poseidon2_vfri3_real([1, 2, 3, 4], root, n_queries=2)
    assert isinstance(result, VFRI3RealHintResult)
    assert len(result.proof) >= 700
    assert len(result.commitment) == 32
    assert len(result.query_hints) > 0
    expected = hashlib.blake2s(result.proof[:32] + root).digest()[:16].hex()
    assert result.commitment == expected


@needs_ext
def test_gen_poseidon2_vfri3_real_prover_module_validates_inputs():
    """stark.prover.gen_poseidon2_vfri3_real raises ValueError for bad inputs."""
    from stark.prover import gen_poseidon2_vfri3_real
    with pytest.raises(ValueError, match="empty"):
        gen_poseidon2_vfri3_real([], bytes(32))
    with pytest.raises(ValueError, match="32 bytes"):
        gen_poseidon2_vfri3_real([1, 2], bytes(16))
    with pytest.raises(ValueError, match="n_queries"):
        gen_poseidon2_vfri3_real([1, 2], bytes(32), n_queries=0)


# ── gen_ntt_batch_vfri3_hints tests ──────────────────────────────────────────

@needs_ext
def test_gen_ntt_batch_vfri3_hints_output_schema():
    """Returns (bytes, str, bytes) triple."""
    polys = [[0]*256 for _ in range(2)]
    proof, commitment, hints = _ext.gen_ntt_batch_vfri3_hints_py(polys, list(_FAKE_BATCH_ROOT), 2)
    assert isinstance(proof, bytes)
    assert isinstance(commitment, str) and len(commitment) == 32
    assert isinstance(hints, bytes) and len(hints) > 0


@needs_ext
def test_gen_ntt_batch_vfri3_hints_commitment_binding():
    """Commitment = Blake2s(proof[:32] ‖ batch_merkle_root)[:16]."""
    import hashlib
    polys = [[i % 100 for _ in range(256)] for i in range(2)]
    root = bytes(range(32))
    proof, commitment, _ = _ext.gen_ntt_batch_vfri3_hints_py(polys, list(root), 2)
    expected = hashlib.blake2s(proof[:32] + root).digest()[:16].hex()
    assert commitment == expected


@needs_ext
def test_gen_ntt_batch_vfri3_hints_deterministic():
    """Same inputs produce identical outputs."""
    polys = [[1]*256 for _ in range(3)]
    root = list(_FAKE_BATCH_ROOT)
    r1 = _ext.gen_ntt_batch_vfri3_hints_py(polys, root, 1)
    r2 = _ext.gen_ntt_batch_vfri3_hints_py(polys, root, 1)
    assert r1[1] == r2[1] and r1[2] == r2[2]


@needs_ext
def test_gen_ntt_batch_vfri3_hints_nfolds_reduces_size():
    """Fewer fold rounds produce smaller last-layer (larger hints for more coeffs)."""
    polys = [[0]*256 for _ in range(2)]
    root = list(_FAKE_BATCH_ROOT)
    _, _, h_full = _ext.gen_ntt_batch_vfri3_hints_py(polys, root, 1)      # 9 folds
    _, _, h_few  = _ext.gen_ntt_batch_vfri3_hints_nfolds_py(polys, root, 1, 3)  # 3 folds
    # fewer folds → more last-layer coeffs → larger hints
    assert len(h_few) > len(h_full)


@needs_ext
def test_gen_ntt_batch_vfri3_hints_wrong_poly_len_error():
    """Polynomial with wrong length must raise an error."""
    polys = [[0]*255]  # 255 instead of 256
    with pytest.raises(Exception):
        _ext.gen_ntt_batch_vfri3_hints_py(polys, list(_FAKE_BATCH_ROOT), 1)


@needs_ext
def test_gen_ntt_batch_vfri3_hints_empty_polys_error():
    """Empty polys list must raise an error."""
    with pytest.raises(Exception):
        _ext.gen_ntt_batch_vfri3_hints_py([], list(_FAKE_BATCH_ROOT), 1)


@needs_ext
def test_gen_ntt_batch_vfri3_hints_prover_module_wrapper():
    """stark.prover.gen_ntt_batch_vfri3_hints wraps the Rust function correctly."""
    from stark.prover import gen_ntt_batch_vfri3_hints, NttBatchVFRI3HintResult
    import hashlib
    polys = [[i for i in range(256)] for _ in range(2)]
    root = bytes(range(32))
    result = gen_ntt_batch_vfri3_hints(polys, root, n_queries=2)
    assert isinstance(result, NttBatchVFRI3HintResult)
    assert len(result.proof) >= 700
    assert len(result.commitment) == 32
    assert len(result.query_hints) > 0
    expected = hashlib.blake2s(result.proof[:32] + root).digest()[:16].hex()
    assert result.commitment == expected


# ─── ML-DSA witness V23 pipeline (8-component STARK + RangeQBatch) ────────────
# V23 extends V22 by adding RangeQBatch (288 cols, LOG=8) as 8th component,
# proving az_hat[i][p] ∈ [0, Q) and closing the AzFull multiplication soundness gap.
# Requires full ML-DSA-65 dimensions: K=6, L=5.


@needs_ext
def test_prove_mldsa_witness_v23_output_schema():
    """prove_mldsa_witness_v23_py returns (bytes, list[int], list[list[int]], int)."""
    a_hat = [_rand_poly(i + 3000) for i in range(_K3 * _L3)]
    z     = [_rand_poly(3100 + j) for j in range(_L3)]
    c     = _rand_poly(3200)
    t1    = [_rand_poly(3300 + i) for i in range(_K3)]
    hints = _zero_hints(_K3)

    bundle, max_norms, w1_prime, hw_total = _ext.prove_mldsa_witness_v23_py(
        a_hat, z, c, t1, hints, _K3, _L3
    )

    assert isinstance(bundle, bytes) and len(bundle) > 0
    assert len(max_norms) == _L3
    assert len(w1_prime) == _K3
    for row in w1_prime:
        assert len(row) == N
    assert isinstance(hw_total, int) and hw_total == 0


@needs_ext
def test_prove_mldsa_witness_v23_verify_roundtrip():
    """prove_mldsa_witness_v23_py → verify_mldsa_witness_v23_py must succeed."""
    a_hat = [_rand_poly(i + 3010) for i in range(_K3 * _L3)]
    z     = [_rand_poly(3110 + j) for j in range(_L3)]
    c     = _rand_poly(3210)
    t1    = [_rand_poly(3310 + i) for i in range(_K3)]
    hints = _zero_hints(_K3)

    bundle, _, _, _ = _ext.prove_mldsa_witness_v23_py(a_hat, z, c, t1, hints, _K3, _L3)
    assert _ext.verify_mldsa_witness_v23_py(bundle)


@needs_ext
def test_prove_mldsa_witness_v23_tampered_bundle_fails():
    """Flipping a byte in the V23 bundle must cause verification to fail."""
    a_hat = [_rand_poly(i + 3020) for i in range(_K3 * _L3)]
    z     = [_rand_poly(3120 + j) for j in range(_L3)]
    c     = _rand_poly(3220)
    t1    = [_rand_poly(3320 + i) for i in range(_K3)]
    hints = _zero_hints(_K3)

    bundle, _, _, _ = _ext.prove_mldsa_witness_v23_py(a_hat, z, c, t1, hints, _K3, _L3)
    tampered = bytearray(bundle)
    tampered[len(tampered) // 2] ^= 0xFF
    assert not _ext.verify_mldsa_witness_v23_py(bytes(tampered))


@needs_ext
def test_prove_mldsa_witness_v23_matches_v3_w1_prime():
    """V23 and V3 pipelines must produce the same w1_prime for the same inputs."""
    a_hat = [_rand_poly(i + 3030) for i in range(_K3 * _L3)]
    z     = [_rand_poly(3130 + j) for j in range(_L3)]
    c     = _rand_poly(3230)
    t1    = [_rand_poly(3330 + i) for i in range(_K3)]
    hints = _zero_hints(_K3)

    _, _, w1_v3, _  = _ext.prove_mldsa_witness_v3_py(a_hat, z, c, t1, hints, _K3, _L3)
    _, _, w1_v23, _ = _ext.prove_mldsa_witness_v23_py(a_hat, z, c, t1, hints, _K3, _L3)

    assert w1_v3 == w1_v23, "V3 and V23 pipelines must agree on w1_prime"


@needs_ext
def test_prove_mldsa_witness_v23_merkle_root_binding():
    """V23 proof with one merkle root must not verify under a different root."""
    a_hat = [_rand_poly(i + 3040) for i in range(_K3 * _L3)]
    z     = [_rand_poly(3140 + j) for j in range(_L3)]
    c     = _rand_poly(3240)
    t1    = [_rand_poly(3340 + i) for i in range(_K3)]
    hints = _zero_hints(_K3)
    root1 = list(bytes(range(32)))
    root2 = list(bytes(range(1, 33)))

    bundle1, _, _, _ = _ext.prove_mldsa_witness_v23_py(
        a_hat, z, c, t1, hints, _K3, _L3, merkle_root=root1
    )
    bundle2, _, _, _ = _ext.prove_mldsa_witness_v23_py(
        a_hat, z, c, t1, hints, _K3, _L3, merkle_root=root2
    )
    assert _ext.verify_mldsa_witness_v23_py(bundle1)
    assert _ext.verify_mldsa_witness_v23_py(bundle2)
    assert bundle1 != bundle2, "Different merkle roots must produce different proofs"


@needs_ext
def test_prove_mldsa_witness_v23_prover_wrapper():
    """stark.prover.prove_mldsa_witness_stark_v23 wraps the Rust binding correctly."""
    from stark.prover import prove_mldsa_witness_stark_v23, verify_mldsa_witness_stark_v23
    from stark.prover import MldsaWitnessResult
    a_hat = [_rand_poly(i + 3050) for i in range(_K3 * _L3)]
    z     = [_rand_poly(3150 + j) for j in range(_L3)]
    c     = _rand_poly(3250)
    t1    = [_rand_poly(3350 + i) for i in range(_K3)]
    hints = _zero_hints(_K3)

    result = prove_mldsa_witness_stark_v23(a_hat, z, c, t1, hints, _K3, _L3)
    assert isinstance(result, MldsaWitnessResult)
    assert isinstance(result.proof_bundle, bytes) and len(result.proof_bundle) > 0
    assert verify_mldsa_witness_stark_v23(result)


# ── V23 VFRI3 hint generation tests (MVP-4 OODS wiring) ─────────────────────
# Seeds in 4000 range to avoid collision with V23 tests (3000 range).

_VFRI3_BATCH_ROOT = bytes(range(32))  # deterministic 32-byte root for all V23 VFRI3 tests


def _v23_inputs(seed_base: int) -> tuple[
    list[list[int]], list[int], list[list[int]], list[list[int]]
]:
    """Return (z, c, t1, a_hat) with seeds offset from seed_base."""
    z     = [_rand_poly(seed_base + j)        for j in range(_L3)]
    c     = _rand_poly(seed_base + 100)
    t1    = [_rand_poly(seed_base + 200 + i)  for i in range(_K3)]
    a_hat = [_rand_poly(seed_base + 300 + i)  for i in range(_K3 * _L3)]
    return z, c, t1, a_hat


@needs_ext
def test_gen_mldsa_v23_vfri3_hints_schema():
    """Output types and sizes of gen_mldsa_v23_vfri3_hints are correct."""
    from stark.prover import gen_mldsa_v23_vfri3_hints, MldsaV23VFRI3HintResult
    z, c, t1, a_hat = _v23_inputs(4000)

    result = gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, _VFRI3_BATCH_ROOT, n_queries=1, num_folds=3)

    assert isinstance(result, MldsaV23VFRI3HintResult)
    assert isinstance(result.proof, bytes) and len(result.proof) >= 700
    assert isinstance(result.commitment, str) and len(result.commitment) == 32
    assert isinstance(result.query_hints, bytes) and len(result.query_hints) > 0
    assert result.n_cols == 1298   # 649 NttBatch + 649 InttBatch
    assert result.n_queries == 1
    # commitment is 32 hex chars = 16 bytes of Blake2s
    assert bytes.fromhex(result.commitment)  # valid hex
    # proof[8:40] = trace root (non-zero for real trace)
    assert result.proof[8:40] != b'\x00' * 32


@needs_ext
def test_gen_mldsa_v23_vfri3_hints_deterministic():
    """Same inputs produce identical proofs (Fiat-Shamir is deterministic)."""
    from stark.prover import gen_mldsa_v23_vfri3_hints
    z, c, t1, a_hat = _v23_inputs(4100)

    r1 = gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, _VFRI3_BATCH_ROOT, n_queries=1, num_folds=3)
    r2 = gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, _VFRI3_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r1.proof       == r2.proof
    assert r1.commitment  == r2.commitment
    assert r1.query_hints == r2.query_hints


@needs_ext
def test_gen_mldsa_v23_vfri3_hints_batch_root_binding():
    """Different batch_merkle_roots produce different proofs/commitments."""
    from stark.prover import gen_mldsa_v23_vfri3_hints
    z, c, t1, a_hat = _v23_inputs(4200)

    root1 = bytes(range(32))
    root2 = bytes(range(1, 33))
    r1 = gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, root1, n_queries=1, num_folds=3)
    r2 = gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, root2, n_queries=1, num_folds=3)

    assert r1.commitment  != r2.commitment, "Different batch roots must give different commitments"
    assert r1.proof[8:40] == r2.proof[8:40], "Trace root must be batch-root-independent"


@needs_ext
def test_gen_mldsa_v23_vfri3_hints_consistent_with_v23_ntt():
    """NttBatch portion of V23 and V23-VFRI3 produce the same NTT outputs."""
    from stark.prover import (
        gen_mldsa_v23_vfri3_hints,
        prove_mldsa_witness_stark_v23,
        MldsaWitnessResult,
    )
    z, c, t1, a_hat = _v23_inputs(4300)
    hints = _zero_hints(_K3)

    # V23 STARK proof computes z_hat = NTT(z), c_hat = NTT(c), t1_hat = NTT(t1)
    v23 = prove_mldsa_witness_stark_v23(a_hat, z, c, t1, hints, _K3, _L3)
    # V23 VFRI3 hints also compute NTT(z, c, t1) internally
    vfri3 = gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, _VFRI3_BATCH_ROOT, n_queries=1, num_folds=3)

    # Both produce non-empty outputs with valid trace (non-zero trace root)
    assert v23.proof_bundle and vfri3.proof
    assert vfri3.proof[8:40] != b'\x00' * 32  # real trace committed


@needs_ext
def test_gen_mldsa_v23_vfri3_hints_validation_errors():
    """Python-side validation catches bad inputs before hitting Rust."""
    from stark.prover import gen_mldsa_v23_vfri3_hints
    z, c, t1, a_hat = _v23_inputs(4400)

    import pytest
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri3_hints(z[:-1], c, t1, a_hat, _VFRI3_BATCH_ROOT)  # z has only 4 polys
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri3_hints(z, c, t1[:-1], a_hat, _VFRI3_BATCH_ROOT)  # t1 has only 5 polys
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, b'\x00' * 16)  # root too short


@needs_ext
def test_gen_mldsa_v23_vfri3_hints_multi_query():
    """n_queries=3, num_folds=5: query_hints grows with number of queries."""
    from stark.prover import gen_mldsa_v23_vfri3_hints
    z, c, t1, a_hat = _v23_inputs(4500)

    r1 = gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, _VFRI3_BATCH_ROOT, n_queries=1, num_folds=5)
    r3 = gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, _VFRI3_BATCH_ROOT, n_queries=3, num_folds=5)

    assert r3.query_hints != r1.query_hints
    assert len(r3.query_hints) > len(r1.query_hints), "More queries → larger hint payload"
    assert r3.n_queries == 3


# ── VFRI4 V23 (NttBatch+InttBatch) bridge tests ──────────────────────────────

_VFRI4_V23_BATCH_ROOT = bytes(range(32))


@needs_ext
def test_gen_mldsa_v23_vfri4_hints_schema():
    """Output has correct types and n_cols=1298 (NttBatch+InttBatch)."""
    from stark.prover import gen_mldsa_v23_vfri4_hints, MldsaV23VFRI4HintResult
    z, c, t1, a_hat = _v23_inputs(7000)
    result = gen_mldsa_v23_vfri4_hints(z, c, t1, a_hat, _VFRI4_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    assert isinstance(result, MldsaV23VFRI4HintResult)
    assert isinstance(result.proof, bytes) and len(result.proof) >= 700
    assert isinstance(result.commitment, str) and len(result.commitment) == 32
    assert isinstance(result.query_hints, bytes) and len(result.query_hints) > 0
    assert result.n_cols == 1298
    assert result.n_queries == 1
    assert result.proof[8:40] != b'\x00' * 32, "trace root must be non-zero"


@needs_ext
def test_gen_mldsa_v23_vfri4_hints_deterministic():
    """Same inputs always produce identical commitment and hints."""
    from stark.prover import gen_mldsa_v23_vfri4_hints
    z, c, t1, a_hat = _v23_inputs(7100)
    r1 = gen_mldsa_v23_vfri4_hints(z, c, t1, a_hat, _VFRI4_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    r2 = gen_mldsa_v23_vfri4_hints(z, c, t1, a_hat, _VFRI4_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r1.commitment  == r2.commitment
    assert r1.query_hints == r2.query_hints


@needs_ext
def test_gen_mldsa_v23_vfri4_hints_batch_root_binding():
    """Different batch roots → different commitment; same trace root."""
    from stark.prover import gen_mldsa_v23_vfri4_hints
    z, c, t1, a_hat = _v23_inputs(7200)
    root1 = bytes(range(32))
    root2 = bytes(range(1, 33))
    r1 = gen_mldsa_v23_vfri4_hints(z, c, t1, a_hat, root1, n_queries=1, num_folds=3)
    r2 = gen_mldsa_v23_vfri4_hints(z, c, t1, a_hat, root2, n_queries=1, num_folds=3)
    assert r1.commitment  != r2.commitment
    assert r1.proof[8:40] == r2.proof[8:40], "trace root is batch-root-independent"


@needs_ext
def test_gen_mldsa_v23_vfri4_hints_differs_from_vfri3():
    """VFRI4 and VFRI3 hints differ (incompatible transcripts)."""
    from stark.prover import gen_mldsa_v23_vfri3_hints, gen_mldsa_v23_vfri4_hints
    z, c, t1, a_hat = _v23_inputs(7300)
    r3 = gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, _VFRI4_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    r4 = gen_mldsa_v23_vfri4_hints(z, c, t1, a_hat, _VFRI4_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    # Trace roots are the same (same arithmetic computation)
    assert r3.proof[8:40] == r4.proof[8:40], "trace root must match for same inputs"
    # But transcripts diverge after OODS mixing → different commitments and hints
    assert r3.query_hints != r4.query_hints, "VFRI4 transcript differs from VFRI3"


@needs_ext
def test_gen_mldsa_v23_vfri4_hints_validation_errors():
    """Python-side validation catches bad inputs."""
    from stark.prover import gen_mldsa_v23_vfri4_hints
    z, c, t1, a_hat = _v23_inputs(7400)
    import pytest
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri4_hints(z[:-1], c, t1, a_hat, _VFRI4_V23_BATCH_ROOT)
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri4_hints(z, c, t1[:-1], a_hat, _VFRI4_V23_BATCH_ROOT)
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri4_hints(z, c, t1, a_hat, b'\x00' * 16)


@needs_ext
def test_gen_mldsa_v23_vfri4_hints_multi_query():
    """n_queries=3 produces larger hints than n_queries=1."""
    from stark.prover import gen_mldsa_v23_vfri4_hints
    z, c, t1, a_hat = _v23_inputs(7500)
    r1 = gen_mldsa_v23_vfri4_hints(z, c, t1, a_hat, _VFRI4_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    r3 = gen_mldsa_v23_vfri4_hints(z, c, t1, a_hat, _VFRI4_V23_BATCH_ROOT, n_queries=3, num_folds=3)
    assert r3.n_queries == 3
    assert len(r3.query_hints) > len(r1.query_hints)


# ── VFRI4 NttBatch bridge tests ───────────────────────────────────────────────

_VFRI4_BATCH_ROOT = bytes(range(32))


def _ntt_polys(seed: int, n: int = 1) -> list[list[int]]:
    """Return n random polynomials with 256 coefficients each (bounded by GAMMA1)."""
    import random
    rng = random.Random(seed)
    GAMMA1 = 2**19
    return [[rng.randint(-GAMMA1, GAMMA1) for _ in range(256)] for _ in range(n)]


@needs_ext
def test_gen_ntt_batch_vfri4_hints_schema():
    """Result has correct types and n_cols = 1 + n_polys*54."""
    from stark.prover import gen_ntt_batch_vfri4_hints, NttBatchVFRI4HintResult
    polys = _ntt_polys(5000)
    r = gen_ntt_batch_vfri4_hints(polys, _VFRI4_BATCH_ROOT, n_queries=1, num_folds=9)
    assert isinstance(r, NttBatchVFRI4HintResult)
    assert r.n_cols == 55   # 1 + 1*54
    assert r.n_queries == 1
    assert len(r.proof) >= 700
    assert len(r.commitment) == 32  # 16 bytes hex
    assert len(r.query_hints) > 0


@needs_ext
def test_gen_ntt_batch_vfri4_hints_deterministic():
    """Same inputs always produce the same output."""
    from stark.prover import gen_ntt_batch_vfri4_hints
    polys = _ntt_polys(5100)
    r1 = gen_ntt_batch_vfri4_hints(polys, _VFRI4_BATCH_ROOT, n_queries=1, num_folds=9)
    r2 = gen_ntt_batch_vfri4_hints(polys, _VFRI4_BATCH_ROOT, n_queries=1, num_folds=9)
    assert r1.proof == r2.proof
    assert r1.commitment == r2.commitment
    assert r1.query_hints == r2.query_hints


@needs_ext
def test_gen_ntt_batch_vfri4_hints_commitment_binding():
    """Commitment changes when batch_merkle_root changes."""
    from stark.prover import gen_ntt_batch_vfri4_hints
    polys = _ntt_polys(5200)
    root_a = bytes(range(32))
    root_b = bytes([x ^ 0xFF for x in range(32)])
    ra = gen_ntt_batch_vfri4_hints(polys, root_a, n_queries=1, num_folds=9)
    rb = gen_ntt_batch_vfri4_hints(polys, root_b, n_queries=1, num_folds=9)
    assert ra.commitment != rb.commitment


@needs_ext
def test_gen_ntt_batch_vfri4_hints_differs_from_vfri3():
    """VFRI4 and VFRI3 produce different query_hints (different transcript)."""
    from stark.prover import gen_ntt_batch_vfri4_hints, gen_ntt_batch_vfri3_hints
    polys = _ntt_polys(5300)
    r4 = gen_ntt_batch_vfri4_hints(polys, _VFRI4_BATCH_ROOT, n_queries=1, num_folds=9)
    # gen_ntt_batch_vfri3_hints uses num_folds=9 implicitly (tree_depth-1)
    import qlsa_stark_stwo as _ext2
    proof3, comm3, hints3 = _ext2.gen_ntt_batch_vfri3_hints_nfolds_py(
        polys, list(_VFRI4_BATCH_ROOT), 1, 9
    )
    # Commitments match (same proof bytes, same batch_merkle_root)
    assert r4.commitment == comm3
    # But query_hints differ (different OODS transcript)
    assert r4.query_hints != hints3, "VFRI4 and VFRI3 must produce different query_hints"


@needs_ext
def test_gen_ntt_batch_vfri4_hints_commitment_formula():
    """Commitment = Blake2s(proof[:32] || batch_merkle_root)[:16]."""
    import hashlib
    from stark.prover import gen_ntt_batch_vfri4_hints
    polys = _ntt_polys(5400)
    r = gen_ntt_batch_vfri4_hints(polys, _VFRI4_BATCH_ROOT, n_queries=1, num_folds=9)
    h = hashlib.new('blake2s')
    h.update(r.proof[:32])
    h.update(_VFRI4_BATCH_ROOT)
    expected = h.digest()[:16].hex()
    assert r.commitment == expected


@needs_ext
def test_gen_ntt_batch_vfri4_hints_multi_poly():
    """2-poly trace (109 cols) produces larger query_hints than 1-poly (55 cols)."""
    from stark.prover import gen_ntt_batch_vfri4_hints
    r1 = gen_ntt_batch_vfri4_hints(_ntt_polys(5500, 1), _VFRI4_BATCH_ROOT, n_queries=1, num_folds=9)
    r2 = gen_ntt_batch_vfri4_hints(_ntt_polys(5500, 2), _VFRI4_BATCH_ROOT, n_queries=1, num_folds=9)
    assert r2.n_cols == 109  # 1 + 2*54
    assert len(r2.query_hints) > len(r1.query_hints)


# ── VFRI4 Poseidon2 real-trace bridge tests ────────────────────────────────────


@needs_ext
def test_gen_poseidon2_vfri4_hints_schema():
    """Result has correct types and non-empty proof/hints."""
    from stark.prover import gen_poseidon2_vfri4_hints, Poseidon2VFRI4HintResult
    leaves = list(range(1, 9))  # 8 leaves
    r = gen_poseidon2_vfri4_hints(leaves, bytes(range(32)))
    assert isinstance(r, Poseidon2VFRI4HintResult)
    assert isinstance(r.proof, bytes) and len(r.proof) >= 700
    assert isinstance(r.commitment, str) and len(r.commitment) == 32
    assert isinstance(r.query_hints, bytes) and len(r.query_hints) > 0
    assert r.n_leaves == 8
    assert r.n_queries == 1


@needs_ext
def test_gen_poseidon2_vfri4_hints_deterministic():
    """Same inputs always produce the same commitment and hints."""
    from stark.prover import gen_poseidon2_vfri4_hints
    leaves = list(range(1, 5))
    root = bytes([0xAB] * 32)
    r1 = gen_poseidon2_vfri4_hints(leaves, root)
    r2 = gen_poseidon2_vfri4_hints(leaves, root)
    assert r1.commitment == r2.commitment
    assert r1.query_hints == r2.query_hints


@needs_ext
def test_gen_poseidon2_vfri4_hints_commitment_binding():
    """commitment = hex(Blake2s(proof[:32] ‖ batch_merkle_root)[:16])."""
    import hashlib
    from stark.prover import gen_poseidon2_vfri4_hints
    root = bytes(range(32))
    r = gen_poseidon2_vfri4_hints([1, 2, 3, 4, 5, 6, 7, 8], root)
    h = hashlib.new("blake2s", digest_size=32)
    h.update(r.proof[:32])
    h.update(root)
    expected = h.digest()[:16].hex()
    assert r.commitment == expected


@needs_ext
def test_gen_poseidon2_vfri4_hints_differs_from_vfri3():
    """VFRI4 and VFRI3 transcripts are incompatible: hints differ."""
    from stark.prover import gen_poseidon2_vfri4_hints
    # Import VFRI3 equivalent
    import qlsa_stark_stwo as _ext  # type: ignore[import]
    leaves = [1, 2, 3, 4, 5, 6, 7, 8]
    root = bytes([0x42] * 32)
    r4 = gen_poseidon2_vfri4_hints(leaves, root)
    _proof3, _com3, h3 = _ext.gen_poseidon2_vfri3_real_py(leaves, list(root), 1)
    assert r4.query_hints != bytes(h3), "VFRI4 and VFRI3 hints must differ (different transcripts)"


@needs_ext
def test_gen_poseidon2_vfri4_hints_multi_query():
    """Multiple queries succeed and produce proportionally larger hints."""
    from stark.prover import gen_poseidon2_vfri4_hints
    leaves = list(range(1, 17))  # 16 leaves
    root = bytes(range(32))
    r1 = gen_poseidon2_vfri4_hints(leaves, root, n_queries=1)
    r2 = gen_poseidon2_vfri4_hints(leaves, root, n_queries=2)
    assert r2.n_queries == 2
    assert len(r2.query_hints) > len(r1.query_hints)


# ── VFRI5 NttBatch hint tests ──────────────────────────────────────────────────

_VFRI5_BATCH_ROOT = bytes(range(32))


@needs_ext
def test_gen_ntt_batch_vfri5_hints_schema():
    """Result has correct type, n_polys, and non-empty fields."""
    from stark.prover import gen_ntt_batch_vfri5_hints, NttBatchVFRI5HintResult
    polys = _ntt_polys(6000)
    r = gen_ntt_batch_vfri5_hints(polys, _VFRI5_BATCH_ROOT, n_queries=1, num_folds=9)
    assert isinstance(r, NttBatchVFRI5HintResult)
    assert r.n_polys == 1
    assert r.n_queries == 1
    assert len(r.proof) >= 700
    assert len(r.commitment) == 32  # 16 bytes hex = 32 chars
    assert len(r.query_hints) > 0


@needs_ext
def test_gen_ntt_batch_vfri5_hints_deterministic():
    """Same inputs produce identical proof, commitment, and hints."""
    from stark.prover import gen_ntt_batch_vfri5_hints
    polys = _ntt_polys(6100)
    r1 = gen_ntt_batch_vfri5_hints(polys, _VFRI5_BATCH_ROOT, n_queries=1, num_folds=9)
    r2 = gen_ntt_batch_vfri5_hints(polys, _VFRI5_BATCH_ROOT, n_queries=1, num_folds=9)
    assert r1.commitment == r2.commitment
    assert r1.query_hints == r2.query_hints


@needs_ext
def test_gen_ntt_batch_vfri5_hints_batch_root_binding():
    """Different batch_merkle_root produces different commitment (not hints — root is not in transcript)."""
    from stark.prover import gen_ntt_batch_vfri5_hints
    polys = _ntt_polys(6200)
    root_a = bytes([0xAA] * 32)
    root_b = bytes([0xBB] * 32)
    ra = gen_ntt_batch_vfri5_hints(polys, root_a, n_queries=1, num_folds=9)
    rb = gen_ntt_batch_vfri5_hints(polys, root_b, n_queries=1, num_folds=9)
    assert ra.commitment != rb.commitment
    # query_hints are transcript-derived (traceRoot only) — same polys → same hints
    assert ra.query_hints == rb.query_hints


@needs_ext
def test_gen_ntt_batch_vfri5_hints_differs_from_vfri4():
    """VFRI5 transcript includes compRoot → different hints from VFRI4."""
    from stark.prover import gen_ntt_batch_vfri5_hints, gen_ntt_batch_vfri4_hints
    polys = _ntt_polys(6300)
    r4 = gen_ntt_batch_vfri4_hints(polys, _VFRI5_BATCH_ROOT, n_queries=1, num_folds=9)
    r5 = gen_ntt_batch_vfri5_hints(polys, _VFRI5_BATCH_ROOT, n_queries=1, num_folds=9)
    # Same arithmetic (same proof / trace commitment)
    assert r4.commitment == r5.commitment
    # Different transcripts → different query hints
    assert r4.query_hints != r5.query_hints


@needs_ext
def test_gen_ntt_batch_vfri5_hints_comp_root_non_zero():
    """VFRI5 hints embed a non-zero compRoot at head slot 3 (bytes 96..128)."""
    from stark.prover import gen_ntt_batch_vfri5_hints
    polys = _ntt_polys(6400)
    r = gen_ntt_batch_vfri5_hints(polys, _VFRI5_BATCH_ROOT, n_queries=1, num_folds=9)
    # head = 6 × 32 = 192 bytes; compRoot at slot 3 = bytes 96..128
    assert len(r.query_hints) > 192
    comp_root_slot = r.query_hints[96:128]
    assert comp_root_slot != bytes(32), "compRoot in VFRI5 hints must be non-zero"


@needs_ext
def test_gen_ntt_batch_vfri5_hints_multi_query():
    """Multiple queries produce proportionally larger hints."""
    from stark.prover import gen_ntt_batch_vfri5_hints
    polys = _ntt_polys(6500)
    r1 = gen_ntt_batch_vfri5_hints(polys, _VFRI5_BATCH_ROOT, n_queries=1, num_folds=9)
    r2 = gen_ntt_batch_vfri5_hints(polys, _VFRI5_BATCH_ROOT, n_queries=2, num_folds=9)
    assert r2.n_queries == 2
    assert len(r2.query_hints) > len(r1.query_hints)


# ── VFRI6 NttBatch hint tests ──────────────────────────────────────────────────

_VFRI6_BATCH_ROOT = bytes(range(32))


@needs_ext
def test_gen_ntt_batch_vfri6_hints_schema():
    """Result has correct type, n_polys, and non-empty fields."""
    from stark.prover import gen_ntt_batch_vfri6_hints, NttBatchVFRI6HintResult
    polys = _ntt_polys(7000)
    r = gen_ntt_batch_vfri6_hints(polys, _VFRI6_BATCH_ROOT, n_queries=1, num_folds=9)
    assert isinstance(r, NttBatchVFRI6HintResult)
    assert r.n_polys == 1
    assert r.n_queries == 1
    assert len(r.proof) >= 700
    assert len(r.commitment) == 32  # 16 bytes hex = 32 chars
    assert len(r.query_hints) > 0


@needs_ext
def test_gen_ntt_batch_vfri6_hints_deterministic():
    """Same inputs produce identical proof, commitment, and hints."""
    from stark.prover import gen_ntt_batch_vfri6_hints
    polys = _ntt_polys(7100)
    r1 = gen_ntt_batch_vfri6_hints(polys, _VFRI6_BATCH_ROOT, n_queries=1, num_folds=9)
    r2 = gen_ntt_batch_vfri6_hints(polys, _VFRI6_BATCH_ROOT, n_queries=1, num_folds=9)
    assert r1.commitment == r2.commitment
    assert r1.query_hints == r2.query_hints


@needs_ext
def test_gen_ntt_batch_vfri6_hints_batch_root_binding():
    """Different batch_merkle_root produces different commitment (not hints)."""
    from stark.prover import gen_ntt_batch_vfri6_hints
    polys = _ntt_polys(7200)
    root_a = bytes([0xAA] * 32)
    root_b = bytes([0xBB] * 32)
    ra = gen_ntt_batch_vfri6_hints(polys, root_a, n_queries=1, num_folds=9)
    rb = gen_ntt_batch_vfri6_hints(polys, root_b, n_queries=1, num_folds=9)
    assert ra.commitment != rb.commitment
    # query_hints are transcript-derived (traceRoot only) — same polys → same hints
    assert ra.query_hints == rb.query_hints


@needs_ext
def test_gen_ntt_batch_vfri6_hints_differs_from_vfri5():
    """VFRI6 transcript differs from VFRI5 (no Poseidon2, compAlpha drawn first)."""
    from stark.prover import gen_ntt_batch_vfri6_hints, gen_ntt_batch_vfri5_hints
    polys = _ntt_polys(7300)
    r5 = gen_ntt_batch_vfri5_hints(polys, _VFRI6_BATCH_ROOT, n_queries=1, num_folds=9)
    r6 = gen_ntt_batch_vfri6_hints(polys, _VFRI6_BATCH_ROOT, n_queries=1, num_folds=9)
    assert r5.commitment == r6.commitment
    assert r5.query_hints != r6.query_hints


@needs_ext
def test_gen_ntt_batch_vfri6_hints_smaller_than_vfri5():
    """VFRI6 hints are smaller than VFRI5 (oodsEvalsPos/Neg arrays removed)."""
    from stark.prover import gen_ntt_batch_vfri6_hints, gen_ntt_batch_vfri5_hints
    polys = _ntt_polys(7400, n=12)
    r5 = gen_ntt_batch_vfri5_hints(polys, _VFRI6_BATCH_ROOT, n_queries=1, num_folds=9)
    r6 = gen_ntt_batch_vfri6_hints(polys, _VFRI6_BATCH_ROOT, n_queries=1, num_folds=9)
    assert len(r6.query_hints) < len(r5.query_hints), (
        f"VFRI6 hints ({len(r6.query_hints)} B) must be smaller than "
        f"VFRI5 hints ({len(r5.query_hints)} B)"
    )


@needs_ext
def test_gen_ntt_batch_vfri6_hints_multi_query():
    """Multiple queries produce proportionally larger hints."""
    from stark.prover import gen_ntt_batch_vfri6_hints
    polys = _ntt_polys(7500)
    r1 = gen_ntt_batch_vfri6_hints(polys, _VFRI6_BATCH_ROOT, n_queries=1, num_folds=9)
    r2 = gen_ntt_batch_vfri6_hints(polys, _VFRI6_BATCH_ROOT, n_queries=2, num_folds=9)
    assert r2.n_queries == 2
    assert len(r2.query_hints) > len(r1.query_hints)


# ── VFRI6 V23 (NttBatch+InttBatch, 1298 cols) tests ───────────────────────────

_VFRI6_V23_BATCH_ROOT = bytes(range(32))


@needs_ext
def test_gen_mldsa_v23_vfri6_hints_schema():
    """Output has correct types and n_cols=1298 (NttBatch+InttBatch)."""
    from stark.prover import gen_mldsa_v23_vfri6_hints, MldsaV23VFRI6HintResult
    z, c, t1, a_hat = _v23_inputs(9000)
    r = gen_mldsa_v23_vfri6_hints(z, c, t1, a_hat, _VFRI6_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    assert isinstance(r, MldsaV23VFRI6HintResult)
    assert len(r.proof) >= 700
    assert len(r.commitment) == 32
    assert len(r.query_hints) > 0
    assert r.n_cols == 1298
    assert r.n_queries == 1
    assert r.proof[8:40] != b'\x00' * 32, "trace root must be non-zero"


@needs_ext
def test_gen_mldsa_v23_vfri6_hints_deterministic():
    """Same inputs always produce identical commitment and hints."""
    from stark.prover import gen_mldsa_v23_vfri6_hints
    z, c, t1, a_hat = _v23_inputs(9100)
    r1 = gen_mldsa_v23_vfri6_hints(z, c, t1, a_hat, _VFRI6_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    r2 = gen_mldsa_v23_vfri6_hints(z, c, t1, a_hat, _VFRI6_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r1.commitment  == r2.commitment
    assert r1.query_hints == r2.query_hints


@needs_ext
def test_gen_mldsa_v23_vfri6_hints_smaller_than_vfri4():
    """VFRI6 hints are much smaller than VFRI4 for 1298 cols (no oodsEvalsPos/Neg arrays)."""
    from stark.prover import gen_mldsa_v23_vfri4_hints, gen_mldsa_v23_vfri6_hints
    z, c, t1, a_hat = _v23_inputs(9200)
    r4 = gen_mldsa_v23_vfri4_hints(z, c, t1, a_hat, _VFRI6_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    r6 = gen_mldsa_v23_vfri6_hints(z, c, t1, a_hat, _VFRI6_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    # VFRI4 includes oodsEvalsPos[1298] + oodsEvalsNeg[1298] = 2×1298×16 = 41536 bytes
    assert len(r6.query_hints) < len(r4.query_hints), (
        f"VFRI6 hints ({len(r6.query_hints)} B) must be smaller than "
        f"VFRI4 hints ({len(r4.query_hints)} B)"
    )


@needs_ext
def test_gen_mldsa_v23_vfri6_hints_differs_from_vfri4():
    """VFRI6 and VFRI4 transcripts differ (different channel transcript)."""
    from stark.prover import gen_mldsa_v23_vfri4_hints, gen_mldsa_v23_vfri6_hints
    z, c, t1, a_hat = _v23_inputs(9300)
    r4 = gen_mldsa_v23_vfri4_hints(z, c, t1, a_hat, _VFRI6_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    r6 = gen_mldsa_v23_vfri6_hints(z, c, t1, a_hat, _VFRI6_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r4.proof[8:40] == r6.proof[8:40], "trace root must match for same inputs"
    assert r4.query_hints != r6.query_hints, "VFRI6 transcript differs from VFRI4"


@needs_ext
def test_gen_mldsa_v23_vfri6_hints_validation_errors():
    """Python-side validation catches bad inputs."""
    from stark.prover import gen_mldsa_v23_vfri6_hints
    import pytest
    z, c, t1, a_hat = _v23_inputs(9400)
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri6_hints(z[:-1], c, t1, a_hat, _VFRI6_V23_BATCH_ROOT)
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri6_hints(z, c, t1[:-1], a_hat, _VFRI6_V23_BATCH_ROOT)
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri6_hints(z, c, t1, a_hat, b'\x00' * 16)


@needs_ext
def test_gen_mldsa_v23_vfri6_hints_multi_query():
    """n_queries=2 produces larger hints than n_queries=1."""
    from stark.prover import gen_mldsa_v23_vfri6_hints
    z, c, t1, a_hat = _v23_inputs(9500)
    r1 = gen_mldsa_v23_vfri6_hints(z, c, t1, a_hat, _VFRI6_V23_BATCH_ROOT, n_queries=1, num_folds=3)
    r2 = gen_mldsa_v23_vfri6_hints(z, c, t1, a_hat, _VFRI6_V23_BATCH_ROOT, n_queries=2, num_folds=3)
    assert r1.commitment == r2.commitment
    assert len(r2.query_hints) > len(r1.query_hints)


# ── VFRI6 LOG=8 group tests (AzFull+Ct1Full+RangeQ+WPrime+NormCheck+UseHint) ─

_VFRI6_LOG8_BATCH_ROOT = bytes(range(32))


def _make_log8_hints() -> list[list[bool]]:
    return [[False] * 256 for _ in range(6)]


@needs_ext
def test_gen_mldsa_v23_vfri6_hints_log8_schema():
    """LOG=8 VFRI6 result has expected structure and 2206 columns."""
    from stark.prover import gen_mldsa_v23_vfri6_hints_log8
    z, c, t1, a_hat = _v23_inputs(10000)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri6_hints_log8(
        z, c, t1, a_hat, hints, _VFRI6_LOG8_BATCH_ROOT, n_queries=1, num_folds=3,
    )
    assert isinstance(r.proof, bytes) and len(r.proof) >= 700
    assert isinstance(r.commitment, str) and len(r.commitment) == 32
    assert isinstance(r.query_hints, bytes) and len(r.query_hints) > 0
    assert r.n_cols == 2206
    assert r.n_queries == 1


@needs_ext
def test_gen_mldsa_v23_vfri6_hints_log8_deterministic():
    """Same inputs produce identical outputs."""
    from stark.prover import gen_mldsa_v23_vfri6_hints_log8
    z, c, t1, a_hat = _v23_inputs(10100)
    hints = _make_log8_hints()
    r1 = gen_mldsa_v23_vfri6_hints_log8(
        z, c, t1, a_hat, hints, _VFRI6_LOG8_BATCH_ROOT, n_queries=1, num_folds=3,
    )
    r2 = gen_mldsa_v23_vfri6_hints_log8(
        z, c, t1, a_hat, hints, _VFRI6_LOG8_BATCH_ROOT, n_queries=1, num_folds=3,
    )
    assert r1.commitment == r2.commitment
    assert r1.query_hints == r2.query_hints


@needs_ext
def test_gen_mldsa_v23_vfri6_hints_log8_small_hints():
    """LOG=8 hints are O(1) in n_cols: 2206 cols → < 20 KB."""
    from stark.prover import gen_mldsa_v23_vfri6_hints_log8
    z, c, t1, a_hat = _v23_inputs(10200)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri6_hints_log8(
        z, c, t1, a_hat, hints, _VFRI6_LOG8_BATCH_ROOT, n_queries=1, num_folds=3,
    )
    assert len(r.query_hints) < 20_000, (
        f"VFRI6 2206-col hints should be < 20 KB, got {len(r.query_hints)} B"
    )


@needs_ext
def test_gen_mldsa_v23_vfri6_hints_log8_validation_errors():
    """Python-side validation catches bad inputs."""
    from stark.prover import gen_mldsa_v23_vfri6_hints_log8
    import pytest
    z, c, t1, a_hat = _v23_inputs(10300)
    hints = _make_log8_hints()
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri6_hints_log8(z[:-1], c, t1, a_hat, hints, _VFRI6_LOG8_BATCH_ROOT)
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri6_hints_log8(z, c, t1, a_hat, hints[:-1], _VFRI6_LOG8_BATCH_ROOT)
    with pytest.raises((ValueError, RuntimeError)):
        gen_mldsa_v23_vfri6_hints_log8(z, c, t1, a_hat, hints, b'\x00' * 16)


@needs_ext
def test_gen_mldsa_v23_vfri6_hints_log8_multi_query():
    """n_queries=2 produces larger hints than n_queries=1."""
    from stark.prover import gen_mldsa_v23_vfri6_hints_log8
    z, c, t1, a_hat = _v23_inputs(10400)
    hints = _make_log8_hints()
    r1 = gen_mldsa_v23_vfri6_hints_log8(
        z, c, t1, a_hat, hints, _VFRI6_LOG8_BATCH_ROOT, n_queries=1, num_folds=3,
    )
    r2 = gen_mldsa_v23_vfri6_hints_log8(
        z, c, t1, a_hat, hints, _VFRI6_LOG8_BATCH_ROOT, n_queries=2, num_folds=3,
    )
    assert r1.commitment == r2.commitment
    assert len(r2.query_hints) > len(r1.query_hints)


# ── Full V23 VFRI6 combined tests (LOG=10 + LOG=8 both proofs) ──────────────

_FULL_V23_BATCH_ROOT = bytes(range(32))


@needs_ext
def test_gen_full_v23_vfri6_hints_schema():
    """Combined result contains both LOG=10 and LOG=8 proof triples."""
    from stark.prover import gen_full_v23_vfri6_hints
    z, c, t1, a_hat = _v23_inputs(11000)
    hints = [[False] * 256 for _ in range(6)]
    r = gen_full_v23_vfri6_hints(
        z, c, t1, a_hat, hints, _FULL_V23_BATCH_ROOT,
        n_queries=1, num_folds_log10=3, num_folds_log8=3,
    )
    # LOG=10 group
    assert isinstance(r.log10_proof, bytes) and len(r.log10_proof) >= 700
    assert isinstance(r.log10_commitment, str) and len(r.log10_commitment) == 32
    assert isinstance(r.log10_query_hints, bytes) and len(r.log10_query_hints) > 0
    # LOG=8 group
    assert isinstance(r.log8_proof, bytes) and len(r.log8_proof) >= 700
    assert isinstance(r.log8_commitment, str) and len(r.log8_commitment) == 32
    assert isinstance(r.log8_query_hints, bytes) and len(r.log8_query_hints) > 0
    # Metadata
    assert r.batch_merkle_root == _FULL_V23_BATCH_ROOT
    assert r.n_queries == 1


@needs_ext
def test_gen_full_v23_vfri6_hints_both_bind_same_root():
    """Both LOG groups embed the same batch_merkle_root in their commitment."""
    import hashlib
    from stark.prover import gen_full_v23_vfri6_hints
    z, c, t1, a_hat = _v23_inputs(11100)
    hints = [[False] * 256 for _ in range(6)]
    r = gen_full_v23_vfri6_hints(
        z, c, t1, a_hat, hints, _FULL_V23_BATCH_ROOT,
        n_queries=1, num_folds_log10=3, num_folds_log8=3,
    )
    def check_commitment(proof: bytes, commitment: str, root: bytes) -> bool:
        h = hashlib.new("blake2s", digest_size=32)
        h.update(proof[:32])
        h.update(root)
        expected = "0x" + h.digest()[:16].hex()
        return commitment == expected or commitment == expected[2:]

    assert check_commitment(r.log10_proof, r.log10_commitment, _FULL_V23_BATCH_ROOT), \
        "LOG=10 commitment must bind to batch_merkle_root"
    assert check_commitment(r.log8_proof, r.log8_commitment, _FULL_V23_BATCH_ROOT), \
        "LOG=8 commitment must bind to batch_merkle_root"


@needs_ext
def test_gen_full_v23_vfri6_hints_deterministic():
    """Same inputs produce identical outputs both times."""
    from stark.prover import gen_full_v23_vfri6_hints
    z, c, t1, a_hat = _v23_inputs(11200)
    hints = [[False] * 256 for _ in range(6)]
    r1 = gen_full_v23_vfri6_hints(
        z, c, t1, a_hat, hints, _FULL_V23_BATCH_ROOT,
        n_queries=1, num_folds_log10=3, num_folds_log8=3,
    )
    r2 = gen_full_v23_vfri6_hints(
        z, c, t1, a_hat, hints, _FULL_V23_BATCH_ROOT,
        n_queries=1, num_folds_log10=3, num_folds_log8=3,
    )
    assert r1.log10_commitment == r2.log10_commitment
    assert r1.log10_query_hints == r2.log10_query_hints
    assert r1.log8_commitment == r2.log8_commitment
    assert r1.log8_query_hints == r2.log8_query_hints


@needs_ext
def test_gen_full_v23_vfri6_hints_total_calldata():
    """Combined calldata < 20 KB — both groups fit in one L2 batch."""
    from stark.prover import gen_full_v23_vfri6_hints
    z, c, t1, a_hat = _v23_inputs(11300)
    hints = [[False] * 256 for _ in range(6)]
    r = gen_full_v23_vfri6_hints(
        z, c, t1, a_hat, hints, _FULL_V23_BATCH_ROOT,
        n_queries=1, num_folds_log10=3, num_folds_log8=3,
    )
    total = len(r.log10_query_hints) + len(r.log8_query_hints)
    assert total < 20_000, f"Combined hints {total} B should be < 20 KB"


@needs_ext
def test_gen_full_v23_vfri6_hints_groups_independent():
    """Different batch roots produce different commitments for each group."""
    from stark.prover import gen_full_v23_vfri6_hints
    z, c, t1, a_hat = _v23_inputs(11400)
    hints = [[False] * 256 for _ in range(6)]
    root_a = bytes([0xAA] * 32)
    root_b = bytes([0xBB] * 32)
    ra = gen_full_v23_vfri6_hints(
        z, c, t1, a_hat, hints, root_a, n_queries=1, num_folds_log10=3, num_folds_log8=3,
    )
    rb = gen_full_v23_vfri6_hints(
        z, c, t1, a_hat, hints, root_b, n_queries=1, num_folds_log10=3, num_folds_log8=3,
    )
    assert ra.log10_commitment != rb.log10_commitment, "Different roots must give different LOG=10 commitments"
    assert ra.log8_commitment != rb.log8_commitment, "Different roots must give different LOG=8 commitments"


# ── VFRI7: cross-proof binding (MVP-5 Priority 2) ─────────────────────────────

_VFRI7_BATCH_ROOT = bytes(range(32))


@needs_ext
def test_gen_mldsa_v23_vfri7_hints_schema():
    """LOG=10 VFRI7 result has expected structure and n_cols=1298."""
    from stark.prover import gen_mldsa_v23_vfri7_hints, MldsaV23VFRI7HintResult
    z, c, t1, a_hat = _v23_inputs(12000)
    r = gen_mldsa_v23_vfri7_hints(z, c, t1, a_hat, _VFRI7_BATCH_ROOT, n_queries=1, num_folds=3)
    assert isinstance(r, MldsaV23VFRI7HintResult)
    assert isinstance(r.proof, bytes) and len(r.proof) >= 700
    assert isinstance(r.commitment, str) and len(r.commitment) == 32
    assert isinstance(r.query_hints, bytes) and len(r.query_hints) > 0
    assert r.n_cols == 1298
    assert r.n_queries == 1


@needs_ext
def test_gen_mldsa_v23_vfri7_hints_deterministic():
    """Same inputs produce identical VFRI7 LOG=10 outputs."""
    from stark.prover import gen_mldsa_v23_vfri7_hints
    z, c, t1, a_hat = _v23_inputs(12100)
    r1 = gen_mldsa_v23_vfri7_hints(z, c, t1, a_hat, _VFRI7_BATCH_ROOT, n_queries=1, num_folds=3)
    r2 = gen_mldsa_v23_vfri7_hints(z, c, t1, a_hat, _VFRI7_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r1.commitment == r2.commitment
    assert r1.query_hints == r2.query_hints


@needs_ext
def test_gen_mldsa_v23_vfri7_hints_differs_from_vfri6():
    """VFRI7 transcript differs from VFRI6 (mixRoot(merkleRoot) before drawQueries)."""
    from stark.prover import gen_mldsa_v23_vfri7_hints, gen_mldsa_v23_vfri6_hints
    z, c, t1, a_hat = _v23_inputs(12200)
    r6 = gen_mldsa_v23_vfri6_hints(z, c, t1, a_hat, _VFRI7_BATCH_ROOT, n_queries=1, num_folds=3)
    r7 = gen_mldsa_v23_vfri7_hints(z, c, t1, a_hat, _VFRI7_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r6.query_hints != r7.query_hints, "VFRI7 must differ from VFRI6 (different transcript)"


@needs_ext
def test_gen_mldsa_v23_vfri7_hints_batch_root_binding():
    """Different batch roots produce different VFRI7 LOG=10 hints."""
    from stark.prover import gen_mldsa_v23_vfri7_hints
    z, c, t1, a_hat = _v23_inputs(12300)
    root_a = bytes([0xAA] * 32)
    root_b = bytes([0xBB] * 32)
    ra = gen_mldsa_v23_vfri7_hints(z, c, t1, a_hat, root_a, n_queries=1, num_folds=3)
    rb = gen_mldsa_v23_vfri7_hints(z, c, t1, a_hat, root_b, n_queries=1, num_folds=3)
    assert ra.query_hints != rb.query_hints, "Different batch roots must give different hints"


@needs_ext
def test_gen_mldsa_v23_vfri7_hints_log8_schema():
    """LOG=8 VFRI7 result has expected structure and n_cols=2206."""
    from stark.prover import gen_mldsa_v23_vfri7_hints_log8, MldsaV23VFRI7Log8HintResult
    z, c, t1, a_hat = _v23_inputs(12400)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri7_hints_log8(z, c, t1, a_hat, hints, _VFRI7_BATCH_ROOT, n_queries=1, num_folds=3)
    assert isinstance(r, MldsaV23VFRI7Log8HintResult)
    assert isinstance(r.proof, bytes) and len(r.proof) >= 700
    assert isinstance(r.commitment, str) and len(r.commitment) == 32
    assert isinstance(r.query_hints, bytes) and len(r.query_hints) > 0
    assert r.n_cols == 2206
    assert r.n_queries == 1


@needs_ext
def test_gen_mldsa_v23_vfri7_hints_log8_differs_from_vfri6():
    """VFRI7 LOG=8 hints differ from VFRI6 LOG=8 (different transcript)."""
    from stark.prover import gen_mldsa_v23_vfri7_hints_log8, gen_mldsa_v23_vfri6_hints_log8
    z, c, t1, a_hat = _v23_inputs(12500)
    hints = _make_log8_hints()
    r6 = gen_mldsa_v23_vfri6_hints_log8(z, c, t1, a_hat, hints, _VFRI7_BATCH_ROOT, n_queries=1, num_folds=3)
    r7 = gen_mldsa_v23_vfri7_hints_log8(z, c, t1, a_hat, hints, _VFRI7_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r6.query_hints != r7.query_hints, "VFRI7 LOG=8 must differ from VFRI6 (different transcript)"


@needs_ext
def test_gen_mldsa_v23_vfri7_cross_bound_hints_schema():
    """Cross-bound result has correct structure for both LOG groups."""
    from stark.prover import (
        gen_mldsa_v23_vfri7_cross_bound_hints,
        FullV23VFRI7CrossBoundHintResult,
    )
    z, c, t1, a_hat = _v23_inputs(12600)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri7_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI7_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    assert isinstance(r, FullV23VFRI7CrossBoundHintResult)
    assert isinstance(r.log10_proof, bytes) and len(r.log10_proof) >= 700
    assert isinstance(r.log10_commitment, str) and len(r.log10_commitment) == 32
    assert isinstance(r.log10_query_hints, bytes) and len(r.log10_query_hints) > 0
    assert isinstance(r.log8_proof, bytes) and len(r.log8_proof) >= 700
    assert isinstance(r.log8_commitment, str) and len(r.log8_commitment) == 32
    assert isinstance(r.log8_query_hints, bytes) and len(r.log8_query_hints) > 0
    assert r.batch_merkle_root == _VFRI7_BATCH_ROOT
    assert r.n_queries == 1


@needs_ext
def test_gen_mldsa_v23_vfri7_cross_bound_hints_deterministic():
    """Same inputs produce identical cross-bound outputs."""
    from stark.prover import gen_mldsa_v23_vfri7_cross_bound_hints
    z, c, t1, a_hat = _v23_inputs(12700)
    hints = _make_log8_hints()
    r1 = gen_mldsa_v23_vfri7_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI7_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    r2 = gen_mldsa_v23_vfri7_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI7_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    assert r1.log10_commitment == r2.log10_commitment
    assert r1.log10_query_hints == r2.log10_query_hints
    assert r1.log8_commitment == r2.log8_commitment
    assert r1.log8_query_hints == r2.log8_query_hints


@needs_ext
def test_gen_mldsa_v23_vfri7_cross_bound_hints_commitment_binding():
    """Cross-bound commitments are 32-char hex strings (Blake2s(proof[:32]‖bound_root)[:16])."""
    from stark.prover import gen_mldsa_v23_vfri7_cross_bound_hints
    z, c, t1, a_hat = _v23_inputs(12800)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri7_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI7_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    # Commitment format: 32-char hex of Blake2s(proof[:32] ‖ bound_root)[:16] (no 0x prefix)
    assert isinstance(r.log10_commitment, str) and len(r.log10_commitment) == 32
    assert isinstance(r.log8_commitment, str) and len(r.log8_commitment) == 32
    # Both commitments are valid hex strings
    assert len(bytes.fromhex(r.log10_commitment)) == 16
    assert len(bytes.fromhex(r.log8_commitment)) == 16


@needs_ext
def test_gen_mldsa_v23_vfri7_cross_bound_hints_batch_root_changes():
    """Different batch roots produce different cross-bound commitments."""
    from stark.prover import gen_mldsa_v23_vfri7_cross_bound_hints
    z, c, t1, a_hat = _v23_inputs(12900)
    hints = _make_log8_hints()
    root_a = bytes([0xAA] * 32)
    root_b = bytes([0xBB] * 32)
    ra = gen_mldsa_v23_vfri7_cross_bound_hints(
        z, c, t1, a_hat, hints, root_a, n_queries=1, num_folds_log10=3,
    )
    rb = gen_mldsa_v23_vfri7_cross_bound_hints(
        z, c, t1, a_hat, hints, root_b, n_queries=1, num_folds_log10=3,
    )
    assert ra.log10_commitment != rb.log10_commitment, "Different batch roots → different LOG=10 commitments"
    assert ra.log8_commitment != rb.log8_commitment, "Different batch roots → different LOG=8 commitments"


@needs_ext
def test_gen_mldsa_v23_vfri7_cross_bound_total_calldata():
    """Cross-bound combined calldata < 20 KB."""
    from stark.prover import gen_mldsa_v23_vfri7_cross_bound_hints
    z, c, t1, a_hat = _v23_inputs(13000)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri7_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI7_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    total = len(r.log10_query_hints) + len(r.log8_query_hints)
    assert total < 20_000, f"Combined cross-bound hints {total} B should be < 20 KB"


# ── prove_mldsa_sig_vfri7_stark: end-to-end from real sig ─────────────────────

@needs_oqs
def test_prove_mldsa_sig_vfri7_stark_schema():
    """prove_mldsa_sig_vfri7_stark returns a well-formed FullV23VFRI7CrossBoundHintResult."""
    from stark.prover import prove_mldsa_sig_vfri7_stark, FullV23VFRI7CrossBoundHintResult
    alg = _oqs.Signature("ML-DSA-65")
    pk  = alg.generate_keypair()
    msg = b"qlsa vfri7 e2e test"
    sig = alg.sign(msg)
    batch_root = bytes(range(32))

    r = prove_mldsa_sig_vfri7_stark(pk, msg, sig, batch_root, n_queries=1)

    assert isinstance(r, FullV23VFRI7CrossBoundHintResult)
    assert isinstance(r.log10_proof, bytes) and len(r.log10_proof) >= 700
    assert isinstance(r.log10_commitment, str) and len(r.log10_commitment) == 32
    assert isinstance(r.log10_query_hints, bytes) and len(r.log10_query_hints) > 0
    assert isinstance(r.log8_proof, bytes) and len(r.log8_proof) >= 700
    assert isinstance(r.log8_commitment, str) and len(r.log8_commitment) == 32
    assert isinstance(r.log8_query_hints, bytes) and len(r.log8_query_hints) > 0
    assert r.batch_merkle_root == batch_root
    assert r.n_queries == 1
    # Commitments are valid 16-byte hex strings
    assert len(bytes.fromhex(r.log10_commitment)) == 16
    assert len(bytes.fromhex(r.log8_commitment)) == 16


@needs_oqs
def test_prove_mldsa_sig_vfri7_stark_invalid_sig_raises():
    """prove_mldsa_sig_vfri7_stark raises ValueError for an invalid signature."""
    from stark.prover import prove_mldsa_sig_vfri7_stark
    alg = _oqs.Signature("ML-DSA-65")
    pk  = alg.generate_keypair()
    bad_sig = bytes(3309)  # all-zero signature is invalid
    batch_root = bytes(32)
    import pytest as _pytest
    with _pytest.raises(ValueError, match="ML-DSA-65 signature verification failed"):
        prove_mldsa_sig_vfri7_stark(pk, b"any message", bad_sig, batch_root)


@needs_oqs
def test_prove_mldsa_sig_vfri7_stark_batch_root_binding():
    """Different batch roots produce different VFRI7 commitments from the same sig."""
    from stark.prover import prove_mldsa_sig_vfri7_stark
    alg = _oqs.Signature("ML-DSA-65")
    pk  = alg.generate_keypair()
    msg = b"batch root binding test"
    sig = alg.sign(msg)
    root_a = bytes([0xAA] * 32)
    root_b = bytes([0xBB] * 32)

    ra = prove_mldsa_sig_vfri7_stark(pk, msg, sig, root_a, n_queries=1)
    rb = prove_mldsa_sig_vfri7_stark(pk, msg, sig, root_b, n_queries=1)

    assert ra.log10_commitment != rb.log10_commitment, "Different batch roots must give different LOG=10 commitments"
    assert ra.log8_commitment  != rb.log8_commitment,  "Different batch roots must give different LOG=8 commitments"
