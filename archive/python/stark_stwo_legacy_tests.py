"""ARCHIVED — NOT IMPORTED, NOT COLLECTED BY pytest.

Removed by the Ф1 narrowing; restored here from tests/test_stark_stwo.py@f2020d9 so the code
stays visible in the repository rather than only in git history.
To bring an item back, paste it into tests/test_stark_stwo.py and re-run the suite.
"""

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


# ── VFRI8: Poseidon2 trace commitment ─────────────────────────────────────────

@needs_ext
def test_gen_mldsa_v23_vfri8_hints_schema():
    """LOG=10 VFRI8 result has expected structure and n_cols=1298."""
    from stark.prover import gen_mldsa_v23_vfri8_hints, MldsaV23VFRI8HintResult
    z, c, t1, a_hat = _v23_inputs(14000)
    r = gen_mldsa_v23_vfri8_hints(z, c, t1, a_hat, _VFRI8_BATCH_ROOT, n_queries=1, num_folds=3)
    assert isinstance(r, MldsaV23VFRI8HintResult)
    assert r.n_cols == 1298
    assert r.n_queries == 1
    assert isinstance(r.proof, bytes) and len(r.proof) >= 700
    assert isinstance(r.commitment, str) and len(r.commitment) == 32
    assert isinstance(r.query_hints, bytes) and len(r.query_hints) > 0

@needs_ext
def test_gen_mldsa_v23_vfri8_hints_deterministic():
    """Same inputs produce identical VFRI8 LOG=10 outputs."""
    from stark.prover import gen_mldsa_v23_vfri8_hints
    z, c, t1, a_hat = _v23_inputs(14100)
    r1 = gen_mldsa_v23_vfri8_hints(z, c, t1, a_hat, _VFRI8_BATCH_ROOT, n_queries=1, num_folds=3)
    r2 = gen_mldsa_v23_vfri8_hints(z, c, t1, a_hat, _VFRI8_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r1.commitment == r2.commitment
    assert r1.query_hints == r2.query_hints

@needs_ext
def test_gen_mldsa_v23_vfri8_hints_differs_from_vfri7():
    """VFRI8 Poseidon2 transcript differs from VFRI7 Blake2s transcript."""
    from stark.prover import gen_mldsa_v23_vfri8_hints, gen_mldsa_v23_vfri7_hints
    z, c, t1, a_hat = _v23_inputs(14200)
    r7 = gen_mldsa_v23_vfri7_hints(z, c, t1, a_hat, _VFRI8_BATCH_ROOT, n_queries=1, num_folds=3)
    r8 = gen_mldsa_v23_vfri8_hints(z, c, t1, a_hat, _VFRI8_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r7.query_hints != r8.query_hints, "VFRI8 must differ from VFRI7 (Poseidon2 vs Blake2s)"

@needs_ext
def test_gen_mldsa_v23_vfri8_hints_batch_root_binding():
    """Different batch roots produce different VFRI8 LOG=10 hints."""
    from stark.prover import gen_mldsa_v23_vfri8_hints
    z, c, t1, a_hat = _v23_inputs(14300)
    root_a = bytes([0xAA] * 32)
    root_b = bytes([0xBB] * 32)
    ra = gen_mldsa_v23_vfri8_hints(z, c, t1, a_hat, root_a, n_queries=1, num_folds=3)
    rb = gen_mldsa_v23_vfri8_hints(z, c, t1, a_hat, root_b, n_queries=1, num_folds=3)
    assert ra.query_hints != rb.query_hints, "Different batch roots must produce different VFRI8 hints"

@needs_ext
def test_gen_mldsa_v23_vfri8_hints_log8_schema():
    """LOG=8 VFRI8 result has expected structure and n_cols=2206."""
    from stark.prover import gen_mldsa_v23_vfri8_hints_log8, MldsaV23VFRI8Log8HintResult
    z, c, t1, a_hat = _v23_inputs(14400)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri8_hints_log8(z, c, t1, a_hat, hints, _VFRI8_BATCH_ROOT, n_queries=1, num_folds=3)
    assert isinstance(r, MldsaV23VFRI8Log8HintResult)
    assert r.n_cols == 2206
    assert r.n_queries == 1
    assert isinstance(r.proof, bytes) and len(r.proof) >= 700
    assert isinstance(r.commitment, str) and len(r.commitment) == 32
    assert isinstance(r.query_hints, bytes) and len(r.query_hints) > 0

@needs_ext
def test_gen_mldsa_v23_vfri8_hints_log8_differs_from_vfri7():
    """VFRI8 LOG=8 hints differ from VFRI7 LOG=8 (Poseidon2 vs Blake2s)."""
    from stark.prover import gen_mldsa_v23_vfri8_hints_log8, gen_mldsa_v23_vfri7_hints_log8
    z, c, t1, a_hat = _v23_inputs(14500)
    hints = _make_log8_hints()
    r7 = gen_mldsa_v23_vfri7_hints_log8(z, c, t1, a_hat, hints, _VFRI8_BATCH_ROOT, n_queries=1, num_folds=3)
    r8 = gen_mldsa_v23_vfri8_hints_log8(z, c, t1, a_hat, hints, _VFRI8_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r7.query_hints != r8.query_hints, "VFRI8 LOG=8 must differ from VFRI7 (different hash backend)"

@needs_ext
def test_gen_mldsa_v23_vfri8_cross_bound_hints_schema():
    """Cross-bound VFRI8 result has correct structure for both LOG groups."""
    from stark.prover import (
        gen_mldsa_v23_vfri8_cross_bound_hints,
        FullV23VFRI8CrossBoundHintResult,
    )
    z, c, t1, a_hat = _v23_inputs(14600)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri8_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI8_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    assert isinstance(r, FullV23VFRI8CrossBoundHintResult)
    assert isinstance(r.log10_proof, bytes) and len(r.log10_proof) >= 700
    assert isinstance(r.log10_commitment, str) and len(r.log10_commitment) == 32
    assert isinstance(r.log10_query_hints, bytes) and len(r.log10_query_hints) > 0
    assert isinstance(r.log8_proof, bytes) and len(r.log8_proof) >= 700
    assert isinstance(r.log8_commitment, str) and len(r.log8_commitment) == 32
    assert isinstance(r.log8_query_hints, bytes) and len(r.log8_query_hints) > 0
    assert r.batch_merkle_root == _VFRI8_BATCH_ROOT
    assert r.n_queries == 1

@needs_ext
def test_gen_mldsa_v23_vfri8_cross_bound_hints_deterministic():
    """Same inputs produce identical cross-bound VFRI8 outputs."""
    from stark.prover import gen_mldsa_v23_vfri8_cross_bound_hints
    z, c, t1, a_hat = _v23_inputs(14700)
    hints = _make_log8_hints()
    r1 = gen_mldsa_v23_vfri8_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI8_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    r2 = gen_mldsa_v23_vfri8_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI8_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    assert r1.log10_commitment == r2.log10_commitment
    assert r1.log10_query_hints == r2.log10_query_hints
    assert r1.log8_commitment == r2.log8_commitment
    assert r1.log8_query_hints == r2.log8_query_hints

@needs_ext
def test_gen_mldsa_v23_vfri8_cross_bound_hints_batch_root_changes():
    """Different batch roots produce different cross-bound VFRI8 commitments."""
    from stark.prover import gen_mldsa_v23_vfri8_cross_bound_hints
    z, c, t1, a_hat = _v23_inputs(14800)
    hints = _make_log8_hints()
    root_a = bytes([0xAA] * 32)
    root_b = bytes([0xBB] * 32)
    ra = gen_mldsa_v23_vfri8_cross_bound_hints(
        z, c, t1, a_hat, hints, root_a, n_queries=1, num_folds_log10=3,
    )
    rb = gen_mldsa_v23_vfri8_cross_bound_hints(
        z, c, t1, a_hat, hints, root_b, n_queries=1, num_folds_log10=3,
    )
    assert ra.log10_commitment != rb.log10_commitment, "Different batch roots → different LOG=10 commitments"
    assert ra.log8_commitment != rb.log8_commitment, "Different batch roots → different LOG=8 commitments"

@needs_ext
def test_gen_mldsa_v23_vfri8_cross_bound_total_calldata():
    """Cross-bound VFRI8 combined calldata < 20 KB."""
    from stark.prover import gen_mldsa_v23_vfri8_cross_bound_hints
    z, c, t1, a_hat = _v23_inputs(14900)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri8_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI8_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    total = len(r.log10_query_hints) + len(r.log8_query_hints)
    assert total < 20_000, f"Combined cross-bound VFRI8 hints {total} B should be < 20 KB"

@needs_ext
def test_gen_mldsa_v23_vfri8_cross_bound_differs_from_vfri7():
    """VFRI8 cross-bound hints differ from VFRI7 (Poseidon2 vs Blake2s transcript)."""
    from stark.prover import (
        gen_mldsa_v23_vfri8_cross_bound_hints,
        gen_mldsa_v23_vfri7_cross_bound_hints,
    )
    z, c, t1, a_hat = _v23_inputs(15000)
    hints = _make_log8_hints()
    r7 = gen_mldsa_v23_vfri7_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI8_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    r8 = gen_mldsa_v23_vfri8_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI8_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    assert r7.log10_query_hints != r8.log10_query_hints, "VFRI8 must differ from VFRI7 (Poseidon2 vs Blake2s)"
    assert r7.log8_query_hints != r8.log8_query_hints, "VFRI8 LOG=8 must differ from VFRI7"


# ── VFRI9: last-layer FRI check + wide Poseidon2 nodes ────────────────────────

@needs_ext
def test_gen_mldsa_v23_vfri9_hints_schema():
    """LOG=10 VFRI9 result has expected structure and n_cols=1298."""
    from stark.prover import gen_mldsa_v23_vfri9_hints, MldsaV23VFRI9HintResult
    z, c, t1, a_hat = _v23_inputs(16000)
    r = gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, _VFRI9_BATCH_ROOT, n_queries=1, num_folds=3)
    assert isinstance(r, MldsaV23VFRI9HintResult)
    assert r.n_cols == 1298
    assert r.n_queries == 1
    assert isinstance(r.proof, bytes) and len(r.proof) >= 700
    assert isinstance(r.commitment, str) and len(r.commitment) == 32
    assert isinstance(r.query_hints, bytes) and len(r.query_hints) > 0
    # Version marker: proof[0:8] = 3 (little-endian)
    assert int.from_bytes(r.proof[0:8], "little") == 3

@needs_ext
def test_gen_mldsa_v23_vfri9_hints_deterministic():
    """Same inputs produce identical VFRI9 LOG=10 outputs."""
    from stark.prover import gen_mldsa_v23_vfri9_hints
    z, c, t1, a_hat = _v23_inputs(16100)
    r1 = gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, _VFRI9_BATCH_ROOT, n_queries=1, num_folds=3)
    r2 = gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, _VFRI9_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r1.commitment == r2.commitment
    assert r1.query_hints == r2.query_hints

@needs_ext
def test_gen_mldsa_v23_vfri9_hints_differs_from_vfri8():
    """VFRI9 wide-node transcript differs from VFRI8."""
    from stark.prover import gen_mldsa_v23_vfri9_hints, gen_mldsa_v23_vfri8_hints
    z, c, t1, a_hat = _v23_inputs(16200)
    r8 = gen_mldsa_v23_vfri8_hints(z, c, t1, a_hat, _VFRI9_BATCH_ROOT, n_queries=1, num_folds=3)
    r9 = gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, _VFRI9_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r8.query_hints != r9.query_hints, "VFRI9 must differ from VFRI8 (wide nodes + last layer)"
    assert r8.proof[8:40] != r9.proof[8:40], "VFRI9 trace root must differ (wide leaf hash)"

@needs_ext
def test_gen_mldsa_v23_vfri9_full_root_binding():
    """VFRI9 binds ALL 32 bytes of the batch root, not just the low 4 bytes."""
    from stark.prover import gen_mldsa_v23_vfri9_hints
    z, c, t1, a_hat = _v23_inputs(16300)
    # Roots agreeing in the low 4 bytes but differing in the high bytes.
    root_a = bytes([0xAA] + [0] * 27 + [1, 2, 3, 4])
    root_b = bytes([0xBB] + [0] * 27 + [1, 2, 3, 4])
    ra = gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, root_a, n_queries=1, num_folds=3)
    rb = gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, root_b, n_queries=1, num_folds=3)
    assert ra.query_hints != rb.query_hints, \
        "VFRI9 Fiat-Shamir must depend on the full 32-byte batch root"

@needs_ext
def test_gen_mldsa_v23_vfri9_hints_log8_schema():
    """LOG=8 VFRI9 result has expected structure and n_cols=2206."""
    from stark.prover import gen_mldsa_v23_vfri9_hints_log8, MldsaV23VFRI9Log8HintResult
    z, c, t1, a_hat = _v23_inputs(16400)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri9_hints_log8(z, c, t1, a_hat, hints, _VFRI9_BATCH_ROOT, n_queries=1, num_folds=3)
    assert isinstance(r, MldsaV23VFRI9Log8HintResult)
    assert r.n_cols == 2206
    assert isinstance(r.proof, bytes) and len(r.proof) >= 700
    assert isinstance(r.commitment, str) and len(r.commitment) == 32
    assert isinstance(r.query_hints, bytes) and len(r.query_hints) > 0

@needs_ext
def test_gen_mldsa_v23_vfri9_last_layer_evals_present():
    """VFRI9 hints carry the last-layer evaluations array (head slot 3)."""
    from stark.prover import gen_mldsa_v23_vfri9_hints
    z, c, t1, a_hat = _v23_inputs(16500)
    r = gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, _VFRI9_BATCH_ROOT, n_queries=1, num_folds=3)
    h = r.query_hints
    evals_offset = int.from_bytes(h[3 * 32 + 24:4 * 32], "big")
    assert evals_offset == 6 * 32, "lastLayerEvals must directly follow the 6-slot head"
    evals_len = int.from_bytes(h[evals_offset + 24:evals_offset + 32], "big")
    # tree_depth=10, 3 folds → 1024 / 2^3 = 128 last-layer evaluations
    assert evals_len == 128

@needs_ext
def test_gen_mldsa_v23_vfri9_cross_bound_hints_schema():
    """Cross-bound VFRI9 result has correct structure for both LOG groups."""
    from stark.prover import (
        gen_mldsa_v23_vfri9_cross_bound_hints,
        FullV23VFRI9CrossBoundHintResult,
    )
    z, c, t1, a_hat = _v23_inputs(16600)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri9_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI9_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    assert isinstance(r, FullV23VFRI9CrossBoundHintResult)
    assert isinstance(r.log10_proof, bytes) and len(r.log10_proof) >= 700
    assert isinstance(r.log10_commitment, str) and len(r.log10_commitment) == 32
    assert isinstance(r.log10_query_hints, bytes) and len(r.log10_query_hints) > 0
    assert isinstance(r.log8_proof, bytes) and len(r.log8_proof) >= 700
    assert isinstance(r.log8_commitment, str) and len(r.log8_commitment) == 32
    assert isinstance(r.log8_query_hints, bytes) and len(r.log8_query_hints) > 0
    assert r.batch_merkle_root == _VFRI9_BATCH_ROOT
    assert r.n_queries == 1

@needs_ext
def test_gen_mldsa_v23_vfri9_cross_bound_deterministic():
    """Same inputs produce identical cross-bound VFRI9 outputs."""
    from stark.prover import gen_mldsa_v23_vfri9_cross_bound_hints
    z, c, t1, a_hat = _v23_inputs(16700)
    hints = _make_log8_hints()
    r1 = gen_mldsa_v23_vfri9_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI9_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    r2 = gen_mldsa_v23_vfri9_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI9_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    assert r1.log10_commitment == r2.log10_commitment
    assert r1.log10_query_hints == r2.log10_query_hints
    assert r1.log8_commitment == r2.log8_commitment
    assert r1.log8_query_hints == r2.log8_query_hints

@needs_ext
def test_gen_mldsa_v23_vfri9_num_folds_mismatch_raises():
    """Conflicting num_folds for the two LOG groups raises ValueError."""
    from stark.prover import gen_mldsa_v23_vfri9_cross_bound_hints
    z, c, t1, a_hat = _v23_inputs(16800)
    hints = _make_log8_hints()
    import pytest as _pytest
    with _pytest.raises(ValueError, match="num_folds"):
        gen_mldsa_v23_vfri9_cross_bound_hints(
            z, c, t1, a_hat, hints, _VFRI9_BATCH_ROOT,
            n_queries=1, num_folds_log10=3, num_folds_log8=4,
        )

@needs_oqs
def test_prove_mldsa_sig_vfri9_stark_schema():
    """prove_mldsa_sig_vfri9_stark returns a well-formed FullV23VFRI9CrossBoundHintResult."""
    from stark.prover import prove_mldsa_sig_vfri9_stark, FullV23VFRI9CrossBoundHintResult
    alg = _oqs.Signature("ML-DSA-65")
    pk  = alg.generate_keypair()
    msg = b"qlsa vfri9 e2e test"
    sig = alg.sign(msg)
    batch_root = bytes(range(32))

    r = prove_mldsa_sig_vfri9_stark(pk, msg, sig, batch_root, n_queries=1)

    assert isinstance(r, FullV23VFRI9CrossBoundHintResult)
    assert len(r.log10_proof) >= 700
    assert len(bytes.fromhex(r.log10_commitment)) == 16
    assert len(bytes.fromhex(r.log8_commitment)) == 16
    assert r.batch_merkle_root == batch_root


# ── VFRI10: VFRI9 protocol on the Poseidon2 t=4 hash backend ──────────────────

@needs_ext
def test_gen_mldsa_v23_vfri10_hints_schema():
    """LOG=10 VFRI10 result has expected structure, n_cols=1298, marker=4."""
    from stark.prover import gen_mldsa_v23_vfri10_hints, MldsaV23VFRI10HintResult
    z, c, t1, a_hat = _v23_inputs(17000)
    r = gen_mldsa_v23_vfri10_hints(z, c, t1, a_hat, _VFRI10_BATCH_ROOT, n_queries=1, num_folds=3)
    assert isinstance(r, MldsaV23VFRI10HintResult)
    assert r.n_cols == 1298
    assert r.n_queries == 1
    assert isinstance(r.proof, bytes) and len(r.proof) >= 700
    assert isinstance(r.commitment, str) and len(r.commitment) == 32
    assert isinstance(r.query_hints, bytes) and len(r.query_hints) > 0
    # Version marker: proof[0:8] = 4 (little-endian; VFRI9 uses 3)
    assert int.from_bytes(r.proof[0:8], "little") == 4

@needs_ext
def test_gen_mldsa_v23_vfri10_hints_deterministic():
    """Same inputs produce identical VFRI10 LOG=10 outputs."""
    from stark.prover import gen_mldsa_v23_vfri10_hints
    z, c, t1, a_hat = _v23_inputs(17100)
    r1 = gen_mldsa_v23_vfri10_hints(z, c, t1, a_hat, _VFRI10_BATCH_ROOT, n_queries=1, num_folds=3)
    r2 = gen_mldsa_v23_vfri10_hints(z, c, t1, a_hat, _VFRI10_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r1.commitment == r2.commitment
    assert r1.query_hints == r2.query_hints

@needs_ext
def test_gen_mldsa_v23_vfri10_hints_differs_from_vfri9():
    """VFRI10 t=4 backend yields a different transcript and trace root than VFRI9."""
    from stark.prover import gen_mldsa_v23_vfri10_hints, gen_mldsa_v23_vfri9_hints
    z, c, t1, a_hat = _v23_inputs(17200)
    r9 = gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, _VFRI10_BATCH_ROOT, n_queries=1, num_folds=3)
    r10 = gen_mldsa_v23_vfri10_hints(z, c, t1, a_hat, _VFRI10_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r9.query_hints != r10.query_hints, "VFRI10 must differ from VFRI9 (t=4 backend)"
    assert r9.proof[8:40] != r10.proof[8:40], "VFRI10 trace root must differ (t=4 leaf hash)"

@needs_ext
def test_gen_mldsa_v23_vfri10_full_root_binding():
    """VFRI10 binds ALL 32 bytes of the batch root, not just the low 4 bytes."""
    from stark.prover import gen_mldsa_v23_vfri10_hints
    z, c, t1, a_hat = _v23_inputs(17300)
    root_a = bytes([0xAA] + [0] * 27 + [1, 2, 3, 4])
    root_b = bytes([0xBB] + [0] * 27 + [1, 2, 3, 4])
    ra = gen_mldsa_v23_vfri10_hints(z, c, t1, a_hat, root_a, n_queries=1, num_folds=3)
    rb = gen_mldsa_v23_vfri10_hints(z, c, t1, a_hat, root_b, n_queries=1, num_folds=3)
    assert ra.query_hints != rb.query_hints, \
        "VFRI10 Fiat-Shamir must depend on the full 32-byte batch root"

@needs_ext
def test_gen_mldsa_v23_vfri10_hints_log8_schema():
    """LOG=8 VFRI10 result has expected structure and n_cols=2206."""
    from stark.prover import gen_mldsa_v23_vfri10_hints_log8, MldsaV23VFRI10Log8HintResult
    z, c, t1, a_hat = _v23_inputs(17400)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri10_hints_log8(z, c, t1, a_hat, hints, _VFRI10_BATCH_ROOT, n_queries=1, num_folds=3)
    assert isinstance(r, MldsaV23VFRI10Log8HintResult)
    assert r.n_cols == 2206
    assert isinstance(r.proof, bytes) and len(r.proof) >= 700
    assert isinstance(r.commitment, str) and len(r.commitment) == 32
    assert isinstance(r.query_hints, bytes) and len(r.query_hints) > 0

@needs_ext
def test_gen_mldsa_v23_vfri10_cross_bound_hints_schema():
    """Cross-bound VFRI10 result has correct structure for both LOG groups."""
    from stark.prover import (
        gen_mldsa_v23_vfri10_cross_bound_hints,
        FullV23VFRI10CrossBoundHintResult,
    )
    z, c, t1, a_hat = _v23_inputs(17600)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri10_cross_bound_hints(
        z, c, t1, a_hat, hints, _VFRI10_BATCH_ROOT, n_queries=1, num_folds_log10=3,
    )
    assert isinstance(r, FullV23VFRI10CrossBoundHintResult)
    assert isinstance(r.log10_proof, bytes) and len(r.log10_proof) >= 700
    assert isinstance(r.log10_commitment, str) and len(r.log10_commitment) == 32
    assert isinstance(r.log10_query_hints, bytes) and len(r.log10_query_hints) > 0
    assert isinstance(r.log8_proof, bytes) and len(r.log8_proof) >= 700
    assert isinstance(r.log8_commitment, str) and len(r.log8_commitment) == 32
    assert isinstance(r.log8_query_hints, bytes) and len(r.log8_query_hints) > 0
    assert r.batch_merkle_root == _VFRI10_BATCH_ROOT
    assert r.n_queries == 1
    # Both groups carry the VFRI10 version marker.
    assert int.from_bytes(r.log10_proof[0:8], "little") == 4
    assert int.from_bytes(r.log8_proof[0:8], "little") == 4

@needs_ext
def test_gen_mldsa_v23_vfri10_num_folds_mismatch_raises():
    """Conflicting num_folds for the two LOG groups raises ValueError."""
    from stark.prover import gen_mldsa_v23_vfri10_cross_bound_hints
    z, c, t1, a_hat = _v23_inputs(17800)
    hints = _make_log8_hints()
    import pytest as _pytest
    with _pytest.raises(ValueError, match="num_folds"):
        gen_mldsa_v23_vfri10_cross_bound_hints(
            z, c, t1, a_hat, hints, _VFRI10_BATCH_ROOT,
            n_queries=1, num_folds_log10=3, num_folds_log8=4,
        )

@needs_oqs
def test_prove_mldsa_sig_vfri10_stark_schema():
    """prove_mldsa_sig_vfri10_stark returns a well-formed cross-bound result."""
    from stark.prover import prove_mldsa_sig_vfri10_stark, FullV23VFRI10CrossBoundHintResult
    alg = _oqs.Signature("ML-DSA-65")
    pk  = alg.generate_keypair()
    msg = b"qlsa vfri10 e2e test"
    sig = alg.sign(msg)
    batch_root = bytes(range(32))

    r = prove_mldsa_sig_vfri10_stark(pk, msg, sig, batch_root, n_queries=1)

    assert isinstance(r, FullV23VFRI10CrossBoundHintResult)
    assert len(r.log10_proof) >= 700
    assert len(bytes.fromhex(r.log10_commitment)) == 16
    assert len(bytes.fromhex(r.log8_commitment)) == 16
    assert r.batch_merkle_root == batch_root
    assert int.from_bytes(r.log10_proof[0:8], "little") == 4


# ── VFRI11: VFRI10 protocol on the Poseidon2 t=8 hash backend ─────────────────

@needs_ext
def test_gen_mldsa_v23_vfri11_hints_differs_from_vfri10():
    """VFRI11 t=8 backend yields a different transcript and trace root than VFRI10."""
    from stark.prover import gen_mldsa_v23_vfri11_hints, gen_mldsa_v23_vfri10_hints
    z, c, t1, a_hat = _v23_inputs(19200)
    r10 = gen_mldsa_v23_vfri10_hints(z, c, t1, a_hat, _VFRI11_BATCH_ROOT, n_queries=1, num_folds=3)
    r11 = gen_mldsa_v23_vfri11_hints(z, c, t1, a_hat, _VFRI11_BATCH_ROOT, n_queries=1, num_folds=3)
    assert r10.query_hints != r11.query_hints, "VFRI11 must differ from VFRI10 (t=8 backend)"
    assert r10.proof[8:40] != r11.proof[8:40], "VFRI11 trace root must differ (t=8 leaf hash)"
