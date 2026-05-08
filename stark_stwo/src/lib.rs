pub mod air;
pub mod mldsa;
pub mod mldsa_intt_air;
pub mod mldsa_norm_check_air;
pub mod mldsa_ntt_air;
pub mod mldsa_poly_add_air;
pub mod mldsa_poly_mul_air;
pub mod mldsa_verify_stark;
pub mod poseidon2;
pub mod poseidon2_air;
pub mod poseidon2_merkle_air;
pub mod trace;

use blake2::{Blake2s256, Digest};
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::fields::m31::BaseField; // used in tests
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::verifier::verify;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::TraceLocationAllocator;

use air::{HashChainComponent, HashChainEval};

// ─── Commitment helpers ────────────────────────────────────────────────────────
//
// Two distinct commitment schemes coexist:
//
// A) Hash-chain / Poseidon2 / Merkle circuits (128-bit with proof-binding suffix):
//    bytes [0:4]  — M31 field element (circuit output, le-u32)
//    bytes [4:16] — Blake2s(m31_le ∥ proof[0:32])[0:12]  96-bit proof-binding suffix
//    Used by prove/verify_hash_chain, prove/verify_hash_chain_poseidon2, prove/verify_merkle_root.
//
// B) Polynomial circuits — NTT / INTT / PolyMul / PolyAdd (128-bit output fingerprint):
//    bytes [0:3]  — fp[0] = Blake2s256(output_coeffs)[0:4]  % M31_MODULUS
//    bytes [4:7]  — fp[1] = Blake2s256(output_coeffs)[4:8]  % M31_MODULUS
//    bytes [8:11] — fp[2] = Blake2s256(output_coeffs)[8:12] % M31_MODULUS
//    bytes [12:15]— fp[3] = Blake2s256(output_coeffs)[12:16]% M31_MODULUS
//    ALL 4 words are mixed into the Fiat-Shamir channel → 128-bit FS binding.
//    Used by prove/verify_ntt, prove/verify_poly_mul, prove/verify_poly_add (INTT).
//    Birthday bound: ~2^{-64} for collision in 4 independent M31 words.

// ── Scheme A helpers ─────────────────────────────────────────────────────────

/// Build a 128-bit commitment (32 hex chars) from the circuit output and proof bytes.
fn build_commitment_128(m31_val: u32, proof_bytes: &[u8]) -> String {
    let m31_le = m31_val.to_le_bytes();
    let mut h = Blake2s256::new();
    h.update(m31_le);
    h.update(&proof_bytes[..proof_bytes.len().min(32)]);
    let hash = h.finalize();
    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&m31_le);
    buf[4..16].copy_from_slice(&hash[0..12]);
    hex::encode(buf)
}

/// Parse and validate a Scheme-A commitment. Returns the M31 value for Fiat-Shamir mixing.
/// Returns Err if the hex is malformed, the M31 is out of range, or the suffix is wrong.
fn parse_commitment_128(commitment_hex: &str, proof_bytes: &[u8]) -> Result<u32, String> {
    let bytes = hex::decode(commitment_hex)
        .map_err(|e| format!("invalid commitment hex: {e}"))?;
    if bytes.len() != 16 {
        return Err(format!(
            "commitment must be 16 bytes (32 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let m31_bytes: [u8; 4] = bytes[0..4].try_into().unwrap();
    let m31_val = u32::from_le_bytes(m31_bytes);
    if m31_val >= M31_MODULUS {
        return Err("commitment M31 component out of M31 field range [0, 2^31 − 2]".into());
    }
    let mut h = Blake2s256::new();
    h.update(m31_bytes);
    h.update(&proof_bytes[..proof_bytes.len().min(32)]);
    let expected = h.finalize();
    if bytes[4..16] != expected[0..12] {
        return Err("commitment integrity check failed (suffix mismatch)".into());
    }
    Ok(m31_val)
}

// ── Scheme B helpers ─────────────────────────────────────────────────────────

/// Compute a 128-bit output fingerprint for polynomial circuits (NTT, INTT, PolyMul, PolyAdd).
///
/// Returns 4 M31-reduced u32 words derived from Blake2s256(output_coefficients).
/// All 4 words must be mixed into the Fiat-Shamir channel via `channel.mix_u32s(&fp)`.
/// This gives 128-bit binding of the FRI query challenges to the circuit output,
/// replacing the previous 32-bit binding that was vulnerable to birthday attacks (~2^16).
pub fn output_fingerprint(coeffs: &[i64]) -> [u32; 4] {
    let mut h = Blake2s256::new();
    for &c in coeffs { h.update(&(c as u32).to_le_bytes()); }
    let hash = h.finalize();
    std::array::from_fn(|i| {
        u32::from_le_bytes(hash[i*4..(i+1)*4].try_into().unwrap()) % M31_MODULUS
    })
}

/// Encode a Scheme-B polynomial commitment as a 32-hex-char string.
pub(crate) fn build_poly_commitment(fp: &[u32; 4]) -> String {
    let mut buf = [0u8; 16];
    for (i, &w) in fp.iter().enumerate() {
        buf[i*4..(i+1)*4].copy_from_slice(&w.to_le_bytes());
    }
    hex::encode(buf)
}

/// Decode and validate a Scheme-B polynomial commitment.
/// Returns Err if hex is malformed or any word exceeds M31_MODULUS.
pub(crate) fn parse_poly_commitment(commitment_hex: &str) -> Result<[u32; 4], String> {
    let bytes = hex::decode(commitment_hex)
        .map_err(|e| format!("invalid commitment hex: {e}"))?;
    if bytes.len() != 16 {
        return Err(format!(
            "commitment must be 16 bytes (32 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let words: [u32; 4] = std::array::from_fn(|i| {
        u32::from_le_bytes(bytes[i*4..(i+1)*4].try_into().unwrap())
    });
    for (i, &w) in words.iter().enumerate() {
        if w >= M31_MODULUS {
            return Err(format!("commitment word {i} = {w} out of M31 range [0, 2^31-2]"));
        }
    }
    Ok(words)
}

/// log2 of the FRI blowup factor. 4 → blowup 16× (security margin ~120-bit at 30 FRI rounds).
/// Do NOT reduce below 4 for any network-facing deployment.
const LOG_BLOWUP: u32 = 4;

fn make_config(log_size: u32) -> PcsConfig {
    let mut c = PcsConfig::default();
    c.fri_config.log_blowup_factor = LOG_BLOWUP;
    PcsConfig {
        lifting_log_size: Some(log_size + LOG_BLOWUP),
        ..c
    }
}

/// Prove a hash-chain over `leaves`.
///
/// Returns `(proof_bytes, commitment_hex, log_size)`.
/// `commitment_hex` is the 8-char little-endian hex of `h[last_row]` (4 bytes, M31).
pub fn prove_hash_chain(leaves: &[u64]) -> Result<(Vec<u8>, String, u32), String> {
    if leaves.is_empty() {
        return Err("leaves must not be empty".into());
    }
    let log_size = trace::compute_log_size(leaves.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("input too large: log_size {log_size} exceeds MAX_LOG_SIZE {MAX_LOG_SIZE}"));
    }

    let (columns, commitment) = trace::build_trace(leaves);

    // lifting_log_size = log_size + LOG_BLOWUP so that max_log_degree_bound = log_size.
    // This keeps the OODS mask step (CanonicCoset::new(log_size).step()) and the vanishing
    // denominator consistent between the domain evaluator and the OODS point evaluator.
    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Preprocessed trace (none for this circuit)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    // Main trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    // Bind commitment to Fiat-Shamir transcript (C-2 fix).
    channel.mix_u32s(&[commitment.0]);

    let component = HashChainComponent::new(
        &mut TraceLocationAllocator::default(),
        HashChainEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        channel,
        commitment_scheme,
    )
    .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    let commitment_hex = build_commitment_128(commitment.0, &proof_bytes);

    Ok((proof_bytes, commitment_hex, log_size))
}

/// Maximum log2 trace size accepted by the verifier (2^28 rows ≈ 268 M rows).
/// Prevents an untrusted `log_size` field from triggering OOM inside Stwo.
const MAX_LOG_SIZE: u32 = 28;

/// M31 field modulus = 2^31 − 1. Commitments are M31 elements; values ≥ this
/// are not canonical field elements and must be rejected before `from_u32_unchecked`.
const M31_MODULUS: u32 = (1u32 << 31) - 1;

/// Maximum proof size accepted by the verifiers (8 MB).
/// Realistic Stwo proofs are 90–200 KB; 8 MB gives generous headroom while preventing
/// crafted oversized proofs from triggering multi-second heap allocations (DoS risk).
const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;

/// Verify a proof previously produced by `prove_hash_chain`.
pub fn verify_hash_chain(
    proof_bytes: &[u8],
    commitment_hex: &str,
    log_size: u32,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;

    if log_size < trace::MIN_LOG_SIZE || log_size > MAX_LOG_SIZE {
        return Err(format!(
            "log_size {log_size} out of valid range [{}, {MAX_LOG_SIZE}]",
            trace::MIN_LOG_SIZE
        ));
    }

    // Parse and validate 128-bit commitment; extracts M31 for Fiat-Shamir.
    let commitment_val = parse_commitment_128(commitment_hex, proof_bytes)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(proof_bytes, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>())
            .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;

    let component = HashChainComponent::new(
        &mut TraceLocationAllocator::default(),
        HashChainEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected 2 commitments, got {}",
            proof.commitments.len()
        ));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Mirror the prover's channel.mix_u32s (Fiat-Shamir binding, C-2 fix).
    verifier_channel.mix_u32s(&[commitment_val]);

    let result = verify::<Blake2sM31MerkleChannel>(
        &[&component],
        verifier_channel,
        commitment_scheme,
        proof,
    );

    Ok(result.is_ok())
}

// ─── Poseidon2-over-M31 hash chain (MVP-3+) ──────────────────────────────────

/// Prove a Poseidon2 sponge hash chain over `leaves`.
///
/// Returns `(proof_bytes, commitment_hex, log_size)`.
/// `commitment_hex` is the 8-char little-endian hex of the M31 commitment (s0 at
/// the last real row — i.e. after absorbing all leaves).
pub fn prove_hash_chain_poseidon2(leaves: &[u64]) -> Result<(Vec<u8>, String, u32), String> {
    use poseidon2_air::{build_trace, compute_log_size, preprocessed_column_ids};

    if leaves.is_empty() {
        return Err("leaves must not be empty".into());
    }
    let log_size = compute_log_size(leaves.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("input too large: log_size {log_size} exceeds MAX_LOG_SIZE {MAX_LOG_SIZE}"));
    }

    let (main_cols, preproc_cols, commitment) = build_trace(leaves);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: preprocessed columns (rc0, rc1, is_init, init_row)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: main trace (s0, s1, t0, t1, inp0, leaf)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_cols);
    tree_builder.commit(channel);

    // Bind commitment to Fiat-Shamir transcript (C-2 fix).
    channel.mix_u32s(&[commitment.0]);

    let ids = preprocessed_column_ids();
    let component = poseidon2_air::Poseidon2Component::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&ids),
        poseidon2_air::Poseidon2Eval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        channel,
        commitment_scheme,
    )
    .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    let commitment_hex = build_commitment_128(commitment.0, &proof_bytes);
    Ok((proof_bytes, commitment_hex, log_size))
}

/// Verify a proof previously produced by `prove_hash_chain_poseidon2`.
pub fn verify_hash_chain_poseidon2(
    proof_bytes: &[u8],
    commitment_hex: &str,
    log_size: u32,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use poseidon2_air::preprocessed_column_ids;

    if log_size < poseidon2_air::MIN_LOG_SIZE || log_size > MAX_LOG_SIZE {
        return Err(format!(
            "log_size {log_size} out of valid range [{}, {MAX_LOG_SIZE}]",
            poseidon2_air::MIN_LOG_SIZE
        ));
    }

    // Parse 128-bit commitment, validate suffix, extract M31 for Fiat-Shamir.
    let commitment_val_p2 = parse_commitment_128(commitment_hex, proof_bytes)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(proof_bytes, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>())
            .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;

    let ids = preprocessed_column_ids();
    let component = poseidon2_air::Poseidon2Component::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&ids),
        poseidon2_air::Poseidon2Eval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected 2 commitments, got {}",
            proof.commitments.len()
        ));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Mirror the prover's channel.mix_u32s so the Fiat-Shamir transcript matches (C-2 fix).
    verifier_channel.mix_u32s(&[commitment_val_p2]);

    let result = verify::<Blake2sM31MerkleChannel>(
        &[&component],
        verifier_channel,
        commitment_scheme,
        proof,
    );

    Ok(result.is_ok())
}

// ─── NTT STARK prover/verifier (MVP-3+) ──────────────────────────────────────

/// Prove a forward NTT over Z_q[X]/(X^{256}+1) using a Circle STARK.
///
/// Input `f` must have coefficients in `[0, Q)` (Q = 8 380 417).
///
/// Returns `(proof_bytes, commitment_hex, ntt_out)`:
/// - `proof_bytes`: serialised STARK proof (~90–200 KB)
/// - `commitment_hex`: 32-hex-char 128-bit Scheme-B commitment (4 M31 words)
/// - `ntt_out`: the NTT of `f` (forward transform result)
///
/// # Soundness
/// The butterfly-addition/subtraction constraints (C2–C5) are fully sound in M31.
/// The multiplication constraint (C1) requires range-check arguments for full
/// soundness (planned for MVP-4); the proof is sound for honest provers.
/// Fiat-Shamir binding: 128-bit (4 M31 words mixed into channel).
pub fn prove_ntt(f: &[i64; 256]) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    use mldsa_ntt_air::{MlDsaNttButterflyEval, MlDsaNttButterflyComponent, LOG_N_BUTTERFLIES, build_trace};

    // Input validation: all coefficients must be in [0, Q).
    for (i, &c) in f.iter().enumerate() {
        if c < 0 || c >= Q {
            return Err(format!("f[{i}] = {c} out of range [0, Q)"));
        }
    }

    let log_size = LOG_N_BUTTERFLIES;
    let (columns, ntt_out) = build_trace(f);

    // 128-bit fingerprint of the NTT output mixed into Fiat-Shamir (Scheme B).
    let fp = output_fingerprint(&ntt_out);
    let commitment_hex = build_poly_commitment(&fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: preprocessed (none for this circuit)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    // Tree 1: main trace (9 columns)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    // Mix all 4 fingerprint words (128-bit FS binding).
    channel.mix_u32s(&fp);

    let component = MlDsaNttButterflyComponent::new(
        &mut TraceLocationAllocator::default(),
        MlDsaNttButterflyEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        channel,
        commitment_scheme,
    )
    .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, ntt_out))
}

/// Verify an NTT STARK proof produced by [`prove_ntt`].
///
/// The proof is valid iff the prover correctly computed all 1024 butterfly
/// operations of the forward NTT and committed to the output consistently.
pub fn verify_ntt(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_ntt_air::{MlDsaNttButterflyEval, MlDsaNttButterflyComponent, LOG_N_BUTTERFLIES};

    let log_size = LOG_N_BUTTERFLIES;

    // Parse Scheme-B commitment → 4 M31 words for Fiat-Shamir replay.
    let fp = parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;

    let component = MlDsaNttButterflyComponent::new(
        &mut TraceLocationAllocator::default(),
        MlDsaNttButterflyEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected ≥ 2 commitments, got {}",
            proof.commitments.len()
        ));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Replay Fiat-Shamir: mix the same 4-word fingerprint as the prover.
    verifier_channel.mix_u32s(&fp);

    let result = verify::<Blake2sM31MerkleChannel>(
        &[&component],
        verifier_channel,
        commitment_scheme,
        proof,
    );

    Ok(result.is_ok())
}

// ─── Pointwise multiplication STARK (MVP-3+) ─────────────────────────────────

/// Prove that `c[i] = a[i] × b[i] (mod Q)` for i = 0..255 (NTT-domain product).
///
/// Returns `(proof_bytes, commitment_hex, product)`.
/// The commitment fingerprints the 256 output coefficients via Blake2s.
pub fn prove_poly_mul(
    a: &[i64; 256],
    b: &[i64; 256],
) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    use mldsa_poly_mul_air::{PolyMulEval, PolyMulComponent, LOG_N_ROWS, build_trace};

    for (i, (&av, &bv)) in a.iter().zip(b.iter()).enumerate() {
        if av < 0 || av >= Q { return Err(format!("a[{i}] = {av} out of [0, Q)")); }
        if bv < 0 || bv >= Q { return Err(format!("b[{i}] = {bv} out of [0, Q)")); }
    }

    let log_size = LOG_N_ROWS;
    let (columns, product) = build_trace(a, b);

    let fp = output_fingerprint(&product);
    let commitment_hex = build_poly_commitment(&fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    channel.mix_u32s(&fp);

    let component = PolyMulComponent::new(
        &mut TraceLocationAllocator::default(),
        PolyMulEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, product))
}

/// Verify a pointwise-multiplication proof produced by [`prove_poly_mul`].
pub fn verify_poly_mul(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_poly_mul_air::{PolyMulEval, PolyMulComponent, LOG_N_ROWS};

    let log_size = LOG_N_ROWS;
    let fp = parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;

    let component = PolyMulComponent::new(
        &mut TraceLocationAllocator::default(),
        PolyMulEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Polynomial addition STARK (MVP-3+) ──────────────────────────────────────

/// Prove that `c[i] = (a[i] + b[i]) mod Q` for i = 0..255.
///
/// Returns `(proof_bytes, commitment_hex, sum)`.
/// The commitment fingerprints the 256 output coefficients via Blake2s.
///
/// # Soundness
/// The addition/boolean constraints are **fully sound** in M31: all operands are
/// < Q < 2²³, so sums stay below M31 and there is no wrap-around ambiguity.
pub fn prove_poly_add(
    a: &[i64; 256],
    b: &[i64; 256],
) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    use mldsa_poly_add_air::{PolyAddEval, PolyAddComponent, LOG_N_ROWS, build_trace};

    for (i, (&av, &bv)) in a.iter().zip(b.iter()).enumerate() {
        if av < 0 || av >= Q { return Err(format!("a[{i}] = {av} out of [0, Q)")); }
        if bv < 0 || bv >= Q { return Err(format!("b[{i}] = {bv} out of [0, Q)")); }
    }

    let log_size = LOG_N_ROWS;
    let (columns, sum) = build_trace(a, b);

    let fp = output_fingerprint(&sum);
    let commitment_hex = build_poly_commitment(&fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    channel.mix_u32s(&fp);

    let component = PolyAddComponent::new(
        &mut TraceLocationAllocator::default(),
        PolyAddEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, sum))
}

/// Verify a polynomial-addition proof produced by [`prove_poly_add`].
pub fn verify_poly_add(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_poly_add_air::{PolyAddEval, PolyAddComponent, LOG_N_ROWS};

    let log_size = LOG_N_ROWS;
    let fp = parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;

    let component = PolyAddComponent::new(
        &mut TraceLocationAllocator::default(),
        PolyAddEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Polynomial subtraction STARK (MVP-3+) ───────────────────────────────────

/// Prove that `c[i] = (a[i] − b[i]) mod Q` for i = 0..255.
///
/// Implemented as `prove_poly_add(a, b_neg)` where `b_neg[i] = (Q − b[i]) mod Q`.
/// This reuses the fully-sound poly_add AIR without introducing a new AIR.
///
/// Returns `(proof_bytes, commitment_hex, diff)`.
pub fn prove_poly_sub(
    a: &[i64; 256],
    b: &[i64; 256],
) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    for (i, (&av, &bv)) in a.iter().zip(b.iter()).enumerate() {
        if av < 0 || av >= Q { return Err(format!("a[{i}] = {av} out of [0, Q)")); }
        if bv < 0 || bv >= Q { return Err(format!("b[{i}] = {bv} out of [0, Q)")); }
    }
    // Negate b in Z_q: b_neg[i] = (Q − b[i]) mod Q.
    let mut b_neg = [0i64; 256];
    for i in 0..256 {
        b_neg[i] = if b[i] == 0 { 0 } else { Q - b[i] };
    }
    prove_poly_add(a, &b_neg)
}

/// Verify a polynomial-subtraction proof produced by [`prove_poly_sub`].
///
/// Verification is identical to [`verify_poly_add`] because the same AIR is used.
pub fn verify_poly_sub(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    verify_poly_add(proof_bytes, commitment_hex)
}

// ─── Coefficient norm check STARK (MVP-3+) ───────────────────────────────────

/// Prove that `norm[i] = min(z[i], Q − z[i])` for i = 0..255 (absolute centered value).
///
/// Returns `(proof_bytes, commitment_hex, norm_poly, max_norm)`:
/// - `norm_poly[i]` is the absolute centered value of each coefficient.
/// - `max_norm` is the ∞-norm of `z` (for external bound check: must be < γ₁ − β).
///
/// The STARK proves the norm computation is correct.  The bound check
/// `max_norm < NORM_BOUND` is asserted externally; range-proof soundness is
/// deferred to MVP-4.
pub fn prove_norm_check(z: &[i64; 256]) -> Result<(Vec<u8>, String, [i64; 256], i64), String> {
    use mldsa::Q;
    use mldsa_norm_check_air::{NormCheckEval, NormCheckComponent, LOG_N_ROWS, build_trace};

    for (i, &c) in z.iter().enumerate() {
        if c < 0 || c >= Q { return Err(format!("z[{i}] = {c} out of [0, Q)")); }
    }

    let log_size = LOG_N_ROWS;
    let (columns, norm_out) = build_trace(z);

    let max_norm = norm_out.iter().copied().max().unwrap_or(0);

    let fp = output_fingerprint(&norm_out);
    let commitment_hex = build_poly_commitment(&fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    channel.mix_u32s(&fp);

    let component = NormCheckComponent::new(
        &mut TraceLocationAllocator::default(),
        NormCheckEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("norm_check proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, norm_out, max_norm))
}

/// Verify a norm-check proof produced by [`prove_norm_check`].
pub fn verify_norm_check(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_norm_check_air::{NormCheckEval, NormCheckComponent, LOG_N_ROWS};

    let log_size = LOG_N_ROWS;
    let fp = parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;

    let component = NormCheckComponent::new(
        &mut TraceLocationAllocator::default(),
        NormCheckEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── ML-DSA batch verification + STARK proof ─────────────────────────────────

/// Verify N ML-DSA-65 signatures and generate a STARK proof over the valid set.
///
/// Each entry is `(pk, msg, sig)` as raw byte slices.
/// Returns `(proof_bytes, commitment_hex, log_size, verified_count, rejected_count)`.
///
/// Only valid signatures contribute to the proof. At least one must be valid.
pub fn prove_mldsa_batch(
    entries: &[(Vec<u8>, Vec<u8>, Vec<u8>)],
) -> Result<(Vec<u8>, String, u32, usize, usize), String> {
    use sha3::{Sha3_256, Digest};
    use mldsa::verify::ml_dsa_verify;

    let mut leaves: Vec<u64> = Vec::new();
    let mut rejected = 0usize;

    for (pk, msg, sig) in entries {
        if ml_dsa_verify(pk, msg, sig) {
            // Leaf = first 8 bytes of SHA3-256(pk ∥ msg) as little-endian u64.
            let mut h = Sha3_256::new();
            h.update(pk);
            h.update(msg);
            let digest = h.finalize();
            let leaf = u64::from_le_bytes(digest[..8].try_into().unwrap());
            leaves.push(leaf);
        } else {
            rejected += 1;
        }
    }

    let verified = leaves.len();
    if leaves.is_empty() {
        return Err("no valid ML-DSA-65 signatures in batch".into());
    }

    let (proof_bytes, commitment, log_size) = prove_hash_chain(&leaves)?;
    Ok((proof_bytes, commitment, log_size, verified, rejected))
}

// ─── Poseidon2 Merkle-tree STARK ─────────────────────────────────────────────

/// Prove that `leaves` hash to a Merkle root via Poseidon2 compression.
///
/// Returns `(proof_bytes, commitment_hex, log_size)`.
/// `commitment_hex` is the 8-char little-endian hex of the Merkle root (M31).
pub fn prove_merkle_root(leaves: &[u64]) -> Result<(Vec<u8>, String, u32), String> {
    use poseidon2_merkle_air::{build_trace, compute_log_size};

    if leaves.is_empty() {
        return Err("leaves must not be empty".into());
    }
    let log_size = compute_log_size(leaves.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("input too large: log_size {log_size} exceeds MAX_LOG_SIZE {MAX_LOG_SIZE}"));
    }

    let (main_cols, preproc_cols, commitment) = build_trace(leaves);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: preprocessed columns (rc0, rc1, is_init)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: main trace (s0, s1, t0, t1, inp0, left, inp1, right)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_cols);
    tree_builder.commit(channel);

    // Bind commitment to Fiat-Shamir transcript (C-2 fix).
    channel.mix_u32s(&[commitment.0]);

    let component = poseidon2_merkle_air::new_component(log_size);

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        channel,
        commitment_scheme,
    )
    .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    let commitment_hex = build_commitment_128(commitment.0, &proof_bytes);
    Ok((proof_bytes, commitment_hex, log_size))
}

/// Verify a proof previously produced by `prove_merkle_root`.
pub fn verify_merkle_root(
    proof_bytes: &[u8],
    commitment_hex: &str,
    log_size: u32,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;

    if log_size < poseidon2_merkle_air::MIN_LOG_SIZE || log_size > MAX_LOG_SIZE {
        return Err(format!(
            "log_size {log_size} out of valid range [{}, {MAX_LOG_SIZE}]",
            poseidon2_merkle_air::MIN_LOG_SIZE
        ));
    }

    // Parse 128-bit commitment, validate suffix, extract M31 for Fiat-Shamir.
    let commitment_val_merkle = parse_commitment_128(commitment_hex, proof_bytes)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(proof_bytes, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>())
            .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;

    let component = poseidon2_merkle_air::new_component(log_size);

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected 2 commitments, got {}",
            proof.commitments.len()
        ));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Mirror the prover's channel.mix_u32s so the Fiat-Shamir transcript matches (C-2 fix).
    verifier_channel.mix_u32s(&[commitment_val_merkle]);

    let result = verify::<Blake2sM31MerkleChannel>(
        &[&component],
        verifier_channel,
        commitment_scheme,
        proof,
    );

    Ok(result.is_ok())
}

// ─── PyO3 Python extension module ────────────────────────────────────────────
//
// Compiled only with `--features python` (e.g. `maturin develop --features python`).
// Exports the six prove/verify functions plus `prove_mldsa` as a Python native
// extension module named `qlsa_stark_stwo`.
//
//   cd stark_stwo && maturin develop --features python --release
//   python -c "import qlsa_stark_stwo; proof, c, n = qlsa_stark_stwo.prove([1,2,3,4])"

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// prove(leaves) -> (proof: bytes, commitment: str, log_size: int)
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(name = "prove")]
fn py_prove(leaves: Vec<u64>) -> PyResult<(Vec<u8>, String, u32)> {
    prove_hash_chain(&leaves).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// verify(proof, commitment, log_size) -> bool
/// Returns False on any verification failure; never raises.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(name = "verify")]
fn py_verify(proof: Vec<u8>, commitment: String, log_size: u32) -> bool {
    verify_hash_chain(&proof, &commitment, log_size).unwrap_or(false)
}

/// prove_p2(leaves) -> (proof: bytes, commitment: str, log_size: int)
#[cfg(feature = "python")]
#[pyfunction]
fn prove_p2(leaves: Vec<u64>) -> PyResult<(Vec<u8>, String, u32)> {
    prove_hash_chain_poseidon2(&leaves).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// verify_p2(proof, commitment, log_size) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_p2(proof: Vec<u8>, commitment: String, log_size: u32) -> bool {
    verify_hash_chain_poseidon2(&proof, &commitment, log_size).unwrap_or(false)
}

/// prove_merkle(leaves) -> (proof: bytes, commitment: str, log_size: int)
#[cfg(feature = "python")]
#[pyfunction]
fn prove_merkle(leaves: Vec<u64>) -> PyResult<(Vec<u8>, String, u32)> {
    prove_merkle_root(&leaves).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// verify_merkle(proof, commitment, log_size) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_merkle(proof: Vec<u8>, commitment: String, log_size: u32) -> bool {
    verify_merkle_root(&proof, &commitment, log_size).unwrap_or(false)
}

/// prove_ntt_py(f) -> (proof: bytes, commitment: str, ntt_out: list[int])
///
/// `f` is a list of 256 ints in [0, Q) (Q = 8 380 417).
#[cfg(feature = "python")]
#[pyfunction]
fn prove_ntt_py(f: Vec<i64>) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let arr: [i64; 256] = f
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("f must have exactly 256 elements"))?;
    let (proof, commitment, ntt_out) = prove_ntt(&arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, ntt_out.to_vec()))
}

/// verify_ntt_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_ntt_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_ntt(&proof, &commitment).unwrap_or(false)
}

/// prove_mldsa(entries) -> (proof: bytes, commitment: str, log_size: int, verified: int, rejected: int)
///
/// `entries` is a list of ``(pk, msg, sig)`` tuples (all ``bytes``).
/// At least one signature must be valid; raises RuntimeError otherwise.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_mldsa(
    entries: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
) -> PyResult<(Vec<u8>, String, u32, usize, usize)> {
    prove_mldsa_batch(&entries).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

#[cfg(feature = "python")]
#[pymodule]
fn qlsa_stark_stwo(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_prove, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify, m)?)?;
    m.add_function(wrap_pyfunction!(prove_p2, m)?)?;
    m.add_function(wrap_pyfunction!(verify_p2, m)?)?;
    m.add_function(wrap_pyfunction!(prove_merkle, m)?)?;
    m.add_function(wrap_pyfunction!(verify_merkle, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa, m)?)?;
    m.add_function(wrap_pyfunction!(prove_ntt_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_ntt_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_poly_mul_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_poly_mul_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_poly_add_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_poly_add_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_poly_sub_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_poly_sub_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_norm_check_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_norm_check_py, m)?)?;
    Ok(())
}

/// prove_poly_mul_py(a, b) -> (proof: bytes, commitment: str, product: list[int])
#[cfg(feature = "python")]
#[pyfunction]
fn prove_poly_mul_py(a: Vec<i64>, b: Vec<i64>) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let a_arr: [i64; 256] = a.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("a must have exactly 256 elements"))?;
    let b_arr: [i64; 256] = b.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("b must have exactly 256 elements"))?;
    let (proof, commitment, product) = prove_poly_mul(&a_arr, &b_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, product.to_vec()))
}

/// verify_poly_mul_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_poly_mul_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_poly_mul(&proof, &commitment).unwrap_or(false)
}

/// prove_poly_add_py(a, b) -> (proof: bytes, commitment: str, sum: list[int])
#[cfg(feature = "python")]
#[pyfunction]
fn prove_poly_add_py(a: Vec<i64>, b: Vec<i64>) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let a_arr: [i64; 256] = a.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("a must have exactly 256 elements"))?;
    let b_arr: [i64; 256] = b.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("b must have exactly 256 elements"))?;
    let (proof, commitment, sum) = prove_poly_add(&a_arr, &b_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, sum.to_vec()))
}

/// verify_poly_add_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_poly_add_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_poly_add(&proof, &commitment).unwrap_or(false)
}

/// prove_poly_sub_py(a, b) -> (proof: bytes, commitment: str, diff: list[int])
///
/// Proves c[i] = (a[i] − b[i]) mod Q for all i. Uses the poly_add AIR with negated b.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_poly_sub_py(a: Vec<i64>, b: Vec<i64>) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let a_arr: [i64; 256] = a.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("a must have exactly 256 elements"))?;
    let b_arr: [i64; 256] = b.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("b must have exactly 256 elements"))?;
    let (proof, commitment, diff) = prove_poly_sub(&a_arr, &b_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, diff.to_vec()))
}

/// verify_poly_sub_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_poly_sub_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_poly_sub(&proof, &commitment).unwrap_or(false)
}

/// prove_norm_check_py(z) -> (proof: bytes, commitment: str, norm: list[int], max_norm: int)
///
/// Proves norm[i] = min(z[i], Q − z[i]) for all i.
/// Returns also `max_norm` = ||z||_∞  for external bound checking (must be < γ₁ − β = 524092).
#[cfg(feature = "python")]
#[pyfunction]
fn prove_norm_check_py(z: Vec<i64>) -> PyResult<(Vec<u8>, String, Vec<i64>, i64)> {
    let z_arr: [i64; 256] = z.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 256 elements"))?;
    let (proof, commitment, norm, max_norm) = prove_norm_check(&z_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, norm.to_vec(), max_norm))
}

/// verify_norm_check_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_norm_check_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_norm_check(&proof, &commitment).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::{assert_constraints_on_trace, FrameworkEval};

    #[test]
    fn test_constraints_on_trace() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (columns, _commitment) = trace::build_trace(&leaves);
        let log_size = trace::compute_log_size(leaves.len());

        let h_vals: Vec<M31> = columns[0].values.clone();
        let leaf_vals: Vec<M31> = columns[1].values.clone();

        // TreeVec: [preprocessed (empty), original trace (h, leaf)]
        let evals: TreeVec<Vec<&Vec<M31>>> =
            TreeVec::new(vec![vec![], vec![&h_vals, &leaf_vals]]);

        let eval_obj = air::HashChainEval { log_n_rows: log_size };
        assert_constraints_on_trace(
            &evals,
            log_size,
            |eval| { eval_obj.evaluate(eval); },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn test_prove_and_verify() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain(&leaves).expect("proving failed");
        let valid = verify_hash_chain(&proof_bytes, &commitment_hex, log_size)
            .expect("verification failed");
        assert!(valid);
    }

    // ── Poseidon2 tests ───────────────────────────────────────────────────────

    #[test]
    fn test_poseidon2_prove_and_verify() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain_poseidon2(&leaves).expect("poseidon2 proving failed");
        let valid = verify_hash_chain_poseidon2(&proof_bytes, &commitment_hex, log_size)
            .expect("poseidon2 verification failed");
        assert!(valid);
    }

    #[test]
    fn test_poseidon2_commitment_matches_chain() {
        use poseidon2::poseidon2_chain;
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (_, commitment_hex, _) =
            prove_hash_chain_poseidon2(&leaves).expect("poseidon2 proving failed");
        let (expected_s0, _) = poseidon2_chain(&leaves);
        let expected_m31_hex = hex::encode(BaseField::from_u32_unchecked(expected_s0 as u32).0.to_le_bytes());
        // Commitment is now 128-bit; the first 8 chars (4 bytes) encode the M31 value.
        assert_eq!(&commitment_hex[..8], expected_m31_hex);
    }

    #[test]
    fn test_poseidon2_tampered_proof_fails() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain_poseidon2(&leaves).expect("poseidon2 proving failed");
        let mut bad_proof = proof_bytes.clone();
        bad_proof[20] ^= 0xFF;
        let result = verify_hash_chain_poseidon2(&bad_proof, &commitment_hex, log_size)
            .unwrap_or(false);
        assert!(!result);
    }

    #[test]
    fn test_wrong_commitment_fails_hash_chain() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain(&leaves).expect("proving failed");
        // Mutate the M31 component (bytes [0:4]) — the suffix check will catch it.
        let bad_commitment = {
            let mut bytes = hex::decode(&commitment_hex).unwrap();
            let mut val = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            val = val.wrapping_add(1) % M31_MODULUS;
            bytes[0..4].copy_from_slice(&val.to_le_bytes());
            hex::encode(&bytes)
        };
        // Wrong commitment → suffix mismatch; parse_commitment_128 returns Err → false.
        let result = verify_hash_chain(&proof_bytes, &bad_commitment, log_size)
            .unwrap_or(false);
        assert!(!result, "wrong commitment should cause verification failure");
    }

    #[test]
    fn test_wrong_commitment_fails_poseidon2() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain_poseidon2(&leaves).expect("poseidon2 proving failed");
        let bad_commitment = {
            let mut bytes = hex::decode(&commitment_hex).unwrap();
            let mut val = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            val = val.wrapping_add(1) % M31_MODULUS;
            bytes[0..4].copy_from_slice(&val.to_le_bytes());
            hex::encode(&bytes)
        };
        let result = verify_hash_chain_poseidon2(&proof_bytes, &bad_commitment, log_size)
            .unwrap_or(false);
        assert!(!result, "wrong commitment should cause poseidon2 verification failure");
    }

    #[test]
    fn test_wrong_commitment_fails_merkle() {
        let leaves = vec![1u64, 2, 3, 4];
        let (proof_bytes, commitment_hex, log_size) =
            prove_merkle_root(&leaves).expect("merkle proving failed");
        let bad_commitment = {
            let mut bytes = hex::decode(&commitment_hex).unwrap();
            let mut val = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            val = val.wrapping_add(1) % M31_MODULUS;
            bytes[0..4].copy_from_slice(&val.to_le_bytes());
            hex::encode(&bytes)
        };
        let result = verify_merkle_root(&proof_bytes, &bad_commitment, log_size)
            .unwrap_or(false);
        assert!(!result, "wrong commitment should cause merkle verification failure");
    }

    // ── Poseidon2 Merkle tests ────────────────────────────────────────────────

    #[test]
    fn test_merkle_prove_and_verify() {
        let leaves = vec![1u64, 2, 3, 4];
        let (proof_bytes, commitment_hex, log_size) =
            prove_merkle_root(&leaves).expect("merkle proving failed");
        let valid = verify_merkle_root(&proof_bytes, &commitment_hex, log_size)
            .expect("merkle verification failed");
        assert!(valid);
    }

    #[test]
    fn test_merkle_commitment_matches_root() {
        let leaves = vec![10u64, 20, 30, 40];
        let (_, commitment_hex, _) =
            prove_merkle_root(&leaves).expect("merkle proving failed");
        let expected = poseidon2_merkle_air::merkle_root(&leaves);
        let expected_m31_hex =
            hex::encode(BaseField::from_u32_unchecked(expected as u32).0.to_le_bytes());
        // Commitment is now 128-bit; the first 8 chars (4 bytes) encode the Merkle root M31.
        assert_eq!(&commitment_hex[..8], expected_m31_hex);
    }

    #[test]
    fn test_merkle_tampered_proof_fails() {
        let leaves = vec![1u64, 2, 3, 4];
        let (proof_bytes, commitment_hex, log_size) =
            prove_merkle_root(&leaves).expect("merkle proving failed");
        let mut bad_proof = proof_bytes.clone();
        bad_proof[20] ^= 0xFF;
        let result = verify_merkle_root(&bad_proof, &commitment_hex, log_size)
            .unwrap_or(false);
        assert!(!result);
    }

    // ── NTT STARK prover/verifier tests (MVP-3+) ─────────────────────────────

    fn random_ntt_input(seed: u64) -> [i64; 256] {
        let q = mldsa::Q;
        let mut state = seed;
        let mut f = [0i64; 256];
        for c in f.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *c = ((state >> 33) as i64).abs() % q;
        }
        f
    }

    #[test]
    fn test_prove_and_verify_ntt() {
        let f = random_ntt_input(0xc0ffee);
        let (proof_bytes, commitment_hex, ntt_out) =
            prove_ntt(&f).expect("NTT proving failed");

        // Output must match the reference NTT.
        let mut expected = f;
        mldsa::ntt::ntt(&mut expected);
        assert_eq!(ntt_out, expected, "NTT output mismatch");

        // Proof must verify.
        let valid = verify_ntt(&proof_bytes, &commitment_hex).expect("NTT verification failed");
        assert!(valid, "NTT proof should verify");
    }

    #[test]
    fn test_ntt_tampered_proof_fails() {
        let f = random_ntt_input(42);
        let (proof_bytes, commitment_hex, _) = prove_ntt(&f).expect("NTT proving failed");
        let mut bad_proof = proof_bytes.clone();
        bad_proof[20] ^= 0xFF;
        let result = verify_ntt(&bad_proof, &commitment_hex).unwrap_or(false);
        assert!(!result, "tampered NTT proof should not verify");
    }

    #[test]
    fn test_ntt_wrong_commitment_fails() {
        let f = random_ntt_input(7);
        let (proof_bytes, commitment_hex, _) = prove_ntt(&f).expect("NTT proving failed");
        let bad_commitment = {
            let mut bytes = hex::decode(&commitment_hex).unwrap();
            let mut val = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            val = val.wrapping_add(1) % M31_MODULUS;
            bytes[0..4].copy_from_slice(&val.to_le_bytes());
            hex::encode(&bytes)
        };
        let result = verify_ntt(&proof_bytes, &bad_commitment).unwrap_or(false);
        assert!(!result, "wrong commitment should fail NTT verification");
    }

    #[test]
    fn test_ntt_zero_poly() {
        // NTT of the zero polynomial is the zero polynomial.
        let f = [0i64; 256];
        let (proof_bytes, commitment_hex, ntt_out) =
            prove_ntt(&f).expect("NTT proving of zero failed");
        assert_eq!(ntt_out, [0i64; 256]);
        let valid = verify_ntt(&proof_bytes, &commitment_hex).expect("NTT verification failed");
        assert!(valid);
    }

    // ── Pointwise polynomial multiplication tests (MVP-3+) ───────────────────

    fn random_q_poly(seed: u64) -> [i64; 256] {
        let q = mldsa::Q;
        let mut state = seed;
        let mut f = [0i64; 256];
        for c in f.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *c = ((state >> 33) as i64).abs() % q;
        }
        f
    }

    #[test]
    fn test_prove_and_verify_poly_mul() {
        let a = random_q_poly(100);
        let b = random_q_poly(200);
        let (proof_bytes, commitment_hex, product) =
            prove_poly_mul(&a, &b).expect("poly_mul proving failed");

        // Product must match the reference.
        let reference = mldsa::ntt::pointwise_mul(&a, &b);
        assert_eq!(product, reference);

        let valid = verify_poly_mul(&proof_bytes, &commitment_hex)
            .expect("poly_mul verification failed");
        assert!(valid);
    }

    #[test]
    fn test_poly_mul_tampered_proof_fails() {
        let a = random_q_poly(1);
        let b = random_q_poly(2);
        let (proof_bytes, commitment_hex, _) =
            prove_poly_mul(&a, &b).expect("poly_mul proving failed");
        let mut bad = proof_bytes.clone();
        bad[20] ^= 0xFF;
        assert!(!verify_poly_mul(&bad, &commitment_hex).unwrap_or(false));
    }

    #[test]
    fn test_poly_mul_zero_is_zero() {
        let a = [0i64; 256];
        let b = random_q_poly(3);
        let (proof_bytes, commitment_hex, product) =
            prove_poly_mul(&a, &b).expect("poly_mul proving failed");
        assert_eq!(product, [0i64; 256]);
        assert!(verify_poly_mul(&proof_bytes, &commitment_hex).unwrap_or(false));
    }

    // ── Polynomial addition tests (MVP-3+) ───────────────────────────────────

    #[test]
    fn test_prove_and_verify_poly_add() {
        let a = random_q_poly(300);
        let b = random_q_poly(400);
        let (proof_bytes, commitment_hex, sum) =
            prove_poly_add(&a, &b).expect("poly_add proving failed");

        // Sum must be correct mod Q.
        let q = mldsa::Q;
        for i in 0..256 {
            assert_eq!(sum[i], (a[i] + b[i]).rem_euclid(q), "sum[{i}]");
        }

        let valid = verify_poly_add(&proof_bytes, &commitment_hex)
            .expect("poly_add verification failed");
        assert!(valid, "poly_add proof should verify");
    }

    #[test]
    fn test_poly_add_zero_is_identity() {
        let a = random_q_poly(500);
        let z = [0i64; 256];
        let (proof_bytes, commitment_hex, sum) =
            prove_poly_add(&a, &z).expect("poly_add proving failed");
        assert_eq!(sum, a);
        assert!(verify_poly_add(&proof_bytes, &commitment_hex).unwrap_or(false));
    }

    #[test]
    fn test_poly_add_tampered_proof_fails() {
        let a = random_q_poly(10);
        let b = random_q_poly(20);
        let (proof_bytes, commitment_hex, _) =
            prove_poly_add(&a, &b).expect("poly_add proving failed");
        let mut bad = proof_bytes.clone();
        bad[20] ^= 0xFF;
        assert!(!verify_poly_add(&bad, &commitment_hex).unwrap_or(false));
    }

    // ── Polynomial subtraction tests (MVP-3+) ────────────────────────────────

    #[test]
    fn test_prove_and_verify_poly_sub() {
        let q = mldsa::Q;
        let a = random_q_poly(600);
        let b = random_q_poly(700);
        let (proof_bytes, commitment_hex, diff) =
            prove_poly_sub(&a, &b).expect("poly_sub proving failed");

        for i in 0..256 {
            assert_eq!(diff[i], (a[i] - b[i]).rem_euclid(q), "diff[{i}]");
        }

        let valid = verify_poly_sub(&proof_bytes, &commitment_hex)
            .expect("poly_sub verification failed");
        assert!(valid, "poly_sub proof should verify");
    }

    #[test]
    fn test_poly_sub_self_is_zero() {
        let a = random_q_poly(800);
        let (proof_bytes, commitment_hex, diff) =
            prove_poly_sub(&a, &a).expect("poly_sub (a - a) failed");
        assert_eq!(diff, [0i64; 256]);
        assert!(verify_poly_sub(&proof_bytes, &commitment_hex).unwrap_or(false));
    }

    #[test]
    fn test_poly_sub_zero_is_identity() {
        let a = random_q_poly(900);
        let z = [0i64; 256];
        let (proof_bytes, commitment_hex, diff) =
            prove_poly_sub(&a, &z).expect("poly_sub (a - 0) failed");
        assert_eq!(diff, a);
        assert!(verify_poly_sub(&proof_bytes, &commitment_hex).unwrap_or(false));
    }

    // ── Norm check tests (MVP-3+) ─────────────────────────────────────────────

    #[test]
    fn test_prove_and_verify_norm_check() {
        let z = random_q_poly(1000);
        let (proof_bytes, commitment_hex, norm, max_norm) =
            prove_norm_check(&z).expect("norm_check proving failed");

        // Verify norm values.
        let q = mldsa::Q;
        let half = (q - 1) / 2;
        for i in 0..256 {
            let expected = if z[i] > half { q - z[i] } else { z[i] };
            assert_eq!(norm[i], expected, "norm[{i}]");
        }
        let expected_max = norm.iter().copied().max().unwrap_or(0);
        assert_eq!(max_norm, expected_max);

        let valid = verify_norm_check(&proof_bytes, &commitment_hex)
            .expect("norm_check verification failed");
        assert!(valid, "norm_check proof should verify");
    }

    #[test]
    fn test_norm_check_zero_poly() {
        let z = [0i64; 256];
        let (proof_bytes, commitment_hex, norm, max_norm) =
            prove_norm_check(&z).expect("norm_check of zero failed");
        assert_eq!(norm, [0i64; 256]);
        assert_eq!(max_norm, 0);
        assert!(verify_norm_check(&proof_bytes, &commitment_hex).unwrap_or(false));
    }

    #[test]
    fn test_norm_check_tampered_proof_fails() {
        let z = random_q_poly(1100);
        let (proof_bytes, commitment_hex, _, _) =
            prove_norm_check(&z).expect("norm_check proving failed");
        let mut bad = proof_bytes.clone();
        bad[20] ^= 0xFF;
        assert!(!verify_norm_check(&bad, &commitment_hex).unwrap_or(false));
    }
}
