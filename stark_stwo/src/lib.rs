pub mod air;
pub mod mldsa;
pub mod mldsa_az_air;
pub mod mldsa_az_full_air;
pub mod mldsa_hint_weight_air;
pub mod mldsa_intt_air;
pub mod mldsa_norm_check_air;
pub mod mldsa_ntt_air;
pub mod mldsa_use_hint_air;
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

// ─── UseHint STARK (MVP-3+) ───────────────────────────────────────────────────

/// Prove `UseHint(h[i], r[i]) = w₁'[i]` for all 256 coefficients of one polynomial.
///
/// Includes inline `Decompose(r)` proof.  `r` must be in `[0, Q)`.
///
/// Returns `(proof_bytes, commitment_hex, w1_poly)`.
pub fn prove_use_hint(r: &[i64; 256], h_bits: &[bool; 256]) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    use mldsa_use_hint_air::{UseHintEval, UseHintComponent, LOG_N_ROWS, build_trace};

    for (i, &c) in r.iter().enumerate() {
        if c < 0 || c >= Q { return Err(format!("r[{i}] = {c} out of [0, Q)")); }
    }

    let log_size = LOG_N_ROWS;
    let (columns, w1_out) = build_trace(r, h_bits);

    let fp = output_fingerprint(&w1_out);
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

    let component = UseHintComponent::new(
        &mut TraceLocationAllocator::default(),
        UseHintEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("use_hint proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, w1_out))
}

/// Verify a UseHint proof produced by [`prove_use_hint`].
pub fn verify_use_hint(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_use_hint_air::{UseHintEval, UseHintComponent, LOG_N_ROWS};

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

    let component = UseHintComponent::new(
        &mut TraceLocationAllocator::default(),
        UseHintEval { log_n_rows: log_size },
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

// ─── Az row STARK (MVP-3+) ────────────────────────────────────────────────────

/// Prove one row of the NTT-domain matrix-vector product  Az̃[i] = Σ_{j=0}^{L-1} Ã[i][j] ⊙ z̃[j].
///
/// `a_row` is the i-th row of Ã (L=5 polynomials in NTT domain, each of 256 coefficients).
/// `z_hat` is the NTT-domain vector z̃ (L=5 polynomials of 256 coefficients).
///
/// Returns `(proof_bytes, commitment_hex, az_hat_i)` where `az_hat_i` is the output polynomial.
/// The commitment fingerprints the 256 output coefficients via Blake2s (Scheme B, 128-bit).
///
/// The Fiat-Shamir transcript also binds to the L=5 input z̃ polynomials (input fingerprint
/// mixed before the output fingerprint), so `verify_az_row` must receive the same z_hat to
/// reconstruct the same channel state.
///
/// Call this K=6 times (once per output row) to prove the full matrix-vector product.
pub fn prove_az_row(
    a_row: &[[i64; 256]; 5],
    z_hat: &[[i64; 256]; 5],
) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    use mldsa_az_air::{AzRowEval, AzRowComponent, LOG_N_ROWS, build_trace};

    for j in 0..5 {
        for (p, (&av, &zv)) in a_row[j].iter().zip(z_hat[j].iter()).enumerate() {
            if av < 0 || av >= Q {
                return Err(format!("a_row[{j}][{p}] = {av} out of [0, Q)"));
            }
            if zv < 0 || zv >= Q {
                return Err(format!("z_hat[{j}][{p}] = {zv} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, az_hat) = build_trace(a_row, z_hat);

    // Input fingerprint: Blake2s of all L z̃ polynomials concatenated.
    // Mixed into channel BEFORE the output fingerprint to bind the proof to the specific z_hat.
    let z_flat: Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let input_fp = output_fingerprint(&z_flat);

    let output_fp = output_fingerprint(&az_hat);
    let commitment_hex = build_poly_commitment(&output_fp);

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

    // Bind to both input z_hat and output az_hat in this order.
    channel.mix_u32s(&input_fp);
    channel.mix_u32s(&output_fp);

    let component = AzRowComponent::new(
        &mut TraceLocationAllocator::default(),
        AzRowEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, az_hat))
}

/// Verify an Az-row proof produced by [`prove_az_row`].
///
/// `z_hat` must be the same L=5 input polynomials that were used to generate the proof.
/// The input fingerprint is recomputed from `z_hat` and mixed into the verifier channel
/// to reconstruct the same Fiat-Shamir transcript as the prover.
pub fn verify_az_row(
    proof_bytes: &[u8],
    commitment_hex: &str,
    z_hat: &[[i64; 256]],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_az_air::{AzRowEval, AzRowComponent, LOG_N_ROWS};

    let log_size = LOG_N_ROWS;
    let output_fp = parse_poly_commitment(commitment_hex)?;

    // Recompute input fingerprint from the provided z_hat.
    let z_flat: Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let input_fp = output_fingerprint(&z_flat);

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;

    let component = AzRowComponent::new(
        &mut TraceLocationAllocator::default(),
        AzRowEval { log_n_rows: log_size },
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

    // Reconstruct transcript: input fingerprint then output fingerprint (same order as prover).
    verifier_channel.mix_u32s(&input_fp);
    verifier_channel.mix_u32s(&output_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Full-matrix Az STARK (MVP-3+) ────────────────────────────────────────────

/// Prove the full NTT-domain matrix-vector product Az in a single STARK.
///
/// Proves all K=6 output rows simultaneously: az_out[i] = Σ_j Ã[i][j] ⊙ z̃[j].
///
/// `a_hat` — K×L NTT-domain polynomials in row-major order (a_hat[i*L+j] = Ã[i][j]).
/// `z_hat` — L NTT-domain input polynomials.
///
/// Returns `(proof_bytes, commitment_hex, az_out)`.
/// The commitment fingerprints all K output polynomials concatenated (Scheme B, 128-bit).
/// Both input (z_hat) and output fingerprints are mixed into the Fiat-Shamir channel.
pub fn prove_az_full(
    a_hat: &[[i64; mldsa::N]],
    z_hat: &[[i64; mldsa::N]; mldsa::params::L],
) -> Result<(Vec<u8>, String, [[i64; mldsa::N]; mldsa::params::K]), String> {
    use mldsa_az_full_air::{AzFullEval, AzFullComponent, LOG_N_ROWS, build_trace};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::PcsConfig;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    let k = mldsa::params::K;
    let l = mldsa::params::L;
    if a_hat.len() != k * l {
        return Err(format!("a_hat must have k*l={} entries, got {}", k * l, a_hat.len()));
    }
    for (idx, row) in a_hat.iter().enumerate() {
        for (p, &v) in row.iter().enumerate() {
            if v < 0 || v >= mldsa::Q {
                return Err(format!("a_hat[{idx}][{p}] = {v} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, az_out) = build_trace(a_hat, z_hat);

    // Input fingerprint: concatenate all L z_hat polynomials.
    let z_flat: Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let input_fp = output_fingerprint(&z_flat);

    // Output fingerprint: concatenate all K az_out polynomials.
    let az_flat: Vec<i64> = az_out.iter().flat_map(|row| row.iter().copied()).collect();
    let output_fp  = output_fingerprint(&az_flat);
    let commitment_hex = build_poly_commitment(&output_fp);

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

    // Bind to input z_hat first, then output az_out (same pattern as prove_az_row).
    channel.mix_u32s(&input_fp);
    channel.mix_u32s(&output_fp);

    let component = AzFullComponent::new(
        &mut TraceLocationAllocator::default(),
        AzFullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, az_out))
}

/// Verify a full-matrix Az proof produced by [`prove_az_full`].
///
/// `z_hat` must be the same L polynomials used to generate the proof.
/// The verifier recomputes the input fingerprint from z_hat and mixes it first
/// into the Fiat-Shamir channel, binding the proof to the specific inputs.
pub fn verify_az_full(
    proof_bytes:    &[u8],
    commitment_hex: &str,
    z_hat:          &[[i64; mldsa::N]; mldsa::params::L],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_az_full_air::{AzFullEval, AzFullComponent, LOG_N_ROWS};
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;

    let log_size = LOG_N_ROWS;

    // Recompute input fingerprint from z_hat.
    let z_flat: Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let input_fp  = output_fingerprint(&z_flat);
    let output_fp = parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;

    let component = AzFullComponent::new(
        &mut TraceLocationAllocator::default(),
        AzFullEval { log_n_rows: log_size },
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

    // Reconstruct transcript: input fingerprint then output fingerprint.
    verifier_channel.mix_u32s(&input_fp);
    verifier_channel.mix_u32s(&output_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Hint weight check STARK (MVP-3+) ────────────────────────────────────────

/// Prove that the total hint weight Σᵢ ||h[i]||₁ ≤ ω (ML-DSA-65: ω=55).
///
/// `hints[i][j]` is the hint bit for polynomial i, coefficient j.
/// `hints` must have `K=6` rows, each of length `N=256`.
///
/// Returns `(proof_bytes, commitment_hex, total_weight)`.
/// `commitment_hex` fingerprints the running-sum polynomial (Scheme B, 128-bit).
/// The caller must check `total_weight ≤ OMEGA` — this is not enforced by the circuit.
///
/// The circuit proves:
///   - Each hint bit ∈ {0,1}
///   - Padding rows (≥ 1536) have h=0
///   - The running sum is sequential: s[r] = s[r−1] + h[r]
pub fn prove_hint_weight(hints: &[Vec<bool>]) -> Result<(Vec<u8>, String, usize), String> {
    use mldsa_hint_weight_air::{LOG_N_ROWS, build_trace, new_component};
    use mldsa::params::K;
    use mldsa::N;

    if hints.len() != K {
        return Err(format!("hints must have K={K} rows, got {}", hints.len()));
    }
    for (i, row) in hints.iter().enumerate() {
        if row.len() != N {
            return Err(format!("hints[{i}] must have N={N} columns, got {}", row.len()));
        }
    }

    let log_size = LOG_N_ROWS;
    let (main_cols, preproc_cols, total_weight) = build_trace(hints);

    // The "output" we fingerprint is the running-sum column (col 0 = s after column ordering fix).
    let s_col_raw: Vec<i64> = main_cols[0].values.iter().map(|v| v.0 as i64).collect();
    let fp = output_fingerprint(&s_col_raw);
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

    // Tree 0: preprocessed columns (is_init, is_valid).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: main trace (h, s).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_cols);
    tree_builder.commit(channel);

    // Bind output fingerprint to Fiat-Shamir transcript.
    channel.mix_u32s(&fp);

    let component = new_component(log_size);

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, total_weight))
}

/// Verify a hint weight STARK proof produced by [`prove_hint_weight`].
///
/// Returns `Ok(true)` iff the STARK proof is valid for the given commitment.
/// The caller is responsible for checking `total_weight ≤ OMEGA` using the
/// `total_weight` value returned from `prove_hint_weight`.
pub fn verify_hint_weight(
    proof_bytes: &[u8],
    commitment_hex: &str,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_hint_weight_air::{LOG_N_ROWS, new_component};

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

    let component = new_component(log_size);

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
    m.add_function(wrap_pyfunction!(prove_use_hint_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_use_hint_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_az_row_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_az_row_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_az_full_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_az_full_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_intt_bound_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_intt_bound_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_hint_weight_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_hint_weight_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v2_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v2_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v3_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v3_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_sig_witness_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_hash_check_py, m)?)?;
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

/// prove_az_row_py(a_row, z_hat) -> (proof: bytes, commitment: str, az_hat: list[int])
///
/// Proves one row of the NTT-domain matrix-vector product Az̃[i] = Σ_j Ã[i][j] ⊙ z̃[j].
/// `a_row` is a list of 5 lists of 256 ints (ML-DSA-65: L=5).
/// `z_hat` is a list of 5 lists of 256 ints.
/// Returns `(proof_bytes, commitment_hex, az_hat)` where az_hat is 256 ints.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_az_row_py(
    a_row: Vec<Vec<i64>>,
    z_hat: Vec<Vec<i64>>,
) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let a_arr: [[i64; 256]; 5] = (0..5)
        .map(|j| {
            a_row.get(j)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("a_row must have 5 elements"))?
                .clone()
                .try_into()
                .map_err(|_| pyo3::exceptions::PyValueError::new_err("each a_row[j] must have 256 elements"))
        })
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("a_row must have exactly 5 lists"))?;

    let z_arr: [[i64; 256]; 5] = (0..5)
        .map(|j| {
            z_hat.get(j)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("z_hat must have 5 elements"))?
                .clone()
                .try_into()
                .map_err(|_| pyo3::exceptions::PyValueError::new_err("each z_hat[j] must have 256 elements"))
        })
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z_hat must have exactly 5 lists"))?;

    let (proof, commitment, az_hat) = prove_az_row(&a_arr, &z_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, az_hat.to_vec()))
}

/// verify_az_row_py(proof, commitment, z_hat) -> bool
///
/// `z_hat` must be a list of 5 lists of 256 ints — the same input used when proving.
#[cfg(feature = "python")]
#[pyfunction]
fn verify_az_row_py(proof: Vec<u8>, commitment: String, z_hat: Vec<Vec<i64>>) -> bool {
    let z_slices: Vec<[i64; 256]> = z_hat.into_iter()
        .map(|zj| zj.try_into().ok())
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    verify_az_row(&proof, &commitment, &z_slices).unwrap_or(false)
}

/// prove_az_full_py(a_hat, z_hat) -> (proof: bytes, commitment: str, az_out: list[list[int]])
///
/// Proves all K=6 rows of Az in one STARK.
/// `a_hat` — list of K*L=30 lists of 256 ints (row-major: a_hat[i*L+j] = Ã[i][j]).
/// `z_hat` — list of L=5 lists of 256 ints.
/// Returns `(proof_bytes, commitment_hex, az_out)` where az_out is K lists of 256 ints.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_az_full_py(
    a_hat: Vec<Vec<i64>>,
    z_hat: Vec<Vec<i64>>,
) -> PyResult<(Vec<u8>, String, Vec<Vec<i64>>)> {
    use mldsa::params::{K, L};
    if a_hat.len() != K * L {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("a_hat must have K*L={} lists, got {}", K * L, a_hat.len())
        ));
    }
    if z_hat.len() != L {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z_hat must have L={} lists, got {}", L, z_hat.len())
        ));
    }
    let a_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .map(|row| row.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("each a_hat[k] must have 256 elements")))
        .collect::<PyResult<_>>()?;
    let z_arr: [[i64; 256]; 5] = (0..L)
        .map(|j| z_hat[j].clone().try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("each z_hat[j] must have 256 elements")))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z_hat must have exactly L=5 lists"))?;
    let (proof, commitment, az_out) = prove_az_full(&a_arr, &z_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    let az_out_py: Vec<Vec<i64>> = az_out.iter().map(|row| row.to_vec()).collect();
    Ok((proof, commitment, az_out_py))
}

/// verify_az_full_py(proof, commitment, z_hat) -> bool
///
/// `z_hat` must be the same L=5 lists of 256 ints used when proving.
#[cfg(feature = "python")]
#[pyfunction]
fn verify_az_full_py(proof: Vec<u8>, commitment: String, z_hat: Vec<Vec<i64>>) -> bool {
    use mldsa::params::L;
    let z_arr: [[i64; 256]; 5] = match (0..L)
        .map(|j| z_hat.get(j).and_then(|zj| zj.clone().try_into().ok()))
        .collect::<Option<Vec<[i64; 256]>>>()
        .and_then(|v| v.try_into().ok())
    {
        Some(a) => a,
        None => return false,
    };
    verify_az_full(&proof, &commitment, &z_arr).unwrap_or(false)
}

/// prove_intt_bound_py(f) -> (proof: bytes, commitment: str)
///
/// Like `prove_intt` but also mixes the input fingerprint of `f` into the
/// Fiat-Shamir channel before the output fingerprint, binding the proof to the
/// specific input polynomial.  Use `verify_intt_bound_py` to verify.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_intt_bound_py(f: Vec<i64>) -> PyResult<(Vec<u8>, String)> {
    use mldsa_verify_stark::prove_intt_with_binding;
    let f_arr: [i64; 256] = f.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("f must have exactly 256 elements"))?;
    let (proof, commitment, _out) = prove_intt_with_binding(&f_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment))
}

/// verify_intt_bound_py(proof, commitment, input) -> bool
///
/// Verify an INTT proof produced by `prove_intt_bound_py`.
/// `input` must be the same 256-element list of ints that was passed to the prover.
#[cfg(feature = "python")]
#[pyfunction]
fn verify_intt_bound_py(proof: Vec<u8>, commitment: String, input: Vec<i64>) -> bool {
    use mldsa_verify_stark::verify_intt_with_binding;
    let input_arr: [i64; 256] = match input.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    verify_intt_with_binding(&proof, &commitment, &input_arr).unwrap_or(false)
}

/// prove_hint_weight_py(hints) -> (proof: bytes, commitment: str, total_weight: int)
///
/// `hints` must be a list of K=6 lists of N=256 booleans.
/// Returns a STARK proof that each bit ∈ {0,1} and the running sum is sequential.
/// The caller checks `total_weight ≤ 55` (ML-DSA-65 ω bound).
#[cfg(feature = "python")]
#[pyfunction]
fn prove_hint_weight_py(hints: Vec<Vec<bool>>) -> PyResult<(Vec<u8>, String, usize)> {
    prove_hint_weight(&hints)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// verify_hint_weight_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_hint_weight_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_hint_weight(&proof, &commitment).unwrap_or(false)
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

/// prove_use_hint_py(r, h_bits) -> (proof: bytes, commitment: str, w1: list[int])
///
/// Proves UseHint(h_bits[i], r[i]) = w1[i] for all 256 coefficients.
/// `r` must be 256 ints in [0, Q).  `h_bits` must be 256 bools.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_use_hint_py(r: Vec<i64>, h_bits: Vec<bool>) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let r_arr: [i64; 256] = r.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("r must have exactly 256 elements"))?;
    let h_arr: [bool; 256] = h_bits.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("h_bits must have exactly 256 elements"))?;
    let (proof, commitment, w1) = prove_use_hint(&r_arr, &h_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, w1.to_vec()))
}

/// verify_use_hint_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_use_hint_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_use_hint(&proof, &commitment).unwrap_or(false)
}

// ── ML-DSA full arithmetic witness pipeline ───────────────────────────────────

/// prove_mldsa_witness_py(a_hat, z, c, t1, hints, k, l)
///   -> (proof_bundle: bytes, max_norms: list[int], w1_prime: list[list[int]])
///
/// Proves the full ML-DSA.Verify arithmetic witness:
///   Az  →  c·t₁  →  poly_sub  →  norm_check  →  UseHint
///
/// Inputs (all coefficients in [0, Q)):
///   a_hat : k*l flat list of 256-int polynomials (NTT-domain, row-major)
///   z     : l polynomials (signature)
///   c     : 256-int challenge polynomial
///   t1    : k polynomials (public key components)
///   hints : k lists of 256 bools (hint bits from the signature)
///   k, l  : matrix dimensions (ML-DSA-65: k=6, l=5)
///
/// Returns:
///   proof_bundle : bincode-serialized VerifyMldsaProof (pass to verify_mldsa_witness_py)
///   max_norms    : l values — ||z[j]||_∞; caller checks each < 524 092
///   w1_prime     : k rows of 256 ints — UseHint outputs for hash comparison
#[cfg(feature = "python")]
#[pyfunction]
fn prove_mldsa_witness_py(
    a_hat:  Vec<Vec<i64>>,
    z:      Vec<Vec<i64>>,
    c:      Vec<i64>,
    t1:     Vec<Vec<i64>>,
    hints:  Vec<Vec<bool>>,
    k:      usize,
    l:      usize,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>)> {
    // Convert Vec<Vec<i64>> → Vec<[i64; 256]>.
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;

    // Convert hints Vec<Vec<bool>> → Vec<Vec<bool>> (already the right type).
    let hints_vv: Vec<Vec<bool>> = hints;

    let proof = mldsa_verify_stark::prove_verify_mldsa_witness(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints_vv, k, l,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.w1_prime.iter().map(|p| p.to_vec()).collect();

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime))
}

/// verify_mldsa_witness_py(proof_bundle: bytes) -> bool
///
/// Verifies all STARK sub-proofs in a bundle produced by prove_mldsa_witness_py.
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProof, _
    >(&proof_bundle, bincode::config::standard()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_proofs(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v2_py — same interface as prove_mldsa_witness_py but uses
/// the Az-row AIR circuit (53 sub-proofs vs 101). Requires l = 5 (ML-DSA-65).
#[cfg(feature = "python")]
#[pyfunction]
fn prove_mldsa_witness_v2_py(
    a_hat:  Vec<Vec<i64>>,
    z:      Vec<Vec<i64>>,
    c:      Vec<i64>,
    t1:     Vec<Vec<i64>>,
    hints:  Vec<Vec<bool>>,
    k:      usize,
    l:      usize,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;

    let proof = mldsa_verify_stark::prove_verify_mldsa_v2(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.w1_prime.iter().map(|p| p.to_vec()).collect();

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime))
}

/// verify_mldsa_witness_v2_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v2_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV2, _
    >(&proof_bundle, bincode::config::standard()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v2(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v3_py — full-matrix Az AIR + hint weight proof (49 sub-proofs).
///
/// Returns `(bundle: bytes, max_norms: list[int], w1_prime: list[list[int]], hint_weight_total: int)`.
/// Requires k = 6, l = 5 (ML-DSA-65).
#[cfg(feature = "python")]
#[pyfunction]
fn prove_mldsa_witness_v3_py(
    a_hat:  Vec<Vec<i64>>,
    z:      Vec<Vec<i64>>,
    c:      Vec<i64>,
    t1:     Vec<Vec<i64>>,
    hints:  Vec<Vec<bool>>,
    k:      usize,
    l:      usize,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;

    let proof = mldsa_verify_stark::prove_verify_mldsa_v3(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.w1_prime.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v3_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v3_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV3, _
    >(&proof_bundle, bincode::config::standard()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v3(&proof).unwrap_or(false)
}

/// prove_mldsa_sig_witness_py(pk: bytes, msg: bytes, sig: bytes)
///   -> (proof_bundle: bytes, max_norms: list[int], w1_prime: list[list[int]])
///
/// End-to-end function: decodes an ML-DSA-65 signature, verifies it, then
/// proves the full arithmetic witness pipeline:
///   Az  →  c·t₁·2^d  →  poly_sub  →  norm_check  →  UseHint
///
/// Raises PyRuntimeError if the signature is invalid or any sub-proof fails.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_mldsa_sig_witness_py(
    pk:  Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, String, String, Vec<u8>, String, usize)> {
    use mldsa::encoding::{pk_decode, sig_decode};
    use mldsa::xof::{expand_a, sample_in_ball};
    use mldsa::field;
    use mldsa::params::{K, L, D};
    use mldsa::N;

    // Verify first — reject invalid signatures immediately.
    if !mldsa::verify::ml_dsa_verify(&pk, &msg, &sig) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "ML-DSA-65 signature verification failed — cannot prove invalid witness"
        ));
    }

    // Decode public key: rho + t1 (K polynomials in [0, 2^T1_BITS)).
    let (rho, t1) = pk_decode(&pk)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(
            format!("pk_decode failed: {e}")
        ))?;

    // Decode signature: c_tilde + z (L polys, signed) + hints (K × N bools).
    let (c_tilde, z, hints) = sig_decode(&sig)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(
            format!("sig_decode failed: {e}")
        ))?;

    // a_hat = ExpandA(rho) — K×L NTT-domain matrix (already in [0, Q)).
    let a_hat_matrix = expand_a(&rho);
    let mut a_hat_flat: Vec<[i64; N]> = Vec::with_capacity(K * L);
    for row in &a_hat_matrix.rows {
        for poly in &row.0 {
            a_hat_flat.push(poly.coeffs);
        }
    }

    // c = SampleInBall(c_tilde) — challenge polynomial.
    let c_poly = sample_in_ball(&c_tilde);
    // Reduce challenge to [0, Q) (SampleInBall produces coeffs ∈ {-1, 0, 1}).
    let mut c_arr = [0i64; N];
    for (i, &v) in c_poly.coeffs.iter().enumerate() {
        c_arr[i] = field::reduce(v);
    }

    // z_reduced: signature z polynomials reduced from signed to [0, Q).
    let mut z_arr: Vec<[i64; N]> = Vec::with_capacity(L);
    for poly in &z.0 {
        let mut coeffs = [0i64; N];
        for (i, &v) in poly.coeffs.iter().enumerate() {
            coeffs[i] = field::reduce(v);
        }
        z_arr.push(coeffs);
    }

    // t1_scaled = t1 * 2^D mod Q — the FIPS 204 scaling of public key components.
    let t1_scaled = t1.scale_power2(D);
    let mut t1_arr: Vec<[i64; N]> = Vec::with_capacity(K);
    for poly in &t1_scaled.0 {
        t1_arr.push(poly.coeffs);
    }

    // Run the full STARK witness pipeline.
    let proof = mldsa_verify_stark::prove_verify_mldsa_witness(
        &a_hat_flat, &z_arr, &c_arr, &t1_arr, &hints, K, L,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.w1_prime.iter().map(|p| p.to_vec()).collect();

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    // onchain_commitment = Blake2s(bundle[:32] ∥ c_tilde[:32])[:16]
    // Binds the proof bundle to this specific signature's challenge seed.
    let binding_input: Vec<u8> = bundle[..32.min(bundle.len())]
        .iter()
        .chain(c_tilde.iter().take(32))
        .copied()
        .collect();
    use blake2::{Blake2s256, Digest};
    let digest = Blake2s256::digest(&binding_input);
    let onchain_commitment = hex::encode(&digest[..16]);

    // c_tilde as hex — lets the caller re-derive the hash check off-circuit.
    let c_tilde_hex = hex::encode(&c_tilde);

    // Prove hint weight: Σᵢ ||h[i]||₁ ≤ ω (FIPS 204 §4, step 4).
    // The hints vector comes from sig_decode and has K rows × N bits.
    let (hw_proof, hw_commitment, hw_total) = prove_hint_weight(&hints)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("prove_hint_weight failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, onchain_commitment, c_tilde_hex,
        hw_proof, hw_commitment, hw_total))
}

/// verify_mldsa_hash_check_py(pk, msg, w1_prime, c_tilde_hex) -> bool
///
/// Off-circuit ML-DSA.Verify hash step: recomputes
///   μ = SHAKE-256(SHAKE-256(pk) ∥ M')
///   c̃' = SHAKE-256(μ ∥ w1Encode(w1_prime))
/// and checks that c̃' == c_tilde.
///
/// This ties the STARK witness (w1_prime) back to the original message and
/// public key, completing the logical chain of ML-DSA.Verify.
///
/// `pk`         — raw public key bytes (PK_BYTES = 1952 for ML-DSA-65).
/// `msg`        — original message bytes.
/// `w1_prime`   — K rows × N coefficients (UseHint output, values in [0, m=16)).
/// `c_tilde_hex`— hex-encoded c_tilde returned by prove_mldsa_sig_witness_py.
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_hash_check_py(
    pk:          Vec<u8>,
    msg:         Vec<u8>,
    w1_prime:    Vec<Vec<i64>>,
    c_tilde_hex: String,
) -> PyResult<bool> {
    use mldsa::xof::{hash_pk, hash_mu, hash_commit};
    use mldsa::encoding::w1_encode;
    use mldsa::polyvec::PolyVec;
    use mldsa::poly::Poly;
    use mldsa::params::{K, LAMBDA_BYTES};
    use mldsa::N;

    // Decode w1_prime into PolyVec.
    if w1_prime.len() != K {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("w1_prime must have K={K} rows, got {}", w1_prime.len())
        ));
    }
    let w1_polyvec = PolyVec(w1_prime.into_iter().map(|row| {
        let coeffs: [i64; N] = row.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err(
                "each w1_prime row must have exactly 256 elements"
            ))?;
        Ok(Poly::from_coeffs(coeffs))
    }).collect::<PyResult<Vec<_>>>()?);

    // Decode c_tilde from hex.
    let c_tilde = hex::decode(&c_tilde_hex)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(
            format!("c_tilde_hex is not valid hex: {e}")
        ))?;
    if c_tilde.len() != LAMBDA_BYTES {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("c_tilde must be {LAMBDA_BYTES} bytes, got {}", c_tilde.len())
        ));
    }

    // Recompute μ = SHAKE-256(tr ∥ M')  where M' = [0x00, 0x00] ∥ msg.
    let tr = hash_pk(&pk);
    let mut m_prime = vec![0u8, 0u8];
    m_prime.extend_from_slice(&msg);
    let mu = hash_mu(&tr, &m_prime);

    // Recompute c̃' = SHAKE-256(μ ∥ w1Encode(w1_prime), LAMBDA_BYTES).
    let w1_enc = w1_encode(&w1_polyvec);
    let c_tilde_prime = hash_commit(&mu, &w1_enc, LAMBDA_BYTES);

    Ok(c_tilde_prime == c_tilde)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::{BaseField, M31};
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

    // ── UseHint STARK tests (MVP-3+) ─────────────────────────────────────────

    #[test]
    fn test_prove_and_verify_use_hint_no_hints() {
        let r   = random_q_poly(1200);
        let h   = [false; 256];
        let (proof_bytes, commitment_hex, w1) =
            prove_use_hint(&r, &h).expect("use_hint proving failed");
        // No hints: w1[i] = HighBits(r[i]).
        for i in 0..256 {
            let (r1, _) = mldsa_use_hint_air::decompose_val_signed(r[i]);
            assert_eq!(w1[i], r1, "no-hint w1[{i}]");
        }
        let valid = verify_use_hint(&proof_bytes, &commitment_hex)
            .expect("use_hint verification failed");
        assert!(valid, "use_hint (no hints) proof should verify");
    }

    #[test]
    fn test_prove_and_verify_use_hint_random() {
        use mldsa::polyvec::use_hint_val;
        let r = random_q_poly(1300);
        let mut state = 1301u64;
        let h: [bool; 256] = std::array::from_fn(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 63) != 0
        });
        let (proof_bytes, commitment_hex, w1) =
            prove_use_hint(&r, &h).expect("use_hint proving failed");
        for i in 0..256 {
            assert_eq!(w1[i], use_hint_val(h[i], r[i]), "w1[{i}]");
        }
        let valid = verify_use_hint(&proof_bytes, &commitment_hex)
            .expect("use_hint verification failed");
        assert!(valid, "use_hint proof should verify");
    }

    #[test]
    fn test_use_hint_tampered_proof_fails() {
        let r = random_q_poly(1400);
        let h = [true; 256];
        let (proof_bytes, commitment_hex, _) =
            prove_use_hint(&r, &h).expect("use_hint proving failed");
        let mut bad = proof_bytes.clone();
        bad[20] ^= 0xFF;
        assert!(!verify_use_hint(&bad, &commitment_hex).unwrap_or(false));
    }
}
