pub mod air;
pub mod mldsa;
pub mod mldsa_intt_air;
pub mod mldsa_ntt_air;
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

// ─── 128-bit commitment helpers ───────────────────────────────────────────────
//
// Layout (16 bytes = 32 hex chars):
//   bytes [0:4]  — M31 field element (le-u32), extracted by verifier for Fiat-Shamir
//   bytes [4:16] — Blake2s(m31_le ∥ proof[0:32])[0:12], 96-bit proof-binding suffix
//
// The M31 component stays 32-bit for Fiat-Shamir mixing (must be known before proving).
// The suffix provides 128-bit total binding for on-chain batch identification and
// prevents birthday collisions that would be feasible with a 32-bit commitment alone.

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

/// Parse and validate a 128-bit commitment. Returns the M31 value for Fiat-Shamir mixing.
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

/// Maximum proof size accepted by the verifiers (32 MB).
/// Prevents crafted length-prefix fields in bincode from triggering unbounded heap
/// allocation before any actual deserialization work begins (audit H-3).
const MAX_PROOF_BYTES: usize = 32 * 1024 * 1024;

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

/// Commit to the NTT output: Blake2s over all 256 coefficients → 4-byte M31 value.
///
/// Calling this before `prove()` lets us mix the output fingerprint into the
/// Fiat-Shamir channel before the FRI queries are determined.
fn ntt_commitment_m31(ntt_out: &[i64; 256]) -> u32 {
    let mut h = Blake2s256::new();
    for c in ntt_out {
        h.update(&(*c as u32).to_le_bytes());
    }
    let hash = h.finalize();
    u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) % M31_MODULUS
}

/// Prove a forward NTT over Z_q[X]/(X^{256}+1) using a Circle STARK.
///
/// Input `f` must have coefficients in `[0, Q)` (Q = 8 380 417).
///
/// Returns `(proof_bytes, commitment_hex, ntt_out)`:
/// - `proof_bytes`: serialised STARK proof (~90–200 KB)
/// - `commitment_hex`: 32-hex-char 128-bit binding of proof to NTT output
/// - `ntt_out`: the NTT of `f` (forward transform result)
///
/// # Soundness
/// The butterfly-addition/subtraction constraints (C2–C5) are fully sound in M31.
/// The multiplication constraint (C1) requires range-check arguments for full
/// soundness (planned for MVP-4); the proof is sound for honest provers.
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

    // Commitment M31 value: fingerprint of the NTT output (mixed into Fiat-Shamir).
    let commitment_m31 = ntt_commitment_m31(&ntt_out);

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

    // Mix NTT output fingerprint into the Fiat-Shamir transcript.
    channel.mix_u32s(&[commitment_m31]);

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

    let commitment_hex = build_commitment_128(commitment_m31, &proof_bytes);
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

    // Parse 128-bit commitment → M31 fingerprint for Fiat-Shamir replay.
    let commitment_m31 = parse_commitment_128(commitment_hex, proof_bytes)?;

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

    // Replay Fiat-Shamir: mix the same NTT output fingerprint as the prover.
    verifier_channel.mix_u32s(&[commitment_m31]);

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

    // Commitment: Blake2s fingerprint of product coefficients.
    let commitment_m31 = {
        let mut h = Blake2s256::new();
        for c in &product { h.update(&(*c as u32).to_le_bytes()); }
        let hash = h.finalize();
        u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) % M31_MODULUS
    };

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

    channel.mix_u32s(&[commitment_m31]);

    let component = PolyMulComponent::new(
        &mut TraceLocationAllocator::default(),
        PolyMulEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    let commitment_hex = build_commitment_128(commitment_m31, &proof_bytes);
    Ok((proof_bytes, commitment_hex, product))
}

/// Verify a pointwise-multiplication proof produced by [`prove_poly_mul`].
pub fn verify_poly_mul(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_poly_mul_air::{PolyMulEval, PolyMulComponent, LOG_N_ROWS};

    let log_size = LOG_N_ROWS;
    let commitment_m31 = parse_commitment_128(commitment_hex, proof_bytes)?;

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
    verifier_channel.mix_u32s(&[commitment_m31]);

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
}
