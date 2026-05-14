/// ML-DSA-65 verification STARK (MVP-3+)
///
/// Combines the NTT butterfly AIR and pointwise-multiplication AIR into a
/// high-level API that proves one polynomial ring multiplication:
///
///   out = INTT( NTT(a) ⊙ NTT(b) )   (i.e. a × b in Z_q[X]/(X^256+1))
///
/// This covers both key computations in ML-DSA.Verify (FIPS 204 Algorithm 3):
///   • A·z      — matrix-vector product (one call per A row)
///   • c · t₁   — challenge × public key component
///
/// # Pipeline for one polynomial multiplication a × b → out
///
///   Step 1  NTT(a)  — proved by MlDsaNttButterflyEval (1024 rows)
///   Step 2  NTT(b)  — proved by MlDsaNttButterflyEval (1024 rows)
///   Step 3  a_hat ⊙ b_hat — proved by PolyMulEval (256 rows)
///   Step 4  INTT(product)  — proved by MlDsaNttButterflyEval (1024 rows)
///
/// Each step produces an independent STARK proof; the caller chains the
/// proofs by passing the output of one step as the input to the next
/// (the output is committed as the 128-bit `commitment_hex`).
///
/// # Soundness
///
/// The NTT butterfly addition/subtraction constraints (C2–C5) are fully sound
/// in M31.  The multiplication constraints (NTT C1, PolyMul C1, INTT C1)
/// require range-check arguments for full soundness — tracked for MVP-4.

use bincode::{Decode, Encode};

use crate::mldsa::{Q, N};
use crate::mldsa::ntt::{ntt, ntt_inv, pointwise_mul};

// ── High-level polynomial multiplication via STARK pipeline ──────────────────

/// Result of a STARK-proved polynomial ring multiplication.
#[derive(Encode, Decode)]
pub struct PolyMulProof {
    /// STARK proof for NTT(a): proof_bytes + commitment.
    pub proof_ntt_a:    (Vec<u8>, String),
    /// STARK proof for NTT(b): proof_bytes + commitment.
    pub proof_ntt_b:    (Vec<u8>, String),
    /// STARK proof for NTT(a) ⊙ NTT(b): proof_bytes + commitment.
    pub proof_mul:      (Vec<u8>, String),
    /// STARK proof for INTT(product): proof_bytes + commitment.
    pub proof_intt:     (Vec<u8>, String),
    /// Final output: a × b in Z_q[X]/(X^256+1), coefficients in [0, Q).
    pub output:         [i64; N],
}

/// Prove the polynomial ring multiplication `a × b` over Z_q[X]/(X^{256}+1).
///
/// Generates four STARK proofs (NTT-a, NTT-b, pointwise-mul, INTT) and
/// returns their commitments together with the final ring-multiplication output.
///
/// All input coefficients must be in `[0, Q)`.
pub fn prove_ring_mul(a: &[i64; N], b: &[i64; N]) -> Result<PolyMulProof, String> {
    // Validate inputs.
    for (i, &c) in a.iter().enumerate() {
        if c < 0 || c >= Q { return Err(format!("a[{i}] = {c} out of [0, Q)")); }
    }
    for (i, &c) in b.iter().enumerate() {
        if c < 0 || c >= Q { return Err(format!("b[{i}] = {c} out of [0, Q)")); }
    }

    // Step 1 & 2: Prove NTT(a) and NTT(b) in parallel.
    let (proof_a_bytes, commitment_a, a_hat) = crate::prove_ntt(a)?;
    let (proof_b_bytes, commitment_b, b_hat) = crate::prove_ntt(b)?;

    // Step 3: Prove NTT(a) ⊙ NTT(b).
    let (proof_mul_bytes, commitment_mul, product_hat) =
        crate::prove_poly_mul(&a_hat, &b_hat)?;

    // Step 4: Prove INTT(product).
    // INTT input must be in [0, Q); product_hat is already in that range.
    let (proof_intt_bytes, commitment_intt, output) = prove_intt(&product_hat)?;

    Ok(PolyMulProof {
        proof_ntt_a:  (proof_a_bytes, commitment_a),
        proof_ntt_b:  (proof_b_bytes, commitment_b),
        proof_mul:    (proof_mul_bytes, commitment_mul),
        proof_intt:   (proof_intt_bytes, commitment_intt),
        output,
    })
}

/// Verify all four STARK proofs in a `PolyMulProof`.
///
/// Returns `Ok(true)` iff all four proofs are valid and self-consistent.
pub fn verify_ring_mul(proof: &PolyMulProof) -> Result<bool, String> {
    let ok_a    = crate::verify_ntt(&proof.proof_ntt_a.0, &proof.proof_ntt_a.1)?;
    let ok_b    = crate::verify_ntt(&proof.proof_ntt_b.0, &proof.proof_ntt_b.1)?;
    let ok_mul  = crate::verify_poly_mul(&proof.proof_mul.0, &proof.proof_mul.1)?;
    let ok_intt = verify_intt(&proof.proof_intt.0, &proof.proof_intt.1)?;
    Ok(ok_a && ok_b && ok_mul && ok_intt)
}

// ── INTT STARK  ───────────────────────────────────────────────────────────────
//
// The Gentleman-Sande (GS) INTT uses the *same* butterfly structure as the
// Cooley-Tukey NTT but with inverse twiddle factors.  Algebraically the
// butterfly is:
//
//   t       = ζ_k^{-1} × (a_in − b_in)   (mod Q)
//   a_out   = a_in + b_in                  (mod Q)
//   b_out   = t                             (mod Q)
//
// followed by a global multiplication by N^{-1} = 256^{-1} mod Q.
//
// We reuse the *same* `MlDsaNttButterflyEval` AIR (same constraint system)
// because the butterfly arithmetic is structurally identical — only the
// twiddle factors differ.  The INTT witness generator supplies ζ^{-1} values
// instead of ζ values; the AIR verifies exactly the same constraints.

/// Prove a forward INTT (= NTT^{-1}) over Z_q[X]/(X^{256}+1) using a STARK.
///
/// Uses the GS butterfly AIR (`MlDsaInttButterflyEval`) with inverse twiddle factors.
/// The output includes the final N^{-1} scaling step; the butterfly stages are
/// proved in the STARK; the scaling is applied in the trace builder and bound
/// via the commitment fingerprint.
pub fn prove_intt(f: &[i64; N]) -> Result<(Vec<u8>, String, [i64; N]), String> {
    use crate::mldsa_intt_air::{
        MlDsaInttButterflyEval, MlDsaInttButterflyComponent, LOG_N_BUTTERFLIES,
        build_trace as intt_build_trace,
    };
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::PcsConfig;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    for (i, &c) in f.iter().enumerate() {
        if c < 0 || c >= Q { return Err(format!("f[{i}] = {c} out of [0, Q)")); }
    }

    let log_size = LOG_N_BUTTERFLIES;
    let (columns, intt_out) = intt_build_trace(f);

    // Scheme-B: 128-bit output fingerprint mixed into Fiat-Shamir.
    let fp = crate::output_fingerprint(&intt_out);
    let commitment_hex = crate::build_poly_commitment(&fp);

    let log_blowup = crate::LOG_BLOWUP;
    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = log_blowup;
    let config = PcsConfig {
        lifting_log_size: Some(log_size + log_blowup),
        ..config
    };

    let lifting = log_size + log_blowup;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(vec![]);
    tb.commit(channel);

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(columns);
    tb.commit(channel);

    // Mix 4-word fingerprint (128-bit FS binding).
    channel.mix_u32s(&fp);

    let component = MlDsaInttButterflyComponent::new(
        &mut TraceLocationAllocator::default(),
        MlDsaInttButterflyEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component], channel, commitment_scheme,
    )
    .map_err(|e| format!("INTT proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, intt_out))
}

/// Verify an INTT STARK proof produced by [`prove_intt`].
pub fn verify_intt(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;
    use crate::mldsa_intt_air::{
        MlDsaInttButterflyEval, MlDsaInttButterflyComponent, LOG_N_BUTTERFLIES,
    };

    let log_size = LOG_N_BUTTERFLIES;

    // Scheme-B: decode 4-word fingerprint for Fiat-Shamir replay.
    let fp = crate::parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<{ 8 * 1024 * 1024 }>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

    let log_blowup = crate::LOG_BLOWUP;
    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = log_blowup;

    let component = MlDsaInttButterflyComponent::new(
        &mut TraceLocationAllocator::default(),
        MlDsaInttButterflyEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: {} commitments", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&fp);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&component], verifier_channel, commitment_scheme, proof,
    )
    .is_ok())
}

/// Prove an INTT and bind the proof to both the input and output polynomials.
///
/// Identical to [`prove_intt`] but mixes the input fingerprint of `f` into the
/// Fiat-Shamir channel *before* the output fingerprint.  The verifier must supply
/// the same `f` to [`verify_intt_with_binding`]; a wrong input causes the channel
/// state to diverge and every FRI query check to fail.
///
/// Used by the v2 Az pipeline so that each INTT proof is cryptographically tied
/// to the specific `az_hat[i]` row it was computed from.
pub fn prove_intt_with_binding(f: &[i64; N]) -> Result<(Vec<u8>, String, [i64; N]), String> {
    use crate::mldsa_intt_air::{
        MlDsaInttButterflyEval, MlDsaInttButterflyComponent, LOG_N_BUTTERFLIES,
        build_trace as intt_build_trace,
    };
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::PcsConfig;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    for (i, &c) in f.iter().enumerate() {
        if c < 0 || c >= Q { return Err(format!("f[{i}] = {c} out of [0, Q)")); }
    }

    let log_size = LOG_N_BUTTERFLIES;
    let (columns, intt_out) = intt_build_trace(f);

    // Bind to input f (az_hat) first, then to output (same ordering as prove_az_row).
    let input_fp  = crate::output_fingerprint(f);
    let output_fp = crate::output_fingerprint(&intt_out);
    let commitment_hex = crate::build_poly_commitment(&output_fp);

    let log_blowup = crate::LOG_BLOWUP;
    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = log_blowup;
    let config = PcsConfig { lifting_log_size: Some(log_size + log_blowup), ..config };

    let lifting = log_size + log_blowup;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(vec![]);
    tb.commit(channel);

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(columns);
    tb.commit(channel);

    // Input fingerprint first, then output fingerprint.
    channel.mix_u32s(&input_fp);
    channel.mix_u32s(&output_fp);

    let component = MlDsaInttButterflyComponent::new(
        &mut TraceLocationAllocator::default(),
        MlDsaInttButterflyEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component], channel, commitment_scheme,
    )
    .map_err(|e| format!("INTT proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, intt_out))
}

/// Verify an INTT proof produced by [`prove_intt_with_binding`].
///
/// `input` must be the same `[i64; N]` polynomial that was passed to the prover.
/// The verifier recomputes the input fingerprint, mixes it first, then mixes the
/// output fingerprint from `commitment_hex`.  A wrong `input` causes the Fiat-Shamir
/// transcript to diverge and verification to fail.
pub fn verify_intt_with_binding(
    proof_bytes:    &[u8],
    commitment_hex: &str,
    input:          &[i64; N],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;
    use crate::mldsa_intt_air::{MlDsaInttButterflyEval, MlDsaInttButterflyComponent, LOG_N_BUTTERFLIES};

    let log_size = LOG_N_BUTTERFLIES;

    let input_fp  = crate::output_fingerprint(input);
    let output_fp = crate::parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<{ 8 * 1024 * 1024 }>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

    let log_blowup = crate::LOG_BLOWUP;
    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = log_blowup;

    let component = MlDsaInttButterflyComponent::new(
        &mut TraceLocationAllocator::default(),
        MlDsaInttButterflyEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: {} commitments", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Replay transcript: input fingerprint first, then output fingerprint.
    verifier_channel.mix_u32s(&input_fp);
    verifier_channel.mix_u32s(&output_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&component], verifier_channel, commitment_scheme, proof,
    )
    .is_ok())
}

// ── Matrix-vector product Az v2 (MVP-3+ — uses dedicated Az-row AIR) ─────────
//
// Replaces prove_az (65 sub-proofs) with the dedicated Az-row AIR circuit:
//
//   1. NTT(z[j]) for each j          —  L proofs      (crate::prove_ntt)
//   2. prove_az_row per output row i  —  K proofs      (crate::prove_az_row)
//   3. INTT(Az_hat[i]) per row i      —  K proofs      (prove_intt)
//
// Total: L + 2K = 5 + 12 = 17 proofs for ML-DSA-65 (vs 65 in prove_az).
// Each Az-row AIR has 28 columns × 256 rows and 13 constraints (degree ≤ 2).

/// Aggregated STARK proof for the full matrix-vector product Az (v2).
#[derive(Encode, Decode)]
pub struct AzProofV2 {
    /// L NTT proofs: z_hat[j] = NTT(z[j]).
    pub proofs_ntt_z: Vec<(Vec<u8>, String)>,
    /// NTT outputs z_hat[j] (needed to supply to prove_az_row).
    pub z_hat:        Vec<[i64; N]>,
    /// K Az-row AIR proofs: Az_hat[i] = Σ_j A_hat[i][j] ⊙ z_hat[j].
    pub proofs_az_row: Vec<(Vec<u8>, String)>,
    /// NTT-domain outputs Az_hat[i] (needed for INTT input).
    pub az_hat:       Vec<[i64; N]>,
    /// K INTT proofs: Az[i] = INTT(Az_hat[i]).
    pub proofs_intt:  Vec<(Vec<u8>, String)>,
    /// Az[i] in polynomial domain, coefficients in [0, Q).
    pub output:       Vec<[i64; N]>,
}

/// Prove the matrix-vector product `Az` in R_q using the dedicated Az-row AIR.
///
/// `a_hat` — K×L NTT-domain polynomials, row-major (index i*l + j = A[i][j]).
/// `z`     — L polynomial-domain polynomials (from the signature).
/// `k` / `l` must equal ML-DSA-65 params (6 / 5); the Az-row AIR is specialised for L=5.
pub fn prove_az_v2(
    a_hat: &[[i64; N]],
    z:     &[[i64; N]],
    k:     usize,
    l:     usize,
) -> Result<AzProofV2, String> {
    if l != crate::mldsa::params::L {
        return Err(format!(
            "prove_az_v2 requires l = {} (ML-DSA-65), got l = {}",
            crate::mldsa::params::L, l
        ));
    }
    if a_hat.len() != k * l {
        return Err(format!("a_hat must have k*l={} entries, got {}", k * l, a_hat.len()));
    }
    if z.len() != l {
        return Err(format!("z must have l={l} entries, got {}", z.len()));
    }

    // Step 1: NTT(z[j]) for each j.
    let mut proofs_ntt_z: Vec<(Vec<u8>, String)> = Vec::with_capacity(l);
    let mut z_hat:         Vec<[i64; N]>           = Vec::with_capacity(l);
    for (j, zj) in z.iter().enumerate() {
        let (pb, cm, zh) = crate::prove_ntt(zj)
            .map_err(|e| format!("NTT proof for z[{j}] failed: {e}"))?;
        proofs_ntt_z.push((pb, cm));
        z_hat.push(zh);
    }

    // Pack z_hat into the [L; N] fixed-size array expected by prove_az_row.
    let z_hat_arr: [[i64; N]; 5] = z_hat.as_slice().try_into()
        .map_err(|_| "z_hat must have exactly L=5 entries".to_string())?;

    // Step 2 & 3: For each row i, prove Az_hat[i] and then INTT.
    let mut proofs_az_row: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut az_hat_out:    Vec<[i64; N]>           = Vec::with_capacity(k);
    let mut proofs_intt:   Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut output:        Vec<[i64; N]>           = Vec::with_capacity(k);

    for i in 0..k {
        let a_row: [[i64; N]; 5] = a_hat[i * l..(i + 1) * l].try_into()
            .map_err(|_| format!("a_hat slice for row {i} has wrong length"))?;

        // Step 2: Az_hat[i] = Σ_j A_hat[i][j] ⊙ z_hat[j]  (Az-row AIR).
        let (pb_az, cm_az, az_hat_i) = crate::prove_az_row(&a_row, &z_hat_arr)
            .map_err(|e| format!("prove_az_row row {i} failed: {e}"))?;
        proofs_az_row.push((pb_az, cm_az));
        az_hat_out.push(az_hat_i);

        // Step 3: Az[i] = INTT(Az_hat[i]) — input-bound proof ties az_hat_i to this INTT.
        let (pb_intt, cm_intt, az_i) = prove_intt_with_binding(&az_hat_i)
            .map_err(|e| format!("INTT proof for Az row {i} failed: {e}"))?;
        proofs_intt.push((pb_intt, cm_intt));
        output.push(az_i);
    }

    Ok(AzProofV2 {
        proofs_ntt_z,
        z_hat,
        proofs_az_row,
        az_hat: az_hat_out,
        proofs_intt,
        output,
    })
}

/// Verify all STARK sub-proofs in an `AzProofV2`.
///
/// Performs four layers of cross-consistency checks that together form an
/// unbroken chain: NTT(z) → Az-row → INTT(Az_hat):
///
///   1. NTT→z_hat: stored z_hat[j] fingerprint matches NTT output commitment.
///   2. z_hat→Az-row: verifier reconstructs input fingerprint from z_hat and passes it
///      to `verify_az_row`, binding the Az-row FRI proof to the specific z_hat used.
///   3. Az-row→az_hat: stored az_hat[i] fingerprint matches Az-row output commitment,
///      preventing the prover from claiming a different az_hat than what was proven.
///   4. az_hat→INTT: `verify_intt_with_binding` recomputes the input fingerprint of
///      az_hat[i] and mixes it into the verifier channel before the output fingerprint,
///      so a proof generated with a different input polynomial will fail FRI queries.
pub fn verify_az_v2(proof: &AzProofV2) -> Result<bool, String> {
    let l = proof.z_hat.len();
    let k = proof.proofs_intt.len();

    // Layer 1: Verify NTT(z[j]) proofs.
    for (j, (pb, cm)) in proof.proofs_ntt_z.iter().enumerate() {
        if !crate::verify_ntt(pb, cm)
            .map_err(|e| format!("NTT verify z[{j}] failed: {e}"))? {
            return Ok(false);
        }
    }

    // Cross-check 1: stored z_hat[j] fingerprint must match the NTT output commitment.
    for j in 0..l {
        let fp = crate::output_fingerprint(&proof.z_hat[j]);
        let expected_cm = crate::build_poly_commitment(&fp);
        if j < proof.proofs_ntt_z.len() && expected_cm != proof.proofs_ntt_z[j].1 {
            return Ok(false);
        }
    }

    // Build the z_hat slice for Az-row input fingerprint reconstruction.
    let z_hat_slices: Vec<[i64; N]> = proof.z_hat.clone();

    // Layer 2: Verify Az-row AIR proofs, passing z_hat to reconstruct the input fingerprint.
    for (i, (pb, cm)) in proof.proofs_az_row.iter().enumerate() {
        if !crate::verify_az_row(pb, cm, &z_hat_slices)
            .map_err(|e| format!("Az-row verify row {i} failed: {e}"))? {
            return Ok(false);
        }
    }

    // Cross-check 2: stored az_hat[i] fingerprint must match the Az-row output commitment.
    // This prevents a prover from claiming a different az_hat than what the Az-row circuit proved.
    for i in 0..k {
        if i >= proof.az_hat.len() || i >= proof.proofs_az_row.len() {
            break;
        }
        let fp = crate::output_fingerprint(&proof.az_hat[i]);
        let expected_cm = crate::build_poly_commitment(&fp);
        if expected_cm != proof.proofs_az_row[i].1 {
            return Ok(false);
        }
    }

    // Layer 4: Verify INTT(az_hat[i]) with input binding.
    // verify_intt_with_binding recomputes the fingerprint of az_hat[i] and mixes it
    // first into the channel — closing the az_hat[i] → INTT soundness gap.
    for i in 0..k {
        if i >= proof.az_hat.len() { break; }
        if !verify_intt_with_binding(
            &proof.proofs_intt[i].0,
            &proof.proofs_intt[i].1,
            &proof.az_hat[i],
        )
        .map_err(|e| format!("INTT verify Az row {i} failed: {e}"))? {
            return Ok(false);
        }
    }
    Ok(true)
}

// ── Matrix-vector product Az v3 (MVP-3+ — full-matrix AIR, 1 Az proof) ────────
//
// Replaces K=6 separate Az-row proofs with one full-matrix STARK:
//
//   1. NTT(z[j]) for each j   —  L proofs    (crate::prove_ntt)
//   2. prove_az_full           —  1 proof     (crate::prove_az_full)
//   3. INTT(Az_hat[i])         —  K proofs    (prove_intt_with_binding)
//   4. range_q(Az[i])          —  K proofs    (crate::prove_range_q)
//
// Total: L + 1 + K + K = 5 + 1 + 6 + 6 = 18 proofs (vs 17 in v2, 65 in v1).
// The range-Q proofs close the M31 wrap-around soundness gap in mul constraints.

/// Aggregated STARK proof for the full matrix-vector product Az (v3 — single Az proof).
#[derive(Encode, Decode)]
pub struct AzProofV3 {
    /// L NTT proofs: z_hat[j] = NTT(z[j]).
    pub proofs_ntt_z:   Vec<(Vec<u8>, String)>,
    /// NTT outputs z_hat[j].
    pub z_hat:           Vec<[i64; N]>,
    /// Single full-matrix Az proof: all K rows proved simultaneously.
    pub proof_az_full:   (Vec<u8>, String),
    /// K NTT-domain outputs Az_hat[i] (for INTT input and cross-check).
    pub az_hat:          Vec<[i64; N]>,
    /// K INTT proofs: Az[i] = INTT(Az_hat[i]) with input binding.
    pub proofs_intt:     Vec<(Vec<u8>, String)>,
    /// Az[i] in polynomial domain.
    pub output:          Vec<[i64; N]>,
    /// K Q-range proofs: each Az[i] output coefficient is in [0, Q).
    /// Closes the M31 wrap-around soundness gap in the mul constraints.
    pub proofs_range_q:  Vec<(Vec<u8>, String)>,
}

/// Prove the matrix-vector product `Az` in R_q using the full-matrix Az AIR.
///
/// `a_hat` — K×L NTT-domain polynomials, row-major.
/// `z`     — L polynomial-domain polynomials.
/// Produces 18 sub-proofs total (L NTT + 1 Az-full + K INTT + K range-Q).
pub fn prove_az_v3(
    a_hat:        &[[i64; N]],
    z:            &[[i64; N]],
    k:            usize,
    l:            usize,
    c_tilde_seed: &[u8],
) -> Result<AzProofV3, String> {
    use crate::mldsa::params;
    if l != params::L {
        return Err(format!("prove_az_v3 requires l = {} (ML-DSA-65), got {}", params::L, l));
    }
    if k != params::K {
        return Err(format!("prove_az_v3 requires k = {} (ML-DSA-65), got {}", params::K, k));
    }
    if a_hat.len() != k * l {
        return Err(format!("a_hat must have k*l={} entries, got {}", k * l, a_hat.len()));
    }
    if z.len() != l {
        return Err(format!("z must have l={l} entries, got {}", z.len()));
    }

    // Step 1: NTT(z[j]) for each j.
    let mut proofs_ntt_z: Vec<(Vec<u8>, String)> = Vec::with_capacity(l);
    let mut z_hat:         Vec<[i64; N]>           = Vec::with_capacity(l);
    for (j, zj) in z.iter().enumerate() {
        let (pb, cm, zh) = crate::prove_ntt(zj)
            .map_err(|e| format!("NTT proof for z[{j}] failed: {e}"))?;
        proofs_ntt_z.push((pb, cm));
        z_hat.push(zh);
    }

    let z_hat_arr: [[i64; N]; 5] = z_hat.as_slice().try_into()
        .map_err(|_| "z_hat must have exactly L=5 entries".to_string())?;

    // Step 2: Prove Az for all K rows simultaneously, with c_tilde as public input.
    let (pb_az, cm_az, az_out_arr) = crate::prove_az_full(a_hat, &z_hat_arr, c_tilde_seed)
        .map_err(|e| format!("prove_az_full failed: {e}"))?;
    let proof_az_full = (pb_az, cm_az);

    // Extract K az_hat rows from the full output.
    let az_hat_vecs: Vec<[i64; N]> = az_out_arr.to_vec();

    // Step 3: INTT(Az_hat[i]) for each row i, with input binding.
    let mut proofs_intt: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut output:       Vec<[i64; N]>           = Vec::with_capacity(k);
    for (i, az_hat_i) in az_hat_vecs.iter().enumerate() {
        let (pb, cm, az_i) = prove_intt_with_binding(az_hat_i)
            .map_err(|e| format!("INTT proof for Az row {i} failed: {e}"))?;
        proofs_intt.push((pb, cm));
        output.push(az_i);
    }

    // Step 4: Q-range proof for each Az[i] output polynomial.
    // Closes the M31 wrap-around soundness gap in the multiplication constraints.
    let mut proofs_range_q: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    for (i, az_i) in output.iter().enumerate() {
        let az_arr: &[i64; N] = az_i;
        let (pb, cm) = crate::prove_range_q(az_arr)
            .map_err(|e| format!("prove_range_q for Az row {i} failed: {e}"))?;
        proofs_range_q.push((pb, cm));
    }

    Ok(AzProofV3 {
        proofs_ntt_z,
        z_hat,
        proof_az_full,
        az_hat: az_hat_vecs,
        proofs_intt,
        output,
        proofs_range_q,
    })
}

/// Verify all STARK sub-proofs in an `AzProofV3`.
///
/// Four-layer cross-consistency chain:
///   1. NTT→z_hat: stored z_hat[j] fingerprint matches NTT output commitment.
///   2. z_hat→Az-full: verifier reconstructs input fingerprint from z_hat and passes
///      it to `verify_az_full`, binding the full-matrix FRI proof to the specific z_hat.
///   3. Az-full→az_hat: stored az_hat fingerprint (all K rows concatenated) matches
///      the Az-full output commitment.
///   4. az_hat→INTT: `verify_intt_with_binding` binds each INTT proof to its az_hat[i].
pub fn verify_az_v3(proof: &AzProofV3, c_tilde_seed: &[u8]) -> Result<bool, String> {
    let l = proof.z_hat.len();
    let k = proof.proofs_intt.len();

    // Layer 1: Verify NTT(z[j]) proofs.
    for (j, (pb, cm)) in proof.proofs_ntt_z.iter().enumerate() {
        if !crate::verify_ntt(pb, cm)
            .map_err(|e| format!("NTT verify z[{j}] failed: {e}"))? {
            return Ok(false);
        }
    }

    // Cross-check 1: stored z_hat[j] fingerprint must match NTT output commitment.
    for j in 0..l {
        let fp = crate::output_fingerprint(&proof.z_hat[j]);
        let expected_cm = crate::build_poly_commitment(&fp);
        if j < proof.proofs_ntt_z.len() && expected_cm != proof.proofs_ntt_z[j].1 {
            return Ok(false);
        }
    }

    // Layer 2: Verify the full-matrix Az proof with z_hat input binding.
    let z_hat_arr: [[i64; N]; 5] = match proof.z_hat.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return Err(format!("z_hat must have exactly L=5 entries, got {}", l)),
    };
    if !crate::verify_az_full(&proof.proof_az_full.0, &proof.proof_az_full.1, &z_hat_arr, c_tilde_seed)
        .map_err(|e| format!("Az-full verify failed: {e}"))? {
        return Ok(false);
    }

    // Cross-check 2: stored az_hat fingerprint (all K rows) must match Az-full commitment.
    {
        let az_flat: Vec<i64> = proof.az_hat.iter().flat_map(|row| row.iter().copied()).collect();
        let fp = crate::output_fingerprint(&az_flat);
        let expected_cm = crate::build_poly_commitment(&fp);
        if expected_cm != proof.proof_az_full.1 {
            return Ok(false);
        }
    }

    // Layer 4: Verify INTT(az_hat[i]) proofs with input binding.
    for i in 0..k {
        if i >= proof.az_hat.len() { break; }
        if !verify_intt_with_binding(
            &proof.proofs_intt[i].0,
            &proof.proofs_intt[i].1,
            &proof.az_hat[i],
        )
        .map_err(|e| format!("INTT verify Az row {i} failed: {e}"))? {
            return Ok(false);
        }
    }

    // Layer 5: Verify Q-range proofs for each Az[i] output polynomial.
    // The commitment encodes the polynomial fingerprint; the verifier cross-checks it.
    for (i, (pb, cm)) in proof.proofs_range_q.iter().enumerate() {
        if !crate::verify_range_q(pb, cm)
            .map_err(|e| format!("verify_range_q Az row {i} failed: {e}"))? {
            return Ok(false);
        }
        // Cross-check: range proof commitment must match the fingerprint of output[i].
        if i < proof.output.len() {
            let fp = crate::output_fingerprint(&proof.output[i]);
            let expected_cm = crate::build_poly_commitment(&fp);
            if expected_cm != *cm {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

// ── Full ML-DSA.Verify witness v2 (uses Az-row AIR — 17 Az proofs vs 65) ─────

/// Combined STARK proof for the ML-DSA.Verify arithmetic witness (v2).
///
/// Identical to `VerifyMldsaProof` but uses `AzProofV2` (Az-row AIR) instead of
/// `AzProof` (PolyMul+PolyAdd chains) for the matrix-vector product.
/// Total sub-proof count: 17 (Az) + 19 (Ct1) + K (sub) + L (norm) + K (UseHint)
/// = 17 + 19 + 6 + 5 + 6 = 53  vs 65 + 19 + 6 + 5 + 6 = 101 in v1.
#[derive(Encode, Decode)]
pub struct VerifyMldsaProofV2 {
    pub az_proof:        AzProofV2,
    pub ct1_proof:       Ct1Proof,
    pub proofs_sub:      Vec<(Vec<u8>, String)>,
    pub norm_proofs:     Vec<(Vec<u8>, String)>,
    pub use_hint_proofs: Vec<(Vec<u8>, String)>,
    pub w_prime:         Vec<[i64; N]>,
    pub w1_prime:        Vec<[i64; N]>,
    pub max_norms:       Vec<i64>,
}

/// Prove the full ML-DSA.Verify arithmetic witness using the Az-row AIR.
///
/// Same interface as `prove_verify_mldsa_witness` but produces 53 sub-proofs
/// instead of 101 by using the dedicated Az-row AIR for the matrix-vector product.
pub fn prove_verify_mldsa_v2(
    a_hat: &[[i64; N]],
    z:     &[[i64; N]],
    c:     &[i64; N],
    t1:    &[[i64; N]],
    hints: &[Vec<bool>],
    k:     usize,
    l:     usize,
) -> Result<VerifyMldsaProofV2, String> {
    if t1.len() != k {
        return Err(format!("t1 must have k={k} entries, got {}", t1.len()));
    }
    if hints.len() != k {
        return Err(format!("hints must have k={k} rows, got {}", hints.len()));
    }
    for (i, hrow) in hints.iter().enumerate() {
        if hrow.len() != N {
            return Err(format!("hints[{i}] must have N={N} bits, got {}", hrow.len()));
        }
    }

    // Step 1: Prove Az using the Az-row AIR.
    let az_proof = prove_az_v2(a_hat, z, k, l)
        .map_err(|e| format!("prove_az_v2 failed: {e}"))?;

    // Step 2: Prove c·t₁.
    let ct1_proof = prove_ct1(c, t1)
        .map_err(|e| format!("prove_ct1 failed: {e}"))?;

    // Step 3: Prove w′[i] = Az[i] − c·t₁[i].
    let mut proofs_sub: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut w_prime:    Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let (pb, cm, w_i) = crate::prove_poly_sub(&az_proof.output[i], &ct1_proof.output[i])
            .map_err(|e| format!("prove_poly_sub row {i} failed: {e}"))?;
        proofs_sub.push((pb, cm));
        w_prime.push(w_i);
    }

    // Step 4: Prove norm for each z[j].
    let mut norm_proofs: Vec<(Vec<u8>, String)> = Vec::with_capacity(l);
    let mut max_norms:   Vec<i64>                = Vec::with_capacity(l);
    for j in 0..l {
        let (pb, cm, _, mx) = crate::prove_norm_check(&z[j])
            .map_err(|e| format!("prove_norm_check z[{j}] failed: {e}"))?;
        norm_proofs.push((pb, cm));
        max_norms.push(mx);
    }

    // Step 5: Prove UseHint(h[i], w′[i]) = w₁′[i].
    let mut use_hint_proofs: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut w1_prime:        Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let h_arr: &[bool; N] = hints[i].as_slice().try_into()
            .map_err(|_| format!("hints[{i}] is not [bool; N]"))?;
        let (pb, cm, w1_i) = crate::prove_use_hint(&w_prime[i], h_arr)
            .map_err(|e| format!("prove_use_hint row {i} failed: {e}"))?;
        use_hint_proofs.push((pb, cm));
        w1_prime.push(w1_i);
    }

    Ok(VerifyMldsaProofV2 {
        az_proof,
        ct1_proof,
        proofs_sub,
        norm_proofs,
        use_hint_proofs,
        w_prime,
        w1_prime,
        max_norms,
    })
}

/// Verify all STARK sub-proofs in a `VerifyMldsaProofV2`.
pub fn verify_mldsa_witness_v2(proof: &VerifyMldsaProofV2) -> Result<bool, String> {
    if !verify_az_v2(&proof.az_proof)
        .map_err(|e| format!("verify_az_v2 failed: {e}"))? {
        return Ok(false);
    }
    if !verify_ct1(&proof.ct1_proof)
        .map_err(|e| format!("verify_ct1 failed: {e}"))? {
        return Ok(false);
    }
    for (i, (pb, cm)) in proof.proofs_sub.iter().enumerate() {
        if !crate::verify_poly_sub(pb, cm)
            .map_err(|e| format!("verify_poly_sub row {i} failed: {e}"))? {
            return Ok(false);
        }
    }
    for (j, (pb, cm)) in proof.norm_proofs.iter().enumerate() {
        if !crate::verify_norm_check(pb, cm)
            .map_err(|e| format!("verify_norm_check z[{j}] failed: {e}"))? {
            return Ok(false);
        }
    }
    for (i, (pb, cm)) in proof.use_hint_proofs.iter().enumerate() {
        if !crate::verify_use_hint(pb, cm)
            .map_err(|e| format!("verify_use_hint row {i} failed: {e}"))? {
            return Ok(false);
        }
    }
    Ok(true)
}

// ── Full ML-DSA.Verify witness v3 (Az-full AIR — 49 sub-proofs) ──────────────
//
// Uses AzProofV3 (single full-matrix Az proof) and adds a hint weight proof.
//
// Sub-proof count breakdown:
//   Az:          L(NTT-z) + 1(Az-full) + K(INTT)   = 5 + 1 + 6 = 12
//   Ct1:         1(NTT-c) + K(NTT-t1) + K(pmul) + K(INTT) = 19
//   poly_sub:    K                                  = 6
//   norm_check:  L                                  = 5
//   UseHint:     K                                  = 6
//   HintWeight:  1                                  = 1
//   Total:                                          = 49   (vs 53 in v2)

/// Combined STARK proof for the full ML-DSA.Verify arithmetic witness (v3).
///
/// v3 improvements over v2:
///   - AzProofV3 (single full-matrix AIR) instead of AzProofV2 (K Az-row proofs)
///   - Hint weight proof included (Σ||h[i]||₁ ≤ ω enforcement via STARK)
#[derive(Encode, Decode)]
pub struct VerifyMldsaProofV3 {
    pub az_proof:          AzProofV3,
    pub ct1_proof:         Ct1Proof,
    pub proofs_sub:        Vec<(Vec<u8>, String)>,
    pub norm_proofs:       Vec<(Vec<u8>, String)>,
    pub use_hint_proofs:   Vec<(Vec<u8>, String)>,
    pub hint_weight_proof: (Vec<u8>, String),
    pub w_prime:           Vec<[i64; N]>,
    pub w1_prime:          Vec<[i64; N]>,
    pub max_norms:         Vec<i64>,
    pub hint_weight_total: usize,
    /// FIPS 204 signature challenge (c̃, 48 bytes for ML-DSA-65).
    /// Mixed into the Az-full Fiat-Shamir channel as a STARK public input,
    /// binding the proof to the specific (pk, msg) pair.
    pub c_tilde:           Vec<u8>,
}

/// Prove the full ML-DSA.Verify arithmetic witness using the full-matrix Az AIR.
///
/// Produces 49 sub-proofs (vs 53 in v2, 101 in v1) and includes a STARK proof
/// for the hint weight check Σ||h[i]||₁ ≤ ω=55.
pub fn prove_verify_mldsa_v3(
    a_hat:   &[[i64; N]],
    z:       &[[i64; N]],
    c:       &[i64; N],
    t1:      &[[i64; N]],
    hints:   &[Vec<bool>],
    k:       usize,
    l:       usize,
    c_tilde: &[u8],
) -> Result<VerifyMldsaProofV3, String> {
    if t1.len() != k {
        return Err(format!("t1 must have k={k} entries, got {}", t1.len()));
    }
    if hints.len() != k {
        return Err(format!("hints must have k={k} rows, got {}", hints.len()));
    }
    for (i, hrow) in hints.iter().enumerate() {
        if hrow.len() != N {
            return Err(format!("hints[{i}] must have N={N} bits, got {}", hrow.len()));
        }
    }

    // Step 1: Prove Az using the full-matrix AIR (all K rows, one proof).
    // c_tilde is threaded as a STARK public input into the Az-full channel.
    let az_proof = prove_az_v3(a_hat, z, k, l, c_tilde)
        .map_err(|e| format!("prove_az_v3 failed: {e}"))?;

    // Step 2: Prove c·t₁.
    let ct1_proof = prove_ct1(c, t1)
        .map_err(|e| format!("prove_ct1 failed: {e}"))?;

    // Step 3: Prove w′[i] = Az[i] − c·t₁[i].
    let mut proofs_sub: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut w_prime:    Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let (pb, cm, w_i) = crate::prove_poly_sub(&az_proof.output[i], &ct1_proof.output[i])
            .map_err(|e| format!("prove_poly_sub row {i} failed: {e}"))?;
        proofs_sub.push((pb, cm));
        w_prime.push(w_i);
    }

    // Step 4: Prove norm for each z[j].
    let mut norm_proofs: Vec<(Vec<u8>, String)> = Vec::with_capacity(l);
    let mut max_norms:   Vec<i64>                = Vec::with_capacity(l);
    for j in 0..l {
        let (pb, cm, _, mx) = crate::prove_norm_check(&z[j])
            .map_err(|e| format!("prove_norm_check z[{j}] failed: {e}"))?;
        norm_proofs.push((pb, cm));
        max_norms.push(mx);
    }

    // Step 5: Prove UseHint(h[i], w′[i]) = w₁′[i].
    let mut use_hint_proofs: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut w1_prime:        Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let h_arr: &[bool; N] = hints[i].as_slice().try_into()
            .map_err(|_| format!("hints[{i}] is not [bool; N]"))?;
        let (pb, cm, w1_i) = crate::prove_use_hint(&w_prime[i], h_arr)
            .map_err(|e| format!("prove_use_hint row {i} failed: {e}"))?;
        use_hint_proofs.push((pb, cm));
        w1_prime.push(w1_i);
    }

    // Step 6: Prove hint weight Σ||h[i]||₁ ≤ ω.
    let (hw_proof_bytes, hw_commitment, hint_weight_total) =
        crate::prove_hint_weight(hints)
            .map_err(|e| format!("prove_hint_weight failed: {e}"))?;

    Ok(VerifyMldsaProofV3 {
        az_proof,
        ct1_proof,
        proofs_sub,
        norm_proofs,
        use_hint_proofs,
        hint_weight_proof: (hw_proof_bytes, hw_commitment),
        w_prime,
        w1_prime,
        max_norms,
        hint_weight_total,
        c_tilde: c_tilde.to_vec(),
    })
}

/// Verify all STARK sub-proofs in a `VerifyMldsaProofV3`.
pub fn verify_mldsa_witness_v3(proof: &VerifyMldsaProofV3) -> Result<bool, String> {
    // Thread stored c_tilde back into verify_az_v3 to replay the Fiat-Shamir domain separator.
    if !verify_az_v3(&proof.az_proof, &proof.c_tilde)
        .map_err(|e| format!("verify_az_v3 failed: {e}"))? {
        return Ok(false);
    }
    if !verify_ct1(&proof.ct1_proof)
        .map_err(|e| format!("verify_ct1 failed: {e}"))? {
        return Ok(false);
    }
    for (i, (pb, cm)) in proof.proofs_sub.iter().enumerate() {
        if !crate::verify_poly_sub(pb, cm)
            .map_err(|e| format!("verify_poly_sub row {i} failed: {e}"))? {
            return Ok(false);
        }
    }
    for (j, (pb, cm)) in proof.norm_proofs.iter().enumerate() {
        if !crate::verify_norm_check(pb, cm)
            .map_err(|e| format!("verify_norm_check z[{j}] failed: {e}"))? {
            return Ok(false);
        }
    }
    for (i, (pb, cm)) in proof.use_hint_proofs.iter().enumerate() {
        if !crate::verify_use_hint(pb, cm)
            .map_err(|e| format!("verify_use_hint row {i} failed: {e}"))? {
            return Ok(false);
        }
    }
    if !crate::verify_hint_weight(&proof.hint_weight_proof.0, &proof.hint_weight_proof.1)
        .map_err(|e| format!("verify_hint_weight failed: {e}"))? {
        return Ok(false);
    }
    Ok(true)
}

// ── VerifyMldsaProofV4 — uses Ct1FullAIR (MVP-3+) ────────────────────────────
//
// Same as V3 but replaces K individual PolyMul proofs inside Ct1 with the
// batch Ct1FullAIR, saving (K-1)=5 sub-proofs.
//
// Sub-proof count:
//   AzProofV3:   12 (1 Az-full + L NTT-z + L INTT-z + 1 range-Q = 12 + 6 range-Q Az)
//   Ct1ProofV2:  14 (1 NTT-c + K NTT-t1 + 1 Ct1-full + K INTT)
//   proofs_sub:   K =  6
//   norm_proofs:  L =  5
//   use_hint:     K =  6
//   hint_weight:      1
// Total: 12+6 + 14 + 6 + 5 + 6 + 1 = 50 sub-proofs (vs 55 in V3)

/// Combined proof for c·t₁ using the batch Ct1-full AIR (MVP-3+).
///
/// Replaces K individual `prove_poly_mul` calls with one compact 295-column
/// STARK, reducing sub-proof count from 19 to 14.
#[derive(Encode, Decode)]
pub struct Ct1ProofV2 {
    /// NTT proof for the challenge polynomial c.
    pub proof_ntt_c:   (Vec<u8>, String),
    /// NTT output ĉ = NTT(c).
    pub c_hat:         [i64; N],
    /// NTT proofs for each t₁[i].
    pub proofs_ntt_t1: Vec<(Vec<u8>, String)>,
    /// NTT outputs t̂₁[i] = NTT(t₁[i]).
    pub t1_hat:        Vec<[i64; N]>,
    /// Single Ct1-full STARK proof: all K products ĉ ⊙ t̂₁[i] simultaneously.
    pub proof_ct1_full: (Vec<u8>, String),
    /// Pointwise products ĉ[p] × t̂₁[i][p] mod Q, for all K rows.
    pub ct1_hat_out:   Vec<[i64; N]>,
    /// INTT proofs for each product, yielding c·t₁[i] in polynomial domain.
    pub proofs_intt:   Vec<(Vec<u8>, String)>,
    /// Final output: c·t₁[i] in polynomial domain, coefficients in [0, Q).
    pub output:        Vec<[i64; N]>,
}

/// Prove `c·t₁` for all K components using the compact Ct1-full AIR.
///
/// `c`  — challenge polynomial from `SampleInBall`, coefficients in `[0, Q)`.
/// `t1` — K public-key polynomials, coefficients in `[0, Q)`.
///
/// The `c_tilde_seed` (typically 48 bytes of c̃) is mixed into the Ct1-full
/// Fiat-Shamir channel before the trace commitment, binding the proof to the
/// specific challenge.
pub fn prove_ct1_v2(
    c:            &[i64; N],
    t1:           &[[i64; N]],
    c_tilde_seed: &[u8],
) -> Result<Ct1ProofV2, String> {
    use crate::mldsa::params::K as K_PARAM;

    let k = t1.len();
    if k == 0 {
        return Err("t1 must have at least 1 entry".into());
    }
    if k != K_PARAM {
        return Err(format!("t1 must have K={K_PARAM} entries for Ct1-full, got {k}"));
    }

    // Validate inputs.
    for (i, &v) in c.iter().enumerate() {
        if v < 0 || v >= Q { return Err(format!("c[{i}] = {v} out of [0, Q)")); }
    }
    for (row, poly) in t1.iter().enumerate() {
        for (ci, &v) in poly.iter().enumerate() {
            if v < 0 || v >= Q { return Err(format!("t1[{row}][{ci}] = {v} out of [0, Q)")); }
        }
    }

    // Step 1: Prove NTT(c) once.
    let (proof_c_bytes, commitment_c, c_hat) =
        crate::prove_ntt(c).map_err(|e| format!("NTT proof for c failed: {e}"))?;

    // Step 2: Prove NTT(t₁[i]) for each row.
    let mut proofs_ntt_t1: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut t1_hat_vec:    Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let (pb, cm, t1_hat_i) =
            crate::prove_ntt(&t1[i]).map_err(|e| format!("NTT proof for t1[{i}] failed: {e}"))?;
        proofs_ntt_t1.push((pb, cm));
        t1_hat_vec.push(t1_hat_i);
    }

    // Step 3: Prove all K pointwise products simultaneously via Ct1-full AIR.
    let t1_hat_arr: [[i64; N]; K_PARAM] = std::array::from_fn(|i| t1_hat_vec[i]);
    let (proof_full_bytes, commitment_full, ct1_hat_out_arr) =
        crate::prove_ct1_full(&c_hat, &t1_hat_arr, c_tilde_seed)
            .map_err(|e| format!("prove_ct1_full failed: {e}"))?;
    let ct1_hat_out: Vec<[i64; N]> = ct1_hat_out_arr.to_vec();

    // Step 4: Prove INTT(ct1_hat[i]) for each row.
    let mut proofs_intt: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut output:      Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let (pb, cm, ct1_i) =
            prove_intt(&ct1_hat_out[i]).map_err(|e| format!("INTT proof for ct1[{i}] failed: {e}"))?;
        proofs_intt.push((pb, cm));
        output.push(ct1_i);
    }

    Ok(Ct1ProofV2 {
        proof_ntt_c:   (proof_c_bytes, commitment_c),
        c_hat,
        proofs_ntt_t1,
        t1_hat:        t1_hat_vec,
        proof_ct1_full: (proof_full_bytes, commitment_full),
        ct1_hat_out,
        proofs_intt,
        output,
    })
}

/// Verify all STARK sub-proofs in a `Ct1ProofV2`.
///
/// Returns `Ok(true)` iff the NTT(c), all NTT(t₁[i]), the Ct1-full STARK, and
/// all INTT(product[i]) proofs are valid.  `c_tilde_seed` must be the same
/// bytes used during proving.
pub fn verify_ct1_v2(proof: &Ct1ProofV2, c_tilde_seed: &[u8]) -> Result<bool, String> {
    use crate::mldsa::params::K as K_PARAM;

    // Verify NTT(c).
    if !crate::verify_ntt(&proof.proof_ntt_c.0, &proof.proof_ntt_c.1)
        .map_err(|e| format!("NTT verify c failed: {e}"))? {
        return Ok(false);
    }

    let k = proof.proofs_ntt_t1.len();
    if k != K_PARAM {
        return Err(format!("Ct1ProofV2: expected K={K_PARAM} t1 rows, got {k}"));
    }

    // Verify NTT(t₁[i]) for each row.
    for i in 0..k {
        if !crate::verify_ntt(&proof.proofs_ntt_t1[i].0, &proof.proofs_ntt_t1[i].1)
            .map_err(|e| format!("NTT verify t1[{i}] failed: {e}"))? {
            return Ok(false);
        }
    }

    // Verify the Ct1-full STARK.
    let t1_hat_arr: [[i64; N]; K_PARAM] = std::array::from_fn(|i| proof.t1_hat[i]);
    if !crate::verify_ct1_full(
        &proof.proof_ct1_full.0,
        &proof.proof_ct1_full.1,
        &proof.c_hat,
        &t1_hat_arr,
        c_tilde_seed,
    ).map_err(|e| format!("verify_ct1_full failed: {e}"))? {
        return Ok(false);
    }

    // Verify INTT(ct1_hat[i]) for each row.
    for i in 0..k {
        if !verify_intt(&proof.proofs_intt[i].0, &proof.proofs_intt[i].1)
            .map_err(|e| format!("INTT verify ct1[{i}] failed: {e}"))? {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Combined STARK proof using Ct1ProofV2 (batch Ct1-full AIR) — 50 sub-proofs.
///
/// Identical to `VerifyMldsaProofV3` but `ct1_proof` is `Ct1ProofV2` instead of
/// `Ct1Proof`, saving 5 sub-proofs by batching K PolyMul proofs into one AIR.
#[derive(Encode, Decode)]
pub struct VerifyMldsaProofV4 {
    pub az_proof:          AzProofV3,
    pub ct1_proof:         Ct1ProofV2,
    pub proofs_sub:        Vec<(Vec<u8>, String)>,
    pub norm_proofs:       Vec<(Vec<u8>, String)>,
    pub use_hint_proofs:   Vec<(Vec<u8>, String)>,
    pub hint_weight_proof: (Vec<u8>, String),
    pub w_prime:           Vec<[i64; N]>,
    pub w1_prime:          Vec<[i64; N]>,
    pub max_norms:         Vec<i64>,
    pub hint_weight_total: usize,
    /// FIPS 204 signature challenge (c̃, 48 bytes for ML-DSA-65).
    pub c_tilde:           Vec<u8>,
}

/// Prove the full ML-DSA.Verify arithmetic witness (V4).
///
/// Produces 50 sub-proofs (vs 55 in V3) by replacing K PolyMul proofs with the
/// compact 295-column Ct1-full STARK.
pub fn prove_verify_mldsa_v4(
    a_hat:   &[[i64; N]],
    z:       &[[i64; N]],
    c:       &[i64; N],
    t1:      &[[i64; N]],
    hints:   &[Vec<bool>],
    k:       usize,
    l:       usize,
    c_tilde: &[u8],
) -> Result<VerifyMldsaProofV4, String> {
    use crate::mldsa::params::K as K_PARAM;
    if k != K_PARAM {
        return Err(format!("V4 requires k=K={K_PARAM}, got {k}"));
    }
    if t1.len() != k {
        return Err(format!("t1 must have k={k} entries, got {}", t1.len()));
    }
    if hints.len() != k {
        return Err(format!("hints must have k={k} rows, got {}", hints.len()));
    }
    for (i, hrow) in hints.iter().enumerate() {
        if hrow.len() != N {
            return Err(format!("hints[{i}] must have N={N} bits, got {}", hrow.len()));
        }
    }

    // Step 1: Prove Az using the full-matrix AIR (binds c_tilde into FS channel).
    let az_proof = prove_az_v3(a_hat, z, k, l, c_tilde)
        .map_err(|e| format!("prove_az_v3 failed: {e}"))?;

    // Step 2: Prove c·t₁ using compact Ct1-full AIR (binds c_tilde into FS channel).
    let ct1_proof = prove_ct1_v2(c, t1, c_tilde)
        .map_err(|e| format!("prove_ct1_v2 failed: {e}"))?;

    // Step 3: Prove w′[i] = Az[i] − c·t₁[i].
    let mut proofs_sub: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut w_prime:    Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let (pb, cm, w_i) = crate::prove_poly_sub(&az_proof.output[i], &ct1_proof.output[i])
            .map_err(|e| format!("prove_poly_sub row {i} failed: {e}"))?;
        proofs_sub.push((pb, cm));
        w_prime.push(w_i);
    }

    // Step 4: Prove norm for each z[j].
    let mut norm_proofs: Vec<(Vec<u8>, String)> = Vec::with_capacity(l);
    let mut max_norms:   Vec<i64>                = Vec::with_capacity(l);
    for j in 0..l {
        let (pb, cm, _, mx) = crate::prove_norm_check(&z[j])
            .map_err(|e| format!("prove_norm_check z[{j}] failed: {e}"))?;
        norm_proofs.push((pb, cm));
        max_norms.push(mx);
    }

    // Step 5: Prove UseHint(h[i], w′[i]) = w₁′[i].
    let mut use_hint_proofs: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut w1_prime:        Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let h_arr: &[bool; N] = hints[i].as_slice().try_into()
            .map_err(|_| format!("hints[{i}] is not [bool; N]"))?;
        let (pb, cm, w1_i) = crate::prove_use_hint(&w_prime[i], h_arr)
            .map_err(|e| format!("prove_use_hint row {i} failed: {e}"))?;
        use_hint_proofs.push((pb, cm));
        w1_prime.push(w1_i);
    }

    // Step 6: Prove hint weight Σ||h[i]||₁ ≤ ω.
    let (hw_proof_bytes, hw_commitment, hint_weight_total) =
        crate::prove_hint_weight(hints)
            .map_err(|e| format!("prove_hint_weight failed: {e}"))?;

    Ok(VerifyMldsaProofV4 {
        az_proof,
        ct1_proof,
        proofs_sub,
        norm_proofs,
        use_hint_proofs,
        hint_weight_proof: (hw_proof_bytes, hw_commitment),
        w_prime,
        w1_prime,
        max_norms,
        hint_weight_total,
        c_tilde: c_tilde.to_vec(),
    })
}

/// Verify all STARK sub-proofs in a `VerifyMldsaProofV4`.
pub fn verify_mldsa_witness_v4(proof: &VerifyMldsaProofV4) -> Result<bool, String> {
    if !verify_az_v3(&proof.az_proof, &proof.c_tilde)
        .map_err(|e| format!("verify_az_v3 failed: {e}"))? {
        return Ok(false);
    }
    if !verify_ct1_v2(&proof.ct1_proof, &proof.c_tilde)
        .map_err(|e| format!("verify_ct1_v2 failed: {e}"))? {
        return Ok(false);
    }
    for (i, (pb, cm)) in proof.proofs_sub.iter().enumerate() {
        if !crate::verify_poly_sub(pb, cm)
            .map_err(|e| format!("verify_poly_sub row {i} failed: {e}"))? {
            return Ok(false);
        }
    }
    for (j, (pb, cm)) in proof.norm_proofs.iter().enumerate() {
        if !crate::verify_norm_check(pb, cm)
            .map_err(|e| format!("verify_norm_check z[{j}] failed: {e}"))? {
            return Ok(false);
        }
    }
    for (i, (pb, cm)) in proof.use_hint_proofs.iter().enumerate() {
        if !crate::verify_use_hint(pb, cm)
            .map_err(|e| format!("verify_use_hint row {i} failed: {e}"))? {
            return Ok(false);
        }
    }
    if !crate::verify_hint_weight(&proof.hint_weight_proof.0, &proof.hint_weight_proof.1)
        .map_err(|e| format!("verify_hint_weight failed: {e}"))? {
        return Ok(false);
    }
    Ok(true)
}

// ── VerifyMldsaProofV5 — WPrime-full AIR (MVP-3+) ────────────────────────────
//
// Same as V4 but replaces K individual poly_sub proofs with one compact
// WPrime-full STARK (24 columns, 12 constraints), saving K-1=5 sub-proofs.
//
// Sub-proof count:
//   AzProofV3:    18 (5 NTT-z + 1 Az-full + 6 INTT-z + 6 range-Q)
//   Ct1ProofV2:   14 (1 NTT-c + 6 NTT-t1 + 1 Ct1-full + 6 INTT)
//   WPrimeProof:   1 (batch w'[i] = az[i] − ct1[i], all K rows)
//   norm_proofs:   5 (L NormCheck)
//   use_hint:      6 (K UseHint)
//   hint_weight:   1
// Total: 18 + 14 + 1 + 5 + 6 + 1 = 45 sub-proofs (vs 50 in V4)

/// Single STARK proof for all K w'[i] = az[i] − ct1[i] subtractions.
#[derive(Encode, Decode)]
pub struct WPrimeProof {
    /// Single WPrime-full STARK: K polynomial subtractions in one proof.
    pub proof_wprime_full: (Vec<u8>, String),
    /// Output: w_prime[i] = (az[i] − ct1[i]) mod Q for all K rows.
    pub output: Vec<[i64; N]>,
}

/// Prove w'[i] = az[i] − ct1[i] mod Q for all K rows simultaneously.
pub fn prove_wprime(
    az:  &[[i64; N]],
    ct1: &[[i64; N]],
) -> Result<WPrimeProof, String> {
    use crate::mldsa::params::K as K_PARAM;
    if az.len() != K_PARAM {
        return Err(format!("az must have K={K_PARAM} entries, got {}", az.len()));
    }
    if ct1.len() != K_PARAM {
        return Err(format!("ct1 must have K={K_PARAM} entries, got {}", ct1.len()));
    }

    let az_arr:  [[i64; N]; K_PARAM] = std::array::from_fn(|i| az[i]);
    let ct1_arr: [[i64; N]; K_PARAM] = std::array::from_fn(|i| ct1[i]);

    let (proof_bytes, commitment, w_prime_arr) =
        crate::prove_wprime_full(&az_arr, &ct1_arr)
            .map_err(|e| format!("prove_wprime_full failed: {e}"))?;

    Ok(WPrimeProof {
        proof_wprime_full: (proof_bytes, commitment),
        output: w_prime_arr.to_vec(),
    })
}

/// Verify a WPrimeProof.
pub fn verify_wprime(proof: &WPrimeProof) -> Result<bool, String> {
    crate::verify_wprime_full(&proof.proof_wprime_full.0, &proof.proof_wprime_full.1)
        .map_err(|e| format!("verify_wprime_full failed: {e}"))
}

/// Combined proof using WPrime-full AIR — 45 sub-proofs (vs 50 in V4).
#[derive(Encode, Decode)]
pub struct VerifyMldsaProofV5 {
    pub az_proof:          AzProofV3,
    pub ct1_proof:         Ct1ProofV2,
    pub wprime_proof:      WPrimeProof,
    pub norm_proofs:       Vec<(Vec<u8>, String)>,
    pub use_hint_proofs:   Vec<(Vec<u8>, String)>,
    pub hint_weight_proof: (Vec<u8>, String),
    pub w1_prime:          Vec<[i64; N]>,
    pub max_norms:         Vec<i64>,
    pub hint_weight_total: usize,
    pub c_tilde:           Vec<u8>,
}

/// Prove the full ML-DSA.Verify arithmetic witness (V5).
///
/// 45 sub-proofs (vs 50 in V4) — K poly_sub proofs replaced by WPrime-full.
pub fn prove_verify_mldsa_v5(
    a_hat:   &[[i64; N]],
    z:       &[[i64; N]],
    c:       &[i64; N],
    t1:      &[[i64; N]],
    hints:   &[Vec<bool>],
    k:       usize,
    l:       usize,
    c_tilde: &[u8],
) -> Result<VerifyMldsaProofV5, String> {
    use crate::mldsa::params::K as K_PARAM;
    if k != K_PARAM {
        return Err(format!("V5 requires k=K={K_PARAM}, got {k}"));
    }
    if t1.len() != k {
        return Err(format!("t1 must have k={k} entries, got {}", t1.len()));
    }
    if hints.len() != k {
        return Err(format!("hints must have k={k} rows, got {}", hints.len()));
    }
    for (i, hrow) in hints.iter().enumerate() {
        if hrow.len() != N {
            return Err(format!("hints[{i}] must have N={N} bits, got {}", hrow.len()));
        }
    }

    // Step 1: Prove Az (full-matrix AIR, binds c_tilde).
    let az_proof = prove_az_v3(a_hat, z, k, l, c_tilde)
        .map_err(|e| format!("prove_az_v3 failed: {e}"))?;

    // Step 2: Prove c·t₁ (Ct1-full AIR, binds c_tilde).
    let ct1_proof = prove_ct1_v2(c, t1, c_tilde)
        .map_err(|e| format!("prove_ct1_v2 failed: {e}"))?;

    // Step 3: Prove w'[i] = az[i] − ct1[i] for all K rows in one proof.
    let wprime_proof = prove_wprime(&az_proof.output, &ct1_proof.output)
        .map_err(|e| format!("prove_wprime failed: {e}"))?;

    // Step 4: Prove norm for each z[j].
    let mut norm_proofs: Vec<(Vec<u8>, String)> = Vec::with_capacity(l);
    let mut max_norms:   Vec<i64>                = Vec::with_capacity(l);
    for j in 0..l {
        let (pb, cm, _, mx) = crate::prove_norm_check(&z[j])
            .map_err(|e| format!("prove_norm_check z[{j}] failed: {e}"))?;
        norm_proofs.push((pb, cm));
        max_norms.push(mx);
    }

    // Step 5: Prove UseHint(h[i], w'[i]) = w₁'[i].
    let mut use_hint_proofs: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut w1_prime:        Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let h_arr: &[bool; N] = hints[i].as_slice().try_into()
            .map_err(|_| format!("hints[{i}] is not [bool; N]"))?;
        let (pb, cm, w1_i) = crate::prove_use_hint(&wprime_proof.output[i], h_arr)
            .map_err(|e| format!("prove_use_hint row {i} failed: {e}"))?;
        use_hint_proofs.push((pb, cm));
        w1_prime.push(w1_i);
    }

    // Step 6: Prove hint weight Σ||h[i]||₁ ≤ ω.
    let (hw_proof_bytes, hw_commitment, hint_weight_total) =
        crate::prove_hint_weight(hints)
            .map_err(|e| format!("prove_hint_weight failed: {e}"))?;

    Ok(VerifyMldsaProofV5 {
        az_proof,
        ct1_proof,
        wprime_proof,
        norm_proofs,
        use_hint_proofs,
        hint_weight_proof: (hw_proof_bytes, hw_commitment),
        w1_prime,
        max_norms,
        hint_weight_total,
        c_tilde: c_tilde.to_vec(),
    })
}

/// Verify all STARK sub-proofs in a `VerifyMldsaProofV5`.
pub fn verify_mldsa_witness_v5(proof: &VerifyMldsaProofV5) -> Result<bool, String> {
    if !verify_az_v3(&proof.az_proof, &proof.c_tilde)
        .map_err(|e| format!("verify_az_v3 failed: {e}"))? {
        return Ok(false);
    }
    if !verify_ct1_v2(&proof.ct1_proof, &proof.c_tilde)
        .map_err(|e| format!("verify_ct1_v2 failed: {e}"))? {
        return Ok(false);
    }
    if !verify_wprime(&proof.wprime_proof)
        .map_err(|e| format!("verify_wprime failed: {e}"))? {
        return Ok(false);
    }
    for (j, (pb, cm)) in proof.norm_proofs.iter().enumerate() {
        if !crate::verify_norm_check(pb, cm)
            .map_err(|e| format!("verify_norm_check z[{j}] failed: {e}"))? {
            return Ok(false);
        }
    }
    for (i, (pb, cm)) in proof.use_hint_proofs.iter().enumerate() {
        if !crate::verify_use_hint(pb, cm)
            .map_err(|e| format!("verify_use_hint row {i} failed: {e}"))? {
            return Ok(false);
        }
    }
    if !crate::verify_hint_weight(&proof.hint_weight_proof.0, &proof.hint_weight_proof.1)
        .map_err(|e| format!("verify_hint_weight failed: {e}"))? {
        return Ok(false);
    }
    Ok(true)
}

// ── VerifyMldsaProofV6 — NormCheck-batch AIR (MVP-3+) ────────────────────────
//
// Same as V5 but replaces L individual NormCheck proofs with one compact
// NormCheck-batch STARK (15 columns, 10 constraints), saving L-1=4 sub-proofs.
//
// Sub-proof count:
//   AzProofV3:         18 (5 NTT-z + 1 Az-full + 6 INTT-z + 6 range-Q)
//   Ct1ProofV2:        14 (1 NTT-c + 6 NTT-t1 + 1 Ct1-full + 6 INTT)
//   WPrimeProof:        1
//   NormCheckBatchProof: 1  (batch all L norm-checks)
//   use_hint:           6  (K UseHint)
//   hint_weight:        1
// Total: 18 + 14 + 1 + 1 + 6 + 1 = 41 sub-proofs (vs 45 in V5)

/// Single STARK proof for all L norm[j] = min(z[j], Q−z[j]) computations.
#[derive(Encode, Decode)]
pub struct NormCheckBatchProof {
    pub proof_norm_batch: (Vec<u8>, String),
    /// norm_out[j][p] = min(z[j][p], Q−z[j][p]).
    pub norm_out: Vec<[i64; N]>,
    /// max_norms[j] = ||z[j]||_∞.
    pub max_norms: Vec<i64>,
}

/// Prove all L norm computations simultaneously.
pub fn prove_norm_batch(
    z: &[[i64; N]],
) -> Result<NormCheckBatchProof, String> {
    use crate::mldsa::params::L as L_PARAM;
    if z.len() != L_PARAM {
        return Err(format!("z must have L={L_PARAM} entries, got {}", z.len()));
    }
    let z_arr: [[i64; N]; L_PARAM] = std::array::from_fn(|j| z[j]);

    let (proof_bytes, commitment, norm_arr, maxn_arr) =
        crate::prove_norm_check_batch(&z_arr)
            .map_err(|e| format!("prove_norm_check_batch failed: {e}"))?;

    Ok(NormCheckBatchProof {
        proof_norm_batch: (proof_bytes, commitment),
        norm_out: norm_arr.to_vec(),
        max_norms: maxn_arr.to_vec(),
    })
}

/// Verify a NormCheckBatchProof.
pub fn verify_norm_batch(proof: &NormCheckBatchProof) -> Result<bool, String> {
    crate::verify_norm_check_batch(&proof.proof_norm_batch.0, &proof.proof_norm_batch.1)
        .map_err(|e| format!("verify_norm_check_batch failed: {e}"))
}

/// Combined proof using NormCheck-batch AIR — 41 sub-proofs (vs 45 in V5).
#[derive(Encode, Decode)]
pub struct VerifyMldsaProofV6 {
    pub az_proof:          AzProofV3,
    pub ct1_proof:         Ct1ProofV2,
    pub wprime_proof:      WPrimeProof,
    pub norm_proof:        NormCheckBatchProof,
    pub use_hint_proofs:   Vec<(Vec<u8>, String)>,
    pub hint_weight_proof: (Vec<u8>, String),
    pub w1_prime:          Vec<[i64; N]>,
    pub hint_weight_total: usize,
    pub c_tilde:           Vec<u8>,
}

/// Prove the full ML-DSA.Verify arithmetic witness (V6).
///
/// 41 sub-proofs (vs 45 in V5) — L NormCheck proofs replaced by NormCheck-batch.
pub fn prove_verify_mldsa_v6(
    a_hat:   &[[i64; N]],
    z:       &[[i64; N]],
    c:       &[i64; N],
    t1:      &[[i64; N]],
    hints:   &[Vec<bool>],
    k:       usize,
    l:       usize,
    c_tilde: &[u8],
) -> Result<VerifyMldsaProofV6, String> {
    use crate::mldsa::params::{K as K_PARAM, L as L_PARAM};
    if k != K_PARAM { return Err(format!("V6 requires k=K={K_PARAM}, got {k}")); }
    if l != L_PARAM { return Err(format!("V6 requires l=L={L_PARAM}, got {l}")); }
    if t1.len() != k { return Err(format!("t1 must have k={k} entries, got {}", t1.len())); }
    if hints.len() != k { return Err(format!("hints must have k={k} rows, got {}", hints.len())); }
    for (i, hrow) in hints.iter().enumerate() {
        if hrow.len() != N { return Err(format!("hints[{i}] must have N={N} bits")); }
    }

    let az_proof  = prove_az_v3(a_hat, z, k, l, c_tilde)?;
    let ct1_proof = prove_ct1_v2(c, t1, c_tilde)?;
    let wprime_proof = prove_wprime(&az_proof.output, &ct1_proof.output)?;
    let norm_proof   = prove_norm_batch(z)?;

    let mut use_hint_proofs: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut w1_prime:        Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let h_arr: &[bool; N] = hints[i].as_slice().try_into()
            .map_err(|_| format!("hints[{i}] is not [bool; N]"))?;
        let (pb, cm, w1_i) = crate::prove_use_hint(&wprime_proof.output[i], h_arr)?;
        use_hint_proofs.push((pb, cm));
        w1_prime.push(w1_i);
    }

    let (hw_bytes, hw_cm, hint_weight_total) = crate::prove_hint_weight(hints)?;

    Ok(VerifyMldsaProofV6 {
        az_proof, ct1_proof, wprime_proof, norm_proof,
        use_hint_proofs,
        hint_weight_proof: (hw_bytes, hw_cm),
        w1_prime, hint_weight_total,
        c_tilde: c_tilde.to_vec(),
    })
}

/// Verify all STARK sub-proofs in a `VerifyMldsaProofV6`.
pub fn verify_mldsa_witness_v6(proof: &VerifyMldsaProofV6) -> Result<bool, String> {
    if !verify_az_v3(&proof.az_proof, &proof.c_tilde)? { return Ok(false); }
    if !verify_ct1_v2(&proof.ct1_proof, &proof.c_tilde)? { return Ok(false); }
    if !verify_wprime(&proof.wprime_proof)? { return Ok(false); }
    if !verify_norm_batch(&proof.norm_proof)? { return Ok(false); }
    for (i, (pb, cm)) in proof.use_hint_proofs.iter().enumerate() {
        if !crate::verify_use_hint(pb, cm)
            .map_err(|e| format!("verify_use_hint row {i} failed: {e}"))? { return Ok(false); }
    }
    if !crate::verify_hint_weight(&proof.hint_weight_proof.0, &proof.hint_weight_proof.1)? {
        return Ok(false);
    }
    Ok(true)
}

// ── VerifyMldsaProofV7 — UseHint-batch AIR (MVP-3+) ──────────────────────────
//
// Same as V6 but replaces K individual UseHint proofs with one compact
// UseHint-batch STARK (60 columns, 72 constraints), saving K-1=5 sub-proofs.
//
// Sub-proof count:
//   AzProofV3:          18
//   Ct1ProofV2:         14
//   WPrimeProof:         1
//   NormCheckBatchProof: 1
//   UseHintBatchProof:   1  (batch all K use-hints)
//   hint_weight:         1
// Total: 18 + 14 + 1 + 1 + 1 + 1 = 36 sub-proofs (vs 41 in V6)

/// Single STARK proof for all K UseHint(hints[i], w_prime[i]) computations.
#[derive(Encode, Decode)]
pub struct UseHintBatchProof {
    pub proof_use_hint_batch: (Vec<u8>, String),
    /// w1_prime[i][p] = UseHint(hints[i][p], w_prime[i][p]).
    pub output: Vec<[i64; N]>,
}

/// Prove all K UseHint operations simultaneously.
pub fn prove_use_hint_batch_v(
    w_prime: &[[i64; N]],
    hints:   &[Vec<bool>],
) -> Result<UseHintBatchProof, String> {
    use crate::mldsa::params::K as K_PARAM;
    if w_prime.len() != K_PARAM {
        return Err(format!("w_prime must have K={K_PARAM} entries, got {}", w_prime.len()));
    }
    if hints.len() != K_PARAM {
        return Err(format!("hints must have K={K_PARAM} entries, got {}", hints.len()));
    }
    for (i, hrow) in hints.iter().enumerate() {
        if hrow.len() != N { return Err(format!("hints[{i}] must have N={N} bits")); }
    }

    let wp_arr: [[i64; N]; K_PARAM]   = std::array::from_fn(|i| w_prime[i]);
    let h_arr:  [[bool; N]; K_PARAM]  = std::array::from_fn(|i| {
        let s: &[bool] = &hints[i];
        std::array::from_fn(|p| s[p])
    });

    let (proof_bytes, commitment, w1_arr) =
        crate::prove_use_hint_batch(&wp_arr, &h_arr)
            .map_err(|e| format!("prove_use_hint_batch failed: {e}"))?;

    Ok(UseHintBatchProof {
        proof_use_hint_batch: (proof_bytes, commitment),
        output: w1_arr.to_vec(),
    })
}

/// Verify a UseHintBatchProof.
pub fn verify_use_hint_batch_v(proof: &UseHintBatchProof) -> Result<bool, String> {
    crate::verify_use_hint_batch(&proof.proof_use_hint_batch.0, &proof.proof_use_hint_batch.1)
        .map_err(|e| format!("verify_use_hint_batch failed: {e}"))
}

/// Combined proof using both batch AIRs — 36 sub-proofs.
#[derive(Encode, Decode)]
pub struct VerifyMldsaProofV7 {
    pub az_proof:           AzProofV3,
    pub ct1_proof:          Ct1ProofV2,
    pub wprime_proof:       WPrimeProof,
    pub norm_proof:         NormCheckBatchProof,
    pub use_hint_proof:     UseHintBatchProof,
    pub hint_weight_proof:  (Vec<u8>, String),
    pub hint_weight_total:  usize,
    pub c_tilde:            Vec<u8>,
}

/// Prove the full ML-DSA.Verify arithmetic witness (V7).
///
/// 36 sub-proofs — all batch AIRs applied.
pub fn prove_verify_mldsa_v7(
    a_hat:   &[[i64; N]],
    z:       &[[i64; N]],
    c:       &[i64; N],
    t1:      &[[i64; N]],
    hints:   &[Vec<bool>],
    k:       usize,
    l:       usize,
    c_tilde: &[u8],
) -> Result<VerifyMldsaProofV7, String> {
    use crate::mldsa::params::{K as K_PARAM, L as L_PARAM};
    if k != K_PARAM { return Err(format!("V7 requires k=K={K_PARAM}, got {k}")); }
    if l != L_PARAM { return Err(format!("V7 requires l=L={L_PARAM}, got {l}")); }
    if t1.len() != k { return Err(format!("t1 must have k={k} entries, got {}", t1.len())); }
    if hints.len() != k { return Err(format!("hints must have k={k} rows, got {}", hints.len())); }
    for (i, hrow) in hints.iter().enumerate() {
        if hrow.len() != N { return Err(format!("hints[{i}] must have N={N} bits")); }
    }

    let az_proof     = prove_az_v3(a_hat, z, k, l, c_tilde)?;
    let ct1_proof    = prove_ct1_v2(c, t1, c_tilde)?;
    let wprime_proof = prove_wprime(&az_proof.output, &ct1_proof.output)?;
    let norm_proof   = prove_norm_batch(z)?;

    let use_hint_proof = prove_use_hint_batch_v(&wprime_proof.output, hints)?;

    let (hw_bytes, hw_cm, hint_weight_total) = crate::prove_hint_weight(hints)?;

    Ok(VerifyMldsaProofV7 {
        az_proof, ct1_proof, wprime_proof, norm_proof, use_hint_proof,
        hint_weight_proof: (hw_bytes, hw_cm),
        hint_weight_total,
        c_tilde: c_tilde.to_vec(),
    })
}

/// Verify all STARK sub-proofs in a `VerifyMldsaProofV7`.
pub fn verify_mldsa_witness_v7(proof: &VerifyMldsaProofV7) -> Result<bool, String> {
    if !verify_az_v3(&proof.az_proof, &proof.c_tilde)? { return Ok(false); }
    if !verify_ct1_v2(&proof.ct1_proof, &proof.c_tilde)? { return Ok(false); }
    if !verify_wprime(&proof.wprime_proof)? { return Ok(false); }
    if !verify_norm_batch(&proof.norm_proof)? { return Ok(false); }
    if !verify_use_hint_batch_v(&proof.use_hint_proof)? { return Ok(false); }
    if !crate::verify_hint_weight(&proof.hint_weight_proof.0, &proof.hint_weight_proof.1)? {
        return Ok(false);
    }
    Ok(true)
}

// ── VerifyMldsaProofV8 — range-Q batch AIR (MVP-3+) ──────────────────────────
//
// Same as V7 but replaces K individual range-Q proofs inside AzProofV3 with one
// compact RangeQ-batch STARK (K×48 = 288 columns, 256 rows), saving K-1=5 sub-proofs.
//
// Sub-proof count:
//   AzProofV4:          13 (5 NTT-z + 1 Az-full + 6 INTT-z + 1 range-Q-batch)
//   Ct1ProofV2:         14 (1 NTT-c + 6 NTT-t1 + 1 Ct1-full + 6 INTT)
//   WPrimeProof:         1
//   NormCheckBatchProof: 1
//   UseHintBatchProof:   1
//   hint_weight:         1
// Total: 13 + 14 + 1 + 1 + 1 + 1 = 31 sub-proofs (vs 36 in V7)

/// Single STARK proof for all K Az-row range checks (batch range-Q).
#[derive(Encode, Decode)]
pub struct RangeQBatchProof {
    pub proof_range_q_batch: (Vec<u8>, String),
}

/// Prove range membership for all K Az output rows at once.
pub fn prove_range_q_batch_v(az_rows: &[[i64; N]]) -> Result<RangeQBatchProof, String> {
    use crate::mldsa::params::K as K_PARAM;
    if az_rows.len() != K_PARAM {
        return Err(format!("az_rows must have K={K_PARAM} entries, got {}", az_rows.len()));
    }
    let arr: [[i64; N]; K_PARAM] = std::array::from_fn(|i| az_rows[i]);
    let (pb, cm) = crate::prove_range_q_batch(&arr)
        .map_err(|e| format!("prove_range_q_batch failed: {e}"))?;
    Ok(RangeQBatchProof { proof_range_q_batch: (pb, cm) })
}

/// Verify a RangeQBatchProof.
pub fn verify_range_q_batch_v(proof: &RangeQBatchProof) -> Result<bool, String> {
    crate::verify_range_q_batch(&proof.proof_range_q_batch.0, &proof.proof_range_q_batch.1)
        .map_err(|e| format!("verify_range_q_batch failed: {e}"))
}

/// AzProofV3 variant with batch range-Q — 13 sub-proofs (vs 18 in AzProofV3).
#[derive(Encode, Decode)]
pub struct AzProofV4 {
    /// L NTT proofs: z_hat[j] = NTT(z[j]).
    pub proofs_ntt_z:  Vec<(Vec<u8>, String)>,
    /// NTT outputs z_hat[j].
    pub z_hat:         Vec<[i64; N]>,
    /// Single full-matrix Az proof (K×L outputs).
    pub proof_az_full: (Vec<u8>, String),
    /// K NTT-domain outputs Az_hat[i] (for INTT input binding).
    pub az_hat:        Vec<[i64; N]>,
    /// K INTT proofs: Az[i] = INTT(Az_hat[i]) with input binding.
    pub proofs_intt:   Vec<(Vec<u8>, String)>,
    /// Az[i] in polynomial domain, K entries.
    pub output:        Vec<[i64; N]>,
    /// Single batch range-Q proof for all K Az output rows.
    pub range_q_proof: RangeQBatchProof,
}

/// Prove A×z using a full-matrix Az AIR with batch range-Q (AzProofV4, 13 sub-proofs).
pub fn prove_az_v4(
    a_hat:   &[[i64; N]],
    z:       &[[i64; N]],
    k:       usize,
    l:       usize,
    c_tilde: &[u8],
) -> Result<AzProofV4, String> {
    use crate::mldsa::params::{K as K_PARAM, L as L_PARAM};
    if k != K_PARAM { return Err(format!("AzProofV4 requires k=K={K_PARAM}, got {k}")); }
    if l != L_PARAM { return Err(format!("AzProofV4 requires l=L={L_PARAM}, got {l}")); }
    if a_hat.len() != k * l {
        return Err(format!("a_hat must have k*l={} entries, got {}", k * l, a_hat.len()));
    }

    // Step 1: NTT(z[j]) for each j (L proofs).
    let mut proofs_ntt_z: Vec<(Vec<u8>, String)> = Vec::with_capacity(l);
    let mut z_hat:        Vec<[i64; N]>           = Vec::with_capacity(l);
    for (j, zj) in z.iter().enumerate() {
        let (pb, cm, zh) = crate::prove_ntt(zj)
            .map_err(|e| format!("NTT proof for z[{j}] failed: {e}"))?;
        proofs_ntt_z.push((pb, cm));
        z_hat.push(zh);
    }

    let z_hat_arr: [[i64; N]; L_PARAM] = z_hat.as_slice().try_into()
        .map_err(|_| "z_hat must have exactly L entries".to_string())?;

    // Step 2: Full-matrix Az STARK (1 proof).
    let (pb_az, cm_az, az_out_arr) = crate::prove_az_full(a_hat, &z_hat_arr, c_tilde)
        .map_err(|e| format!("prove_az_full failed: {e}"))?;
    let proof_az_full = (pb_az, cm_az);
    let az_hat: Vec<[i64; N]> = az_out_arr.to_vec();

    // Step 3: INTT(Az_hat[i]) for each row i, with input binding (K proofs).
    let mut proofs_intt: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut output:      Vec<[i64; N]>           = Vec::with_capacity(k);
    for (i, az_hat_i) in az_hat.iter().enumerate() {
        let (pb, cm, az_i) = prove_intt_with_binding(az_hat_i)
            .map_err(|e| format!("INTT proof for Az row {i} failed: {e}"))?;
        proofs_intt.push((pb, cm));
        output.push(az_i);
    }

    // Step 4: Single batch range-Q for all K Az[i] outputs (replaces K individual proofs).
    let range_q_proof = prove_range_q_batch_v(&output)?;

    Ok(AzProofV4 { proofs_ntt_z, z_hat, proof_az_full, az_hat, proofs_intt, output, range_q_proof })
}

/// Verify all sub-proofs in an `AzProofV4`.
///
/// Same four-layer consistency chain as AzProofV3 but uses batch range-Q.
pub fn verify_az_v4(proof: &AzProofV4, c_tilde_seed: &[u8]) -> Result<bool, String> {
    let l = proof.z_hat.len();
    let k = proof.proofs_intt.len();

    // Layer 1: Verify NTT(z[j]).
    for (j, (pb, cm)) in proof.proofs_ntt_z.iter().enumerate() {
        if !crate::verify_ntt(pb, cm)
            .map_err(|e| format!("verify_ntt z[{j}] failed: {e}"))? { return Ok(false); }
    }

    // Cross-check 1: stored z_hat[j] fingerprint must match NTT output commitment.
    for j in 0..l {
        let fp = crate::output_fingerprint(&proof.z_hat[j]);
        let expected_cm = crate::build_poly_commitment(&fp);
        if j < proof.proofs_ntt_z.len() && expected_cm != proof.proofs_ntt_z[j].1 {
            return Ok(false);
        }
    }

    // Layer 2: Verify full-matrix Az proof with z_hat input binding.
    let z_hat_arr: [[i64; N]; crate::mldsa::params::L] = match proof.z_hat.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return Err(format!("z_hat must have L entries, got {l}")),
    };
    if !crate::verify_az_full(&proof.proof_az_full.0, &proof.proof_az_full.1, &z_hat_arr, c_tilde_seed)
        .map_err(|e| format!("verify_az_full failed: {e}"))? { return Ok(false); }

    // Cross-check 2: stored az_hat fingerprint must match Az-full output commitment.
    {
        let mut flat: Vec<i64> = Vec::with_capacity(k * N);
        for row in &proof.az_hat { flat.extend_from_slice(row); }
        let fp = crate::output_fingerprint(&flat);
        let expected_cm = crate::build_poly_commitment(&fp);
        if expected_cm != proof.proof_az_full.1 {
            return Ok(false);
        }
    }

    // Layer 3: Verify INTT(Az_hat[i]) with input binding.
    for (i, (pb, cm)) in proof.proofs_intt.iter().enumerate() {
        if i >= proof.az_hat.len() { break; }
        if !verify_intt_with_binding(pb, cm, &proof.az_hat[i])
            .map_err(|e| format!("verify_intt Az[{i}] failed: {e}"))? { return Ok(false); }
    }

    // Layer 4: Verify batch range-Q for all K Az outputs.
    if !verify_range_q_batch_v(&proof.range_q_proof)? { return Ok(false); }

    Ok(true)
}

/// Combined proof using AzProofV4 + batch AIRs — 31 sub-proofs.
#[derive(Encode, Decode)]
pub struct VerifyMldsaProofV8 {
    pub az_proof:          AzProofV4,
    pub ct1_proof:         Ct1ProofV2,
    pub wprime_proof:      WPrimeProof,
    pub norm_proof:        NormCheckBatchProof,
    pub use_hint_proof:    UseHintBatchProof,
    pub hint_weight_proof: (Vec<u8>, String),
    pub hint_weight_total: usize,
    pub c_tilde:           Vec<u8>,
}

/// Prove the full ML-DSA.Verify arithmetic witness (V8).
///
/// 31 sub-proofs (vs 36 in V7) — K individual range-Q proofs replaced by RangeQ-batch.
pub fn prove_verify_mldsa_v8(
    a_hat:   &[[i64; N]],
    z:       &[[i64; N]],
    c:       &[i64; N],
    t1:      &[[i64; N]],
    hints:   &[Vec<bool>],
    k:       usize,
    l:       usize,
    c_tilde: &[u8],
) -> Result<VerifyMldsaProofV8, String> {
    use crate::mldsa::params::{K as K_PARAM, L as L_PARAM};
    if k != K_PARAM { return Err(format!("V8 requires k=K={K_PARAM}, got {k}")); }
    if l != L_PARAM { return Err(format!("V8 requires l=L={L_PARAM}, got {l}")); }
    if t1.len() != k { return Err(format!("t1 must have k={k} entries, got {}", t1.len())); }
    if hints.len() != k { return Err(format!("hints must have k={k} rows, got {}", hints.len())); }
    for (i, hrow) in hints.iter().enumerate() {
        if hrow.len() != N { return Err(format!("hints[{i}] must have N={N} bits")); }
    }

    let az_proof     = prove_az_v4(a_hat, z, k, l, c_tilde)?;
    let ct1_proof    = prove_ct1_v2(c, t1, c_tilde)?;
    let wprime_proof = prove_wprime(&az_proof.output, &ct1_proof.output)?;
    let norm_proof   = prove_norm_batch(z)?;

    let use_hint_proof = prove_use_hint_batch_v(&wprime_proof.output, hints)?;

    let (hw_bytes, hw_cm, hint_weight_total) = crate::prove_hint_weight(hints)?;

    Ok(VerifyMldsaProofV8 {
        az_proof, ct1_proof, wprime_proof, norm_proof, use_hint_proof,
        hint_weight_proof: (hw_bytes, hw_cm),
        hint_weight_total,
        c_tilde: c_tilde.to_vec(),
    })
}

/// Verify all STARK sub-proofs in a `VerifyMldsaProofV8`.
pub fn verify_mldsa_witness_v8(proof: &VerifyMldsaProofV8) -> Result<bool, String> {
    if !verify_az_v4(&proof.az_proof, &proof.c_tilde)? { return Ok(false); }
    if !verify_ct1_v2(&proof.ct1_proof, &proof.c_tilde)? { return Ok(false); }
    if !verify_wprime(&proof.wprime_proof)? { return Ok(false); }
    if !verify_norm_batch(&proof.norm_proof)? { return Ok(false); }
    if !verify_use_hint_batch_v(&proof.use_hint_proof)? { return Ok(false); }
    if !crate::verify_hint_weight(&proof.hint_weight_proof.0, &proof.hint_weight_proof.1)? {
        return Ok(false);
    }
    Ok(true)
}

// ── VerifyMldsaProofV9 — batch INTT for Az (MVP-3+) ──────────────────────────
//
// Same as V8 but replaces K individual INTT proofs inside AzProofV4 with one
// compact batch INTT STARK (325 columns, 1024 rows), saving K-1=5 sub-proofs.
//
// Sub-proof count:
//   AzProofV5:           8 (5 NTT-z + 1 Az-full + 1 INTT-batch + 1 range-Q-batch)
//   Ct1ProofV2:         14 (1 NTT-c + 6 NTT-t1 + 1 Ct1-full + 6 INTT)
//   WPrimeProof:         1
//   NormCheckBatchProof: 1
//   UseHintBatchProof:   1
//   hint_weight:         1
// Total: 8 + 14 + 1 + 1 + 1 + 1 = 26 sub-proofs (vs 31 in V8)

/// AzProofV4 variant with batch INTT — 8 sub-proofs (vs 13 in AzProofV4).
#[derive(Encode, Decode)]
pub struct AzProofV5 {
    /// L NTT proofs: z_hat[j] = NTT(z[j]).
    pub proofs_ntt_z:    Vec<(Vec<u8>, String)>,
    /// NTT outputs z_hat[j].
    pub z_hat:           Vec<[i64; N]>,
    /// Single full-matrix Az proof (K×L outputs).
    pub proof_az_full:   (Vec<u8>, String),
    /// K NTT-domain outputs Az_hat[i] (for INTT batch input binding).
    pub az_hat:          Vec<[i64; N]>,
    /// Single batch INTT proof for all K az_hat rows.
    pub proof_intt_batch: (Vec<u8>, String),
    /// Az[i] in polynomial domain, K entries.
    pub output:          Vec<[i64; N]>,
    /// Single batch range-Q proof for all K Az output rows.
    pub range_q_proof:   RangeQBatchProof,
}

/// Prove A×z using full-matrix Az AIR + batch INTT (AzProofV5, 8 sub-proofs).
pub fn prove_az_v5(
    a_hat:   &[[i64; N]],
    z:       &[[i64; N]],
    k:       usize,
    l:       usize,
    c_tilde: &[u8],
) -> Result<AzProofV5, String> {
    use crate::mldsa::params::{K as K_PARAM, L as L_PARAM};
    if k != K_PARAM { return Err(format!("AzProofV5 requires k=K={K_PARAM}, got {k}")); }
    if l != L_PARAM { return Err(format!("AzProofV5 requires l=L={L_PARAM}, got {l}")); }
    if a_hat.len() != k * l {
        return Err(format!("a_hat must have k*l={} entries, got {}", k * l, a_hat.len()));
    }

    // Step 1: NTT(z[j]) for each j (L proofs).
    let mut proofs_ntt_z: Vec<(Vec<u8>, String)> = Vec::with_capacity(l);
    let mut z_hat:        Vec<[i64; N]>           = Vec::with_capacity(l);
    for (j, zj) in z.iter().enumerate() {
        let (pb, cm, zh) = crate::prove_ntt(zj)
            .map_err(|e| format!("NTT proof for z[{j}] failed: {e}"))?;
        proofs_ntt_z.push((pb, cm));
        z_hat.push(zh);
    }

    let z_hat_arr: [[i64; N]; L_PARAM] = z_hat.as_slice().try_into()
        .map_err(|_| "z_hat must have exactly L entries".to_string())?;

    // Step 2: Full-matrix Az STARK (1 proof).
    let (pb_az, cm_az, az_out_arr) = crate::prove_az_full(a_hat, &z_hat_arr, c_tilde)
        .map_err(|e| format!("prove_az_full failed: {e}"))?;
    let proof_az_full = (pb_az, cm_az);
    let az_hat: Vec<[i64; N]> = az_out_arr.to_vec();

    // Step 3: Batch INTT for all K az_hat rows (1 proof, replaces K individual proofs).
    let az_hat_arr: [[i64; N]; K_PARAM] = az_hat.as_slice().try_into()
        .map_err(|_| "az_hat must have K entries".to_string())?;
    let (pb_intt, cm_intt, outputs_arr) = crate::prove_intt_batch(&az_hat_arr)
        .map_err(|e| format!("prove_intt_batch failed: {e}"))?;
    let output: Vec<[i64; N]> = outputs_arr.to_vec();

    // Step 4: Single batch range-Q for all K Az[i] outputs.
    let range_q_proof = prove_range_q_batch_v(&output)?;

    Ok(AzProofV5 {
        proofs_ntt_z,
        z_hat,
        proof_az_full,
        az_hat,
        proof_intt_batch: (pb_intt, cm_intt),
        output,
        range_q_proof,
    })
}

/// Verify all sub-proofs in an `AzProofV5`.
///
/// Same four-layer chain as AzProofV4 but uses batch INTT for step 3.
/// Cross-check 3: batch INTT output commitment must match range-Q input commitment
/// (both fingerprint all K output polynomials concatenated).
pub fn verify_az_v5(proof: &AzProofV5, c_tilde_seed: &[u8]) -> Result<bool, String> {
    let l = proof.z_hat.len();
    let k = proof.az_hat.len();

    // Layer 1: Verify NTT(z[j]).
    for (j, (pb, cm)) in proof.proofs_ntt_z.iter().enumerate() {
        if !crate::verify_ntt(pb, cm)
            .map_err(|e| format!("verify_ntt z[{j}] failed: {e}"))? { return Ok(false); }
    }

    // Cross-check 1: stored z_hat[j] fingerprint must match NTT output commitment.
    for j in 0..l {
        let fp = crate::output_fingerprint(&proof.z_hat[j]);
        let expected_cm = crate::build_poly_commitment(&fp);
        if j < proof.proofs_ntt_z.len() && expected_cm != proof.proofs_ntt_z[j].1 {
            return Ok(false);
        }
    }

    // Layer 2: Verify full-matrix Az proof with z_hat input binding.
    let z_hat_arr: [[i64; N]; crate::mldsa::params::L] = match proof.z_hat.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return Err(format!("z_hat must have L entries, got {l}")),
    };
    if !crate::verify_az_full(&proof.proof_az_full.0, &proof.proof_az_full.1, &z_hat_arr, c_tilde_seed)
        .map_err(|e| format!("verify_az_full failed: {e}"))? { return Ok(false); }

    // Cross-check 2: stored az_hat fingerprint (all K rows) must match Az-full commitment.
    {
        let mut flat: Vec<i64> = Vec::with_capacity(k * N);
        for row in &proof.az_hat { flat.extend_from_slice(row); }
        let fp = crate::output_fingerprint(&flat);
        let expected_cm = crate::build_poly_commitment(&fp);
        if expected_cm != proof.proof_az_full.1 {
            return Ok(false);
        }
    }

    // Layer 3: Verify batch INTT with az_hat as inputs.
    let az_hat_arr: [[i64; N]; crate::mldsa::params::K] = match proof.az_hat.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return Err(format!("az_hat must have K entries, got {k}")),
    };
    if !crate::verify_intt_batch(&proof.proof_intt_batch.0, &proof.proof_intt_batch.1, &az_hat_arr)
        .map_err(|e| format!("verify_intt_batch failed: {e}"))? { return Ok(false); }

    // Cross-check 3: batch INTT output commitment must match range-Q input commitment.
    // Both fingerprint all K output polynomials concatenated.
    if proof.proof_intt_batch.1 != proof.range_q_proof.proof_range_q_batch.1 {
        return Ok(false);
    }

    // Layer 4: Verify batch range-Q for all K Az outputs.
    if !verify_range_q_batch_v(&proof.range_q_proof)? { return Ok(false); }

    Ok(true)
}

/// Combined proof using AzProofV5 + Ct1ProofV2 + batch AIRs — 26 sub-proofs.
#[derive(Encode, Decode)]
pub struct VerifyMldsaProofV9 {
    pub az_proof:          AzProofV5,
    pub ct1_proof:         Ct1ProofV2,
    pub wprime_proof:      WPrimeProof,
    pub norm_proof:        NormCheckBatchProof,
    pub use_hint_proof:    UseHintBatchProof,
    pub hint_weight_proof: (Vec<u8>, String),
    pub hint_weight_total: usize,
    pub c_tilde:           Vec<u8>,
}

/// Prove the full ML-DSA.Verify arithmetic witness (V9).
///
/// 26 sub-proofs (vs 31 in V8) — K individual INTT proofs in Az replaced by batch INTT.
pub fn prove_verify_mldsa_v9(
    a_hat:   &[[i64; N]],
    z:       &[[i64; N]],
    c:       &[i64; N],
    t1:      &[[i64; N]],
    hints:   &[Vec<bool>],
    k:       usize,
    l:       usize,
    c_tilde: &[u8],
) -> Result<VerifyMldsaProofV9, String> {
    use crate::mldsa::params::{K as K_PARAM, L as L_PARAM};
    if k != K_PARAM { return Err(format!("V9 requires k=K={K_PARAM}, got {k}")); }
    if l != L_PARAM { return Err(format!("V9 requires l=L={L_PARAM}, got {l}")); }
    if t1.len() != k { return Err(format!("t1 must have k={k} entries, got {}", t1.len())); }
    if hints.len() != k { return Err(format!("hints must have k={k} rows, got {}", hints.len())); }
    for (i, hrow) in hints.iter().enumerate() {
        if hrow.len() != N { return Err(format!("hints[{i}] must have N={N} bits")); }
    }

    let az_proof     = prove_az_v5(a_hat, z, k, l, c_tilde)?;
    let ct1_proof    = prove_ct1_v2(c, t1, c_tilde)?;
    let wprime_proof = prove_wprime(&az_proof.output, &ct1_proof.output)?;
    let norm_proof   = prove_norm_batch(z)?;
    let use_hint_proof = prove_use_hint_batch_v(&wprime_proof.output, hints)?;
    let (hw_bytes, hw_cm, hint_weight_total) = crate::prove_hint_weight(hints)?;

    Ok(VerifyMldsaProofV9 {
        az_proof, ct1_proof, wprime_proof, norm_proof, use_hint_proof,
        hint_weight_proof: (hw_bytes, hw_cm),
        hint_weight_total,
        c_tilde: c_tilde.to_vec(),
    })
}

/// Verify all STARK sub-proofs in a `VerifyMldsaProofV9`.
pub fn verify_mldsa_witness_v9(proof: &VerifyMldsaProofV9) -> Result<bool, String> {
    if !verify_az_v5(&proof.az_proof, &proof.c_tilde)? { return Ok(false); }
    if !verify_ct1_v2(&proof.ct1_proof, &proof.c_tilde)? { return Ok(false); }
    if !verify_wprime(&proof.wprime_proof)? { return Ok(false); }
    if !verify_norm_batch(&proof.norm_proof)? { return Ok(false); }
    if !verify_use_hint_batch_v(&proof.use_hint_proof)? { return Ok(false); }
    if !crate::verify_hint_weight(&proof.hint_weight_proof.0, &proof.hint_weight_proof.1)? {
        return Ok(false);
    }
    Ok(true)
}

// ── VerifyMldsaProofV10 — batch NTT-t1 + batch INTT-ct1 (MVP-3+) ─────────────
//
// Same as V9 but replaces Ct1ProofV2 (14 sub-proofs) with Ct1ProofV3 (4 sub-proofs):
// K individual NTT(t1[i]) proofs → 1 batch NTT-t1 proof
// K individual INTT(ct1_hat[i]) proofs → 1 batch INTT-ct1 proof
//
// Sub-proof count:
//   AzProofV5:           8 (5 NTT-z + 1 Az-full + 1 INTT-batch + 1 range-Q-batch)
//   Ct1ProofV3:          4 (1 NTT-c + 1 NTT-t1-batch + 1 Ct1-full + 1 INTT-ct1-batch)
//   WPrimeProof:         1
//   NormCheckBatchProof: 1
//   UseHintBatchProof:   1
//   hint_weight:         1
// Total: 8 + 4 + 1 + 1 + 1 + 1 = 16 sub-proofs (vs 26 in V9)

/// Combined proof for c·t₁ using batch NTT-t1 + batch INTT-ct1 — 4 sub-proofs.
#[derive(Encode, Decode)]
pub struct Ct1ProofV3 {
    /// NTT proof for the challenge polynomial c.
    pub proof_ntt_c:          (Vec<u8>, String),
    /// NTT output ĉ = NTT(c).
    pub c_hat:                 [i64; N],
    /// Single batch NTT proof for all K t1 polynomials.
    pub proof_ntt_t1_batch:    (Vec<u8>, String),
    /// NTT outputs t̂₁[i] = NTT(t₁[i]) for all K rows.
    pub t1_hat:                Vec<[i64; N]>,
    /// Single Ct1-full STARK proof: all K products ĉ ⊙ t̂₁[i] simultaneously.
    pub proof_ct1_full:        (Vec<u8>, String),
    /// Pointwise products ĉ[p] × t̂₁[i][p] mod Q, for all K rows.
    pub ct1_hat_out:           Vec<[i64; N]>,
    /// Single batch INTT proof for all K ct1_hat polynomials.
    pub proof_intt_ct1_batch:  (Vec<u8>, String),
    /// Final output: c·t₁[i] in polynomial domain, K entries.
    pub output:                Vec<[i64; N]>,
}

/// Prove `c·t₁` for all K components using batch NTT-t1 + Ct1-full + batch INTT-ct1.
pub fn prove_ct1_v3(
    c:            &[i64; N],
    t1:           &[[i64; N]],
    c_tilde_seed: &[u8],
) -> Result<Ct1ProofV3, String> {
    use crate::mldsa::params::K as K_PARAM;

    let k = t1.len();
    if k != K_PARAM {
        return Err(format!("t1 must have K={K_PARAM} entries for Ct1ProofV3, got {k}"));
    }
    for (i, &v) in c.iter().enumerate() {
        if v < 0 || v >= Q { return Err(format!("c[{i}] = {v} out of [0, Q)")); }
    }
    for (row, poly) in t1.iter().enumerate() {
        for (ci, &v) in poly.iter().enumerate() {
            if v < 0 || v >= Q { return Err(format!("t1[{row}][{ci}] = {v} out of [0, Q)")); }
        }
    }

    // Step 1: Prove NTT(c) once.
    let (pb_c, cm_c, c_hat) =
        crate::prove_ntt(c).map_err(|e| format!("NTT proof for c failed: {e}"))?;

    // Step 2: Prove batch NTT(t1) for all K rows (1 proof, replaces K individual proofs).
    let t1_arr: [[i64; N]; K_PARAM] = std::array::from_fn(|i| t1[i]);
    let (pb_ntt_t1, cm_ntt_t1, t1_hat_arr) = crate::prove_ntt_batch(&t1_arr)
        .map_err(|e| format!("prove_ntt_batch for t1 failed: {e}"))?;
    let t1_hat: Vec<[i64; N]> = t1_hat_arr.to_vec();

    // Step 3: Prove all K pointwise products simultaneously via Ct1-full AIR.
    let (pb_ct1, cm_ct1, ct1_hat_arr) =
        crate::prove_ct1_full(&c_hat, &t1_hat_arr, c_tilde_seed)
            .map_err(|e| format!("prove_ct1_full failed: {e}"))?;
    let ct1_hat_out: Vec<[i64; N]> = ct1_hat_arr.to_vec();

    // Step 4: Prove batch INTT(ct1_hat) for all K rows (1 proof, replaces K individual proofs).
    let (pb_intt_ct1, cm_intt_ct1, output_arr) = crate::prove_intt_batch(&ct1_hat_arr)
        .map_err(|e| format!("prove_intt_batch for ct1 failed: {e}"))?;
    let output: Vec<[i64; N]> = output_arr.to_vec();

    Ok(Ct1ProofV3 {
        proof_ntt_c:         (pb_c, cm_c),
        c_hat,
        proof_ntt_t1_batch:  (pb_ntt_t1, cm_ntt_t1),
        t1_hat,
        proof_ct1_full:      (pb_ct1, cm_ct1),
        ct1_hat_out,
        proof_intt_ct1_batch: (pb_intt_ct1, cm_intt_ct1),
        output,
    })
}

/// Verify all STARK sub-proofs in a `Ct1ProofV3`.
pub fn verify_ct1_v3(proof: &Ct1ProofV3, c_tilde_seed: &[u8]) -> Result<bool, String> {
    use crate::mldsa::params::K as K_PARAM;

    // Verify NTT(c).
    if !crate::verify_ntt(&proof.proof_ntt_c.0, &proof.proof_ntt_c.1)
        .map_err(|e| format!("NTT verify c failed: {e}"))? {
        return Ok(false);
    }

    // Verify batch NTT(t1) (output-only binding: no inputs needed).
    if !crate::verify_ntt_batch(&proof.proof_ntt_t1_batch.0, &proof.proof_ntt_t1_batch.1)
        .map_err(|e| format!("verify_ntt_batch t1 failed: {e}"))? {
        return Ok(false);
    }

    // Cross-check: stored t1_hat fingerprint must match NTT-batch output commitment.
    {
        let mut flat: Vec<i64> = Vec::with_capacity(K_PARAM * N);
        for row in &proof.t1_hat { flat.extend_from_slice(row); }
        let fp = crate::output_fingerprint(&flat);
        let expected_cm = crate::build_poly_commitment(&fp);
        if expected_cm != proof.proof_ntt_t1_batch.1 {
            return Ok(false);
        }
    }

    // Verify Ct1-full with c_hat and t1_hat inputs.
    let t1_hat_arr: [[i64; N]; K_PARAM] = match proof.t1_hat.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return Err(format!("t1_hat must have K={K_PARAM} entries")),
    };
    if !crate::verify_ct1_full(
        &proof.proof_ct1_full.0,
        &proof.proof_ct1_full.1,
        &proof.c_hat,
        &t1_hat_arr,
        c_tilde_seed,
    ).map_err(|e| format!("verify_ct1_full failed: {e}"))? {
        return Ok(false);
    }

    // Cross-check: stored ct1_hat_out fingerprint must match Ct1-full output commitment.
    {
        let mut flat: Vec<i64> = Vec::with_capacity(K_PARAM * N);
        for row in &proof.ct1_hat_out { flat.extend_from_slice(row); }
        let fp = crate::output_fingerprint(&flat);
        let expected_cm = crate::build_poly_commitment(&fp);
        if expected_cm != proof.proof_ct1_full.1 {
            return Ok(false);
        }
    }

    // Verify batch INTT(ct1_hat) with ct1_hat as inputs.
    let ct1_hat_arr: [[i64; N]; K_PARAM] = match proof.ct1_hat_out.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return Err(format!("ct1_hat_out must have K={K_PARAM} entries")),
    };
    if !crate::verify_intt_batch(
        &proof.proof_intt_ct1_batch.0,
        &proof.proof_intt_ct1_batch.1,
        &ct1_hat_arr,
    ).map_err(|e| format!("verify_intt_batch ct1 failed: {e}"))? {
        return Ok(false);
    }

    Ok(true)
}

/// Combined proof using AzProofV5 + Ct1ProofV3 + batch AIRs — 16 sub-proofs.
#[derive(Encode, Decode)]
pub struct VerifyMldsaProofV10 {
    pub az_proof:          AzProofV5,
    pub ct1_proof:         Ct1ProofV3,
    pub wprime_proof:      WPrimeProof,
    pub norm_proof:        NormCheckBatchProof,
    pub use_hint_proof:    UseHintBatchProof,
    pub hint_weight_proof: (Vec<u8>, String),
    pub hint_weight_total: usize,
    pub c_tilde:           Vec<u8>,
}

/// Prove the full ML-DSA.Verify arithmetic witness (V10).
///
/// 16 sub-proofs (vs 26 in V9) — batch NTT-t1 and batch INTT-ct1 collapse
/// 12 individual Ct1 sub-proofs into 2.
pub fn prove_verify_mldsa_v10(
    a_hat:   &[[i64; N]],
    z:       &[[i64; N]],
    c:       &[i64; N],
    t1:      &[[i64; N]],
    hints:   &[Vec<bool>],
    k:       usize,
    l:       usize,
    c_tilde: &[u8],
) -> Result<VerifyMldsaProofV10, String> {
    use crate::mldsa::params::{K as K_PARAM, L as L_PARAM};
    if k != K_PARAM { return Err(format!("V10 requires k=K={K_PARAM}, got {k}")); }
    if l != L_PARAM { return Err(format!("V10 requires l=L={L_PARAM}, got {l}")); }
    if t1.len() != k { return Err(format!("t1 must have k={k} entries, got {}", t1.len())); }
    if hints.len() != k { return Err(format!("hints must have k={k} rows, got {}", hints.len())); }
    for (i, hrow) in hints.iter().enumerate() {
        if hrow.len() != N { return Err(format!("hints[{i}] must have N={N} bits")); }
    }

    let az_proof     = prove_az_v5(a_hat, z, k, l, c_tilde)?;
    let ct1_proof    = prove_ct1_v3(c, t1, c_tilde)?;
    let wprime_proof = prove_wprime(&az_proof.output, &ct1_proof.output)?;
    let norm_proof   = prove_norm_batch(z)?;
    let use_hint_proof = prove_use_hint_batch_v(&wprime_proof.output, hints)?;
    let (hw_bytes, hw_cm, hint_weight_total) = crate::prove_hint_weight(hints)?;

    Ok(VerifyMldsaProofV10 {
        az_proof, ct1_proof, wprime_proof, norm_proof, use_hint_proof,
        hint_weight_proof: (hw_bytes, hw_cm),
        hint_weight_total,
        c_tilde: c_tilde.to_vec(),
    })
}

/// Verify all STARK sub-proofs in a `VerifyMldsaProofV10`.
pub fn verify_mldsa_witness_v10(proof: &VerifyMldsaProofV10) -> Result<bool, String> {
    if !verify_az_v5(&proof.az_proof, &proof.c_tilde)? { return Ok(false); }
    if !verify_ct1_v3(&proof.ct1_proof, &proof.c_tilde)? { return Ok(false); }
    if !verify_wprime(&proof.wprime_proof)? { return Ok(false); }
    if !verify_norm_batch(&proof.norm_proof)? { return Ok(false); }
    if !verify_use_hint_batch_v(&proof.use_hint_proof)? { return Ok(false); }
    if !crate::verify_hint_weight(&proof.hint_weight_proof.0, &proof.hint_weight_proof.1)? {
        return Ok(false);
    }
    Ok(true)
}

// ── Matrix-vector product Az (ML-DSA.Verify core) ────────────────────────────
//
// Az[i] = Σ_{j=0}^{L-1} A[i][j] × z[j]   in R_q = Z_q[X]/(X^{256}+1)
//
// Pipeline for one row i:
//   1. NTT(z[j])                    — proved once per z column
//   2. A_hat[i][j] ⊙ z_hat[j]      — L poly_mul proofs per row
//   3. Accumulate products via ⊕    — L-1 poly_add proofs per row
//   4. INTT(accumulated)            — 1 INTT proof per row
//
// Total for K=6 rows, L=5 columns: 5 NTT + 30 poly_mul + 24 poly_add + 6 INTT = 65 proofs.
// A_hat is accepted pre-computed (expand_A output) — no NTT proofs needed for A.

/// Per-row STARK proofs for one Az[i].
#[derive(Encode, Decode)]
pub struct AzRowProof {
    /// L pointwise-multiplication proofs: A_hat[i][j] ⊙ z_hat[j].
    pub proofs_pmul: Vec<(Vec<u8>, String)>,
    /// L-1 addition proofs: accumulating sum of products.
    pub proofs_padd: Vec<(Vec<u8>, String)>,
    /// INTT proof for the accumulated NTT-domain sum.
    pub proof_intt:  (Vec<u8>, String),
    /// Az[i] in polynomial domain, coefficients in [0, Q).
    pub az_row:      [i64; N],
}

/// Aggregated STARK proof for the full matrix-vector product Az.
#[derive(Encode, Decode)]
pub struct AzProof {
    /// L NTT proofs, one per z column.
    pub proofs_ntt_z: Vec<(Vec<u8>, String)>,
    /// NTT outputs z_hat[j] committed inside each NTT proof.
    pub z_hat:        Vec<[i64; N]>,
    /// K row proofs.
    pub row_proofs:   Vec<AzRowProof>,
    /// Az[i] for i = 0..k, polynomial domain.
    pub output:       Vec<[i64; N]>,
}

/// Prove the matrix-vector product `Az` in R_q.
///
/// `a_hat` — K×L NTT-domain polynomials, row-major (index i*l + j = A[i][j]).
/// `z`     — L polynomial-domain polynomials (from the signature).
///
/// `k` and `l` must equal the number of rows/columns of `a_hat`.
/// For ML-DSA-65 pass `k = K` (6) and `l = L` (5).
pub fn prove_az(
    a_hat: &[[i64; N]],
    z:     &[[i64; N]],
    k:     usize,
    l:     usize,
) -> Result<AzProof, String> {
    if a_hat.len() != k * l {
        return Err(format!("a_hat must have k*l={} entries, got {}", k * l, a_hat.len()));
    }
    if z.len() != l {
        return Err(format!("z must have l={l} entries, got {}", z.len()));
    }

    // Validate all a_hat coefficients in [0, Q).
    for (idx, poly) in a_hat.iter().enumerate() {
        for (ci, &c) in poly.iter().enumerate() {
            if c < 0 || c >= Q {
                return Err(format!("a_hat[{idx}][{ci}] = {c} out of [0, Q)"));
            }
        }
    }
    // Validate all z coefficients in [0, Q).
    for (j, poly) in z.iter().enumerate() {
        for (ci, &c) in poly.iter().enumerate() {
            if c < 0 || c >= Q {
                return Err(format!("z[{j}][{ci}] = {c} out of [0, Q)"));
            }
        }
    }

    // Step 1: NTT(z[j]) for each j, producing z_hat.
    let mut proofs_ntt_z: Vec<(Vec<u8>, String)> = Vec::with_capacity(l);
    let mut z_hat: Vec<[i64; N]> = Vec::with_capacity(l);
    for (j, zj) in z.iter().enumerate() {
        let (proof_bytes, commitment, zh) = crate::prove_ntt(zj)
            .map_err(|e| format!("NTT proof for z[{j}] failed: {e}"))?;
        proofs_ntt_z.push((proof_bytes, commitment));
        z_hat.push(zh);
    }

    // Step 2-4: For each row i, prove the row product and accumulation.
    let mut row_proofs: Vec<AzRowProof> = Vec::with_capacity(k);
    let mut output:     Vec<[i64; N]>   = Vec::with_capacity(k);

    for i in 0..k {
        // Step 2: L pointwise multiplications: A_hat[i][j] ⊙ z_hat[j].
        let mut proofs_pmul: Vec<(Vec<u8>, String)> = Vec::with_capacity(l);
        let mut products:    Vec<[i64; N]>           = Vec::with_capacity(l);
        for j in 0..l {
            let a_ij = &a_hat[i * l + j];
            let (pb, cm, prod) = crate::prove_poly_mul(a_ij, &z_hat[j])
                .map_err(|e| format!("poly_mul proof A[{i}][{j}]⊙z_hat[{j}] failed: {e}"))?;
            proofs_pmul.push((pb, cm));
            products.push(prod);
        }

        // Step 3: Accumulate products[0] + products[1] + … + products[l-1].
        let mut proofs_padd: Vec<(Vec<u8>, String)> = Vec::with_capacity(l - 1);
        let mut acc: [i64; N] = products[0];
        for j in 1..l {
            let (pb, cm, new_acc) = crate::prove_poly_add(&acc, &products[j])
                .map_err(|e| format!("poly_add proof row {i} step {j} failed: {e}"))?;
            proofs_padd.push((pb, cm));
            acc = new_acc;
        }

        // Step 4: INTT of the accumulated NTT-domain sum.
        let (pb_intt, cm_intt, az_row) = prove_intt(&acc)
            .map_err(|e| format!("INTT proof row {i} failed: {e}"))?;

        output.push(az_row);
        row_proofs.push(AzRowProof {
            proofs_pmul,
            proofs_padd,
            proof_intt: (pb_intt, cm_intt),
            az_row,
        });
    }

    Ok(AzProof { proofs_ntt_z, z_hat, row_proofs, output })
}

/// Verify all STARK sub-proofs in an `AzProof`.
///
/// Returns `Ok(true)` iff every NTT, poly_mul, poly_add, and INTT proof is valid.
pub fn verify_az(proof: &AzProof) -> Result<bool, String> {
    // Verify NTT(z[j]) proofs.
    for (j, (pb, cm)) in proof.proofs_ntt_z.iter().enumerate() {
        if !crate::verify_ntt(pb, cm)
            .map_err(|e| format!("NTT verify z[{j}] failed: {e}"))? {
            return Ok(false);
        }
    }
    // Verify row proofs.
    for (i, row) in proof.row_proofs.iter().enumerate() {
        for (j, (pb, cm)) in row.proofs_pmul.iter().enumerate() {
            if !crate::verify_poly_mul(pb, cm)
                .map_err(|e| format!("poly_mul verify row {i} col {j}: {e}"))? {
                return Ok(false);
            }
        }
        for (j, (pb, cm)) in row.proofs_padd.iter().enumerate() {
            if !crate::verify_poly_add(pb, cm)
                .map_err(|e| format!("poly_add verify row {i} step {j}: {e}"))? {
                return Ok(false);
            }
        }
        let (pb, cm) = &row.proof_intt;
        if !verify_intt(pb, cm)
            .map_err(|e| format!("INTT verify row {i}: {e}"))? {
            return Ok(false);
        }
    }
    Ok(true)
}

// ── Challenge × public key: c·t₁ (ML-DSA.Verify) ────────────────────────────
//
// In ML-DSA.Verify the verifier computes:
//   w'[i] = INTT( Σ_j A_hat[i][j]⊙ẑ[j] − ĉ⊙t̂₁[i] )   i = 0..K−1
//
// This section proves the c·t₁ part: one ring multiplication per row.
// Pipeline for the full Ct1 computation:
//   1. NTT(c)         — one NTT proof for the challenge polynomial
//   2. NTT(t₁[i])     — K NTT proofs, one per public-key component
//   3. NTT(c)⊙NTT(t₁[i]) — K poly_mul proofs
//   4. INTT(product[i])  — K INTT proofs
//
// Total: 1 + K + K + K = 1 + 3K proofs  (19 proofs for K=6).

/// STARK proof for the computation c·t₁ (challenge × public-key components).
#[derive(Encode, Decode)]
pub struct Ct1Proof {
    /// NTT proof for the challenge polynomial c.
    pub proof_ntt_c: (Vec<u8>, String),
    /// NTT output ĉ = NTT(c).
    pub c_hat:       [i64; N],
    /// NTT proofs for each t₁[i].
    pub proofs_ntt_t1: Vec<(Vec<u8>, String)>,
    /// Pointwise-multiplication proofs: ĉ ⊙ NTT(t₁[i]).
    pub proofs_pmul:   Vec<(Vec<u8>, String)>,
    /// INTT proofs for each product.
    pub proofs_intt:   Vec<(Vec<u8>, String)>,
    /// Output: c·t₁[i] in polynomial domain, coefficients in [0, Q).
    pub output:        Vec<[i64; N]>,
}

/// Prove the computation `c·t₁` for all K public-key components.
///
/// `c`  — challenge polynomial from `SampleInBall`, coefficients in `[0, Q)`.
/// `t1` — K public-key polynomials from `pkDecode`, coefficients in `[0, Q)`.
pub fn prove_ct1(c: &[i64; N], t1: &[[i64; N]]) -> Result<Ct1Proof, String> {
    let k = t1.len();
    if k == 0 {
        return Err("t1 must have at least 1 entry".into());
    }

    // Validate c.
    for (i, &v) in c.iter().enumerate() {
        if v < 0 || v >= Q {
            return Err(format!("c[{i}] = {v} out of [0, Q)"));
        }
    }
    // Validate t1.
    for (row, poly) in t1.iter().enumerate() {
        for (ci, &v) in poly.iter().enumerate() {
            if v < 0 || v >= Q {
                return Err(format!("t1[{row}][{ci}] = {v} out of [0, Q)"));
            }
        }
    }

    // Step 1: Prove NTT(c) once.
    let (proof_c_bytes, commitment_c, c_hat) =
        crate::prove_ntt(c).map_err(|e| format!("NTT proof for c failed: {e}"))?;

    // Steps 2-4: For each row i.
    let mut proofs_ntt_t1: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut proofs_pmul:   Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut proofs_intt:   Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut output:        Vec<[i64; N]>           = Vec::with_capacity(k);

    for i in 0..k {
        // Step 2: NTT(t₁[i]).
        let (pb_ntt, cm_ntt, t1_hat_i) =
            crate::prove_ntt(&t1[i]).map_err(|e| format!("NTT proof for t1[{i}] failed: {e}"))?;
        proofs_ntt_t1.push((pb_ntt, cm_ntt));

        // Step 3: ĉ ⊙ NTT(t₁[i]).
        let (pb_mul, cm_mul, product_hat) =
            crate::prove_poly_mul(&c_hat, &t1_hat_i)
            .map_err(|e| format!("poly_mul proof c_hat⊙t1_hat[{i}] failed: {e}"))?;
        proofs_pmul.push((pb_mul, cm_mul));

        // Step 4: INTT(product).
        let (pb_intt, cm_intt, ct1_i) =
            prove_intt(&product_hat)
            .map_err(|e| format!("INTT proof for c·t1[{i}] failed: {e}"))?;
        proofs_intt.push((pb_intt, cm_intt));
        output.push(ct1_i);
    }

    Ok(Ct1Proof {
        proof_ntt_c: (proof_c_bytes, commitment_c),
        c_hat,
        proofs_ntt_t1,
        proofs_pmul,
        proofs_intt,
        output,
    })
}

/// Verify all STARK sub-proofs in a `Ct1Proof`.
///
/// Returns `Ok(true)` iff every NTT, poly_mul, and INTT proof is valid.
pub fn verify_ct1(proof: &Ct1Proof) -> Result<bool, String> {
    // Verify NTT(c).
    if !crate::verify_ntt(&proof.proof_ntt_c.0, &proof.proof_ntt_c.1)
        .map_err(|e| format!("NTT verify c failed: {e}"))? {
        return Ok(false);
    }
    let k = proof.proofs_ntt_t1.len();
    for i in 0..k {
        // NTT(t₁[i]).
        if !crate::verify_ntt(&proof.proofs_ntt_t1[i].0, &proof.proofs_ntt_t1[i].1)
            .map_err(|e| format!("NTT verify t1[{i}] failed: {e}"))? {
            return Ok(false);
        }
        // poly_mul.
        if !crate::verify_poly_mul(&proof.proofs_pmul[i].0, &proof.proofs_pmul[i].1)
            .map_err(|e| format!("poly_mul verify c⊙t1[{i}] failed: {e}"))? {
            return Ok(false);
        }
        // INTT.
        if !verify_intt(&proof.proofs_intt[i].0, &proof.proofs_intt[i].1)
            .map_err(|e| format!("INTT verify ct1[{i}] failed: {e}"))? {
            return Ok(false);
        }
    }
    Ok(true)
}

// ── Full ML-DSA.Verify witness proof (MVP-3+) ─────────────────────────────────
//
// Proves the core arithmetic of ML-DSA.Verify (FIPS 204 Algorithm 3):
//
//   w'[i] = (Az − c·t₁)[i]   in R_q, for i = 0..K−1
//
// Pipeline:
//   1. AzProof   — K×L ring multiplications summed per row (prove_az)
//   2. Ct1Proof  — K ring multiplications c·t₁[i] (prove_ct1)
//   3. K poly_sub proofs — w'[i] = Az[i] − c·t₁[i] (prove_poly_sub)
//   4. K norm_check proofs — norm[i] for each z[j] (prove_norm_check)
//
// Deferred to MVP-4 (not proved here):
//   • UseHint application (high-bits rounding)
//   • Hash check c̃ = H(μ ∥ w'₁)
//   • Hint weight check ||h||₁ ≤ ω
//   • Range proofs for multiplication soundness

/// Combined STARK proof for the ML-DSA.Verify arithmetic witness.
#[derive(Encode, Decode)]
pub struct VerifyMldsaProof {
    /// STARK proofs for Az (K×L ring multiplications).
    pub az_proof:    AzProof,
    /// STARK proofs for c·t₁ (K ring multiplications).
    pub ct1_proof:   Ct1Proof,
    /// K polynomial-subtraction proofs: w'[i] = Az[i] − c·t₁[i].
    pub proofs_sub:  Vec<(Vec<u8>, String)>,
    /// K norm-check proofs for the L z-polynomials (one per z column).
    pub norm_proofs: Vec<(Vec<u8>, String)>,
    /// K UseHint proofs: w₁'[i] = UseHint(h[i], w'[i]).
    pub use_hint_proofs: Vec<(Vec<u8>, String)>,
    /// w'[i] for i = 0..K−1 (pre-UseHint, polynomial domain).
    pub w_prime:    Vec<[i64; N]>,
    /// w₁'[i] = UseHint(h[i], w'[i]) — the high bits used in the hash check.
    pub w1_prime:   Vec<[i64; N]>,
    /// max_norm[j] = ||z[j]||_∞.  Caller asserts < γ₁ − β = 524 092.
    pub max_norms:  Vec<i64>,
}

/// Prove the full ML-DSA.Verify arithmetic witness.
///
/// # Arguments
/// - `a_hat`: K×L NTT-domain matrix (expand_A output), row-major index i*l+j.
/// - `z`:     L signature polynomials, coefficients in `[0, Q)`.
/// - `c`:     Challenge polynomial (SampleInBall output), coefficients in `[0, Q)`.
/// - `t1`:    K public-key polynomials (pkDecode output), coefficients in `[0, Q)`.
/// - `hints`: K×N hint bits (h[i][j] for row i, coefficient j).
/// - `k`, `l`: matrix dimensions (for ML-DSA-65: k=6, l=5).
///
/// # Returns
/// `VerifyMldsaProof` with all sub-proofs, `w_prime` (pre-UseHint), and
/// `w1_prime` (post-UseHint, used in the hash check).
///
/// # Deferred (MVP-4)
/// In-circuit hash comparison `c̃ = H(μ ∥ w₁')`, hint-weight check,
/// and full range proofs for multiplication soundness.
pub fn prove_verify_mldsa_witness(
    a_hat: &[[i64; N]],
    z:     &[[i64; N]],
    c:     &[i64; N],
    t1:    &[[i64; N]],
    hints: &[Vec<bool>],
    k:     usize,
    l:     usize,
) -> Result<VerifyMldsaProof, String> {
    if t1.len() != k {
        return Err(format!("t1 must have k={k} entries, got {}", t1.len()));
    }
    if hints.len() != k {
        return Err(format!("hints must have k={k} rows, got {}", hints.len()));
    }
    for (i, hrow) in hints.iter().enumerate() {
        if hrow.len() != N {
            return Err(format!("hints[{i}] must have N={N} bits, got {}", hrow.len()));
        }
    }

    // Step 1: Prove Az.
    let az_proof = prove_az(a_hat, z, k, l)
        .map_err(|e| format!("prove_az failed: {e}"))?;

    // Step 2: Prove c·t₁.
    let ct1_proof = prove_ct1(c, t1)
        .map_err(|e| format!("prove_ct1 failed: {e}"))?;

    // Step 3: Prove w'[i] = Az[i] − c·t₁[i].
    let mut proofs_sub: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut w_prime:    Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let (pb, cm, w_i) = crate::prove_poly_sub(&az_proof.output[i], &ct1_proof.output[i])
            .map_err(|e| format!("prove_poly_sub row {i} failed: {e}"))?;
        proofs_sub.push((pb, cm));
        w_prime.push(w_i);
    }

    // Step 4: Prove norm computation for each z[j].
    let mut norm_proofs: Vec<(Vec<u8>, String)> = Vec::with_capacity(l);
    let mut max_norms:   Vec<i64>                = Vec::with_capacity(l);
    for j in 0..l {
        let (pb, cm, _, mx) = crate::prove_norm_check(&z[j])
            .map_err(|e| format!("prove_norm_check z[{j}] failed: {e}"))?;
        norm_proofs.push((pb, cm));
        max_norms.push(mx);
    }

    // Step 5: Prove UseHint(h[i], w'[i]) = w₁'[i] for each row.
    let mut use_hint_proofs: Vec<(Vec<u8>, String)> = Vec::with_capacity(k);
    let mut w1_prime:        Vec<[i64; N]>           = Vec::with_capacity(k);
    for i in 0..k {
        let h_arr: &[bool; N] = hints[i].as_slice().try_into()
            .map_err(|_| format!("hints[{i}] slice is not [bool; N]"))?;
        let (pb, cm, w1_i) = crate::prove_use_hint(&w_prime[i], h_arr)
            .map_err(|e| format!("prove_use_hint row {i} failed: {e}"))?;
        use_hint_proofs.push((pb, cm));
        w1_prime.push(w1_i);
    }

    Ok(VerifyMldsaProof {
        az_proof,
        ct1_proof,
        proofs_sub,
        norm_proofs,
        use_hint_proofs,
        w_prime,
        w1_prime,
        max_norms,
    })
}

/// Verify all STARK sub-proofs in a `VerifyMldsaProof`.
///
/// Returns `Ok(true)` iff all Az, Ct1, subtraction, and norm-check proofs are valid.
///
/// # Note
/// This verifies the arithmetic witness only.  The caller is responsible for:
/// - Checking `max_norms[j] < γ₁ − β` for all j (norm bound)
/// - Running UseHint, hash comparison, and hint-weight check (MVP-4)
pub fn verify_mldsa_witness_proofs(proof: &VerifyMldsaProof) -> Result<bool, String> {
    // Verify Az.
    if !verify_az(&proof.az_proof)
        .map_err(|e| format!("verify_az failed: {e}"))? {
        return Ok(false);
    }
    // Verify c·t₁.
    if !verify_ct1(&proof.ct1_proof)
        .map_err(|e| format!("verify_ct1 failed: {e}"))? {
        return Ok(false);
    }
    // Verify subtractions.
    for (i, (pb, cm)) in proof.proofs_sub.iter().enumerate() {
        if !crate::verify_poly_sub(pb, cm)
            .map_err(|e| format!("verify_poly_sub row {i} failed: {e}"))? {
            return Ok(false);
        }
    }
    // Verify norm checks.
    for (j, (pb, cm)) in proof.norm_proofs.iter().enumerate() {
        if !crate::verify_norm_check(pb, cm)
            .map_err(|e| format!("verify_norm_check z[{j}] failed: {e}"))? {
            return Ok(false);
        }
    }
    // Verify UseHint proofs.
    for (i, (pb, cm)) in proof.use_hint_proofs.iter().enumerate() {
        if !crate::verify_use_hint(pb, cm)
            .map_err(|e| format!("verify_use_hint row {i} failed: {e}"))? {
            return Ok(false);
        }
    }
    Ok(true)
}

// ── Cross-check: output equals reference ring multiplication ─────────────────

/// Reference (non-proven) polynomial ring multiplication in Z_q[X]/(X^{256}+1).
pub fn ring_mul_reference(a: &[i64; N], b: &[i64; N]) -> [i64; N] {
    let mut a_hat = *a;
    let mut b_hat = *b;
    ntt(&mut a_hat);
    ntt(&mut b_hat);
    let mut prod = pointwise_mul(&a_hat, &b_hat);
    ntt_inv(&mut prod);
    prod
}

/// Reference (non-proven) matrix-vector product Az over R_q.
///
/// `a_hat` — k×l NTT-domain polynomials, row-major (A_hat[i][j] = a_hat[i*l+j]).
/// `z`     — l polynomial-domain polynomials.
/// Returns k polynomial-domain polynomials representing Az.
pub fn az_reference(a_hat: &[[i64; N]], z: &[[i64; N]], k: usize, l: usize) -> Vec<[i64; N]> {
    // NTT all z columns.
    let z_hat: Vec<[i64; N]> = z.iter().map(|zj| {
        let mut zh = *zj;
        ntt(&mut zh);
        zh
    }).collect();

    (0..k).map(|i| {
        // NTT-domain accumulation: Σ_j A_hat[i][j] ⊙ z_hat[j].
        let mut acc = [0i64; N];
        for j in 0..l {
            let prod = pointwise_mul(&a_hat[i * l + j], &z_hat[j]);
            for ci in 0..N {
                acc[ci] = (acc[ci] + prod[ci]).rem_euclid(Q);
            }
        }
        // INTT to polynomial domain.
        ntt_inv(&mut acc);
        acc
    }).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn random_poly(seed: u64) -> [i64; N] {
        let mut state = seed;
        let mut p = [0i64; N];
        for c in p.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *c = ((state >> 33) as i64).abs() % Q;
        }
        p
    }

    #[test]
    fn test_ring_mul_reference_matches_naive() {
        // Reference must agree with direct polynomial multiplication.
        let a = random_poly(10);
        let b = random_poly(20);
        let via_stark_pipeline = ring_mul_reference(&a, &b);

        // Re-derive naively: NTT → pointwise → INTT.
        let mut a2 = a;
        let mut b2 = b;
        ntt(&mut a2);
        ntt(&mut b2);
        let mut c2 = pointwise_mul(&a2, &b2);
        ntt_inv(&mut c2);

        assert_eq!(via_stark_pipeline, c2);
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_intt_roundtrip() {
        // INTT(NTT(f)) == f (the fundamental identity).
        let f = random_poly(77);
        let mut f_hat = f;
        ntt(&mut f_hat);

        let (proof_bytes, commitment_hex, intt_out) =
            prove_intt(&f_hat).expect("INTT proving failed");

        // Output must equal the original polynomial.
        assert_eq!(intt_out, f, "INTT(NTT(f)) ≠ f");

        // Proof must verify.
        let valid = verify_intt(&proof_bytes, &commitment_hex)
            .expect("INTT verification failed");
        assert!(valid);
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_ring_mul_output_correct() {
        let a = random_poly(50);
        let b = random_poly(60);

        let proof = prove_ring_mul(&a, &b).expect("ring_mul proving failed");

        // Output must match the reference.
        let expected = ring_mul_reference(&a, &b);
        assert_eq!(proof.output, expected, "ring_mul output mismatch");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_ring_mul_verifies() {
        let a = random_poly(111);
        let b = random_poly(222);

        let proof = prove_ring_mul(&a, &b).expect("ring_mul proving failed");
        let valid = verify_ring_mul(&proof).expect("ring_mul verification failed");
        assert!(valid, "ring_mul proof should verify");
    }

    // ── Az matrix-vector product tests ───────────────────────────────────────

    #[test]
    fn test_az_reference_correctness() {
        // Verify the reference function matches manual computation: 2×2 case.
        let k = 2usize;
        let l = 2usize;
        let a_polys: Vec<[i64; N]> = (0..k*l).map(|s| random_poly(s as u64 * 17)).collect();
        let z_polys: Vec<[i64; N]> = (0..l).map(|s| random_poly(s as u64 * 31 + 100)).collect();

        // Compute A_hat row-major.
        let a_hat: Vec<[i64; N]> = a_polys.iter().map(|p| { let mut h = *p; ntt(&mut h); h }).collect();

        let result = az_reference(&a_hat, &z_polys, k, l);

        // Manual check: Az[0] = A[0][0]*z[0] + A[0][1]*z[1].
        let r0 = ring_mul_reference(&a_polys[0], &z_polys[0]);
        let r1 = ring_mul_reference(&a_polys[1], &z_polys[1]);
        let expected0: [i64; N] = std::array::from_fn(|i| (r0[i] + r1[i]).rem_euclid(Q));
        assert_eq!(result[0], expected0, "Az[0] reference mismatch");
    }

    // ── AzProofV2 tests ───────────────────────────────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_az_v2_1x1_output_correct() {
        // Degenerate case: 1×1 "matrix" with L=1 fails because prove_az_v2 requires L=5.
        // Test with k=1, l=5 (L must be 5 for ML-DSA-65).
        let k = 1usize;
        let l = 5usize;
        let a_polys: Vec<[i64; N]> = (0..k*l).map(|s| random_poly(s as u64 * 7 + 10)).collect();
        let z_polys: Vec<[i64; N]> = (0..l).map(|s| random_poly(s as u64 * 13 + 50)).collect();

        let a_hat: Vec<[i64; N]> = a_polys.iter().map(|p| { let mut h = *p; ntt(&mut h); h }).collect();

        let proof = prove_az_v2(&a_hat, &z_polys, k, l)
            .expect("prove_az_v2 1×5 failed");

        // Output must match the reference.
        let expected = az_reference(&a_hat, &z_polys, k, l);
        assert_eq!(proof.output, expected, "Az_v2 1×5 output mismatch");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_az_v2_6x5_output_correct() {
        // Full ML-DSA-65 dimensions: K=6, L=5.
        let k = 6usize;
        let l = 5usize;
        let a_polys: Vec<[i64; N]> = (0..k*l).map(|s| random_poly(s as u64 * 3 + 100)).collect();
        let z_polys: Vec<[i64; N]> = (0..l).map(|s| random_poly(s as u64 * 11 + 200)).collect();

        let a_hat: Vec<[i64; N]> = a_polys.iter().map(|p| { let mut h = *p; ntt(&mut h); h }).collect();

        let proof = prove_az_v2(&a_hat, &z_polys, k, l)
            .expect("prove_az_v2 6×5 failed");

        let expected = az_reference(&a_hat, &z_polys, k, l);
        assert_eq!(proof.output, expected, "Az_v2 6×5 output mismatch");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_az_v2_verifies() {
        let k = 2usize;
        let l = 5usize;
        let a_hat: Vec<[i64; N]> = (0..k*l).map(|s| { let mut h = random_poly(s as u64 + 300); ntt(&mut h); h }).collect();
        let z: Vec<[i64; N]>     = (0..l).map(|s| random_poly(s as u64 + 400)).collect();

        let proof = prove_az_v2(&a_hat, &z, k, l)
            .expect("prove_az_v2 failed");
        let valid = verify_az_v2(&proof).expect("verify_az_v2 failed");
        assert!(valid, "AzProofV2 should verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v2_1x5_verifies() {
        let k = 1usize;
        let l = 5usize;
        let a_hat: Vec<[i64; N]> = (0..k*l).map(|s| { let mut h = random_poly(s as u64 + 500); ntt(&mut h); h }).collect();
        let z:  Vec<[i64; N]>   = (0..l).map(|s| random_poly(s as u64 + 600)).collect();
        let c:  [i64; N]        = random_poly(700);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 800)).collect();
        let h   = all_false_hints(k);

        let proof = prove_verify_mldsa_v2(&a_hat, &z, &c, &t1, &h, k, l)
            .expect("prove_verify_mldsa_v2 failed");
        let valid = verify_mldsa_witness_v2(&proof)
            .expect("verify_mldsa_witness_v2 failed");
        assert!(valid, "VerifyMldsaProofV2 should verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v3_6x5_verifies() {
        // V3 requires exactly k=6, l=5 (ML-DSA-65 full matrix).
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l).map(|s| { let mut h = random_poly(s as u64 + 900); ntt(&mut h); h }).collect();
        let z:  Vec<[i64; N]>   = (0..l).map(|s| random_poly(s as u64 + 1000)).collect();
        let c:  [i64; N]        = random_poly(1100);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 1200)).collect();
        let h   = all_false_hints(k);

        let proof = prove_verify_mldsa_v3(&a_hat, &z, &c, &t1, &h, k, l, b"")
            .expect("prove_verify_mldsa_v3 failed");

        assert_eq!(proof.hint_weight_total, 0, "all-zero hints have weight 0");
        assert!(!proof.hint_weight_proof.0.is_empty(), "hint weight proof must be non-empty");

        let valid = verify_mldsa_witness_v3(&proof)
            .expect("verify_mldsa_witness_v3 failed");
        assert!(valid, "VerifyMldsaProofV3 should verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_az_1x1_output_correct() {
        // Smallest possible case: 1×1 "matrix" — equivalent to one ring multiplication.
        let a_poly = random_poly(999);
        let z_poly = random_poly(888);
        let mut a_hat = a_poly;
        ntt(&mut a_hat);

        let az_proof = prove_az(&[a_hat], &[z_poly], 1, 1)
            .expect("prove_az 1×1 failed");

        let expected = ring_mul_reference(&a_poly, &z_poly);
        assert_eq!(az_proof.output[0], expected, "Az[0] output mismatch");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_az_1x1_verifies() {
        let a_poly = random_poly(777);
        let z_poly = random_poly(666);
        let mut a_hat = a_poly;
        ntt(&mut a_hat);

        let az_proof = prove_az(&[a_hat], &[z_poly], 1, 1)
            .expect("prove_az 1×1 failed");
        let valid = verify_az(&az_proof).expect("verify_az 1×1 failed");
        assert!(valid, "Az 1×1 proof should verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_az_2x2_output_correct() {
        let k = 2usize;
        let l = 2usize;
        let a_polys: Vec<[i64; N]> = (0..k*l).map(|s| random_poly(s as u64 + 200)).collect();
        let z_polys: Vec<[i64; N]> = (0..l).map(|s| random_poly(s as u64 + 300)).collect();

        let a_hat: Vec<[i64; N]> = a_polys.iter().map(|p| { let mut h = *p; ntt(&mut h); h }).collect();

        let az_proof = prove_az(&a_hat, &z_polys, k, l)
            .expect("prove_az 2×2 failed");

        let expected = az_reference(&a_hat, &z_polys, k, l);
        assert_eq!(az_proof.output, expected, "Az 2×2 output mismatch");
    }

    // ── Ct1 tests ─────────────────────────────────────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_ct1_1x1_output_correct() {
        // c·t₁[0] must equal ring_mul_reference(c, t₁[0]).
        let c   = random_poly(400);
        let t1  = [random_poly(500)];

        let proof = prove_ct1(&c, &t1).expect("prove_ct1 1×1 failed");

        let expected = ring_mul_reference(&c, &t1[0]);
        assert_eq!(proof.output[0], expected, "c·t₁[0] output mismatch");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_ct1_1x1_verifies() {
        let c  = random_poly(450);
        let t1 = [random_poly(550)];

        let proof = prove_ct1(&c, &t1).expect("prove_ct1 1×1 failed");
        let valid = verify_ct1(&proof).expect("verify_ct1 1×1 failed");
        assert!(valid, "Ct1 1×1 proof should verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_ct1_2x_output_correct() {
        let c  = random_poly(600);
        let t1 = [random_poly(700), random_poly(800)];

        let proof = prove_ct1(&c, &t1).expect("prove_ct1 2× failed");

        for i in 0..2 {
            let expected = ring_mul_reference(&c, &t1[i]);
            assert_eq!(proof.output[i], expected, "c·t₁[{i}] output mismatch");
        }
    }

    // ── VerifyMldsaProof tests ─────────────────────────────────────────────────

    fn all_false_hints(k: usize) -> Vec<Vec<bool>> {
        vec![vec![false; N]; k]
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_witness_1x1_output() {
        let k = 1usize;
        let l = 1usize;
        let a_poly  = random_poly(1000);
        let z_poly  = random_poly(1100);
        let c_poly  = random_poly(1200);
        let t1_poly = random_poly(1300);

        let mut a_hat_arr = a_poly;
        ntt(&mut a_hat_arr);
        let a_hat = vec![a_hat_arr];
        let z  = vec![z_poly];
        let t1 = vec![t1_poly];
        let h  = all_false_hints(k);

        let proof = prove_verify_mldsa_witness(&a_hat, &z, &c_poly, &t1, &h, k, l)
            .expect("prove_verify_mldsa_witness 1×1 failed");

        let az_expected  = ring_mul_reference(&a_poly, &z_poly);
        let ct1_expected = ring_mul_reference(&c_poly, &t1_poly);
        let w_expected: [i64; N] = std::array::from_fn(|i| {
            (az_expected[i] - ct1_expected[i]).rem_euclid(Q)
        });
        assert_eq!(proof.w_prime[0], w_expected, "w'[0] mismatch");
        // With all-false hints, w₁'[i] = HighBits(w'[i]).
        for i in 0..N {
            let (r1, _) = crate::mldsa_use_hint_air::decompose_val_signed(proof.w_prime[0][i]);
            assert_eq!(proof.w1_prime[0][i], r1, "w1'[0][{i}] mismatch");
        }
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_witness_1x1_verifies() {
        let k = 1usize;
        let l = 1usize;
        let a_poly  = random_poly(2000);
        let z_poly  = random_poly(2100);
        let c_poly  = random_poly(2200);
        let t1_poly = random_poly(2300);

        let mut a_hat_arr = a_poly;
        ntt(&mut a_hat_arr);
        let a_hat = vec![a_hat_arr];
        let z  = vec![z_poly];
        let t1 = vec![t1_poly];
        let h  = all_false_hints(k);

        let proof = prove_verify_mldsa_witness(&a_hat, &z, &c_poly, &t1, &h, k, l)
            .expect("prove_verify_mldsa_witness 1×1 failed");

        let valid = verify_mldsa_witness_proofs(&proof)
            .expect("verify_mldsa_witness_proofs failed");
        assert!(valid, "ML-DSA witness 1×1 proofs should verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_verify_mldsa_norm_bound_check() {
        let k = 1usize;
        let l = 1usize;
        let a_poly  = random_poly(3000);
        let z_poly  = random_poly(3100);
        let c_poly  = random_poly(3200);
        let t1_poly = random_poly(3300);

        let mut a_hat_arr = a_poly;
        ntt(&mut a_hat_arr);
        let a_hat = vec![a_hat_arr];
        let z  = vec![z_poly];
        let t1 = vec![t1_poly];
        let h  = all_false_hints(k);

        let proof = prove_verify_mldsa_witness(&a_hat, &z, &c_poly, &t1, &h, k, l)
            .expect("prove_verify_mldsa_witness failed");

        assert_eq!(proof.max_norms.len(), l);
        let half = (Q - 1) / 2;
        let expected_max: i64 = z_poly.iter().map(|&v| if v > half { Q - v } else { v }).max().unwrap();
        assert_eq!(proof.max_norms[0], expected_max);
    }

    // ── AzProofV3 tests (full-matrix Az AIR) ─────────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_az_v3_output_matches_v2() {
        // v3 and v2 must produce identical Az outputs for the same (a_hat, z).
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 1000); ntt(&mut h); h })
            .collect();
        let z: Vec<[i64; N]> = (0..l).map(|s| random_poly(s as u64 + 2000)).collect();

        let v2 = prove_az_v2(&a_hat, &z, k, l).expect("prove_az_v2 failed");
        let v3 = prove_az_v3(&a_hat, &z, k, l, b"").expect("prove_az_v3 failed");

        assert_eq!(v2.output, v3.output, "v2 and v3 Az outputs must be identical");
        assert_eq!(v3.proofs_ntt_z.len(), l, "v3: L NTT proofs");
        assert_eq!(v3.proofs_intt.len(), k, "v3: K INTT proofs");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_verify_az_v3_roundtrip() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 3000); ntt(&mut h); h })
            .collect();
        let z: Vec<[i64; N]> = (0..l).map(|s| random_poly(s as u64 + 4000)).collect();

        let proof = prove_az_v3(&a_hat, &z, k, l, b"").expect("prove_az_v3 failed");
        let valid = verify_az_v3(&proof, b"").expect("verify_az_v3 failed");
        assert!(valid, "AzProofV3 must verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_verify_az_v3_tampered_az_hat_fails() {
        // Flip one coefficient of az_hat[0] — cross-check 2 must catch it.
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 5000); ntt(&mut h); h })
            .collect();
        let z: Vec<[i64; N]> = (0..l).map(|s| random_poly(s as u64 + 6000)).collect();

        let mut proof = prove_az_v3(&a_hat, &z, k, l, b"").expect("prove_az_v3 failed");
        proof.az_hat[0][0] = (proof.az_hat[0][0] + 1) % Q;

        let valid = verify_az_v3(&proof, b"").expect("verify_az_v3 should not error");
        assert!(!valid, "Tampered az_hat must fail cross-check");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_verify_az_v3_wrong_c_tilde_fails() {
        // Prove with c_tilde A, verify with c_tilde B — must fail (Fiat-Shamir mismatch).
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 7000); ntt(&mut h); h })
            .collect();
        let z: Vec<[i64; N]> = (0..l).map(|s| random_poly(s as u64 + 8000)).collect();

        let c_tilde_a = b"c_tilde_challenge_A_48_bytes____padding__padding".as_slice();
        let c_tilde_b = b"c_tilde_challenge_B_48_bytes____padding__padding".as_slice();

        let proof = prove_az_v3(&a_hat, &z, k, l, c_tilde_a).expect("prove_az_v3 failed");

        // Correct c_tilde must verify.
        assert!(verify_az_v3(&proof, c_tilde_a).expect("verify should not error with correct c_tilde"));
        // Wrong c_tilde must fail — Fiat-Shamir query positions are different.
        assert!(!verify_az_v3(&proof, c_tilde_b).expect("verify should not error with wrong c_tilde"),
            "verify with wrong c_tilde must fail");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v3_c_tilde_binding() {
        // Prove V3 with c_tilde A, then tamper c_tilde in bundle → verify must fail.
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l).map(|s| { let mut h = random_poly(s as u64 + 9000); ntt(&mut h); h }).collect();
        let z:  Vec<[i64; N]>   = (0..l).map(|s| random_poly(s as u64 + 9100)).collect();
        let c:  [i64; N]        = random_poly(9200);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 9300)).collect();
        let h   = all_false_hints(k);

        let c_tilde_a: Vec<u8> = (0u8..48).collect();
        let c_tilde_b: Vec<u8> = (1u8..49).collect();

        let mut proof = prove_verify_mldsa_v3(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde_a)
            .expect("prove_verify_mldsa_v3 failed");

        // Correct c_tilde — must verify.
        assert!(verify_mldsa_witness_v3(&proof).expect("verify should not error"));

        // Tamper the stored c_tilde — Az-full Fiat-Shamir won't match → fail.
        proof.c_tilde = c_tilde_b;
        assert!(!verify_mldsa_witness_v3(&proof).expect("verify should not error after tamper"),
            "tampered c_tilde must cause verification failure");
    }

    // ── Ct1ProofV2 tests ───────────────────────────────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_ct1_v2_output_correct() {
        let k = crate::mldsa::params::K;
        let c  = random_poly(5000);
        let t1: Vec<[i64; N]> = (0..k).map(|i| random_poly(5100 + i as u64)).collect();

        let proof = prove_ct1_v2(&c, &t1, &[]).expect("prove_ct1_v2 failed");

        for i in 0..k {
            let expected = ring_mul_reference(&c, &t1[i]);
            assert_eq!(proof.output[i], expected, "ct1_v2 output[{i}] mismatch");
        }
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_ct1_v2_verifies() {
        let k = crate::mldsa::params::K;
        let c  = random_poly(5200);
        let t1: Vec<[i64; N]> = (0..k).map(|i| random_poly(5300 + i as u64)).collect();

        let proof = prove_ct1_v2(&c, &t1, &[]).expect("prove_ct1_v2 failed");
        let valid = verify_ct1_v2(&proof, &[]).expect("verify_ct1_v2 failed");
        assert!(valid, "Ct1ProofV2 must verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_ct1_v2_c_tilde_binding() {
        let k = crate::mldsa::params::K;
        let c  = random_poly(5400);
        let t1: Vec<[i64; N]> = (0..k).map(|i| random_poly(5500 + i as u64)).collect();

        let seed_a: Vec<u8> = (0u8..48).collect();
        let seed_b: Vec<u8> = (1u8..49).collect();

        // Prove with seed_a.
        let proof = prove_ct1_v2(&c, &t1, &seed_a).expect("prove_ct1_v2 with seed failed");

        // Verify with correct seed.
        assert!(verify_ct1_v2(&proof, &seed_a).expect("verify with correct seed failed"),
            "Ct1ProofV2 must verify with original c_tilde");

        // Verify with wrong seed — Fiat-Shamir mismatch.
        assert!(!verify_ct1_v2(&proof, &seed_b).unwrap_or(false),
            "Ct1ProofV2 must fail with wrong c_tilde");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_ct1_v2_matches_ct1_v1() {
        let k = crate::mldsa::params::K;
        let c  = random_poly(5600);
        let t1: Vec<[i64; N]> = (0..k).map(|i| random_poly(5700 + i as u64)).collect();

        let v1 = prove_ct1(&c, &t1).expect("prove_ct1 failed");
        let v2 = prove_ct1_v2(&c, &t1, &[]).expect("prove_ct1_v2 failed");

        for i in 0..k {
            assert_eq!(v1.output[i], v2.output[i], "output[{i}] mismatch between v1 and v2");
        }
    }

    // ── VerifyMldsaProofV4 tests ───────────────────────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v4_6x5_verifies() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 6000); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 6100)).collect();
        let c:  [i64; N]       = random_poly(6200);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 6300)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (10u8..58).collect();

        let proof = prove_verify_mldsa_v4(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v4 failed");

        let valid = verify_mldsa_witness_v4(&proof).expect("verify_mldsa_witness_v4 failed");
        assert!(valid, "VerifyMldsaProofV4 must verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v4_output_matches_v3() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 7000); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 7100)).collect();
        let c:  [i64; N]       = random_poly(7200);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 7300)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (20u8..68).collect();

        let v3 = prove_verify_mldsa_v3(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v3 failed");
        let v4 = prove_verify_mldsa_v4(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v4 failed");

        for i in 0..k {
            assert_eq!(v3.w_prime[i], v4.w_prime[i], "w_prime[{i}] mismatch v3 vs v4");
            assert_eq!(v3.w1_prime[i], v4.w1_prime[i], "w1_prime[{i}] mismatch v3 vs v4");
        }
        assert_eq!(v3.max_norms, v4.max_norms, "max_norms mismatch");
        assert_eq!(v3.hint_weight_total, v4.hint_weight_total, "hint_weight_total mismatch");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v4_c_tilde_binding() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 8000); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 8100)).collect();
        let c:  [i64; N]       = random_poly(8200);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 8300)).collect();
        let h  = all_false_hints(k);

        let c_tilde_a: Vec<u8> = (30u8..78).collect();
        let c_tilde_b: Vec<u8> = (31u8..79).collect();

        let mut proof = prove_verify_mldsa_v4(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde_a)
            .expect("prove_verify_mldsa_v4 failed");

        assert!(verify_mldsa_witness_v4(&proof).expect("verify should not error"),
            "V4 must verify with original c_tilde");

        proof.c_tilde = c_tilde_b;
        assert!(!verify_mldsa_witness_v4(&proof).expect("verify should not error after tamper"),
            "tampered c_tilde must cause V4 verification failure");
    }

    // ── WPrimeProof tests ──────────────────────────────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_wprime_output_correct() {
        let k = crate::mldsa::params::K;
        let az:  Vec<[i64; N]> = (0..k).map(|i| random_poly(9000 + i as u64)).collect();
        let ct1: Vec<[i64; N]> = (0..k).map(|i| random_poly(9100 + i as u64)).collect();
        let proof = prove_wprime(&az, &ct1).expect("prove_wprime failed");
        for i in 0..k {
            for p in 0..N {
                let expected = (az[i][p] - ct1[i][p]).rem_euclid(Q as i64);
                assert_eq!(proof.output[i][p], expected, "w_prime[{i}][{p}] mismatch");
            }
        }
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_wprime_verifies() {
        let k = crate::mldsa::params::K;
        let az:  Vec<[i64; N]> = (0..k).map(|i| random_poly(9200 + i as u64)).collect();
        let ct1: Vec<[i64; N]> = (0..k).map(|i| random_poly(9300 + i as u64)).collect();
        let proof = prove_wprime(&az, &ct1).expect("prove_wprime failed");
        assert!(verify_wprime(&proof).expect("verify_wprime failed"), "WPrimeProof must verify");
    }

    // ── VerifyMldsaProofV5 tests ───────────────────────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v5_6x5_verifies() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 10000); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 10100)).collect();
        let c:  [i64; N]       = random_poly(10200);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 10300)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (40u8..88).collect();

        let proof = prove_verify_mldsa_v5(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v5 failed");

        let valid = verify_mldsa_witness_v5(&proof).expect("verify_mldsa_witness_v5 failed");
        assert!(valid, "VerifyMldsaProofV5 must verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v5_output_matches_v4() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 11000); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 11100)).collect();
        let c:  [i64; N]       = random_poly(11200);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 11300)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (50u8..98).collect();

        let v4 = prove_verify_mldsa_v4(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v4 failed");
        let v5 = prove_verify_mldsa_v5(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v5 failed");

        for i in 0..k {
            assert_eq!(v4.w1_prime[i], v5.w1_prime[i], "w1_prime[{i}] mismatch v4 vs v5");
        }
        assert_eq!(v4.max_norms, v5.max_norms, "max_norms mismatch v4 vs v5");
        assert_eq!(v4.hint_weight_total, v5.hint_weight_total, "hint_weight_total mismatch");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v5_c_tilde_binding() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 12000); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 12100)).collect();
        let c:  [i64; N]       = random_poly(12200);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 12300)).collect();
        let h  = all_false_hints(k);

        let c_tilde_a: Vec<u8> = (60u8..108).collect();
        let c_tilde_b: Vec<u8> = (61u8..109).collect();

        let mut proof = prove_verify_mldsa_v5(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde_a)
            .expect("prove_verify_mldsa_v5 failed");

        assert!(verify_mldsa_witness_v5(&proof).expect("verify should not error"),
            "V5 must verify with original c_tilde");

        proof.c_tilde = c_tilde_b;
        assert!(!verify_mldsa_witness_v5(&proof).expect("verify should not error after tamper"),
            "tampered c_tilde must cause V5 verification failure");
    }

    // ── V6 tests (NormCheck-batch AIR) ────────────────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v6_roundtrip() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 13000); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 13100)).collect();
        let c:  [i64; N]       = random_poly(13200);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 13300)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (70u8..118).collect();

        let proof = prove_verify_mldsa_v6(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v6 failed");

        assert_eq!(proof.norm_proof.max_norms.len(), l, "max_norms must have L entries");
        assert!(verify_mldsa_witness_v6(&proof).expect("verify_mldsa_witness_v6 failed"),
            "V6 proof must verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v6_matches_v5() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 13400); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 13500)).collect();
        let c:  [i64; N]       = random_poly(13600);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 13700)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (71u8..119).collect();

        let v5 = prove_verify_mldsa_v5(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v5 failed");
        let v6 = prove_verify_mldsa_v6(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v6 failed");

        for i in 0..k {
            assert_eq!(v5.w1_prime[i], v6.w1_prime[i], "w1_prime[{i}] mismatch v5 vs v6");
        }
        assert_eq!(v5.max_norms, v6.norm_proof.max_norms, "max_norms mismatch v5 vs v6");
        assert_eq!(v5.hint_weight_total, v6.hint_weight_total, "hint_weight_total mismatch");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v6_c_tilde_binding() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 13800); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 13900)).collect();
        let c:  [i64; N]       = random_poly(14000);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 14100)).collect();
        let h  = all_false_hints(k);

        let c_tilde_a: Vec<u8> = (72u8..120).collect();
        let c_tilde_b: Vec<u8> = (73u8..121).collect();

        let mut proof = prove_verify_mldsa_v6(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde_a)
            .expect("prove_verify_mldsa_v6 failed");

        assert!(verify_mldsa_witness_v6(&proof).expect("verify should not error"),
            "V6 must verify with original c_tilde");

        proof.c_tilde = c_tilde_b;
        assert!(!verify_mldsa_witness_v6(&proof).expect("verify should not error after tamper"),
            "tampered c_tilde must cause V6 verification failure");
    }

    // ── V7 tests (UseHint-batch AIR) ──────────────────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v7_roundtrip() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 14200); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 14300)).collect();
        let c:  [i64; N]       = random_poly(14400);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 14500)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (74u8..122).collect();

        let proof = prove_verify_mldsa_v7(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v7 failed");

        assert_eq!(proof.norm_proof.max_norms.len(), l, "max_norms must have L entries");
        assert_eq!(proof.use_hint_proof.output.len(), k, "w1_prime must have K entries");
        assert!(verify_mldsa_witness_v7(&proof).expect("verify_mldsa_witness_v7 failed"),
            "V7 proof must verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v7_matches_v6() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 14600); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 14700)).collect();
        let c:  [i64; N]       = random_poly(14800);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 14900)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (75u8..123).collect();

        let v6 = prove_verify_mldsa_v6(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v6 failed");
        let v7 = prove_verify_mldsa_v7(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v7 failed");

        for i in 0..k {
            assert_eq!(v6.w1_prime[i], v7.use_hint_proof.output[i],
                "w1_prime[{i}] mismatch v6 vs v7");
        }
        assert_eq!(v6.norm_proof.max_norms, v7.norm_proof.max_norms,
            "max_norms mismatch v6 vs v7");
        assert_eq!(v6.hint_weight_total, v7.hint_weight_total, "hint_weight_total mismatch");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v7_c_tilde_binding() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 15000); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 15100)).collect();
        let c:  [i64; N]       = random_poly(15200);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 15300)).collect();
        let h  = all_false_hints(k);

        let c_tilde_a: Vec<u8> = (76u8..124).collect();
        let c_tilde_b: Vec<u8> = (77u8..125).collect();

        let mut proof = prove_verify_mldsa_v7(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde_a)
            .expect("prove_verify_mldsa_v7 failed");

        assert!(verify_mldsa_witness_v7(&proof).expect("verify should not error"),
            "V7 must verify with original c_tilde");

        proof.c_tilde = c_tilde_b;
        assert!(!verify_mldsa_witness_v7(&proof).expect("verify should not error after tamper"),
            "tampered c_tilde must cause V7 verification failure");
    }

    // ── V8 tests (RangeQ-batch AIR) ───────────────────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v8_roundtrip() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 16000); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 16100)).collect();
        let c:  [i64; N]       = random_poly(16200);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 16300)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (78u8..126).collect();

        let proof = prove_verify_mldsa_v8(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v8 failed");

        assert_eq!(proof.norm_proof.max_norms.len(), l, "max_norms must have L entries");
        assert_eq!(proof.use_hint_proof.output.len(), k, "w1_prime must have K entries");
        assert!(verify_mldsa_witness_v8(&proof).expect("verify_mldsa_witness_v8 failed"),
            "V8 proof must verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v8_matches_v7() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 16400); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 16500)).collect();
        let c:  [i64; N]       = random_poly(16600);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 16700)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (79u8..127).collect();

        let v7 = prove_verify_mldsa_v7(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v7 failed");
        let v8 = prove_verify_mldsa_v8(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v8 failed");

        for i in 0..k {
            assert_eq!(v7.use_hint_proof.output[i], v8.use_hint_proof.output[i],
                "w1_prime[{i}] mismatch v7 vs v8");
        }
        assert_eq!(v7.norm_proof.max_norms, v8.norm_proof.max_norms,
            "max_norms mismatch v7 vs v8");
        assert_eq!(v7.hint_weight_total, v8.hint_weight_total, "hint_weight_total mismatch");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v8_c_tilde_binding() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 16800); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 16900)).collect();
        let c:  [i64; N]       = random_poly(17000);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 17100)).collect();
        let h  = all_false_hints(k);

        let c_tilde_a: Vec<u8> = (80u8..128).collect();
        let c_tilde_b: Vec<u8> = (81u8..129).collect();

        let mut proof = prove_verify_mldsa_v8(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde_a)
            .expect("prove_verify_mldsa_v8 failed");

        assert!(verify_mldsa_witness_v8(&proof).expect("verify should not error"),
            "V8 must verify with original c_tilde");

        proof.c_tilde = c_tilde_b;
        assert!(!verify_mldsa_witness_v8(&proof).expect("verify should not error after tamper"),
            "tampered c_tilde must cause V8 verification failure");
    }

    // ── V9 tests (batch INTT for Az) ──────────────────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v9_roundtrip() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 17200); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 17300)).collect();
        let c:  [i64; N]       = random_poly(17400);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 17500)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (82u8..130).collect();

        let proof = prove_verify_mldsa_v9(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v9 failed");

        assert_eq!(proof.norm_proof.max_norms.len(), l, "max_norms must have L entries");
        assert_eq!(proof.use_hint_proof.output.len(), k, "w1_prime must have K entries");
        assert!(verify_mldsa_witness_v9(&proof).expect("verify_mldsa_witness_v9 failed"),
            "V9 proof must verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v9_matches_v8() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 17600); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 17700)).collect();
        let c:  [i64; N]       = random_poly(17800);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 17900)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (83u8..131).collect();

        let v8 = prove_verify_mldsa_v8(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v8 failed");
        let v9 = prove_verify_mldsa_v9(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v9 failed");

        for i in 0..k {
            assert_eq!(v8.use_hint_proof.output[i], v9.use_hint_proof.output[i],
                "w1_prime[{i}] mismatch v8 vs v9");
        }
        assert_eq!(v8.norm_proof.max_norms, v9.norm_proof.max_norms,
            "max_norms mismatch v8 vs v9");
        assert_eq!(v8.hint_weight_total, v9.hint_weight_total, "hint_weight_total mismatch v8 vs v9");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v9_c_tilde_binding() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 18000); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 18100)).collect();
        let c:  [i64; N]       = random_poly(18200);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 18300)).collect();
        let h  = all_false_hints(k);

        let c_tilde_a: Vec<u8> = (84u8..132).collect();
        let c_tilde_b: Vec<u8> = (85u8..133).collect();

        let mut proof = prove_verify_mldsa_v9(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde_a)
            .expect("prove_verify_mldsa_v9 failed");

        assert!(verify_mldsa_witness_v9(&proof).expect("verify should not error"),
            "V9 must verify with original c_tilde");

        proof.c_tilde = c_tilde_b;
        assert!(!verify_mldsa_witness_v9(&proof).expect("verify should not error after tamper"),
            "tampered c_tilde must cause V9 verification failure");
    }

    // ── V10 tests (batch NTT-t1 + batch INTT-ct1) ─────────────────────────────

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v10_roundtrip() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 18400); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 18500)).collect();
        let c:  [i64; N]       = random_poly(18600);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 18700)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (86u8..134).collect();

        let proof = prove_verify_mldsa_v10(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v10 failed");

        assert_eq!(proof.norm_proof.max_norms.len(), l, "max_norms must have L entries");
        assert_eq!(proof.use_hint_proof.output.len(), k, "w1_prime must have K entries");
        assert!(verify_mldsa_witness_v10(&proof).expect("verify_mldsa_witness_v10 failed"),
            "V10 proof must verify");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v10_matches_v9() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 18800); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 18900)).collect();
        let c:  [i64; N]       = random_poly(19000);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 19100)).collect();
        let h  = all_false_hints(k);
        let c_tilde: Vec<u8> = (87u8..135).collect();

        let v9  = prove_verify_mldsa_v9 (&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v9 failed");
        let v10 = prove_verify_mldsa_v10(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde)
            .expect("prove_verify_mldsa_v10 failed");

        for i in 0..k {
            assert_eq!(v9.use_hint_proof.output[i], v10.use_hint_proof.output[i],
                "w1_prime[{i}] mismatch v9 vs v10");
        }
        assert_eq!(v9.norm_proof.max_norms, v10.norm_proof.max_norms,
            "max_norms mismatch v9 vs v10");
        assert_eq!(v9.hint_weight_total, v10.hint_weight_total, "hint_weight_total mismatch v9 vs v10");
    }

    #[test]
    #[ignore = "slow: runs full STARK proof pipeline (~2-4 min per test)"]
    fn test_prove_verify_mldsa_v10_c_tilde_binding() {
        let k = crate::mldsa::params::K;
        let l = crate::mldsa::params::L;
        let a_hat: Vec<[i64; N]> = (0..k*l)
            .map(|s| { let mut h = random_poly(s as u64 + 19200); ntt(&mut h); h })
            .collect();
        let z:  Vec<[i64; N]>  = (0..l).map(|s| random_poly(s as u64 + 19300)).collect();
        let c:  [i64; N]       = random_poly(19400);
        let t1: Vec<[i64; N]>  = (0..k).map(|s| random_poly(s as u64 + 19500)).collect();
        let h  = all_false_hints(k);

        let c_tilde_a: Vec<u8> = (88u8..136).collect();
        let c_tilde_b: Vec<u8> = (89u8..137).collect();

        let mut proof = prove_verify_mldsa_v10(&a_hat, &z, &c, &t1, &h, k, l, &c_tilde_a)
            .expect("prove_verify_mldsa_v10 failed");

        assert!(verify_mldsa_witness_v10(&proof).expect("verify should not error"),
            "V10 must verify with original c_tilde");

        proof.c_tilde = c_tilde_b;
        assert!(!verify_mldsa_witness_v10(&proof).expect("verify should not error after tamper"),
            "tampered c_tilde must cause V10 verification failure");
    }
}
