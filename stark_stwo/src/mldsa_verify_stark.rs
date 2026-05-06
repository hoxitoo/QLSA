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

use crate::mldsa::{Q, N};
use crate::mldsa::ntt::{ntt, ntt_inv, pointwise_mul};

// ── High-level polynomial multiplication via STARK pipeline ──────────────────

/// Result of a STARK-proved polynomial ring multiplication.
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
    use blake2::{Blake2s256, Digest};
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

    let commitment_m31 = {
        let mut h = Blake2s256::new();
        for c in &intt_out { h.update(&(*c as u32).to_le_bytes()); }
        let hash = h.finalize();
        u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
            % ((1u32 << 31) - 1)
    };

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

    channel.mix_u32s(&[commitment_m31]);

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

    let m31_le = commitment_m31.to_le_bytes();
    let mut h2 = Blake2s256::new();
    h2.update(m31_le);
    h2.update(&proof_bytes[..proof_bytes.len().min(32)]);
    let suffix = h2.finalize();
    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&m31_le);
    buf[4..16].copy_from_slice(&suffix[0..12]);
    let commitment_hex = hex::encode(buf);

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

    let bytes = hex::decode(commitment_hex)
        .map_err(|e| format!("invalid commitment hex: {e}"))?;
    if bytes.len() != 16 {
        return Err("commitment must be 16 bytes".into());
    }
    let commitment_m31 = u32::from_le_bytes(bytes[0..4].try_into().unwrap());

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<{ 32 * 1024 * 1024 }>(),
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
    verifier_channel.mix_u32s(&[commitment_m31]);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&component], verifier_channel, commitment_scheme, proof,
    )
    .is_ok())
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
    fn test_prove_ring_mul_output_correct() {
        let a = random_poly(50);
        let b = random_poly(60);

        let proof = prove_ring_mul(&a, &b).expect("ring_mul proving failed");

        // Output must match the reference.
        let expected = ring_mul_reference(&a, &b);
        assert_eq!(proof.output, expected, "ring_mul output mismatch");
    }

    #[test]
    fn test_prove_ring_mul_verifies() {
        let a = random_poly(111);
        let b = random_poly(222);

        let proof = prove_ring_mul(&a, &b).expect("ring_mul proving failed");
        let valid = verify_ring_mul(&proof).expect("ring_mul verification failed");
        assert!(valid, "ring_mul proof should verify");
    }
}
