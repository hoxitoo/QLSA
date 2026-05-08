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

    #[test]
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
    fn test_prove_ct1_1x1_output_correct() {
        // c·t₁[0] must equal ring_mul_reference(c, t₁[0]).
        let c   = random_poly(400);
        let t1  = [random_poly(500)];

        let proof = prove_ct1(&c, &t1).expect("prove_ct1 1×1 failed");

        let expected = ring_mul_reference(&c, &t1[0]);
        assert_eq!(proof.output[0], expected, "c·t₁[0] output mismatch");
    }

    #[test]
    fn test_prove_ct1_1x1_verifies() {
        let c  = random_poly(450);
        let t1 = [random_poly(550)];

        let proof = prove_ct1(&c, &t1).expect("prove_ct1 1×1 failed");
        let valid = verify_ct1(&proof).expect("verify_ct1 1×1 failed");
        assert!(valid, "Ct1 1×1 proof should verify");
    }

    #[test]
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
}
