//! FRI circle/line fold AIR — recursive-verifier gadget (R1).
//!
//! Proves one FRI fold step for a batch of queries:
//!
//! ```text
//! folded = (f₊ + f₋) + α·(f₊ − f₋)·inv
//! ```
//!
//! This is exactly `circle_fold` / `line_fold` from `vfri2_bridge.rs` (the two
//! differ only in whether `inv` is `y⁻¹` or `x⁻¹` — the AIR is identical, so one
//! gadget covers both).  It is the core FRI verification step the recursive
//! verifier must re-prove K times per query, built on the QM31 arithmetic of
//! [`super::qm31_mul_air`].
//!
//! # Lowering to degree 2
//!
//! The naive constraint `folded − (f₊+f₋) − α·(f₊−f₋)·inv` is degree 3 (α × f ×
//! inv).  We add a helper column `p = (f₊−f₋)·inv` (the scaled difference) so
//! both constraint groups are degree 2:
//!
//! ```text
//! C_p :  p_k      = (f₊_k − f₋_k)·inv                      (4 constraints, deg 2)
//! C_f :  folded_k = (f₊_k + f₋_k) + (α·p)_k                (4 constraints, deg 2)
//! ```
//!
//! where `(α·p)` is the QM31 product expanded exactly as in `qm31_mul_air`.
//!
//! # Trace layout (21 columns, no preprocessed columns)
//!
//! ```text
//!  0..4   f₊  (QM31: c0.re,c0.im,c1.re,c1.im)
//!  4..8   f₋  (QM31)
//!  8..12  α   (QM31 folding challenge)
//! 12      inv (M31 scalar: y⁻¹ for circle fold / x⁻¹ for line fold)
//! 13..17  p   (helper: (f₊−f₋)·inv, QM31)
//! 17..21  folded (output, QM31)
//! ```

use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

use crate::recursive::qm31_mul_air::{add_limbs, limbs, pack, scale_limbs, sub_limbs, mul_limbs};
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub const N_COLS: usize = 21;
pub const MIN_LOG_SIZE: u32 = 1;
pub const MAX_LOG_SIZE: u32 = 20;

const M31_P: u64 = (1u64 << 31) - 1;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub type FoldComponent = FrameworkComponent<FoldEval>;

/// One fold operation: `(f₊, f₋, α, inv)`.
pub type FoldOp = (u128, u128, u128, u32);

/// Reference fold over limbs — the value the AIR proves. Mirrors
/// `vfri2_bridge::circle_fold` exactly.
pub fn fold_ref(f_plus: u128, f_minus: u128, alpha: u128, inv: u32) -> u128 {
    let fp = limbs(f_plus);
    let fm = limbs(f_minus);
    let sum = add_limbs(fp, fm);
    let diff = sub_limbs(fp, fm);
    let p = scale_limbs(diff, inv as u64);
    pack(add_limbs(sum, mul_limbs(limbs(alpha), p)))
}

// ── AIR ──────────────────────────────────────────────────────────────────────

pub struct FoldEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for FoldEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // both constraint groups are degree 2
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let mut c: Vec<E::F> = Vec::with_capacity(N_COLS);
        for _ in 0..N_COLS {
            c.push(eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone());
        }
        let fp = [c[0].clone(), c[1].clone(), c[2].clone(), c[3].clone()];
        let fm = [c[4].clone(), c[5].clone(), c[6].clone(), c[7].clone()];
        let a = [c[8].clone(), c[9].clone(), c[10].clone(), c[11].clone()];
        let inv = c[12].clone();
        let p = [c[13].clone(), c[14].clone(), c[15].clone(), c[16].clone()];
        let folded = [c[17].clone(), c[18].clone(), c[19].clone(), c[20].clone()];
        let two = BaseField::from_u32_unchecked(2);

        // C_p: p_k = (f₊_k − f₋_k)·inv
        for k in 0..4 {
            eval.add_constraint(p[k].clone() - (fp[k].clone() - fm[k].clone()) * inv.clone());
        }

        // sum_k = f₊_k + f₋_k
        let sum = [
            fp[0].clone() + fm[0].clone(),
            fp[1].clone() + fm[1].clone(),
            fp[2].clone() + fm[2].clone(),
            fp[3].clone() + fm[3].clone(),
        ];

        // (α·p) via the QM31-mul expansion (x=α, y=p):
        //   u = a2·p2 − a3·p3 ; v = a2·p3 + a3·p2
        let u = a[2].clone() * p[2].clone() - a[3].clone() * p[3].clone();
        let v = a[2].clone() * p[3].clone() + a[3].clone() * p[2].clone();
        let ap0 = a[0].clone() * p[0].clone() - a[1].clone() * p[1].clone() + u.clone() * two - v.clone();
        let ap1 = a[0].clone() * p[1].clone() + a[1].clone() * p[0].clone() + u + v * two;
        let ap2 = a[0].clone() * p[2].clone() - a[1].clone() * p[3].clone()
            + a[2].clone() * p[0].clone() - a[3].clone() * p[1].clone();
        let ap3 = a[0].clone() * p[3].clone() + a[1].clone() * p[2].clone()
            + a[2].clone() * p[1].clone() + a[3].clone() * p[0].clone();
        let ap = [ap0, ap1, ap2, ap3];

        // C_f: folded_k = sum_k + (α·p)_k
        for k in 0..4 {
            eval.add_constraint(folded[k].clone() - (sum[k].clone() + ap[k].clone()));
        }

        eval
    }
}

fn new_component(log_n_rows: u32) -> FoldComponent {
    FoldComponent::new(
        &mut TraceLocationAllocator::default(),
        FoldEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ──────────────────────────────────────────────────────────────

pub fn compute_log_size(n_ops: usize) -> u32 {
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < n_ops.max(1) {
        log += 1;
    }
    log
}

/// Build the fold trace from a batch of `(f₊, f₋, α, inv)` operations. Each row
/// stores the inputs, the helper `p = (f₊−f₋)·inv`, and the output `folded`.
/// Padding rows are all-zero (a valid fold: `0 = 0 + 0·0·0`).
///
/// **Precondition:** all packed QM31 limbs and `inv` must be canonical M31
/// elements (`< M31_P`); debug-asserted (see `qm31_mul_air::build_trace`).
pub fn build_trace(ops: &[FoldOp], log_n_rows: u32) -> TraceColumns {
    let n = 1usize << log_n_rows;
    debug_assert!(ops.len() <= n, "ops exceed trace capacity");
    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_COLS];

    for (r, &(f_plus, f_minus, alpha, inv)) in ops.iter().enumerate() {
        let fp = limbs(f_plus);
        let fm = limbs(f_minus);
        let al = limbs(alpha);
        debug_assert!(
            fp.iter().chain(fm.iter()).chain(al.iter()).all(|&l| l < M31_P) && (inv as u64) < M31_P,
            "non-canonical limb (>= M31_P) in fold build_trace input",
        );
        let p = scale_limbs(sub_limbs(fp, fm), inv as u64);
        let folded = add_limbs(add_limbs(fp, fm), mul_limbs(al, p));

        for k in 0..4 {
            cols[k][r] = BaseField::from_u32_unchecked(fp[k] as u32);
            cols[4 + k][r] = BaseField::from_u32_unchecked(fm[k] as u32);
            cols[8 + k][r] = BaseField::from_u32_unchecked(al[k] as u32);
            cols[13 + k][r] = BaseField::from_u32_unchecked(p[k] as u32);
            cols[17 + k][r] = BaseField::from_u32_unchecked(folded[k] as u32);
        }
        cols[12][r] = BaseField::from_u32_unchecked(inv);
    }

    for col in cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

// ── Prove / verify roundtrip ────────────────────────────────────────────────────

/// Prove a batch of FRI fold steps. Returns `(proof_bytes, log_size)`.
pub fn prove_fold(ops: &[FoldOp]) -> Result<(Vec<u8>, u32), String> {
    if ops.is_empty() {
        return Err("ops must not be empty".into());
    }
    let log_size = compute_log_size(ops.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("too many ops: log_size {log_size} exceeds {MAX_LOG_SIZE}"));
    }
    prove_columns(build_trace(ops, log_size), log_size)
}

fn prove_columns(columns: TraceColumns, log_size: u32) -> Result<(Vec<u8>, u32), String> {
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
    tree_builder.extend_evals(vec![]); // Tree 0: no preprocessed columns
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns); // Tree 1: main trace (21 columns)
    tree_builder.commit(channel);

    let component = new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;
    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;
    Ok((proof_bytes, log_size))
}

/// Verify a proof produced by [`prove_fold`].
pub fn verify_fold(proof_bytes: &[u8], log_size: u32) -> Result<bool, String> {
    if !(MIN_LOG_SIZE..=MAX_LOG_SIZE).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range [{MIN_LOG_SIZE}, {MAX_LOG_SIZE}]"));
    }

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let component = new_component(log_size);
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    let result = verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof);
    Ok(result.is_ok())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_m31(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) % M31_P
    }

    fn rand_qm31(seed: &mut u64) -> u128 {
        (rand_m31(seed) as u128) << 96
            | (rand_m31(seed) as u128) << 64
            | (rand_m31(seed) as u128) << 32
            | rand_m31(seed) as u128
    }

    #[test]
    fn test_fold_ref_alpha_zero_is_sum() {
        // α = 0 ⇒ folded = f₊ + f₋ (the α·diff·inv term vanishes).
        let fp = pack([7, 11, 13, 17]);
        let fm = pack([1, 2, 3, 4]);
        assert_eq!(fold_ref(fp, fm, 0, 5), pack([8, 13, 16, 21]));
    }

    #[test]
    fn test_fold_ref_equal_inputs_is_double() {
        // f₊ = f₋ ⇒ diff = 0 ⇒ folded = 2·f₊ regardless of α, inv.
        let f = pack([3, 5, 7, 9]);
        let mut seed = 0x55;
        let alpha = rand_qm31(&mut seed);
        assert_eq!(fold_ref(f, f, alpha, 12345), pack([6, 10, 14, 18]));
    }

    #[test]
    fn test_build_trace_dimensions() {
        let ops: Vec<FoldOp> = vec![(pack([1, 2, 3, 4]), pack([5, 6, 7, 8]), pack([9, 1, 1, 1]), 7)];
        let log = compute_log_size(ops.len());
        let cols = build_trace(&ops, log);
        assert_eq!(cols.len(), N_COLS);
        assert_eq!(cols[0].values.len(), 1 << log);
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let mut seed = 0xFEED_BEEF;
        let ops: Vec<FoldOp> = (0..16)
            .map(|_| (rand_qm31(&mut seed), rand_qm31(&mut seed), rand_qm31(&mut seed), rand_m31(&mut seed) as u32))
            .collect();
        let (proof, log_size) = prove_fold(&ops).expect("prove");
        assert!(verify_fold(&proof, log_size).expect("verify"), "valid fold proof must verify");
    }

    #[test]
    fn test_single_op_roundtrip() {
        let ops = vec![(pack([2, 0, 1, 0]), pack([0, 1, 0, 1]), pack([1, 1, 0, 0]), 3)];
        let (proof, log_size) = prove_fold(&ops).expect("prove");
        assert!(verify_fold(&proof, log_size).expect("verify"));
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let mut seed = 0x0BAD_F00D;
        let ops: Vec<FoldOp> = (0..8)
            .map(|_| (rand_qm31(&mut seed), rand_qm31(&mut seed), rand_qm31(&mut seed), rand_m31(&mut seed) as u32))
            .collect();
        let (proof, log_size) = prove_fold(&ops).expect("prove");
        let mut bad = proof.clone();
        bad[proof.len() / 2] ^= 0xFF;
        assert!(!verify_fold(&bad, log_size).unwrap_or(false), "tampered fold proof must not verify");
    }

    #[test]
    fn test_wrong_folded_rejected() {
        // Corrupt the folded output → the C_f constraints reject it.
        let ops = vec![(pack([3, 1, 4, 1]), pack([5, 9, 2, 6]), pack([2, 7, 1, 8]), 11)];
        let log = compute_log_size(ops.len());
        let mut cols = build_trace(&ops, log);
        let domain = CanonicCoset::new(log).circle_domain();
        let mut vals = cols[17].values.clone(); // column 17 = folded0
        vals[0] = vals[0] + BaseField::from_u32_unchecked(1);
        cols[17] = CircleEvaluation::new(domain, vals);
        match prove_columns(cols, log) {
            Ok((proof, ls)) => assert!(
                !verify_fold(&proof, ls).unwrap_or(false),
                "a wrong folded value must not yield a verifying proof",
            ),
            Err(_) => {}
        }
    }

    #[test]
    fn test_wrong_helper_p_rejected() {
        // Corrupt the helper column p → the C_p constraints reject it.
        let ops = vec![(pack([3, 1, 4, 1]), pack([5, 9, 2, 6]), pack([2, 7, 1, 8]), 11)];
        let log = compute_log_size(ops.len());
        let mut cols = build_trace(&ops, log);
        let domain = CanonicCoset::new(log).circle_domain();
        let mut vals = cols[13].values.clone(); // column 13 = p0
        vals[0] = vals[0] + BaseField::from_u32_unchecked(1);
        cols[13] = CircleEvaluation::new(domain, vals);
        match prove_columns(cols, log) {
            Ok((proof, ls)) => assert!(
                !verify_fold(&proof, ls).unwrap_or(false),
                "a wrong helper p must not yield a verifying proof",
            ),
            Err(_) => {}
        }
    }
}
