//! Per-query FRI verification-step AIR — recursive-verifier composition (R3.1).
//!
//! The first *composition* gadget: it chains the arithmetic of [`super::oods_air`]
//! and [`super::fold_air`] into the real per-query computation the recursive FRI
//! verifier performs, with the shared `fPlus`/`fMinus` values flowing from the
//! OODS step into the fold step **through shared trace columns** (not a separate
//! proof).  One row proves one query's verification step:
//!
//! ```text
//! OODS+ :  fPlus  · ( px − z_x) = compPos − oodsComboPos
//! OODS− :  fMinus · (−px − z_x) = compNeg − oodsComboNeg
//! fold  :  folded = (fPlus + fMinus) + friAlpha·(fPlus − fMinus)·yInv
//! ```
//!
//! `px` (M31 query x-coordinate) embeds into QM31 as `(px,0,0,0)`; the antipodal
//! denominator uses `−px`.  A degree-lowering helper `p = (fPlus − fMinus)·yInv`
//! keeps every constraint degree ≤ 2.
//!
//! # Honest-prover construction
//!
//! As in `oods_air`, the trace builder takes the free inputs
//! `(fPlus, fMinus, px, z_x, oodsComboPos, oodsComboNeg, friAlpha, yInv)` and
//! derives the consistent `compPos`, `compNeg`, `p`, `folded`; the AIR proves the
//! relations.  (In the full verifier `compPos/Neg` are Merkle-committed and
//! `fPlus/fMinus` are the quotients — the same relations, no inverse needed here.)
//!
//! # Trace layout (42 columns, no preprocessed columns)
//!
//! ```text
//!  0      px            9      yInv
//!  1..5   z_x          10..14  fPlus        14..18  fMinus
//!  5..9   friAlpha     18..22  oodsComboPos 22..26  oodsComboNeg
//! 26..30  compPos      30..34  compNeg
//! 34..38  p (helper)   38..42  folded
//! ```

use std::ops::{Add, Mul, Sub};

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

use crate::recursive::qm31_mul_air::{add_limbs, limbs, mul_limbs, pack, scale_limbs, sub_limbs};
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub const N_COLS: usize = 42;
pub const MIN_LOG_SIZE: u32 = 1;
pub const MAX_LOG_SIZE: u32 = 20;

const M31_P: u64 = (1u64 << 31) - 1;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub type QueryStepComponent = FrameworkComponent<QueryStepEval>;

/// One per-query step: `(fPlus, fMinus, px, z_x, oodsComboPos, oodsComboNeg, friAlpha, yInv)`.
pub type QueryStepOp = (u128, u128, u32, u128, u128, u128, u128, u32);

// ── Generic QM31 multiply over any field-like element ──────────────────────────

/// QM31 product `x·y` (R = 2+i) expanded over four limbs, generic over the
/// element type so the same expression serves both the `u64` reference and the
/// `E::F` constraint. (Cross-checked against `qm31_mul_air::mul_limbs`.)
fn qmul<F>(x: &[F; 4], y: &[F; 4]) -> [F; 4]
where
    F: Clone + Add<Output = F> + Sub<Output = F> + Mul<Output = F> + Mul<BaseField, Output = F>,
{
    let two = BaseField::from_u32_unchecked(2);
    let u = x[2].clone() * y[2].clone() - x[3].clone() * y[3].clone();
    let v = x[2].clone() * y[3].clone() + x[3].clone() * y[2].clone();
    [
        x[0].clone() * y[0].clone() - x[1].clone() * y[1].clone() + u.clone() * two - v.clone(),
        x[0].clone() * y[1].clone() + x[1].clone() * y[0].clone() + u + v * two,
        x[0].clone() * y[2].clone() - x[1].clone() * y[3].clone()
            + x[2].clone() * y[0].clone() - x[3].clone() * y[1].clone(),
        x[0].clone() * y[3].clone() + x[1].clone() * y[2].clone()
            + x[2].clone() * y[1].clone() + x[3].clone() * y[0].clone(),
    ]
}

// ── Reference (derives the consistent compPos/compNeg/p/folded) ────────────────

/// Returns `(compPos, compNeg, p, folded)` derived from the free inputs so all
/// three relations hold by construction.
pub fn step_ref(
    f_plus: u128,
    f_minus: u128,
    px: u32,
    z_x: u128,
    combo_pos: u128,
    combo_neg: u128,
    fri_alpha: u128,
    y_inv: u32,
) -> (u128, u128, u128, u128) {
    let fp = limbs(f_plus);
    let fm = limbs(f_minus);
    let zx = limbs(z_x);
    let px_q = limbs(pack([px as u64, 0, 0, 0]));
    let neg_px_q = sub_limbs([0, 0, 0, 0], px_q);

    let d_pos = sub_limbs(px_q, zx);
    let d_neg = sub_limbs(neg_px_q, zx);
    let comp_pos = pack(add_limbs(mul_limbs(fp, d_pos), limbs(combo_pos)));
    let comp_neg = pack(add_limbs(mul_limbs(fm, d_neg), limbs(combo_neg)));

    let p = scale_limbs(sub_limbs(fp, fm), y_inv as u64);
    let folded = pack(add_limbs(add_limbs(fp, fm), mul_limbs(limbs(fri_alpha), p)));
    (comp_pos, comp_neg, pack(p), folded)
}

// ── AIR ──────────────────────────────────────────────────────────────────────

pub struct QueryStepEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for QueryStepEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // all constraints are degree 2
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let mut c: Vec<E::F> = Vec::with_capacity(N_COLS);
        for _ in 0..N_COLS {
            c.push(eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone());
        }
        let px = c[0].clone();
        let zx = [c[1].clone(), c[2].clone(), c[3].clone(), c[4].clone()];
        let alpha = [c[5].clone(), c[6].clone(), c[7].clone(), c[8].clone()];
        let y_inv = c[9].clone();
        let fp = [c[10].clone(), c[11].clone(), c[12].clone(), c[13].clone()];
        let fm = [c[14].clone(), c[15].clone(), c[16].clone(), c[17].clone()];
        let combo_pos = [c[18].clone(), c[19].clone(), c[20].clone(), c[21].clone()];
        let combo_neg = [c[22].clone(), c[23].clone(), c[24].clone(), c[25].clone()];
        let comp_pos = [c[26].clone(), c[27].clone(), c[28].clone(), c[29].clone()];
        let comp_neg = [c[30].clone(), c[31].clone(), c[32].clone(), c[33].clone()];
        let p = [c[34].clone(), c[35].clone(), c[36].clone(), c[37].clone()];
        let folded = [c[38].clone(), c[39].clone(), c[40].clone(), c[41].clone()];

        let zero = px.clone() - px.clone();
        // d_pos = (px,0,0,0) − z_x ;  d_neg = (−px,0,0,0) − z_x
        let d_pos = [
            px.clone() - zx[0].clone(),
            zero.clone() - zx[1].clone(),
            zero.clone() - zx[2].clone(),
            zero.clone() - zx[3].clone(),
        ];
        let d_neg = [
            (zero.clone() - px) - zx[0].clone(),
            zero.clone() - zx[1].clone(),
            zero.clone() - zx[2].clone(),
            zero - zx[3].clone(),
        ];

        // OODS+ : fPlus·d_pos = compPos − oodsComboPos
        let prod_pos = qmul(&fp, &d_pos);
        for k in 0..4 {
            eval.add_constraint(prod_pos[k].clone() - (comp_pos[k].clone() - combo_pos[k].clone()));
        }
        // OODS− : fMinus·d_neg = compNeg − oodsComboNeg
        let prod_neg = qmul(&fm, &d_neg);
        for k in 0..4 {
            eval.add_constraint(prod_neg[k].clone() - (comp_neg[k].clone() - combo_neg[k].clone()));
        }
        // helper p = (fPlus − fMinus)·yInv
        for k in 0..4 {
            eval.add_constraint(p[k].clone() - (fp[k].clone() - fm[k].clone()) * y_inv.clone());
        }
        // fold : folded = (fPlus + fMinus) + friAlpha·p
        let ap = qmul(&alpha, &p);
        for k in 0..4 {
            eval.add_constraint(
                folded[k].clone() - (fp[k].clone() + fm[k].clone() + ap[k].clone()),
            );
        }

        eval
    }
}

fn new_component(log_n_rows: u32) -> QueryStepComponent {
    QueryStepComponent::new(
        &mut TraceLocationAllocator::default(),
        QueryStepEval { log_n_rows },
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

/// Build the per-query-step trace. Each row derives the consistent
/// `compPos/compNeg/p/folded`. Padding rows are all-zero (a valid step).
///
/// **Precondition:** all packed QM31 limbs, `px`, `yInv` must be canonical M31
/// elements (`< M31_P`); debug-asserted.
pub fn build_trace(ops: &[QueryStepOp], log_n_rows: u32) -> TraceColumns {
    let n = 1usize << log_n_rows;
    debug_assert!(ops.len() <= n, "ops exceed trace capacity");
    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_COLS];

    let set = |cols: &mut Vec<Vec<BaseField>>, base: usize, row: usize, q: u128| {
        let l = limbs(q);
        for k in 0..4 {
            cols[base + k][row] = BaseField::from_u32_unchecked(l[k] as u32);
        }
    };

    for (r, &(f_plus, f_minus, px, z_x, combo_pos, combo_neg, fri_alpha, y_inv)) in ops.iter().enumerate() {
        debug_assert!(
            [f_plus, f_minus, z_x, combo_pos, combo_neg, fri_alpha]
                .iter()
                .all(|&q| limbs(q).iter().all(|&l| l < M31_P))
                && (px as u64) < M31_P
                && (y_inv as u64) < M31_P,
            "non-canonical limb in query_step build_trace input",
        );
        let (comp_pos, comp_neg, p, folded) =
            step_ref(f_plus, f_minus, px, z_x, combo_pos, combo_neg, fri_alpha, y_inv);

        cols[0][r] = BaseField::from_u32_unchecked(px);
        set(&mut cols, 1, r, z_x);
        set(&mut cols, 5, r, fri_alpha);
        cols[9][r] = BaseField::from_u32_unchecked(y_inv);
        set(&mut cols, 10, r, f_plus);
        set(&mut cols, 14, r, f_minus);
        set(&mut cols, 18, r, combo_pos);
        set(&mut cols, 22, r, combo_neg);
        set(&mut cols, 26, r, comp_pos);
        set(&mut cols, 30, r, comp_neg);
        set(&mut cols, 34, r, p);
        set(&mut cols, 38, r, folded);
    }

    for col in cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    cols.into_iter().map(|col| CircleEvaluation::new(domain, col)).collect()
}

// ── Prove / verify roundtrip ────────────────────────────────────────────────────

/// Prove a batch of per-query FRI steps. Returns `(proof_bytes, log_size)`.
pub fn prove_query_step(ops: &[QueryStepOp]) -> Result<(Vec<u8>, u32), String> {
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
    tree_builder.extend_evals(columns); // Tree 1: main trace (42 columns)
    tree_builder.commit(channel);

    let component = new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;
    bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))
        .map(|b| (b, log_size))
}

/// Verify a proof produced by [`prove_query_step`].
pub fn verify_query_step(proof_bytes: &[u8], log_size: u32) -> Result<bool, String> {
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
    use crate::recursive::fold_air::fold_ref;
    use crate::recursive::oods_air::comp_value_ref;

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
    fn test_step_ref_consistent_with_gadget_refs() {
        // The composed step's pieces must match the standalone oods/fold gadgets.
        let mut seed = 0x1234;
        let (fp, fm) = (rand_qm31(&mut seed), rand_qm31(&mut seed));
        let px = rand_m31(&mut seed) as u32;
        let zx = rand_qm31(&mut seed);
        let (cpos, cneg) = (rand_qm31(&mut seed), rand_qm31(&mut seed));
        let alpha = rand_qm31(&mut seed);
        let y_inv = rand_m31(&mut seed) as u32;

        let (comp_pos, comp_neg, _p, folded) =
            step_ref(fp, fm, px, zx, cpos, cneg, alpha, y_inv);

        // OODS+ piece matches oods_air::comp_value_ref (px).
        assert_eq!(comp_pos, comp_value_ref(fp, px, zx, cpos), "OODS+ mismatch");
        // OODS− piece matches comp_value_ref with −px (= P−px).
        let neg_px = if px == 0 { 0 } else { (M31_P - px as u64) as u32 };
        assert_eq!(comp_neg, comp_value_ref(fm, neg_px, zx, cneg), "OODS− mismatch");
        // fold piece matches fold_air::fold_ref.
        assert_eq!(folded, fold_ref(fp, fm, alpha, y_inv), "fold mismatch");
    }

    #[test]
    fn test_build_trace_dimensions() {
        let ops = vec![(pack([1, 2, 3, 4]), pack([5, 6, 7, 8]), 9, pack([1, 1, 1, 1]),
                        pack([2, 2, 2, 2]), pack([3, 3, 3, 3]), pack([4, 4, 4, 4]), 7)];
        let log = compute_log_size(ops.len());
        let cols = build_trace(&ops, log);
        assert_eq!(cols.len(), N_COLS);
        assert_eq!(cols[0].values.len(), 1 << log);
    }

    fn rand_op(seed: &mut u64) -> QueryStepOp {
        (
            rand_qm31(seed), rand_qm31(seed), rand_m31(seed) as u32, rand_qm31(seed),
            rand_qm31(seed), rand_qm31(seed), rand_qm31(seed), rand_m31(seed) as u32,
        )
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let mut seed = 0xC0DE_F00D;
        let ops: Vec<QueryStepOp> = (0..16).map(|_| rand_op(&mut seed)).collect();
        let (proof, log_size) = prove_query_step(&ops).expect("prove");
        assert!(verify_query_step(&proof, log_size).expect("verify"), "valid step proof must verify");
    }

    #[test]
    fn test_single_op_roundtrip() {
        let mut seed = 0x99;
        let ops = vec![rand_op(&mut seed)];
        let (proof, log_size) = prove_query_step(&ops).expect("prove");
        assert!(verify_query_step(&proof, log_size).expect("verify"));
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let mut seed = 0xBEEF;
        let ops: Vec<QueryStepOp> = (0..8).map(|_| rand_op(&mut seed)).collect();
        let (proof, log_size) = prove_query_step(&ops).expect("prove");
        let mut bad = proof.clone();
        bad[proof.len() / 2] ^= 0xFF;
        assert!(!verify_query_step(&bad, log_size).unwrap_or(false), "tampered proof must not verify");
    }

    #[test]
    fn test_wrong_folded_rejected() {
        // Corrupt the folded output → the fold constraints reject it.
        let mut seed = 0x42;
        let ops = vec![rand_op(&mut seed)];
        let log = compute_log_size(ops.len());
        let mut cols = build_trace(&ops, log);
        let domain = CanonicCoset::new(log).circle_domain();
        let mut vals = cols[38].values.clone(); // column 38 = folded0
        vals[0] = vals[0] + BaseField::from_u32_unchecked(1);
        cols[38] = CircleEvaluation::new(domain, vals);
        match prove_columns(cols, log) {
            Ok((proof, ls)) => assert!(
                !verify_query_step(&proof, ls).unwrap_or(false),
                "a wrong folded value must not verify",
            ),
            Err(_) => {}
        }
    }

    #[test]
    fn test_wrong_comp_pos_rejected() {
        // Corrupt compPos → the OODS+ constraints reject it.
        let mut seed = 0x4242;
        let ops = vec![rand_op(&mut seed)];
        let log = compute_log_size(ops.len());
        let mut cols = build_trace(&ops, log);
        let domain = CanonicCoset::new(log).circle_domain();
        let mut vals = cols[26].values.clone(); // column 26 = compPos0
        vals[0] = vals[0] + BaseField::from_u32_unchecked(1);
        cols[26] = CircleEvaluation::new(domain, vals);
        match prove_columns(cols, log) {
            Ok((proof, ls)) => assert!(
                !verify_query_step(&proof, ls).unwrap_or(false),
                "a wrong compPos must not verify",
            ),
            Err(_) => {}
        }
    }
}
