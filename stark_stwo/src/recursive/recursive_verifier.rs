//! Per-query recursive FRI verifier AIR — full composition (R3.3).
//!
//! Unifies [`super::query_step_air`] (OODS± + circle fold) and
//! [`super::fri_fold_chain_air`] (K line-fold rounds) into a **single** AIR
//! component proving one query's entire FRI verification chain, with the
//! connecting value bound by a **cross-row constraint** (not a fingerprint
//! side-channel): the circle-fold output on row 0 becomes the first line-fold
//! input on row 1, and each subsequent input is the previous output.
//!
//! ```text
//! Row 0 (is_step=1):      a = fPlus, b = fMinus
//!   OODS+ : a·( px − z_x) = compPos − oodsComboPos
//!   OODS− : b·(−px − z_x) = compNeg − oodsComboNeg
//!   fold  : out = (a + b) + alpha·(a − b)·inv          [circle fold]
//!
//! Row r∈1..K (chain_on=1): a = out[r−1], b = sibling_r
//!   chain : a = out_prev
//!   fold  : out = (a + b) + alpha·(a − b)·inv          [line fold]
//! ```
//!
//! Both folds share ONE formula by storing the two operands in `a`/`b`:
//! `out = (a+b) + QM31_mul(alpha, (a−b)·inv)`.  This is genuinely sound — the
//! recursive verifier's per-query computation is fully re-proved in one circuit,
//! and the data flow `circleFold → lineFold₁ → … → lineFold_K` is enforced by the
//! `chain` constraint, not asserted by the prover.
//!
//! # Trace layout (42 main columns + 2 preprocessed)
//!
//! ```text
//! Main:
//!  0      px            9      inv  (yInv on row 0 / xInv on rows ≥1)
//!  1.. 5  z_x          10..14  a    (fPlus  / line-fold input)
//!  5.. 9  alpha        14..18  b    (fMinus / sibling)
//! 18..22  oodsComboPos 22..26  oodsComboNeg
//! 26..30  compPos      30..34  compNeg
//! 34..38  p (helper)   38..42  out  (fold output)
//!
//! Preprocessed:
//!  is_step  — 1 on row 0, 0 elsewhere   (gates the OODS constraints)
//!  chain_on — 1 on rows 1..K, 0 else     (gates the cross-row chain constraint)
//! ```

use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
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
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

use crate::recursive::qm31_mul_air::{add_limbs, limbs, mul_limbs, pack, scale_limbs, sub_limbs};
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub const N_MAIN_COLS: usize = 42;
pub const MIN_LOG_SIZE: u32 = 1;
pub const MAX_LOG_SIZE: u32 = 20;

const M31_P: u64 = (1u64 << 31) - 1;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub type RecursiveVerifierComponent = FrameworkComponent<RecursiveVerifierEval>;

/// OODS + circle-fold step inputs for one query:
/// `(fPlus, fMinus, px, z_x, oodsComboPos, oodsComboNeg, friAlpha, yInv)`.
pub type StepOp = (u128, u128, u32, u128, u128, u128, u128, u32);

/// One line-fold round: `(sibling, alpha, xInv)` — the input is chained from the
/// previous output, so it is NOT supplied here.
pub type FoldRound = (u128, u128, u32);

// ── Preprocessed column IDs ───────────────────────────────────────────────────

pub fn pc_is_step() -> PreProcessedColumnId {
    PreProcessedColumnId { id: "rv_is_step".into() }
}
pub fn pc_chain_on() -> PreProcessedColumnId {
    PreProcessedColumnId { id: "rv_chain_on".into() }
}
pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    vec![pc_is_step(), pc_chain_on()]
}

// ── Generic QM31 multiply ──────────────────────────────────────────────────────

use std::ops::{Add, Mul, Sub};

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
            + x[2].clone() * y[0].clone()
            - x[3].clone() * y[1].clone(),
        x[0].clone() * y[3].clone() + x[1].clone() * y[2].clone()
            + x[2].clone() * y[1].clone()
            + x[3].clone() * y[0].clone(),
    ]
}

// ── Reference ───────────────────────────────────────────────────────────────────

/// One fold over the two operands: `(a + b) + alpha·(a − b)·inv`.
fn fold_two(a: u128, b: u128, alpha: u128, inv: u32) -> u128 {
    let al = limbs(a);
    let bl = limbs(b);
    let p = scale_limbs(sub_limbs(al, bl), inv as u64);
    pack(add_limbs(add_limbs(al, bl), mul_limbs(limbs(alpha), p)))
}

/// Full per-query reference: returns the chain of fold outputs.
/// `outputs[0]` is the circle fold; `outputs[r]` (r≥1) is line-fold round r.
pub fn recursive_query_ref(step: &StepOp, rounds: &[FoldRound]) -> Vec<u128> {
    let (f_plus, f_minus, _px, _z_x, _cp, _cn, fri_alpha, y_inv) = *step;
    let mut outs = Vec::with_capacity(rounds.len() + 1);
    // Row 0: circle fold of (fPlus, fMinus).
    outs.push(fold_two(f_plus, f_minus, fri_alpha, y_inv));
    // Rows 1..K: line folds, chained.
    for &(sibling, alpha, x_inv) in rounds {
        let input = *outs.last().unwrap();
        outs.push(fold_two(input, sibling, alpha, x_inv));
    }
    outs
}

/// The final fold value the verifier checks against the FRI last-layer commitment.
pub fn recursive_query_final(step: &StepOp, rounds: &[FoldRound]) -> u128 {
    *recursive_query_ref(step, rounds).last().unwrap()
}

// ── AIR ──────────────────────────────────────────────────────────────────────

pub struct RecursiveVerifierEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for RecursiveVerifierEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // OODS = qmul(a, d) [deg 2] × is_step [preproc] → degree 3; +1 accommodates it.
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_step = eval.get_preprocessed_column(pc_is_step());
        let chain_on = eval.get_preprocessed_column(pc_chain_on());

        // Main columns. `a` (input/fPlus) and `out` need previous-row access for chaining.
        let [px] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [zx0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [zx1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [zx2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [zx3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [al0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [al1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [al2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [al3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [inv] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let [a0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [a1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [a2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [a3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [b0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [b1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [b2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [b3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let [cp0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [cp1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [cp2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [cp3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [cn0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [cn1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [cn2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [cn3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let [compp0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [compp1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [compp2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [compp3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [compn0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [compn1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [compn2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [compn3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let [p0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [p1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [p2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [p3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let [out0_c, out0_p] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [out1_c, out1_p] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [out2_c, out2_p] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [out3_c, out3_p] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);

        let zx = [zx0, zx1, zx2, zx3];
        let alpha = [al0, al1, al2, al3];
        let a = [a0, a1, a2, a3];
        let b = [b0, b1, b2, b3];
        let combo_pos = [cp0, cp1, cp2, cp3];
        let combo_neg = [cn0, cn1, cn2, cn3];
        let comp_pos = [compp0, compp1, compp2, compp3];
        let comp_neg = [compn0, compn1, compn2, compn3];
        let p = [p0, p1, p2, p3];
        let out = [out0_c, out1_c, out2_c, out3_c];
        let out_prev = [out0_p, out1_p, out2_p, out3_p];

        let zero = px.clone() - px.clone();

        // ── C_p: p_k = (a_k − b_k)·inv  (ALL rows, deg 2) ────────────────────────
        for k in 0..4 {
            eval.add_constraint(p[k].clone() - (a[k].clone() - b[k].clone()) * inv.clone());
        }

        // ── C_f: out_k = (a_k + b_k) + QM31_mul(alpha, p)_k  (ALL rows, deg 2) ───
        let ap = qmul(&alpha, &p);
        for k in 0..4 {
            eval.add_constraint(out[k].clone() - (a[k].clone() + b[k].clone() + ap[k].clone()));
        }

        // ── C_oods_pos / C_oods_neg (row 0 only, gated by is_step, deg 3) ────────
        // d_pos = (px,0,0,0) − z_x ; d_neg = (−px,0,0,0) − z_x
        let d_pos = [
            px.clone() - zx[0].clone(),
            zero.clone() - zx[1].clone(),
            zero.clone() - zx[2].clone(),
            zero.clone() - zx[3].clone(),
        ];
        let d_neg = [
            (zero.clone() - px.clone()) - zx[0].clone(),
            zero.clone() - zx[1].clone(),
            zero.clone() - zx[2].clone(),
            zero.clone() - zx[3].clone(),
        ];
        let prod_pos = qmul(&a, &d_pos);
        let prod_neg = qmul(&b, &d_neg);
        for k in 0..4 {
            eval.add_constraint(
                is_step.clone()
                    * (prod_pos[k].clone() - (comp_pos[k].clone() - combo_pos[k].clone())),
            );
            eval.add_constraint(
                is_step.clone()
                    * (prod_neg[k].clone() - (comp_neg[k].clone() - combo_neg[k].clone())),
            );
        }

        // ── C_chain: a_k = out_prev_k  (rows 1..K, gated by chain_on, deg 1) ─────
        for k in 0..4 {
            eval.add_constraint(chain_on.clone() * (a[k].clone() - out_prev[k].clone()));
        }

        eval
    }
}

fn new_component(log_n_rows: u32) -> RecursiveVerifierComponent {
    RecursiveVerifierComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_column_ids()),
        RecursiveVerifierEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ──────────────────────────────────────────────────────────────

pub fn compute_log_size(n_rows: usize) -> u32 {
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < n_rows.max(1) {
        log += 1;
    }
    log
}

/// Set the 4 limbs of a QM31 value into columns `base..base+4` at `row`.
fn set_qm31(cols: &mut [Vec<BaseField>], base: usize, row: usize, q: u128) {
    let l = limbs(q);
    for k in 0..4 {
        cols[base + k][row] = BaseField::from_u32_unchecked(l[k] as u32);
    }
}

/// Fill one query's block (rows `base..base+1+rounds.len()`): row `base` is the
/// OODS + circle-fold step; rows `base+1..` are the K line-fold rounds.  Sets the
/// `is_step` / `chain_on` selectors for the block.  Blocks are independent — the
/// chain selector is 0 on each block's row 0, so a query never folds into the next.
fn fill_query_block(
    cols: &mut [Vec<BaseField>],
    is_step_col: &mut [BaseField],
    chain_on_col: &mut [BaseField],
    base: usize,
    step: &StepOp,
    rounds: &[FoldRound],
) {
    let (f_plus, f_minus, px, z_x, combo_pos, combo_neg, fri_alpha, y_inv) = *step;
    debug_assert!(
        [f_plus, f_minus, z_x, combo_pos, combo_neg, fri_alpha]
            .iter()
            .all(|&q| limbs(q).iter().all(|&l| l < M31_P))
            && (px as u64) < M31_P
            && (y_inv as u64) < M31_P,
        "non-canonical limb in recursive_verifier step input",
    );

    let outs = recursive_query_ref(step, rounds);

    // ── Row `base`: OODS + circle fold ───────────────────────────────────────
    let px_q = pack([px as u64, 0, 0, 0]);
    let neg_px_q = sub_limbs([0, 0, 0, 0], limbs(px_q));
    let d_pos = sub_limbs(limbs(px_q), limbs(z_x));
    let d_neg = sub_limbs(neg_px_q, limbs(z_x));
    let comp_pos = pack(add_limbs(mul_limbs(limbs(f_plus), d_pos), limbs(combo_pos)));
    let comp_neg = pack(add_limbs(mul_limbs(limbs(f_minus), d_neg), limbs(combo_neg)));
    let p0 = scale_limbs(sub_limbs(limbs(f_plus), limbs(f_minus)), y_inv as u64);

    cols[0][base] = BaseField::from_u32_unchecked(px);
    set_qm31(cols, 1, base, z_x);
    set_qm31(cols, 5, base, fri_alpha);
    cols[9][base] = BaseField::from_u32_unchecked(y_inv);
    set_qm31(cols, 10, base, f_plus); // a = fPlus
    set_qm31(cols, 14, base, f_minus); // b = fMinus
    set_qm31(cols, 18, base, combo_pos);
    set_qm31(cols, 22, base, combo_neg);
    set_qm31(cols, 26, base, comp_pos);
    set_qm31(cols, 30, base, comp_neg);
    set_qm31(cols, 34, base, pack(p0));
    set_qm31(cols, 38, base, outs[0]);
    is_step_col[base] = BaseField::from_u32_unchecked(1);

    // ── Rows `base+1..`: line folds ──────────────────────────────────────────
    for (i, &(sibling, alpha, x_inv)) in rounds.iter().enumerate() {
        let r = base + i + 1;
        debug_assert!(
            [sibling, alpha].iter().all(|&q| limbs(q).iter().all(|&l| l < M31_P))
                && (x_inv as u64) < M31_P,
            "non-canonical limb in recursive_verifier fold round",
        );
        let input = outs[i]; // chained: previous output
        let p_r = scale_limbs(sub_limbs(limbs(input), limbs(sibling)), x_inv as u64);

        set_qm31(cols, 5, r, alpha);
        cols[9][r] = BaseField::from_u32_unchecked(x_inv);
        set_qm31(cols, 10, r, input);
        set_qm31(cols, 14, r, sibling);
        set_qm31(cols, 34, r, pack(p_r));
        set_qm31(cols, 38, r, outs[i + 1]); // local output index, not global row
        // z_x / combos / comps remain 0 (is_step = 0 ⇒ unconstrained)
        chain_on_col[r] = BaseField::from_u32_unchecked(1);
    }
}

fn finalize_trace(
    mut cols: Vec<Vec<BaseField>>,
    mut is_step_col: Vec<BaseField>,
    mut chain_on_col: Vec<BaseField>,
    domain: stwo::core::poly::circle::CircleDomain,
) -> (TraceColumns, Vec<TraceCol>) {
    for col in cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    bit_reverse_coset_to_circle_domain_order(&mut is_step_col);
    bit_reverse_coset_to_circle_domain_order(&mut chain_on_col);

    let main_trace: TraceColumns = cols
        .into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect();
    let preproc: Vec<TraceCol> = vec![
        CircleEvaluation::new(domain, is_step_col),
        CircleEvaluation::new(domain, chain_on_col),
    ];
    (main_trace, preproc)
}

/// Build the main trace + preprocessed columns for one query's full FRI chain.
/// Total used rows = `1 + rounds.len()` (row 0 = OODS+circle fold; rows 1..K = line folds).
pub fn build_trace(
    step: &StepOp,
    rounds: &[FoldRound],
    log_n_rows: u32,
) -> (TraceColumns, Vec<TraceCol>) {
    let n = 1usize << log_n_rows;
    debug_assert!(1 + rounds.len() <= n, "rows exceed trace capacity");

    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];
    let mut is_step_col: Vec<BaseField> = vec![bf0; n];
    let mut chain_on_col: Vec<BaseField> = vec![bf0; n];

    fill_query_block(&mut cols, &mut is_step_col, &mut chain_on_col, 0, step, rounds);
    finalize_trace(cols, is_step_col, chain_on_col, domain)
}

/// Build a trace for N queries laid out in consecutive blocks of `1 + num_folds`
/// rows each. All queries must share the same `num_folds` (uniform block size, as
/// in VFRI11). The AIR is unchanged — the per-row `is_step` / `chain_on` selectors
/// gate every block independently.
pub fn build_trace_multi(
    queries: &[(StepOp, Vec<FoldRound>)],
    log_n_rows: u32,
) -> (TraceColumns, Vec<TraceCol>) {
    let n = 1usize << log_n_rows;
    let block = 1 + queries[0].1.len();
    debug_assert!(queries.len() * block <= n, "rows exceed trace capacity");

    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];
    let mut is_step_col: Vec<BaseField> = vec![bf0; n];
    let mut chain_on_col: Vec<BaseField> = vec![bf0; n];

    for (q, (step, rounds)) in queries.iter().enumerate() {
        fill_query_block(
            &mut cols,
            &mut is_step_col,
            &mut chain_on_col,
            q * block,
            step,
            rounds,
        );
    }
    finalize_trace(cols, is_step_col, chain_on_col, domain)
}

// ── Prove / verify roundtrip ────────────────────────────────────────────────────

/// Bind the query's public I/O `(px, final_fold_value)` into the Fiat-Shamir
/// channel after the trace commitment (codebase convention for sub-proof
/// gadgets), so the proof is cryptographically specific to one claimed final
/// fold value — the value a downstream Merkle / last-layer check consumes.
fn mix_public(channel: &mut Blake2sM31Channel, px: u32, final_value: u128) {
    let l = limbs(final_value);
    channel.mix_u32s(&[
        px,
        l[0] as u32,
        l[1] as u32,
        l[2] as u32,
        l[3] as u32,
    ]);
}

/// Prove one query's full recursive FRI verification chain.
/// Returns `(proof_bytes, log_size, final_fold_value)`.
pub fn prove_recursive_query(
    step: &StepOp,
    rounds: &[FoldRound],
) -> Result<(Vec<u8>, u32, u128), String> {
    let log_size = compute_log_size(1 + rounds.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("too many fold rounds: log_size {log_size} exceeds {MAX_LOG_SIZE}"));
    }
    let final_value = recursive_query_final(step, rounds);
    let px = step.2;
    let (main_trace, preproc) = build_trace(step, rounds, log_size);
    let proof_bytes = prove_columns(preproc, main_trace, log_size, px, final_value)?;
    Ok((proof_bytes, log_size, final_value))
}

fn prove_columns(
    preproc: Vec<TraceCol>,
    main_trace: TraceColumns,
    log_size: u32,
    px: u32,
    final_value: u128,
) -> Result<Vec<u8>, String> {
    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree = commitment_scheme.tree_builder();
    tree.extend_evals(preproc);
    tree.commit(channel);

    let mut tree = commitment_scheme.tree_builder();
    tree.extend_evals(main_trace);
    tree.commit(channel);

    mix_public(channel, px, final_value);

    let component = new_component(log_size);
    let proof =
        prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
            .map_err(|e| format!("proving error: {e:?}"))?;

    bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))
}

/// Verify a proof produced by [`prove_recursive_query`] against the claimed
/// public I/O `(px, final_value)`. A wrong `final_value` (or `px`) replays a
/// different transcript and fails verification.
pub fn verify_recursive_query(
    proof_bytes: &[u8],
    log_size: u32,
    px: u32,
    final_value: u128,
) -> Result<bool, String> {
    if !(MIN_LOG_SIZE..=MAX_LOG_SIZE).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range"));
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
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected ≥ 2 commitments, got {}",
            proof.commitments.len()
        ));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    mix_public(verifier_channel, px, final_value);

    let result = verify::<Blake2sM31MerkleChannel>(
        &[&component],
        verifier_channel,
        commitment_scheme,
        proof,
    );
    Ok(result.is_ok())
}

// ── Multi-query aggregation (N queries in one STARK) ─────────────────────────────

/// Final fold value for each query in order.
pub fn recursive_queries_final(queries: &[(StepOp, Vec<FoldRound>)]) -> Vec<u128> {
    queries
        .iter()
        .map(|(step, rounds)| recursive_query_final(step, rounds))
        .collect()
}

fn compute_log_size_multi(n_queries: usize, num_folds: usize) -> u32 {
    let used = n_queries * (1 + num_folds);
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < used.max(1) {
        log += 1;
    }
    log
}

/// Bind every query's public I/O `(px, finalFold)` into the channel, in query
/// order. Both prover and verifier replay this identically.
fn mix_public_multi(channel: &mut Blake2sM31Channel, pxs: &[u32], finals: &[u128]) {
    debug_assert_eq!(pxs.len(), finals.len());
    let mut words: Vec<u32> = Vec::with_capacity(pxs.len() * 5);
    for (i, &px) in pxs.iter().enumerate() {
        let l = limbs(finals[i]);
        words.push(px);
        words.push(l[0] as u32);
        words.push(l[1] as u32);
        words.push(l[2] as u32);
        words.push(l[3] as u32);
    }
    channel.mix_u32s(&words);
}

/// Prove N per-query FRI verification chains in a single STARK (one FRI
/// commitment). All queries must share the same `num_folds`. Returns
/// `(proof_bytes, log_size, final_fold_values)`.
pub fn prove_recursive_queries(
    queries: &[(StepOp, Vec<FoldRound>)],
) -> Result<(Vec<u8>, u32, Vec<u128>), String> {
    if queries.is_empty() {
        return Err("must have ≥ 1 query".into());
    }
    let num_folds = queries[0].1.len();
    if queries.iter().any(|(_, r)| r.len() != num_folds) {
        return Err("all queries must share the same num_folds".into());
    }
    let log_size = compute_log_size_multi(queries.len(), num_folds);
    if log_size > MAX_LOG_SIZE {
        return Err(format!("too many query/fold rows: log_size {log_size} exceeds {MAX_LOG_SIZE}"));
    }

    let finals = recursive_queries_final(queries);
    let pxs: Vec<u32> = queries.iter().map(|(s, _)| s.2).collect();
    let (main_trace, preproc) = build_trace_multi(queries, log_size);
    let proof_bytes = prove_columns_multi(preproc, main_trace, log_size, &pxs, &finals)?;
    Ok((proof_bytes, log_size, finals))
}

fn prove_columns_multi(
    preproc: Vec<TraceCol>,
    main_trace: TraceColumns,
    log_size: u32,
    pxs: &[u32],
    finals: &[u128],
) -> Result<Vec<u8>, String> {
    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree = commitment_scheme.tree_builder();
    tree.extend_evals(preproc);
    tree.commit(channel);

    let mut tree = commitment_scheme.tree_builder();
    tree.extend_evals(main_trace);
    tree.commit(channel);

    mix_public_multi(channel, pxs, finals);

    let component = new_component(log_size);
    let proof =
        prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
            .map_err(|e| format!("proving error: {e:?}"))?;

    bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))
}

/// Verify a proof from [`prove_recursive_queries`] against the claimed per-query
/// public I/O `(pxs, finals)` (same order as the proven queries).
pub fn verify_recursive_queries(
    proof_bytes: &[u8],
    log_size: u32,
    pxs: &[u32],
    finals: &[u128],
) -> Result<bool, String> {
    if !(MIN_LOG_SIZE..=MAX_LOG_SIZE).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range"));
    }
    if pxs.len() != finals.len() {
        return Err("pxs/finals length mismatch".into());
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
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected ≥ 2 commitments, got {}",
            proof.commitments.len()
        ));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    mix_public_multi(verifier_channel, pxs, finals);

    let result = verify::<Blake2sM31MerkleChannel>(
        &[&component],
        verifier_channel,
        commitment_scheme,
        proof,
    );
    Ok(result.is_ok())
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursive::fold_air::fold_ref;
    use crate::recursive::fri_fold_chain_air::{fold_chain_ref, FoldRound as ChainRound};
    use crate::recursive::oods_air::comp_value_ref;
    use crate::recursive::query_step_air::step_ref;

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
    fn sample_step(seed: &mut u64) -> StepOp {
        (
            rand_qm31(seed),
            rand_qm31(seed),
            rand_m31(seed) as u32,
            rand_qm31(seed),
            rand_qm31(seed),
            rand_qm31(seed),
            rand_qm31(seed),
            rand_m31(seed) as u32,
        )
    }
    fn sample_rounds(seed: &mut u64, k: usize) -> Vec<FoldRound> {
        (0..k)
            .map(|_| (rand_qm31(seed), rand_qm31(seed), rand_m31(seed) as u32))
            .collect()
    }

    // The unified reference must agree with the two underlying gadget references.
    #[test]
    fn test_ref_consistent_with_query_step_and_fold_chain() {
        let mut s = 0xfeed_1234u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 4);
        let (f_plus, f_minus, px, z_x, cp, cn, fri_alpha, y_inv) = step;

        let outs = recursive_query_ref(&step, &rounds);

        // Row 0 == circle fold via fold_air::fold_ref (a=fPlus, b=fMinus).
        assert_eq!(outs[0], fold_ref(f_plus, f_minus, fri_alpha, y_inv), "row 0 = circle fold");

        // Row 0 also == the fold output from query_step's step_ref.
        let (qs_comp_pos, qs_comp_neg, _p, qs_folded) =
            step_ref(f_plus, f_minus, px, z_x, cp, cn, fri_alpha, y_inv);
        assert_eq!(outs[0], qs_folded, "row 0 = query_step folded");

        // OODS consistency with oods_air::comp_value_ref (px and −px).
        let neg_px = (M31_P - px as u64) as u32;
        assert_eq!(qs_comp_pos, comp_value_ref(f_plus, px, z_x, cp));
        assert_eq!(qs_comp_neg, comp_value_ref(f_minus, neg_px, z_x, cn));

        // Rows 1..K == the line-fold chain via fri_fold_chain_air::fold_chain_ref,
        // seeded with the circle-fold output as round-0 input.
        let chain_rounds: Vec<ChainRound> = std::iter::once((outs[0], rounds[0].0, rounds[0].1, rounds[0].2))
            .chain(
                (1..rounds.len()).map(|i| (0u128 /*input derived internally*/, rounds[i].0, rounds[i].1, rounds[i].2)),
            )
            .collect();
        let chain = fold_chain_ref(&chain_rounds);
        for i in 0..rounds.len() {
            assert_eq!(outs[i + 1], chain[i], "line-fold round {i} must match fold_chain_ref");
        }
    }

    // Roundtrip: 1 fold round (2 used rows).
    #[test]
    fn test_prove_verify_1_round() {
        let mut s = 0x11u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 1);
        let (bytes, log_size, final_v) = prove_recursive_query(&step, &rounds).unwrap();
        assert!(verify_recursive_query(&bytes, log_size, step.2, final_v).unwrap());
        assert_eq!(final_v, recursive_query_final(&step, &rounds));
    }

    // Roundtrip: 4 fold rounds.
    #[test]
    fn test_prove_verify_4_rounds() {
        let mut s = 0x22u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 4);
        let (bytes, log_size, final_v) = prove_recursive_query(&step, &rounds).unwrap();
        assert!(verify_recursive_query(&bytes, log_size, step.2, final_v).unwrap());
        assert_eq!(final_v, recursive_query_final(&step, &rounds));
    }

    // Roundtrip: 6 fold rounds (production num_folds=6).
    #[test]
    fn test_prove_verify_6_rounds() {
        let mut s = 0x33u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 6);
        let (bytes, log_size, final_v) = prove_recursive_query(&step, &rounds).unwrap();
        assert!(verify_recursive_query(&bytes, log_size, step.2, final_v).unwrap());
    }

    // Rejection: a wrong claimed final fold value replays a different transcript.
    #[test]
    fn test_wrong_final_value_rejected() {
        let mut s = 0x99u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 3);
        let (bytes, log_size, final_v) = prove_recursive_query(&step, &rounds).unwrap();
        // Correct value verifies; a flipped value must not.
        assert!(verify_recursive_query(&bytes, log_size, step.2, final_v).unwrap());
        assert!(!verify_recursive_query(&bytes, log_size, step.2, final_v ^ 1)
            .unwrap_or(false));
    }

    // Rejection: tampered proof bytes.
    #[test]
    fn test_tampered_proof_rejected() {
        let mut s = 0x44u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 3);
        let (mut bytes, log_size, final_v) = prove_recursive_query(&step, &rounds).unwrap();
        let n = bytes.len();
        // Flip a load-bearing byte; a tampered proof must NOT verify
        // (either a decode error or a constraint/FRI failure → Ok(false)).
        bytes[n / 3] ^= 0xff;
        assert!(!verify_recursive_query(&bytes, log_size, step.2, final_v).unwrap_or(false));
    }

    // Rejection: corrupted circle-fold output (row 0 out column) — breaks both
    // C_f on row 0 and the chain into row 1.
    #[test]
    fn test_corrupted_row0_output_rejected() {
        let mut s = 0x55u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 2);
        let log_size = compute_log_size(1 + rounds.len());
        let (mut main_trace, preproc) = build_trace(&step, &rounds, log_size);
        {
            let col = &mut main_trace[38]; // out limb 0
            let mut vals: Vec<BaseField> = col.values.to_vec();
            vals[0] = BaseField::from_u32_unchecked(424242);
            let domain = CanonicCoset::new(log_size).circle_domain();
            *col = CircleEvaluation::new(domain, vals);
        }
        assert!(prove_columns(preproc, main_trace, log_size, step.2, recursive_query_final(&step, &rounds)).is_err());
    }

    // Rejection: corrupted compPos (OODS+ binding) on row 0.
    #[test]
    fn test_corrupted_comp_pos_rejected() {
        let mut s = 0x66u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 2);
        let log_size = compute_log_size(1 + rounds.len());
        let (mut main_trace, preproc) = build_trace(&step, &rounds, log_size);
        {
            let col = &mut main_trace[26]; // compPos limb 0
            let mut vals: Vec<BaseField> = col.values.to_vec();
            vals[0] = BaseField::from_u32_unchecked(777);
            let domain = CanonicCoset::new(log_size).circle_domain();
            *col = CircleEvaluation::new(domain, vals);
        }
        assert!(prove_columns(preproc, main_trace, log_size, step.2, recursive_query_final(&step, &rounds)).is_err());
    }

    // Rejection: broken chain — corrupt line-fold input on row 1.
    #[test]
    fn test_broken_chain_rejected() {
        let mut s = 0x77u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 2);
        let log_size = compute_log_size(1 + rounds.len());
        let (mut main_trace, preproc) = build_trace(&step, &rounds, log_size);
        {
            let col = &mut main_trace[10]; // a (input) limb 0, row 1
            let mut vals: Vec<BaseField> = col.values.to_vec();
            vals[1] = BaseField::from_u32_unchecked(999999);
            let domain = CanonicCoset::new(log_size).circle_domain();
            *col = CircleEvaluation::new(domain, vals);
        }
        assert!(prove_columns(preproc, main_trace, log_size, step.2, recursive_query_final(&step, &rounds)).is_err());
    }

    // ── Multi-query aggregation ─────────────────────────────────────────────────

    fn sample_queries(seed: &mut u64, n: usize, k: usize) -> Vec<(StepOp, Vec<FoldRound>)> {
        (0..n).map(|_| (sample_step(seed), sample_rounds(seed, k))).collect()
    }

    // N queries in one STARK; all final folds match the per-query reference.
    #[test]
    fn test_multi_query_roundtrip() {
        let mut s = 0xa11ce_u64;
        let queries = sample_queries(&mut s, 5, 4); // 5 queries × (1+4) = 25 rows
        let (bytes, log_size, finals) = prove_recursive_queries(&queries).unwrap();

        // Final folds equal each query's independent reference.
        let pxs: Vec<u32> = queries.iter().map(|(st, _)| st.2).collect();
        for (i, (st, r)) in queries.iter().enumerate() {
            assert_eq!(finals[i], recursive_query_final(st, r));
        }
        assert!(verify_recursive_queries(&bytes, log_size, &pxs, &finals).unwrap());
    }

    // A single query through the multi path matches the single-query path's output.
    #[test]
    fn test_multi_query_single_agrees() {
        let mut s = 0xb0b_u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 3);
        let (bytes, log_size, finals) =
            prove_recursive_queries(&[(step, rounds.clone())]).unwrap();
        assert_eq!(finals[0], recursive_query_final(&step, &rounds));
        assert!(verify_recursive_queries(&bytes, log_size, &[step.2], &finals).unwrap());
    }

    // Rejection: a wrong claimed final for one query fails the whole proof.
    #[test]
    fn test_multi_query_wrong_final_rejected() {
        let mut s = 0xc0c0_u64;
        let queries = sample_queries(&mut s, 4, 2);
        let (bytes, log_size, finals) = prove_recursive_queries(&queries).unwrap();
        let pxs: Vec<u32> = queries.iter().map(|(st, _)| st.2).collect();
        assert!(verify_recursive_queries(&bytes, log_size, &pxs, &finals).unwrap());

        // Flip the 3rd query's final value.
        let mut bad = finals.clone();
        bad[2] ^= 1;
        assert!(!verify_recursive_queries(&bytes, log_size, &pxs, &bad).unwrap_or(false));
    }

    // Rejection: mismatched num_folds across queries.
    #[test]
    fn test_multi_query_uneven_folds_error() {
        let mut s = 0xd1d_u64;
        let q0 = (sample_step(&mut s), sample_rounds(&mut s, 3));
        let q1 = (sample_step(&mut s), sample_rounds(&mut s, 4)); // different K
        assert!(prove_recursive_queries(&[q0, q1]).is_err());
    }

    // Error on empty query set.
    #[test]
    fn test_multi_query_empty_error() {
        assert!(prove_recursive_queries(&[]).is_err());
    }
}
