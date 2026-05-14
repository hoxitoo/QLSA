/// ML-DSA-65 batch UseHint AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves UseHint(hints[i], w_prime[i]) = w1_prime[i] for ALL K=6 rows
/// simultaneously in a single STARK (K×10 = 60 columns, 256 rows):
///
///   w1_prime[i][p] = UseHint(hints[i][p], w_prime[i][p])    ∀ i ∈ 0..K, p ∈ 0..N
///
/// This replaces K individual use_hint proofs with one compact proof,
/// saving K-1=5 STARK components in the full VerifyMldsaProofV7 pipeline.
///
/// # Trace layout  (K×10 = 60 columns, 256 rows)
///
/// Per output row i = 0..K-1  (10 columns each — same as UseHintEval):
///   col 10*i+0  r[i]          ∈ [0, Q)   w_prime[i] coefficient
///   col 10*i+1  h[i]          ∈ {0,1}    hint bit
///   col 10*i+2  r1[i]         ∈ [0, m)   HighBits(r[i])
///   col 10*i+3  r0_red[i]     ∈ [0, Q)   r₀ stored non-negative
///   col 10*i+4  sel_neg[i]    ∈ {0,1}    1 iff r₀ < 0
///   col 10*i+5  sel_sp[i]     ∈ {0,1}    1 iff special case
///   col 10*i+6  sel_r0pos[i]  ∈ {0,1}    1 iff h=1 AND r₀ > 0
///   col 10*i+7  carry_up[i]   ∈ {0,1}    1 iff w₁' wraps up
///   col 10*i+8  carry_dn[i]   ∈ {0,1}    1 iff w₁' wraps down
///   col 10*i+9  w1[i]         ∈ [0, m)   UseHint output
///
/// # Constraints  (K×12 = 72 total, max degree 2)
///
/// Per row i in 0..K — identical 12 constraints as UseHintEval:
///   C1–C6   boolean constraints for h, sel_neg, sel_sp, sel_r0pos, carry_up, carry_dn
///   C7–C12  decompose + UseHint logic (same as single-row version)
///
/// # Soundness note
///
/// Identical to single-row UseHintEval (partial — deferred range proofs in MVP-4).

use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

use crate::mldsa::{Q, N};
use crate::mldsa::params::{K, GAMMA2, M};
use crate::mldsa_use_hint_air::{ALPHA, decompose_val_signed};
use crate::mldsa::polyvec::use_hint_val;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub const LOG_N_ROWS: u32 = 8;

/// Columns per K-row block.
const COLS_PER_ROW: usize = 10;
/// Total columns: K × COLS_PER_ROW.
pub const N_COLS: usize = K * COLS_PER_ROW; // 60

pub struct UseHintBatchEval {
    pub log_n_rows: u32,
}

pub type UseHintBatchComponent = FrameworkComponent<UseHintBatchEval>;

impl FrameworkEval for UseHintBatchEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q_bf     = BaseField::from_u32_unchecked(Q as u32);
        let alpha_bf = BaseField::from_u32_unchecked(ALPHA as u32);
        let m_bf     = BaseField::from_u32_unchecked(M as u32);
        let m_minus1 = BaseField::from_u32_unchecked((M - 1) as u32);

        for _i in 0..K {
            let r         = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let h         = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let r1        = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let r0_red    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let sel_neg   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let sel_sp    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let sel_r0pos = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let carry_up  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let carry_dn  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let w1        = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();

            // C1–C6: boolean constraints
            eval.add_constraint(h.clone() * h.clone() - h.clone());
            eval.add_constraint(sel_neg.clone() * sel_neg.clone() - sel_neg.clone());
            eval.add_constraint(sel_sp.clone() * sel_sp.clone() - sel_sp.clone());
            eval.add_constraint(sel_r0pos.clone() * sel_r0pos.clone() - sel_r0pos.clone());
            eval.add_constraint(carry_up.clone() * carry_up.clone() - carry_up.clone());
            eval.add_constraint(carry_dn.clone() * carry_dn.clone() - carry_dn.clone());

            // C7: normal-case decompose
            let decomp = r1.clone() * alpha_bf + r0_red.clone() - sel_neg.clone() * q_bf - r.clone();
            eval.add_constraint(decomp.clone() - sel_sp.clone() * decomp);

            // C8: r1 = 0 in special case
            eval.add_constraint(sel_sp.clone() * r1.clone());

            // C9: special-case r0
            eval.add_constraint(
                sel_sp.clone() * r0_red.clone()
                    - sel_sp.clone() * r.clone()
                    - sel_sp.clone() * sel_neg.clone() * q_bf
                    + sel_sp.clone() * q_bf,
            );

            // C10: carry_up · (r1 − (m−1)) = 0
            eval.add_constraint(carry_up.clone() * r1.clone() - carry_up.clone() * m_minus1);

            // C11: carry_dn · r1 = 0
            eval.add_constraint(carry_dn.clone() * r1.clone());

            // C12: w1 − r1 − 2·h·sel_r0pos + h + carry_up·m − carry_dn·m = 0
            eval.add_constraint(
                w1.clone() - r1.clone()
                    - h.clone() * sel_r0pos.clone()
                    - h.clone() * sel_r0pos.clone()
                    + h.clone()
                    + carry_up * m_bf
                    - carry_dn * m_bf,
            );
        }

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> UseHintBatchComponent {
    UseHintBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        UseHintBatchEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the batch UseHint trace for K polynomials.
///
/// Returns `(columns, w1_out)` where `w1_out[i][p] = UseHint(hints[i][p], w_prime[i][p])`.
pub fn build_trace(
    w_prime: &[[i64; N]; K],
    hints:   &[[bool; N]; K],
) -> (TraceColumns, [[i64; N]; K]) {
    let n      = 1_usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf     = |v: i64| BaseField::from_u32_unchecked(v.rem_euclid(Q) as u32);
    let bfu    = |v: u32| BaseField::from_u32_unchecked(v);
    let bf0    = BaseField::from_u32_unchecked(0);

    // K × 10 column buffers
    let new_buf = || vec![bf0; n];
    let mut col_r:        Vec<Vec<BaseField>> = (0..K).map(|_| new_buf()).collect();
    let mut col_h:        Vec<Vec<BaseField>> = (0..K).map(|_| new_buf()).collect();
    let mut col_r1:       Vec<Vec<BaseField>> = (0..K).map(|_| new_buf()).collect();
    let mut col_r0_red:   Vec<Vec<BaseField>> = (0..K).map(|_| new_buf()).collect();
    let mut col_sel_neg:  Vec<Vec<BaseField>> = (0..K).map(|_| new_buf()).collect();
    let mut col_sel_sp:   Vec<Vec<BaseField>> = (0..K).map(|_| new_buf()).collect();
    let mut col_sel_r0pos: Vec<Vec<BaseField>> = (0..K).map(|_| new_buf()).collect();
    let mut col_carry_up: Vec<Vec<BaseField>> = (0..K).map(|_| new_buf()).collect();
    let mut col_carry_dn: Vec<Vec<BaseField>> = (0..K).map(|_| new_buf()).collect();
    let mut col_w1:       Vec<Vec<BaseField>> = (0..K).map(|_| new_buf()).collect();

    let mut w1_out: [[i64; N]; K] = [[0i64; N]; K];

    for p in 0..N {
        for i in 0..K {
            let ri = w_prime[i][p];
            let hi = hints[i][p];
            let w1_i = use_hint_val(hi, ri);
            w1_out[i][p] = w1_i;

            let (r1_i, r0_i) = decompose_val_signed(ri);
            let sel_neg_i: i64  = if r0_i < 0 { 1 } else { 0 };
            let r0_red_i: i64   = if r0_i < 0 { r0_i + Q } else { r0_i };

            let r0_adj = if ri % ALPHA > GAMMA2 { ri % ALPHA - ALPHA } else { ri % ALPHA };
            let sel_sp_i: i64   = if ri - r0_adj == Q - 1 { 1 } else { 0 };
            let sel_r0pos_i: i64 = if hi && r0_i > 0 { 1 } else { 0 };
            let carry_up_i: i64  = if hi && r0_i > 0 && r1_i == M - 1 { 1 } else { 0 };
            let carry_dn_i: i64  = if hi && r0_i <= 0 && r1_i == 0 { 1 } else { 0 };

            col_r[i][p]        = bf(ri);
            col_h[i][p]        = bfu(hi as u32);
            col_r1[i][p]       = bfu(r1_i as u32);
            col_r0_red[i][p]   = bfu(r0_red_i as u32);
            col_sel_neg[i][p]  = bfu(sel_neg_i as u32);
            col_sel_sp[i][p]   = bfu(sel_sp_i as u32);
            col_sel_r0pos[i][p] = bfu(sel_r0pos_i as u32);
            col_carry_up[i][p] = bfu(carry_up_i as u32);
            col_carry_dn[i][p] = bfu(carry_dn_i as u32);
            col_w1[i][p]       = bfu(w1_i as u32);
        }
    }

    for i in 0..K {
        for col in [
            &mut col_r[i], &mut col_h[i], &mut col_r1[i], &mut col_r0_red[i],
            &mut col_sel_neg[i], &mut col_sel_sp[i], &mut col_sel_r0pos[i],
            &mut col_carry_up[i], &mut col_carry_dn[i], &mut col_w1[i],
        ] {
            bit_reverse_coset_to_circle_domain_order(col);
        }
    }

    // Pack in evaluate() read order: per i: r, h, r1, r0_red, sel_neg, sel_sp,
    //                                       sel_r0pos, carry_up, carry_dn, w1.
    let mut columns: TraceColumns = Vec::with_capacity(N_COLS);
    for i in 0..K {
        columns.push(CircleEvaluation::new(domain, col_r[i].clone()));
        columns.push(CircleEvaluation::new(domain, col_h[i].clone()));
        columns.push(CircleEvaluation::new(domain, col_r1[i].clone()));
        columns.push(CircleEvaluation::new(domain, col_r0_red[i].clone()));
        columns.push(CircleEvaluation::new(domain, col_sel_neg[i].clone()));
        columns.push(CircleEvaluation::new(domain, col_sel_sp[i].clone()));
        columns.push(CircleEvaluation::new(domain, col_sel_r0pos[i].clone()));
        columns.push(CircleEvaluation::new(domain, col_carry_up[i].clone()));
        columns.push(CircleEvaluation::new(domain, col_carry_dn[i].clone()));
        columns.push(CircleEvaluation::new(domain, col_w1[i].clone()));
    }

    debug_assert_eq!(columns.len(), N_COLS);
    (columns, w1_out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    fn random_poly(seed: u64) -> [i64; N] {
        let mut state = seed;
        let mut p = [0i64; N];
        for c in p.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *c = ((state >> 33) as i64).abs() % Q;
        }
        p
    }

    fn random_hints(seed: u64) -> [bool; N] {
        let mut state = seed;
        let mut h = [false; N];
        for b in h.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (state >> 63) != 0;
        }
        h
    }

    #[test]
    fn test_column_count() {
        assert_eq!(N_COLS, 60);
        assert_eq!(COLS_PER_ROW, 10);
    }

    #[test]
    fn test_use_hint_batch_all_false_hints() {
        let w_prime: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 7 + 1));
        let hints: [[bool; N]; K]  = std::array::from_fn(|_| [false; N]);
        let (_, w1_out) = build_trace(&w_prime, &hints);

        for i in 0..K {
            for p in 0..N {
                let (r1, _) = decompose_val_signed(w_prime[i][p]);
                assert_eq!(w1_out[i][p], r1,
                    "no-hint w1[{i}][{p}]: expected r1={r1}, got {}", w1_out[i][p]);
            }
        }
    }

    #[test]
    fn test_use_hint_batch_correctness() {
        let w_prime: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 11 + 2));
        let hints: [[bool; N]; K]  = std::array::from_fn(|i| random_hints(i as u64 * 13 + 3));
        let (_, w1_out) = build_trace(&w_prime, &hints);

        for i in 0..K {
            for p in 0..N {
                let expected = use_hint_val(hints[i][p], w_prime[i][p]);
                assert_eq!(w1_out[i][p], expected,
                    "w1[{i}][{p}]: expected {expected}, got {}", w1_out[i][p]);
            }
        }
    }

    #[test]
    fn test_use_hint_batch_matches_single_per_row() {
        use crate::mldsa_use_hint_air;
        let w_prime: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 17 + 5));
        let hints: [[bool; N]; K]  = std::array::from_fn(|i| random_hints(i as u64 * 19 + 7));
        let (_, w1_batch) = build_trace(&w_prime, &hints);

        for i in 0..K {
            let (_, w1_single) = mldsa_use_hint_air::build_trace(&w_prime[i], &hints[i]);
            assert_eq!(w1_batch[i], w1_single, "row {i}: batch ≠ single");
        }
    }

    #[test]
    fn test_constraints_on_trace() {
        let w_prime: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 3 + 77));
        let hints: [[bool; N]; K]  = std::array::from_fn(|i| random_hints(i as u64 * 5 + 33));
        let (cols, _) = build_trace(&w_prime, &hints);
        let col_vals: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vals.iter().collect();
        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], col_refs]);
        let evaluator = UseHintBatchEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
