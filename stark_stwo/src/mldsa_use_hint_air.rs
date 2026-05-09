/// ML-DSA-65 UseHint AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves UseHint(h[i], r[i]) = w₁'[i] for all 256 coefficients of one polynomial.
/// The Decompose(r) step is proved inline — no separate AIR needed.
///
/// # Algorithm (FIPS 204 §2.5, Algorithms 35 and 37)
///
///   Decompose(r, 2γ₂) → (r₁, r₀):
///     r₀ = r mod± 2γ₂   (centered: r₀ ∈ (−γ₂, γ₂])
///     r₁ = (r − r₀) / 2γ₂   (with special case at r = q−1 → r₁ = 0, r₀ -= 1)
///
///   UseHint(h, r) → r₁':
///     if h = 0:       r₁' = r₁
///     if h = 1, r₀>0: r₁' = (r₁ + 1) mod m
///     if h = 1, r₀≤0: r₁' = (r₁ − 1 + m) mod m
///   where m = (q−1)/(2γ₂) = 16 for ML-DSA-65.
///
/// # Trace layout  (10 columns, N = 256 rows)
///
///   col 0  r          ∈ [0, Q)      input coefficient w'[i]
///   col 1  h          ∈ {0,1}       hint bit
///   col 2  r1         ∈ [0, m)      HighBits(r) = r₁
///   col 3  r0_red     ∈ [0, Q)      r₀ stored non-neg: r₀+Q if r₀<0, else r₀
///   col 4  sel_neg    ∈ {0,1}       1 iff r₀ < 0 (i.e. r0_red = r₀+Q)
///   col 5  sel_sp     ∈ {0,1}       1 iff special case (r−r₀_orig = Q−1)
///   col 6  sel_r0pos  ∈ {0,1}       1 iff h=1 AND r₀ > 0
///   col 7  carry_up   ∈ {0,1}       1 iff w₁' wraps up: r1=m−1, h=1, r0>0
///   col 8  carry_dn   ∈ {0,1}       1 iff w₁' wraps down: r1=0, h=1, r0≤0
///   col 9  w1         ∈ [0, m)      UseHint output w₁'[i]
///
/// # Constraints  (all degree ≤ 2)
///
///   C1   h² − h = 0
///   C2   sel_neg² − sel_neg = 0
///   C3   sel_sp² − sel_sp = 0
///   C4   sel_r0pos² − sel_r0pos = 0
///   C5   carry_up² − carry_up = 0
///   C6   carry_dn² − carry_dn = 0
///   C7   (1−sel_sp)·(r1·α + r0_red − sel_neg·Q − r) = 0
///   C8   sel_sp·r1 = 0
///   C9   sel_sp·(r0_red − r − sel_neg·Q + Q) = 0
///   C10  carry_up·(r1 − (m−1)) = 0
///   C11  carry_dn·r1 = 0
///   C12  w1 − r1 − 2·h·sel_r0pos + h + carry_up·m − carry_dn·m = 0
///
/// # Partial soundness note (MVP-3+)
///
/// Constraints C1–C12 ensure computational consistency for an honest prover.
/// The *direction* of sel_r0pos (r₀>0 vs r₀≤0) and the ranges r₁∈[0,m),
/// w₁'∈[0,m), r₀∈(−γ₂,γ₂] are NOT enforced without range-proof arguments
/// — these are deferred to MVP-4.

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
use crate::mldsa::params::{GAMMA2, M};
use crate::mldsa::polyvec::use_hint_val;

// ── Constants ─────────────────────────────────────────────────────────────────

/// 2γ₂ — the Decompose modulus.
pub const ALPHA: i64 = 2 * GAMMA2;

/// log₂(N) = 8  →  256 rows.
pub const LOG_N_ROWS: u32 = 8;

// ── Type aliases ─────────────────────────────────────────────────────────────

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct UseHintEval {
    pub log_n_rows: u32,
}

pub type UseHintComponent = FrameworkComponent<UseHintEval>;

impl FrameworkEval for UseHintEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q_bf     = BaseField::from_u32_unchecked(Q as u32);
        let alpha_bf = BaseField::from_u32_unchecked(ALPHA as u32);
        let m_bf     = BaseField::from_u32_unchecked(M as u32);

        let [r]         = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [h]         = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [r1]        = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [r0_red]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [sel_neg]   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [sel_sp]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [sel_r0pos] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [carry_up]  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [carry_dn]  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [w1]        = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        // C1–C6: boolean constraints
        eval.add_constraint(h.clone() * h.clone() - h.clone());
        eval.add_constraint(sel_neg.clone() * sel_neg.clone() - sel_neg.clone());
        eval.add_constraint(sel_sp.clone() * sel_sp.clone() - sel_sp.clone());
        eval.add_constraint(sel_r0pos.clone() * sel_r0pos.clone() - sel_r0pos.clone());
        eval.add_constraint(carry_up.clone() * carry_up.clone() - carry_up.clone());
        eval.add_constraint(carry_dn.clone() * carry_dn.clone() - carry_dn.clone());

        // C7: normal-case decompose: (1−sel_sp)·(r1·α + r0_red − sel_neg·Q − r) = 0
        let decomp = r1.clone() * alpha_bf + r0_red.clone() - sel_neg.clone() * q_bf - r.clone();
        eval.add_constraint(decomp.clone() - sel_sp.clone() * decomp);

        // C8: r1 = 0 in special case
        eval.add_constraint(sel_sp.clone() * r1.clone());

        // C9: special-case r0: sel_sp·(r0_red − r − sel_neg·Q + Q) = 0
        // Derivation: special case gives r0_final = r − Q, and r0_red = r0_final + sel_neg·Q,
        // so r0_red − r − sel_neg·Q + Q = 0.  Distribute sel_sp to avoid E::F ± BaseField.
        eval.add_constraint(
            sel_sp.clone() * r0_red.clone()
                - sel_sp.clone() * r.clone()
                - sel_sp.clone() * sel_neg.clone() * q_bf
                + sel_sp.clone() * q_bf,
        );

        // C10: carry_up·r1 − carry_up·(m−1) = 0
        // Distribute to avoid E::F - BaseField.
        let m_minus1 = BaseField::from_u32_unchecked((M - 1) as u32);
        eval.add_constraint(carry_up.clone() * r1.clone() - carry_up.clone() * m_minus1);

        // C11: carry_dn·r1 = 0
        eval.add_constraint(carry_dn.clone() * r1.clone());

        // C12: w1 − r1 − 2·h·sel_r0pos + h + carry_up·m − carry_dn·m = 0
        // Use (h·sel_r0pos + h·sel_r0pos) to avoid BaseField * E::F type issue.
        eval.add_constraint(
            w1.clone() - r1.clone()
                - h.clone() * sel_r0pos.clone()
                - h.clone() * sel_r0pos.clone()
                + h.clone()
                + carry_up * m_bf
                - carry_dn * m_bf,
        );

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> UseHintComponent {
    UseHintComponent::new(
        &mut TraceLocationAllocator::default(),
        UseHintEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the UseHint trace for one polynomial.
///
/// `r`  — w' coefficients in `[0, Q)` (INTT output).
/// `h`  — N hint bits (one per coefficient).
///
/// Returns `(columns, w1_poly)` where `w1_poly[i] = UseHint(h[i], r[i])`.
pub fn build_trace(r: &[i64; N], h_bits: &[bool; N]) -> (TraceColumns, [i64; N]) {
    let n      = 1_usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf     = |v: i64| BaseField::from_u32_unchecked(v.rem_euclid(Q) as u32);
    let bfu    = |v: u32| BaseField::from_u32_unchecked(v);
    let bf0    = BaseField::from_u32_unchecked(0);

    let mut col_r        = vec![bf0; n];
    let mut col_h        = vec![bf0; n];
    let mut col_r1       = vec![bf0; n];
    let mut col_r0_red   = vec![bf0; n];
    let mut col_sel_neg  = vec![bf0; n];
    let mut col_sel_sp   = vec![bf0; n];
    let mut col_sel_r0pos = vec![bf0; n];
    let mut col_carry_up = vec![bf0; n];
    let mut col_carry_dn = vec![bf0; n];
    let mut col_w1       = vec![bf0; n];
    let mut w1_out       = [0i64; N];

    for i in 0..N {
        let ri    = r[i];
        let hi    = h_bits[i];
        let w1_i  = use_hint_val(hi, ri);
        w1_out[i] = w1_i;

        // Decompose ri.
        let (r1_i, r0_i) = decompose_val_signed(ri);

        // r0_red: store r₀ as non-negative.
        let sel_neg_i: i64 = if r0_i < 0 { 1 } else { 0 };
        let r0_red_i: i64  = if r0_i < 0 { r0_i + Q } else { r0_i };

        // Special case: r − r₀_orig = Q−1 (but after adjustment in decompose).
        // The special case triggers when the *adjusted* r0 (before −1 correction)
        // would make r − r0_adj = Q−1. We detect it as r1_i=0 AND ri≥ALPHA (meaning
        // it wasn't just a small r).  Equivalently: check the FIPS 204 condition directly.
        let r0_adj = if ri % ALPHA > GAMMA2 { ri % ALPHA - ALPHA } else { ri % ALPHA };
        let sel_sp_i: i64 = if ri - r0_adj == Q - 1 { 1 } else { 0 };

        // sel_r0pos: h=1 AND r₀ > 0.
        let sel_r0pos_i: i64 = if hi && r0_i > 0 { 1 } else { 0 };

        // Carry flags.
        let carry_up_i: i64 = if hi && r0_i > 0 && r1_i == M - 1 { 1 } else { 0 };
        let carry_dn_i: i64 = if hi && r0_i <= 0 && r1_i == 0 { 1 } else { 0 };

        col_r[i]         = bf(ri);
        col_h[i]         = bfu(hi as u32);
        col_r1[i]        = bfu(r1_i as u32);
        col_r0_red[i]    = bfu(r0_red_i as u32);
        col_sel_neg[i]   = bfu(sel_neg_i as u32);
        col_sel_sp[i]    = bfu(sel_sp_i as u32);
        col_sel_r0pos[i] = bfu(sel_r0pos_i as u32);
        col_carry_up[i]  = bfu(carry_up_i as u32);
        col_carry_dn[i]  = bfu(carry_dn_i as u32);
        col_w1[i]        = bfu(w1_i as u32);
    }

    for col in [
        &mut col_r, &mut col_h, &mut col_r1, &mut col_r0_red,
        &mut col_sel_neg, &mut col_sel_sp, &mut col_sel_r0pos,
        &mut col_carry_up, &mut col_carry_dn, &mut col_w1,
    ] {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    let columns = vec![
        CircleEvaluation::new(domain, col_r),
        CircleEvaluation::new(domain, col_h),
        CircleEvaluation::new(domain, col_r1),
        CircleEvaluation::new(domain, col_r0_red),
        CircleEvaluation::new(domain, col_sel_neg),
        CircleEvaluation::new(domain, col_sel_sp),
        CircleEvaluation::new(domain, col_sel_r0pos),
        CircleEvaluation::new(domain, col_carry_up),
        CircleEvaluation::new(domain, col_carry_dn),
        CircleEvaluation::new(domain, col_w1),
    ];

    (columns, w1_out)
}

// ── Internal helper: decompose with signed r₀ ────────────────────────────────

pub(crate) fn decompose_val_signed(r: i64) -> (i64, i64) {
    use crate::mldsa::field;
    let r = field::reduce(r);
    let r0 = {
        let rem = r % ALPHA;
        if rem > GAMMA2 { rem - ALPHA } else { rem }
    };
    let (r1, r0_final) = if r - r0 == Q - 1 {
        (0i64, r0 - 1)
    } else {
        ((r - r0) / ALPHA, r0)
    };
    (r1, r0_final)
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
    fn test_use_hint_no_hint_is_high_bits() {
        let r = random_poly(10);
        let h = [false; N];
        let (_, w1) = build_trace(&r, &h);
        for i in 0..N {
            let (r1, _) = decompose_val_signed(r[i]);
            assert_eq!(w1[i], r1, "no-hint w1[{i}]");
        }
    }

    #[test]
    fn test_use_hint_output_matches_reference() {
        let r = random_poly(20);
        let h = random_hints(21);
        let (_, w1) = build_trace(&r, &h);
        for i in 0..N {
            let expected = use_hint_val(h[i], r[i]);
            assert_eq!(w1[i], expected, "w1[{i}]: h={} r={}", h[i], r[i]);
        }
    }

    #[test]
    fn test_use_hint_output_in_range() {
        let r = random_poly(30);
        let h = random_hints(31);
        let (_, w1) = build_trace(&r, &h);
        for i in 0..N {
            assert!(w1[i] >= 0 && w1[i] < M, "w1[{i}]={} out of [0,M)", w1[i]);
        }
    }

    #[test]
    fn test_special_case_q_minus_1() {
        // r = Q-1 is the canonical "special case" for decompose.
        let mut r = [0i64; N];
        r[0] = Q - 1;
        r[1] = Q - 2;
        let h = [true; N];
        let (_, w1) = build_trace(&r, &h);
        // r=Q-1: decompose gives (r1=0, r0=-1). UseHint(true, Q-1): r0=-1≤0 → w1=(0-1+M)%M=M-1.
        assert_eq!(w1[0], M - 1, "special case Q-1 with hint");
        // r=Q-2: decompose normal, r0 = (Q-2)%alpha = some value.
        assert_eq!(w1[1], use_hint_val(true, Q - 2));
    }

    #[test]
    fn test_constraints_on_trace() {
        let r = random_poly(42);
        let h = random_hints(43);
        let (cols, _) = build_trace(&r, &h);

        let vecs: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let refs: Vec<&Vec<M31>> = vecs.iter().collect();

        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![],
            refs,
        ]);

        let evaluator = UseHintEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
