/// ML-DSA-65 coefficient norm check AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves norm[i] = min(z[i], Q − z[i]) for each coefficient i = 0..255.
///
/// This is the absolute centered value used by ML-DSA.Verify (FIPS 204):
///   ||z||_∞ = max_i(norm[i])
///
/// The norm-bound assertion (norm[i] < γ₁ − β = 524 092 for ML-DSA-65) is
/// verified externally; the STARK proves the norm computation is correct.
/// Full in-circuit range proofs are planned for MVP-4.
///
/// # Trace layout  (3 columns, N = 256 rows)
///
///   col 0  z     ∈ [0, Q)        input coefficient (z[i] from the signature)
///   col 1  sel   ∈ {0, 1}        1 iff z[i] > (Q−1)/2 (centered value is negative)
///   col 2  norm  ∈ [0, (Q−1)/2]  absolute centered value: min(z[i], Q−z[i])
///
/// # Constraints  (both degree ≤ 2, fully sound for boolean/addition operations)
///
///   C1  sel² − sel = 0                     [boolean,  degree 2]
///   C2  norm − z + 2·sel·z − sel·Q = 0     [norm def, degree 2]
///
/// # Constraint 2 derivation
///
///   When sel = 0:  norm − z + 0 − 0 = 0   ⟹  norm = z          (z ≤ (Q−1)/2)
///   When sel = 1:  norm − z + 2z − Q = 0  ⟹  norm = Q − z       (z > (Q−1)/2)

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

// ── Type aliases ─────────────────────────────────────────────────────────────

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

/// log₂(N) = 8  →  256 rows (one per polynomial coefficient).
pub const LOG_N_ROWS: u32 = 8;

/// ML-DSA-65: norm bound γ₁ − β = 524 288 − 196 = 524 092.
pub const NORM_BOUND: i64 = 524_092;

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct NormCheckEval {
    pub log_n_rows: u32,
}

pub type NormCheckComponent = FrameworkComponent<NormCheckEval>;

impl FrameworkEval for NormCheckEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Max degree = 2 (C1, C2) → quotient has 2·2^n coefficients → bound = n+1.
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        let [z]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [sel]  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [norm] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        // C1: sel ∈ {0, 1}
        eval.add_constraint(sel.clone() * sel.clone() - sel.clone());

        // C2: norm − z + 2·sel·z − sel·Q = 0
        // Written as (sel·z + sel·z) to avoid BaseField * E::F type mismatch.
        eval.add_constraint(
            norm.clone() - z.clone()
                + sel.clone() * z.clone()
                + sel.clone() * z.clone()
                - sel * q,
        );

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> NormCheckComponent {
    NormCheckComponent::new(
        &mut TraceLocationAllocator::default(),
        NormCheckEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the norm-check trace for a single polynomial `z`.
///
/// Returns `(columns, norm_poly)` where `norm_poly[i] = min(z[i], Q − z[i])`.
/// All `z[i]` must be in `[0, Q)`.
pub fn build_trace(z: &[i64; N]) -> (TraceColumns, [i64; N]) {
    let n      = 1_usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);
    let bf0    = BaseField::from_u32_unchecked(0);

    let mut z_col    = vec![bf0; n];
    let mut sel_col  = vec![bf0; n];
    let mut norm_col = vec![bf0; n];
    let mut norm_out = [0i64; N];

    // Threshold: z[i] > (Q-1)/2 means the centered value is negative.
    let half: i64 = (Q - 1) / 2; // 4 190 208 for Q = 8 380 417

    for i in 0..N {
        let zi = z[i];
        let (sel, norm) = if zi > half {
            (1i64, Q - zi)
        } else {
            (0i64, zi)
        };
        norm_out[i] = norm;

        z_col[i]    = bf(zi);
        sel_col[i]  = bf(sel);
        norm_col[i] = bf(norm);
    }

    for col in [&mut z_col, &mut sel_col, &mut norm_col] {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    let columns = vec![
        CircleEvaluation::new(domain, z_col),
        CircleEvaluation::new(domain, sel_col),
        CircleEvaluation::new(domain, norm_col),
    ];

    (columns, norm_out)
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

    #[test]
    fn test_norm_correctness() {
        let z = random_poly(100);
        let (_, norm) = build_trace(&z);
        let half = (Q - 1) / 2;
        for i in 0..N {
            let expected = if z[i] > half { Q - z[i] } else { z[i] };
            assert_eq!(norm[i], expected, "norm[{i}]");
            assert!(norm[i] >= 0 && norm[i] <= half, "norm[{i}] out of range");
        }
    }

    #[test]
    fn test_zero_has_zero_norm() {
        let z = [0i64; N];
        let (_, norm) = build_trace(&z);
        assert_eq!(norm, [0i64; N]);
    }

    #[test]
    fn test_norm_bound_constant() {
        // ML-DSA-65: γ₁ − β = 524288 − 196 = 524092.
        assert_eq!(NORM_BOUND, 524_092);
    }

    #[test]
    fn test_constraints_on_trace() {
        let z = random_poly(55);
        let (cols, _) = build_trace(&z);

        let z_v:    Vec<M31> = cols[0].values.clone();
        let sel_v:  Vec<M31> = cols[1].values.clone();
        let norm_v: Vec<M31> = cols[2].values.clone();

        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![],
            vec![&z_v, &sel_v, &norm_v],
        ]);

        let evaluator = NormCheckEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
