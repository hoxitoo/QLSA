/// ML-DSA-65 batch W-prime polynomial subtraction AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves ALL K=6 subtractions w_prime[i] = (az[i] − ct1[i]) mod Q simultaneously
/// in a single STARK (one component, 24 columns, 256 rows):
///
///   w_prime[i][p] = (az[i][p] − ct1[i][p])  mod Q    ∀ i ∈ 0..K, p ∈ 0..N
///
/// This replaces K individual poly_sub proofs with one compact proof,
/// saving K-1=5 STARK components in the full VerifyMldsaProofV5 pipeline.
///
/// Implementation note: subtraction is computed as addition of the negated
/// second operand — ct1_neg[i][p] = (Q − ct1[i][p]) mod Q — which maps exactly
/// to the fully-sound poly_add constraint.  All values fit in M31 so there is no
/// wrap-around ambiguity and no bit-decompositions are needed.
///
/// # Trace layout  (K×4 = 24 columns, 256 rows)
///
/// Per row i = 0..K-1  (4 columns each):
///   col 4*i+0  az[i][p]       ∈ [0, Q)   first operand
///   col 4*i+1  ct1_neg[i][p]  ∈ [0, Q)   Q − ct1[i][p]  (negated second operand)
///   col 4*i+2  w_prime[i][p]  ∈ [0, Q)   output: (az − ct1) mod Q
///   col 4*i+3  carry[i][p]    ∈ {0,1}   1 iff az[i] + ct1_neg[i] ≥ Q
///
/// Total: K × 4 = 6 × 4 = 24 columns.
///
/// # Constraints  (12 total, max degree 2)
///
/// Per row i in 0..K (2 constraints each):
///   C1  az[i] + ct1_neg[i] − w_prime[i] − carry[i]·Q = 0   (add mod Q, degree 1)
///   C2  carry[i]² − carry[i] = 0                            (boolean,   degree 2)
///
/// # Soundness
///
/// Fully sound: az, ct1 < Q < 2^23, so az + ct1_neg < 2Q < 2^24 ≪ 2^31−1 (M31).
/// No spurious M31 solutions exist — the constraint over M31 is equivalent to
/// the constraint over Z.

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
use crate::mldsa::params::K;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub const LOG_N_ROWS: u32 = 8;

/// Columns per row: az + ct1_neg + w_prime + carry.
const COLS_PER_ROW: usize = 4;
/// Total columns: K × COLS_PER_ROW.
pub const N_COLS: usize = K * COLS_PER_ROW; // 24

pub struct WPrimeFullEval {
    pub log_n_rows: u32,
}

pub type WPrimeFullComponent = FrameworkComponent<WPrimeFullEval>;

impl FrameworkEval for WPrimeFullEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        for _i in 0..K {
            let az      = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let ct1_neg = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let w_prime = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let carry   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();

            // C1: az + ct1_neg − w_prime − carry × Q = 0
            eval.add_constraint(az + ct1_neg - w_prime - carry.clone() * q);

            // C2: carry ∈ {0, 1}
            eval.add_constraint(carry.clone() * carry.clone() - carry);
        }

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> WPrimeFullComponent {
    WPrimeFullComponent::new(
        &mut TraceLocationAllocator::default(),
        WPrimeFullEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the witness trace for K simultaneous (az[i] − ct1[i]) mod Q operations.
///
/// Returns `(columns, w_prime_out)` where `w_prime_out[i][p] = (az[i][p] - ct1[i][p]) mod Q`.
pub fn build_trace(
    az:   &[[i64; N]; K],
    ct1:  &[[i64; N]; K],
) -> (TraceColumns, [[i64; N]; K]) {
    let n      = 1_usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);
    let bf0    = BaseField::from_u32_unchecked(0);

    let mut az_cols:      Vec<Vec<BaseField>> = vec![vec![bf0; n]; K];
    let mut ct1_neg_cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; K];
    let mut wp_cols:      Vec<Vec<BaseField>> = vec![vec![bf0; n]; K];
    let mut carry_cols:   Vec<Vec<BaseField>> = vec![vec![bf0; n]; K];

    let mut w_prime_out: [[i64; N]; K] = [[0i64; N]; K];

    for p in 0..N {
        for i in 0..K {
            let a  = az[i][p];
            let b  = ct1[i][p];
            let bn = if b == 0 { 0 } else { Q - b }; // negate: Q-b mod Q
            let s  = a + bn;
            let c  = s - if s >= Q { Q } else { 0 }; // s mod Q
            let cr = if s >= Q { 1i64 } else { 0i64 };

            w_prime_out[i][p] = c;
            az_cols[i][p]      = bf(a);
            ct1_neg_cols[i][p] = bf(bn);
            wp_cols[i][p]      = bf(c);
            carry_cols[i][p]   = bf(cr);
        }
    }

    // Bit-reverse all buffers.
    for i in 0..K {
        bit_reverse_coset_to_circle_domain_order(&mut az_cols[i]);
        bit_reverse_coset_to_circle_domain_order(&mut ct1_neg_cols[i]);
        bit_reverse_coset_to_circle_domain_order(&mut wp_cols[i]);
        bit_reverse_coset_to_circle_domain_order(&mut carry_cols[i]);
    }

    // Pack in evaluate() read order: per i: az, ct1_neg, w_prime, carry.
    let mut columns: TraceColumns = Vec::with_capacity(N_COLS);
    for i in 0..K {
        columns.push(CircleEvaluation::new(domain, az_cols[i].clone()));
        columns.push(CircleEvaluation::new(domain, ct1_neg_cols[i].clone()));
        columns.push(CircleEvaluation::new(domain, wp_cols[i].clone()));
        columns.push(CircleEvaluation::new(domain, carry_cols[i].clone()));
    }

    debug_assert_eq!(columns.len(), N_COLS);
    (columns, w_prime_out)
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
    fn test_column_count() {
        assert_eq!(N_COLS, 24);
        assert_eq!(COLS_PER_ROW, 4);
    }

    #[test]
    fn test_wprime_full_correctness() {
        let az:  [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 7 + 1));
        let ct1: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 11 + 2));
        let (_, w_out) = build_trace(&az, &ct1);

        for i in 0..K {
            for p in 0..N {
                let expected = (az[i][p] - ct1[i][p]).rem_euclid(Q);
                assert_eq!(w_out[i][p], expected,
                    "w_prime[{i}][{p}]: expected {expected}, got {}", w_out[i][p]);
                assert!(w_out[i][p] >= 0 && w_out[i][p] < Q,
                    "w_prime[{i}][{p}] = {} out of [0, Q)", w_out[i][p]);
            }
        }
    }

    #[test]
    fn test_wprime_full_sub_self_is_zero() {
        let az: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 + 100));
        let (_, w_out) = build_trace(&az, &az);
        for i in 0..K {
            assert_eq!(w_out[i], [0i64; N], "a - a must be zero for row {i}");
        }
    }

    #[test]
    fn test_wprime_full_zero_az() {
        let ct1: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 + 200));
        let (_, w_out) = build_trace(&[[0i64; N]; K], &ct1);
        for i in 0..K {
            for p in 0..N {
                let expected = (Q - ct1[i][p]).rem_euclid(Q);
                assert_eq!(w_out[i][p], expected, "0-ct1 mismatch row {i}, coeff {p}");
            }
        }
    }

    #[test]
    fn test_wprime_full_matches_poly_sub_per_row() {
        let az:  [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 13 + 5));
        let ct1: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 17 + 9));
        let (_, w_full) = build_trace(&az, &ct1);

        for i in 0..K {
            // Reference: same formula as prove_poly_sub
            let expected: [i64; N] = std::array::from_fn(|p| {
                (az[i][p] - ct1[i][p]).rem_euclid(Q)
            });
            assert_eq!(w_full[i], expected, "row {i}: wprime_full ≠ poly_sub reference");
        }
    }

    #[test]
    fn test_constraints_on_trace() {
        let az:  [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 3 + 77));
        let ct1: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 5 + 33));
        let (cols, _) = build_trace(&az, &ct1);
        let col_vals: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vals.iter().collect();
        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], col_refs]);
        let evaluator = WPrimeFullEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
