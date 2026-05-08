/// ML-DSA-65 polynomial addition AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves c[i] = (a[i] + b[i]) mod Q for all i = 0..255.
///
/// This is the accumulation primitive for the matrix-vector product Az:
///   Az[i] = Σ_{j=0}^{L-1} A_hat[i][j] ⊙ z_hat[j]
///
/// Unlike multiplication, the addition constraint is **fully sound** in M31:
/// all operands are < Q < 2^{23}, so sums stay below M31 (2^{31}−1) and there
/// is no wrap-around ambiguity — the M31 equation is equivalent to the integer
/// equation.
///
/// # Trace layout  (4 columns, N = 256 rows)
///
///   col 0  a      ∈ [0, Q)   first addend
///   col 1  b      ∈ [0, Q)   second addend
///   col 2  c      ∈ [0, Q)   sum (a + b) mod Q
///   col 3  carry  ∈ {0,1}   1 iff a + b ≥ Q
///
/// # Constraints (both degree ≤ 2, both **fully sound**)
///
///   C1  a + b − c − carry × Q = 0   [add mod Q, degree 1]
///   C2  carry² − carry = 0           [boolean,   degree 2]

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

/// log₂(N) = 8  →  256 rows.
pub const LOG_N_ROWS: u32 = 8;

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct PolyAddEval {
    pub log_n_rows: u32,
}

pub type PolyAddComponent = FrameworkComponent<PolyAddEval>;

impl FrameworkEval for PolyAddEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Max degree = 2 (C2) → quotient has 2·2^n coefficients → bound = n+1.
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        let [a]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [b]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [c]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [carry] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        // C1: a + b − c − carry × Q = 0  (fully sound in M31, degree 1)
        eval.add_constraint(a + b - c - carry.clone() * q);

        // C2: carry ∈ {0, 1}
        eval.add_constraint(carry.clone() * carry.clone() - carry);

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> PolyAddComponent {
    PolyAddComponent::new(
        &mut TraceLocationAllocator::default(),
        PolyAddEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the addition trace for `a + b` in Z_q (coefficient-wise).
///
/// Returns `(columns, sum)` where `sum[i] = (a[i] + b[i]) mod Q`.
pub fn build_trace(a: &[i64; N], b: &[i64; N]) -> (TraceColumns, [i64; N]) {
    let n     = 1_usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf_zero = BaseField::from_u32_unchecked(0);
    let bf      = |v: i64| BaseField::from_u32_unchecked(v as u32);

    let mut a_col     = vec![bf_zero; n];
    let mut b_col     = vec![bf_zero; n];
    let mut c_col     = vec![bf_zero; n];
    let mut carry_col = vec![bf_zero; n];
    let mut sum       = [0i64; N];

    for i in 0..N {
        let raw   = a[i] + b[i];
        let carry = if raw >= Q { 1i64 } else { 0i64 };
        let c_val = raw - carry * Q;
        sum[i] = c_val;

        a_col[i]     = bf(a[i]);
        b_col[i]     = bf(b[i]);
        c_col[i]     = bf(c_val);
        carry_col[i] = bf(carry);
    }

    for col in [&mut a_col, &mut b_col, &mut c_col, &mut carry_col] {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    let columns = vec![
        CircleEvaluation::new(domain, a_col),
        CircleEvaluation::new(domain, b_col),
        CircleEvaluation::new(domain, c_col),
        CircleEvaluation::new(domain, carry_col),
    ];

    (columns, sum)
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
    fn test_sum_correctness() {
        let a = random_poly(1);
        let b = random_poly(2);
        let (_, sum) = build_trace(&a, &b);
        for i in 0..N {
            assert_eq!(sum[i], (a[i] + b[i]).rem_euclid(Q), "sum[{i}]");
            assert!(sum[i] >= 0 && sum[i] < Q);
        }
    }

    #[test]
    fn test_add_zero_is_identity() {
        let a = random_poly(7);
        let z = [0i64; N];
        let (_, sum) = build_trace(&a, &z);
        assert_eq!(sum, a);
    }

    #[test]
    fn test_add_commutativity() {
        let a = random_poly(3);
        let b = random_poly(4);
        let (_, ab) = build_trace(&a, &b);
        let (_, ba) = build_trace(&b, &a);
        assert_eq!(ab, ba);
    }

    #[test]
    fn test_constraints_on_trace() {
        let a = random_poly(42);
        let b = random_poly(43);
        let (cols, _) = build_trace(&a, &b);

        let a_v:     Vec<M31> = cols[0].values.clone();
        let b_v:     Vec<M31> = cols[1].values.clone();
        let c_v:     Vec<M31> = cols[2].values.clone();
        let carry_v: Vec<M31> = cols[3].values.clone();

        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![],
            vec![&a_v, &b_v, &c_v, &carry_v],
        ]);

        let evaluator = PolyAddEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
