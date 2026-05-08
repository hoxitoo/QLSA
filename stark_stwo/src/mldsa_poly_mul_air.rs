/// ML-DSA-65 pointwise polynomial multiplication AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves that `c[i] = a[i] × b[i] (mod Q)` for all i = 0..255 in one trace.
///
/// This is the core operation in ML-DSA verification:
///   - `Az`   = NTT(A_row) ⊙ NTT(z)   for each row of A   (matrix-vector product)
///   - `ct₁`  = NTT(c)    ⊙ NTT(t₁)                        (challenge multiplication)
///
/// By proving the pointwise multiplication in NTT domain, combined with the NTT
/// butterfly proofs (mldsa_ntt_air), we obtain a full STARK proof of the
/// polynomial ring multiplication A·z and c·t₁ over Z_q[X]/(X^{256}+1).
///
/// # Trace layout  (4 columns, N = 256 rows)
///
///   col 0  a       ∈ [0, Q)   first operand
///   col 1  b       ∈ [0, Q)   second operand
///   col 2  c       ∈ [0, Q)   product c = a × b mod Q        (witness)
///   col 3  carry   ∈ [0, Q)   carry = ⌊a × b / Q⌋            (witness)
///
/// # Constraint (degree 2)
///
///   C1  a × b − c − carry × Q = 0   [mul mod Q, degree 2]
///
/// # Soundness note
///
/// C1 is evaluated in M31 arithmetic.  Since a × b can reach ~2^{46} and M31
/// wraps at 2^{31}−1, the M31 equation is necessary but not sufficient for the
/// integer equation.  Full soundness requires range-check arguments on all
/// columns (planned for MVP-4).  The addition/subtraction structure of the NTT
/// butterfly AIR (C2–C5) is fully sound; only multiplication constraints carry
/// this limitation.

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

/// Trace rows = N = 256 (one per NTT-domain coefficient).
pub const LOG_N_ROWS: u32 = 8; // 2^8 = 256

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct PolyMulEval {
    pub log_n_rows: u32,
}

pub type PolyMulComponent = FrameworkComponent<PolyMulEval>;

impl FrameworkEval for PolyMulEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Single degree-2 constraint → bound = n+1.
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        let [a]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [b]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [c]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [carry] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        // C1: a × b − c − carry × Q = 0  (degree 2)
        eval.add_constraint(a * b - c - carry * q);

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> PolyMulComponent {
    PolyMulComponent::new(
        &mut TraceLocationAllocator::default(),
        PolyMulEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the pointwise-multiplication trace for `a ⊙ b` in Z_q.
///
/// Both slices must be in NTT domain with coefficients in `[0, Q)`.
/// Returns `(columns, product)` where `product[i] = a[i] × b[i] mod Q`.
pub fn build_trace(a: &[i64; N], b: &[i64; N]) -> (TraceColumns, [i64; N]) {
    let n     = 1_usize << LOG_N_ROWS;  // = N = 256
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf_zero = BaseField::from_u32_unchecked(0);
    let bf      = |v: i64| BaseField::from_u32_unchecked(v as u32);

    let mut a_col     = vec![bf_zero; n];
    let mut b_col     = vec![bf_zero; n];
    let mut c_col     = vec![bf_zero; n];
    let mut carry_col = vec![bf_zero; n];
    let mut product   = [0i64; N];

    for i in 0..N {
        let prod    = a[i] * b[i];
        let c_val   = prod % Q;
        let carry_v = prod / Q;
        product[i]  = c_val;

        a_col[i]     = bf(a[i]);
        b_col[i]     = bf(b[i]);
        c_col[i]     = bf(c_val);
        carry_col[i] = bf(carry_v);
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

    (columns, product)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;
    use crate::mldsa::ntt::pointwise_mul;

    fn random_ntt_poly(seed: u64) -> [i64; N] {
        let mut state = seed;
        let mut p = [0i64; N];
        for c in p.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *c = ((state >> 33) as i64).abs() % Q;
        }
        p
    }

    #[test]
    fn test_product_matches_reference() {
        let a = random_ntt_poly(1);
        let b = random_ntt_poly(2);
        let (_, product) = build_trace(&a, &b);
        let reference = pointwise_mul(&a, &b);
        assert_eq!(product, reference);
    }

    #[test]
    fn test_product_in_range() {
        let a = random_ntt_poly(99);
        let b = random_ntt_poly(100);
        let (_, product) = build_trace(&a, &b);
        for (i, &c) in product.iter().enumerate() {
            assert!(c >= 0 && c < Q, "product[{i}] = {c} out of [0, Q)");
        }
    }

    #[test]
    fn test_zero_mul_is_zero() {
        let a = [0i64; N];
        let b = random_ntt_poly(5);
        let (_, product) = build_trace(&a, &b);
        assert_eq!(product, [0i64; N]);
    }

    #[test]
    fn test_identity_mul() {
        // Multiplying by 1 is the identity (in Z_q, the NTT of [1,0,...,0] is
        // all-1s only in specific transforms; here we test coefficient-wise).
        let a = random_ntt_poly(13);
        let ones = [1i64; N];
        let (_, product) = build_trace(&a, &ones);
        assert_eq!(product, a);
    }

    #[test]
    fn test_constraints_on_trace() {
        let a = random_ntt_poly(42);
        let b = random_ntt_poly(43);
        let (cols, _) = build_trace(&a, &b);

        let a_v:     Vec<M31> = cols[0].values.clone();
        let b_v:     Vec<M31> = cols[1].values.clone();
        let c_v:     Vec<M31> = cols[2].values.clone();
        let carry_v: Vec<M31> = cols[3].values.clone();

        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![],
            vec![&a_v, &b_v, &c_v, &carry_v],
        ]);

        let evaluator = PolyMulEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
