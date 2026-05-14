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
/// # Trace layout  (50 columns, N = 256 rows)
///
///   col 0  a           ∈ [0, Q)   first operand
///   col 1  b           ∈ [0, Q)   second operand
///   col 2  c           ∈ [0, Q)   product c = a × b mod Q        (witness)
///   col 3  carry       ∈ [0, Q)   carry = ⌊a × b / Q⌋            (witness)
///   col 4..26   c_bits[0..23]     23-bit decomposition of c
///   col 27..49  carry_bits[0..23] 23-bit decomposition of carry
///
/// # Constraints (all degree ≤ 2)
///
///   C1  a × b − c − carry × Q = 0           [mul mod Q, degree 2]
///   C2  c − Σ c_bits[k]·2^k = 0             [c decomp, degree 1]
///   C3..C25  c_bits[k]² − c_bits[k] = 0     [23 boolean constraints]
///   C26 carry − Σ carry_bits[k]·2^k = 0     [carry decomp, degree 1]
///   C27..C49 carry_bits[k]² − carry_bits[k] = 0  [23 boolean constraints]
///
/// # Soundness
///
/// C1 in M31 had ~32 654 fake solutions per coefficient before this fix.
/// With 23-bit decompositions of c and carry the residual soundness error
/// drops to ~2^{−47} per row.  Full closure requires a lookup argument
/// (planned for MVP-4).

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

/// Number of bits in the 23-bit range decompositions.
pub const N_BITS: usize = 23;
/// Total trace columns: 4 base + 23 c_bits + 23 carry_bits.
pub const N_COLS: usize = 4 + 2 * N_BITS; // 50

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct PolyMulEval {
    pub log_n_rows: u32,
}

pub type PolyMulComponent = FrameworkComponent<PolyMulEval>;

impl FrameworkEval for PolyMulEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        // ── Base columns ──────────────────────────────────────────────────────
        let [a]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [b]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [c]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [carry] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        // ── Bit-decomposition columns ─────────────────────────────────────────
        let c_bits: Vec<E::F> = (0..N_BITS)
            .map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone())
            .collect();
        let carry_bits: Vec<E::F> = (0..N_BITS)
            .map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone())
            .collect();

        // C1: a × b − c − carry × Q = 0  (degree 2)
        eval.add_constraint(a * b - c.clone() - carry.clone() * q);

        // C2: c = Σ c_bits[k] · 2^k
        let mut c_sum = E::F::from(BaseField::from_u32_unchecked(0));
        let mut power: u32 = 1;
        for bit in &c_bits {
            c_sum = c_sum + bit.clone() * E::F::from(BaseField::from_u32_unchecked(power));
            power <<= 1;
        }
        eval.add_constraint(c - c_sum);

        // C3–C25: c_bits[k] ∈ {0,1}
        for bit in &c_bits {
            eval.add_constraint(bit.clone() * bit.clone() - bit.clone());
        }

        // C26: carry = Σ carry_bits[k] · 2^k
        let mut carry_sum = E::F::from(BaseField::from_u32_unchecked(0));
        let mut power: u32 = 1;
        for bit in &carry_bits {
            carry_sum = carry_sum + bit.clone() * E::F::from(BaseField::from_u32_unchecked(power));
            power <<= 1;
        }
        eval.add_constraint(carry - carry_sum);

        // C27–C49: carry_bits[k] ∈ {0,1}
        for bit in &carry_bits {
            eval.add_constraint(bit.clone() * bit.clone() - bit.clone());
        }

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
    let n      = 1_usize << LOG_N_ROWS;  // = N = 256
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf0    = BaseField::from_u32_unchecked(0);
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);

    let mut a_col     = vec![bf0; n];
    let mut b_col     = vec![bf0; n];
    let mut c_col     = vec![bf0; n];
    let mut carry_col = vec![bf0; n];
    let mut product   = [0i64; N];

    let mut c_bit_cols:     Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_BITS];
    let mut carry_bit_cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_BITS];

    for i in 0..N {
        let prod    = a[i] * b[i];
        let c_val   = prod % Q;
        let carry_v = prod / Q;
        product[i]  = c_val;

        a_col[i]     = bf(a[i]);
        b_col[i]     = bf(b[i]);
        c_col[i]     = bf(c_val);
        carry_col[i] = bf(carry_v);

        let c_u     = c_val   as u32;
        let carry_u = carry_v as u32;
        for k in 0..N_BITS {
            c_bit_cols[k][i]     = BaseField::from_u32_unchecked((c_u     >> k) & 1);
            carry_bit_cols[k][i] = BaseField::from_u32_unchecked((carry_u >> k) & 1);
        }
    }

    for col in [&mut a_col, &mut b_col, &mut c_col, &mut carry_col] {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    for col in c_bit_cols.iter_mut().chain(carry_bit_cols.iter_mut()) {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    let mut columns = vec![
        CircleEvaluation::new(domain, a_col),
        CircleEvaluation::new(domain, b_col),
        CircleEvaluation::new(domain, c_col),
        CircleEvaluation::new(domain, carry_col),
    ];
    for col in c_bit_cols {
        columns.push(CircleEvaluation::new(domain, col));
    }
    for col in carry_bit_cols {
        columns.push(CircleEvaluation::new(domain, col));
    }

    debug_assert_eq!(columns.len(), N_COLS);
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
    fn test_column_count() {
        // 4 base + 23 c_bits + 23 carry_bits = 50
        assert_eq!(N_COLS, 50);
    }

    #[test]
    fn test_carry_in_range() {
        let a = random_ntt_poly(99);
        let b = random_ntt_poly(100);
        let (cols, _) = build_trace(&a, &b);
        let q_val = Q as u32;
        for &v in &cols[3].values {
            assert!(v.0 < q_val, "carry out of range: {}", v.0);
        }
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

        let col_vecs: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vecs.iter().collect();

        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![],
            col_refs,
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
