/// ML-DSA-65 full c·t₁ batch product AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves ALL K=6 products ct1_hat[i] = c_hat × t1_hat[i] simultaneously
/// in a single STARK (one component, 295 columns, 256 rows):
///
///   ct1_hat[i][p] = c_hat[p] × t1_hat[i][p]   mod Q    ∀ i ∈ 0..K, p ∈ 0..N
///
/// This replaces K individual PolyMul sub-proofs with one compact proof,
/// saving (K-1) STARK components in the full VerifyMldsaProofV4 pipeline.
///
/// # Trace layout  (295 columns, 256 rows)
///
/// Shared input (1 column):
///   col 0     c_hat[p]        ∈ [0, Q)   shared challenge polynomial
///
/// Per output row i = 0..K-1  (49 columns each):
///   col 1+i*49+ 0      t1_hat[i][p]  ∈ [0, Q)   input: hint polynomial
///   col 1+i*49+ 1      ct1[i][p]     ∈ [0, Q)   output: product mod Q
///   col 1+i*49+ 2      carry[i][p]   ∈ [0, Q)   carry = c·t1 / Q
///   col 1+i*49+ 3..25  ct1_bits[i][k] ∈ {0,1}   23-bit decomp of ct1
///   col 1+i*49+26..48  carry_bits[i][k] ∈ {0,1} 23-bit decomp of carry
///
/// Total: 1 + K×49 = 1 + 6×49 = 295 columns.
///
/// # Constraints  (294 total, max degree 2)
///
/// Per row i in 0..K (49 constraints each):
///   C1      c_hat × t1_hat[i] − ct1[i] − carry[i]·Q = 0   (mul mod Q)
///   C2      ct1[i] − Σ ct1_bits[i][k]·2^k = 0              (decomposition)
///   C3–C25  ct1_bits[i][k]² − ct1_bits[i][k] = 0           (23 booleans)
///   C26     carry[i] − Σ carry_bits[i][k]·2^k = 0          (decomposition)
///   C27–C49 carry_bits[i][k]² − carry_bits[i][k] = 0       (23 booleans)
///
/// # Soundness
///
/// Same residual ~2^{-47} per multiplication as the Az-full AIR.
/// Full closure requires lookup arguments (planned for MVP-4).

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

/// Bits per 23-bit range decomposition (same as Az-full).
pub const N_BITS: usize = 23;
/// Columns per K-row block: t1 + ct1 + carry + N_BITS ct1-bits + N_BITS carry-bits.
const COLS_PER_ROW: usize = 1 + 1 + 1 + N_BITS + N_BITS; // 49
/// Total columns: 1 shared c_hat + K × COLS_PER_ROW.
pub const N_COLS: usize = 1 + K * COLS_PER_ROW; // 295

pub struct Ct1FullEval {
    pub log_n_rows: u32,
}

pub type Ct1FullComponent = FrameworkComponent<Ct1FullEval>;

impl FrameworkEval for Ct1FullEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q  = BaseField::from_u32_unchecked(Q as u32);
        let bf = |v: u32| E::F::from(BaseField::from_u32_unchecked(v));

        // Shared c_hat column (1 col)
        let c_hat = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();

        for _i in 0..K {
            // Per-row columns: t1, ct1, carry
            let t1    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let ct1   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let carry = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();

            // Bit decomposition columns
            let ct1_bits: [E::F; 23] = std::array::from_fn(|_|
                eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
            );
            let carry_bits: [E::F; 23] = std::array::from_fn(|_|
                eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
            );

            // C1: c_hat × t1 = ct1 + carry × Q
            eval.add_constraint(
                c_hat.clone() * t1 - ct1.clone() - carry.clone() * q
            );

            // C2: ct1 decomposition; C3–C25: boolean bits
            {
                let mut sum = bf(0);
                let mut pw: u32 = 1;
                for k in 0..N_BITS {
                    sum = sum + ct1_bits[k].clone() * bf(pw);
                    pw <<= 1;
                }
                eval.add_constraint(ct1.clone() - sum);
                for k in 0..N_BITS {
                    let b = ct1_bits[k].clone();
                    eval.add_constraint(b.clone() * b - ct1_bits[k].clone());
                }
            }

            // C26: carry decomposition; C27–C49: boolean bits
            {
                let mut sum = bf(0);
                let mut pw: u32 = 1;
                for k in 0..N_BITS {
                    sum = sum + carry_bits[k].clone() * bf(pw);
                    pw <<= 1;
                }
                eval.add_constraint(carry.clone() - sum);
                for k in 0..N_BITS {
                    let b = carry_bits[k].clone();
                    eval.add_constraint(b.clone() * b - carry_bits[k].clone());
                }
            }
        }

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> Ct1FullComponent {
    Ct1FullComponent::new(
        &mut TraceLocationAllocator::default(),
        Ct1FullEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the witness trace for K simultaneous c·t₁[i] products.
///
/// Returns `(columns, ct1_out)` where `ct1_out[i][p] = c_hat[p] × t1_hat[i][p] mod Q`.
pub fn build_trace(
    c_hat:  &[i64; N],
    t1_hat: &[[i64; N]; K],
) -> (TraceColumns, [[i64; N]; K]) {
    let n      = 1_usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);
    let bf0    = BaseField::from_u32_unchecked(0);

    // Column buffers: 1 shared + K × COLS_PER_ROW
    let mut c_col:        Vec<BaseField>                = vec![bf0; n];
    let mut t1_cols:      Vec<Vec<BaseField>>           = vec![vec![bf0; n]; K];
    let mut ct1_cols:     Vec<Vec<BaseField>>           = vec![vec![bf0; n]; K];
    let mut carry_cols:   Vec<Vec<BaseField>>           = vec![vec![bf0; n]; K];
    let mut ct1_bit_cols: Vec<[Vec<BaseField>; N_BITS]> =
        (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();
    let mut carry_bit_cols: Vec<[Vec<BaseField>; N_BITS]> =
        (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();

    let mut ct1_out: [[i64; N]; K] = [[0i64; N]; K];

    for p in 0..N {
        let cv = c_hat[p];
        c_col[p] = bf(cv);

        for i in 0..K {
            let tv  = t1_hat[i][p];
            let raw = cv * tv;
            let r   = raw.rem_euclid(Q);
            let cr  = raw.div_euclid(Q);

            ct1_out[i][p]  = r;
            t1_cols[i][p]  = bf(tv);
            ct1_cols[i][p] = bf(r);
            carry_cols[i][p] = bf(cr);

            let ru  = r  as u32;
            let cru = cr as u32;
            for k in 0..N_BITS {
                ct1_bit_cols[i][k][p]   = BaseField::from_u32_unchecked((ru  >> k) & 1);
                carry_bit_cols[i][k][p] = BaseField::from_u32_unchecked((cru >> k) & 1);
            }
        }
    }

    // Bit-reverse all buffers (Circle STARK ordering).
    bit_reverse_coset_to_circle_domain_order(&mut c_col);
    for i in 0..K {
        bit_reverse_coset_to_circle_domain_order(&mut t1_cols[i]);
        bit_reverse_coset_to_circle_domain_order(&mut ct1_cols[i]);
        bit_reverse_coset_to_circle_domain_order(&mut carry_cols[i]);
        for k in 0..N_BITS {
            bit_reverse_coset_to_circle_domain_order(&mut ct1_bit_cols[i][k]);
            bit_reverse_coset_to_circle_domain_order(&mut carry_bit_cols[i][k]);
        }
    }

    // Pack in evaluate() read order:
    //   c_hat, then per i: t1[i], ct1[i], carry[i],
    //                      ct1_bits[i][0..N_BITS], carry_bits[i][0..N_BITS]
    let mut columns: TraceColumns = Vec::with_capacity(N_COLS);
    columns.push(CircleEvaluation::new(domain, c_col));
    for i in 0..K {
        columns.push(CircleEvaluation::new(domain, t1_cols[i].clone()));
        columns.push(CircleEvaluation::new(domain, ct1_cols[i].clone()));
        columns.push(CircleEvaluation::new(domain, carry_cols[i].clone()));
        for k in 0..N_BITS {
            columns.push(CircleEvaluation::new(domain, ct1_bit_cols[i][k].clone()));
        }
        for k in 0..N_BITS {
            columns.push(CircleEvaluation::new(domain, carry_bit_cols[i][k].clone()));
        }
    }

    debug_assert_eq!(columns.len(), N_COLS);
    (columns, ct1_out)
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
        assert_eq!(N_COLS, 295);
        assert_eq!(COLS_PER_ROW, 49);
    }

    #[test]
    fn test_ct1_full_correctness() {
        let c_hat  = random_poly(42);
        let t1_hat: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 7 + 1));
        let (_, ct1_out) = build_trace(&c_hat, &t1_hat);
        for i in 0..K {
            for p in 0..N {
                let expected = (c_hat[p] * t1_hat[i][p]).rem_euclid(Q);
                assert_eq!(ct1_out[i][p], expected,
                    "ct1[{i}][{p}]: expected {expected}, got {}", ct1_out[i][p]);
                assert!(ct1_out[i][p] >= 0 && ct1_out[i][p] < Q,
                    "ct1[{i}][{p}] = {} out of [0, Q)", ct1_out[i][p]);
            }
        }
    }

    #[test]
    fn test_ct1_full_zero_c() {
        let t1_hat: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 + 100));
        let (_, ct1_out) = build_trace(&[0i64; N], &t1_hat);
        for i in 0..K {
            assert_eq!(ct1_out[i], [0i64; N], "row {i} must be zero for c_hat=0");
        }
    }

    #[test]
    fn test_ct1_full_zero_t1() {
        let c_hat = random_poly(77);
        let (_, ct1_out) = build_trace(&c_hat, &[[0i64; N]; K]);
        for i in 0..K {
            assert_eq!(ct1_out[i], [0i64; N], "row {i} must be zero for t1=0");
        }
    }

    #[test]
    fn test_ct1_full_matches_polymul_per_row() {
        use crate::mldsa_poly_mul_air;
        let c_hat  = random_poly(13);
        let t1_hat: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 11 + 5));
        let (_, ct1_full) = build_trace(&c_hat, &t1_hat);
        for i in 0..K {
            let (_, single_out) = mldsa_poly_mul_air::build_trace(&c_hat, &t1_hat[i]);
            assert_eq!(ct1_full[i], single_out, "row {i}: ct1_full ≠ polymul_air");
        }
    }

    #[test]
    fn test_constraints_on_trace() {
        let c_hat  = random_poly(999);
        let t1_hat: [[i64; N]; K] = std::array::from_fn(|i| random_poly(i as u64 * 17 + 3));
        let (cols, _) = build_trace(&c_hat, &t1_hat);
        let col_vals: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vals.iter().collect();
        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], col_refs]);
        let evaluator = Ct1FullEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
