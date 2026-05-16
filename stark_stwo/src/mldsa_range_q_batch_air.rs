/// ML-DSA-65 batch range-Q check AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves poly[j][p] ∈ [0, Q) for all K=6 polynomials simultaneously in a
/// single STARK (K×48 = 288 columns, 256 rows):
///
///   ∀ j ∈ 0..K, p ∈ 0..N:  poly[j][p] ∈ [0, Q)
///
/// This replaces K individual range-Q proofs with one compact proof,
/// saving K-1=5 STARK components in the full VerifyMldsaProofV8 pipeline.
///
/// # Trace layout  (K×48 = 288 columns, 256 rows)
///
/// Per polynomial j = 0..K-1  (48 columns each):
///   col 48*j+0      v[j][p]          ∈ [0, Q)   input coefficient
///   col 48*j+1..23  b_v[j][0..22]    ∈ {0,1}    23-bit decomp of v[j][p]
///   col 48*j+24     d[j][p]          = Q-1-v     complement
///   col 48*j+25..47 b_d[j][0..22]    ∈ {0,1}    23-bit decomp of d[j][p]
///
/// # Constraints  (K×48 = 288 total, max degree 2)
///
/// Per polynomial j in 0..K:
///   C0    v[j] = Σ_{k=0}^{22} b_v[j][k] · 2^k           (decomp of v)
///   C1–23 b_v[j][k]² − b_v[j][k] = 0,  k = 0..22         (boolean ×23)
///   C24   Σ_{k=0}^{22} b_d[j][k] · 2^k + v[j] = Q − 1   (decomp of d)
///   C25–47 b_d[j][k]² − b_d[j][k] = 0,  k = 0..22        (boolean ×23)
///
/// C0 + C24 together enforce v[j][p] ∈ [0, Q) with the same 2^{-47} per-row
/// soundness as the single-polynomial range_check_air.

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

use crate::mldsa::{Q, N};
use crate::mldsa::params::K;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub const LOG_N_ROWS: u32 = 8; // 2^8 = N = 256

/// Bit-width of the decomposition (same as range_check_air).
pub const N_BITS: usize = 23;
/// Columns per polynomial block: v + bits_v + d + bits_d.
pub const COLS_PER_POLY: usize = 1 + N_BITS + 1 + N_BITS; // 48
/// Total columns: K × COLS_PER_POLY.
pub const N_COLS: usize = K * COLS_PER_POLY; // 288

pub struct RangeQBatchEval {
    pub log_n_rows: u32,
}

pub type RangeQBatchComponent = FrameworkComponent<RangeQBatchEval>;

impl FrameworkEval for RangeQBatchEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q_minus_1 = BaseField::from_u32_unchecked((Q - 1) as u32);
        let q_minus_1_ef = E::F::from(q_minus_1);

        for _j in 0..K {
            // Col 0: v.
            let v = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();

            // Cols 1–23: bits of v.
            let mut b_v: Vec<E::F> = Vec::with_capacity(N_BITS);
            for _ in 0..N_BITS {
                b_v.push(eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone());
            }

            // C0: v = Σ b_v[k] * 2^k
            let mut pow2: u32 = 1;
            let mut sum_v = b_v[0].clone();
            for k in 1..N_BITS {
                pow2 <<= 1;
                sum_v = sum_v + b_v[k].clone() * BaseField::from_u32_unchecked(pow2);
            }
            eval.add_constraint(v.clone() - sum_v);

            // C1–C23: b_v[k] ∈ {0, 1}
            for bk in &b_v {
                eval.add_constraint(bk.clone() * bk.clone() - bk.clone());
            }

            // Col 24: d = Q-1-v (consumed via decomp constraint below).
            let _d = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();

            // Cols 25–47: bits of d.
            let mut b_d: Vec<E::F> = Vec::with_capacity(N_BITS);
            for _ in 0..N_BITS {
                b_d.push(eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone());
            }

            // C24: Σ b_d[k] * 2^k + v = Q-1  (encodes both d decomp and d = Q-1-v)
            let mut pow2: u32 = 1;
            let mut sum_d = b_d[0].clone();
            for k in 1..N_BITS {
                pow2 <<= 1;
                sum_d = sum_d + b_d[k].clone() * BaseField::from_u32_unchecked(pow2);
            }
            eval.add_constraint(sum_d + v - q_minus_1_ef.clone());

            // C25–C47: b_d[k] ∈ {0, 1}
            for bk in &b_d {
                eval.add_constraint(bk.clone() * bk.clone() - bk.clone());
            }
        }

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> RangeQBatchComponent {
    RangeQBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        RangeQBatchEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the batch range-Q trace for K polynomials.
///
/// Returns `(columns, valid)` where `valid` is false if any coefficient
/// of any polynomial falls outside [0, Q).
pub fn build_trace(polys: &[[i64; N]; K]) -> (TraceColumns, bool) {
    let n      = 1_usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf0    = BaseField::from_u32_unchecked(0);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_COLS];
    let mut valid = true;

    for p in 0..n {
        for j in 0..K {
            let v = polys[j][p];
            if v < 0 || v >= Q {
                valid = false;
            }
            let vc = v.rem_euclid(Q) as u32;
            let dc = (Q - 1) as u32 - vc;

            let base = j * COLS_PER_POLY;
            cols[base][p] = BaseField::from_u32_unchecked(vc);

            let mut vv = vc;
            for k in 0..N_BITS {
                cols[base + 1 + k][p] = BaseField::from_u32_unchecked(vv & 1);
                vv >>= 1;
            }

            cols[base + 1 + N_BITS][p] = BaseField::from_u32_unchecked(dc);

            let mut dd = dc;
            for k in 0..N_BITS {
                cols[base + 2 + N_BITS + k][p] = BaseField::from_u32_unchecked(dd & 1);
                dd >>= 1;
            }
        }
    }

    for col in cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    let columns: TraceColumns = cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect();

    (columns, valid)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    fn random_poly_in_q(seed: u64) -> [i64; N] {
        let mut state = seed;
        let mut p = [0i64; N];
        for c in p.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let v = ((state >> 33) as i64).abs() % Q;
            *c = v;
        }
        p
    }

    #[test]
    fn test_column_count() {
        assert_eq!(COLS_PER_POLY, 48);
        assert_eq!(N_COLS, K * 48);
    }

    #[test]
    fn test_valid_trace() {
        let polys: [[i64; N]; K] = std::array::from_fn(|j| random_poly_in_q(j as u64 + 1));
        let (_, valid) = build_trace(&polys);
        assert!(valid, "all-valid polynomials must produce valid=true");
    }

    #[test]
    fn test_invalid_trace() {
        let mut polys: [[i64; N]; K] = std::array::from_fn(|j| random_poly_in_q(j as u64 + 100));
        polys[2][17] = Q; // one out-of-range value
        let (_, valid) = build_trace(&polys);
        assert!(!valid, "polynomial with v=Q must produce valid=false");
    }

    #[test]
    fn test_constraints_on_trace() {
        let polys: [[i64; N]; K] = std::array::from_fn(|j| random_poly_in_q(j as u64 * 7 + 3));
        let (cols, valid) = build_trace(&polys);
        assert!(valid);
        let col_vals: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vals.iter().collect();
        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], col_refs]);
        let evaluator = RangeQBatchEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn test_matches_single_range_check() {
        use crate::range_check_air;
        let polys: [[i64; N]; K] = std::array::from_fn(|j| random_poly_in_q(j as u64 * 11 + 5));
        let (batch_cols, batch_valid) = build_trace(&polys);
        assert!(batch_valid);

        for j in 0..K {
            let (single_cols, single_valid) = range_check_air::build_trace(&polys[j]);
            assert!(single_valid);
            // First column of batch-j block must match single col[0].
            let base = j * COLS_PER_POLY;
            assert_eq!(
                batch_cols[base].values, single_cols[0].values,
                "v-column mismatch for j={j}"
            );
        }
    }
}
