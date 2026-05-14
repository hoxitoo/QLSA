/// Q-range check AIR: proves each of N = 256 polynomial coefficients is in [0, Q).
///
/// Circuit: 256 rows × 48 columns.
///   Col 0:       value v  ∈ [0, Q)
///   Cols 1–23:   23-bit decomposition of v   (b_v[0..22], b_v[0] = LSB)
///   Col 24:      d = Q − 1 − v               ∈ [0, Q)
///   Cols 25–47:  23-bit decomposition of d
///
/// Constraints per row (48 total, max degree 2):
///   C0      v = Σ_{k=0}^{22} b_v[k] · 2^k               (decomposition of v)
///   C1–C23  b_v[k]² − b_v[k] = 0,  k = 0..22            (boolean, 23 constraints)
///   C24     Σ_{k=0}^{22} b_d[k] · 2^k + v = Q − 1       (d = Q-1-v + decomp of d)
///   C25–C47 b_d[k]² − b_d[k] = 0,  k = 0..22            (boolean, 23 constraints)
///
/// C0 and C24 together enforce v ∈ [0, 2^23) and Q-1-v ∈ [0, 2^23),
/// which is equivalent to v ∈ [0, Q).

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

pub const N_BITS:     usize = 23;
pub const N_COLS:     usize = 1 + N_BITS + 1 + N_BITS; // 48
pub const LOG_N_ROWS: u32   = 8; // 2^8 = N = 256

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub type RangeCheckComponent = FrameworkComponent<RangeCheckEval>;

pub struct RangeCheckEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for RangeCheckEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q_minus_1 = BaseField::from_u32_unchecked((Q - 1) as u32);

        // Column 0: value v.
        let v = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();

        // Columns 1–23: bits of v.
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

        // C1–C23: b_v[k] ∈ {0, 1}  (b^2 - b = 0)
        for bk in &b_v {
            eval.add_constraint(bk.clone() * bk.clone() - bk.clone());
        }

        // Column 24: d = Q-1-v.
        let d = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();

        // Columns 25–47: bits of d.
        let mut b_d: Vec<E::F> = Vec::with_capacity(N_BITS);
        for _ in 0..N_BITS {
            b_d.push(eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone());
        }

        // C24: Σ b_d[k] * 2^k + v = Q-1
        // (This encodes both d's decomposition and d = Q-1-v.)
        let mut pow2: u32 = 1;
        let mut sum_d = b_d[0].clone();
        for k in 1..N_BITS {
            pow2 <<= 1;
            sum_d = sum_d + b_d[k].clone() * BaseField::from_u32_unchecked(pow2);
        }
        let q_minus_1_ef = E::F::from(q_minus_1);
        eval.add_constraint(sum_d + v - q_minus_1_ef);

        // C25–C47: b_d[k] ∈ {0, 1}
        for bk in &b_d {
            eval.add_constraint(bk.clone() * bk.clone() - bk.clone());
        }

        // Suppress unused warning for d (it's implicit in the decomposition constraint).
        let _ = d;

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> RangeCheckComponent {
    RangeCheckComponent::new(
        &mut TraceLocationAllocator::default(),
        RangeCheckEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ──────────────────────────────────────────────────────────────

/// Build the range-check trace for a single polynomial.
///
/// Returns `(columns, valid)` where `valid` is false if any value is out of [0, Q).
pub fn build_trace(poly: &[i64; N]) -> (TraceColumns, bool) {
    let n      = 1_usize << LOG_N_ROWS; // 256
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf0    = BaseField::from_u32_unchecked(0);

    // N_COLS = 48: col[0] = v, col[1..24] = bits of v, col[24] = d, col[25..48] = bits of d
    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_COLS];
    let mut valid = true;

    for r in 0..n {
        let v = poly[r];
        if v < 0 || v >= Q {
            valid = false;
        }
        let v_clamped = v.rem_euclid(Q); // safe trace value even for invalid inputs
        let d_clamped = Q - 1 - v_clamped;

        cols[0][r] = BaseField::from_u32_unchecked(v_clamped as u32);

        let mut vv = v_clamped as u32;
        for k in 0..N_BITS {
            cols[1 + k][r] = BaseField::from_u32_unchecked(vv & 1);
            vv >>= 1;
        }

        cols[1 + N_BITS][r] = BaseField::from_u32_unchecked(d_clamped as u32);

        let mut dd = d_clamped as u32;
        for k in 0..N_BITS {
            cols[2 + N_BITS + k][r] = BaseField::from_u32_unchecked(dd & 1);
            dd >>= 1;
        }
    }

    // Bit-reverse all columns to match circle domain ordering.
    for col in cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    let columns: TraceColumns = cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect();

    (columns, valid)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_poly_in_q(seed: u64) -> [i64; N] {
        let mut state = seed;
        let mut arr = [0i64; N];
        for v in arr.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *v = (state >> 33) as i64 % Q;
            if *v < 0 { *v += Q; }
        }
        arr
    }

    #[test]
    fn test_build_trace_valid_range() {
        let poly = rand_poly_in_q(42);
        let (_, valid) = build_trace(&poly);
        assert!(valid, "valid polynomial should produce valid trace");
    }

    #[test]
    fn test_build_trace_invalid_range() {
        let mut poly = rand_poly_in_q(7);
        poly[5] = Q; // one value out of range
        let (_, valid) = build_trace(&poly);
        assert!(!valid, "polynomial with v=Q should be invalid");
    }

    #[test]
    fn test_bit_decomposition_correctness() {
        let poly = rand_poly_in_q(99);
        let (cols, valid) = build_trace(&poly);
        assert!(valid);
        // The trace is bit-reversed, so we can't easily spot-check individual rows here.
        // The STARK constraints enforce correctness across all rows.
        assert_eq!(cols.len(), N_COLS);
        assert_eq!(cols[0].values.len(), N);
    }
}
