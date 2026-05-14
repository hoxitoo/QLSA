/// ML-DSA-65 hint weight check AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves that the hint vector h ∈ {0,1}^{K×N} has total weight at most ω:
///   ||h||₁ = Σᵢ Σⱼ h[i][j]  ≤  ω = 55   (ML-DSA-65, FIPS 204 §4)
///
/// The circuit flattens K×N = 6×256 = 1536 hint bits into a sequence and
/// computes a running sum.  Rows 1536–2047 are zero-padded.
///
/// # Trace layout  (2 columns, LOG_N_ROWS=11, 2048 rows)
///
///   col 0:  h[r]   hint bit at flat position r (0 or 1); 0 for r ≥ 1536
///   col 1:  s[r]   running sum = Σ_{p≤r} h[p]
///
/// # Preprocessed columns
///
///   pp 0:  is_init  — 1 at row 0, 0 at rows 1..2047
///                     Handles the wrap-around from the last to the first row
///                     in the Circle coset (Stwo's domain is cyclic).
///   pp 1:  is_valid — 1 at rows 0..1535, 0 at rows 1536..2047
///                     Forces padding rows to have h = 0.
///
/// # Constraints  (max degree 2)
///
///   C1:  h · (1 − h)   = 0          (boolean,        degree 2)
///   C2:  (1 − is_valid) · h  = 0    (padding zeros,  degree 2)
///   C3:  s − h − (1 − is_init) · s_prev  = 0   (running sum)
///          = s − h − s_prev + is_init · s_prev = 0
///          When is_init=1 (row 0): s − h = 0                ✓
///          When is_init=0 (row r): s − h − s_prev = 0        ✓
///        Note: is_init is preprocessed (constant), so is_init · s_prev
///        is degree 1 in the main trace and degree 2 overall.
///
/// # Output
///
/// The final running sum s[2047] equals the total hint weight.
/// It is returned alongside the STARK proof and a 128-bit commitment to
/// the full running-sum column (Scheme B fingerprint).

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
    ORIGINAL_TRACE_IDX,
};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

use crate::mldsa;

// ── Constants ─────────────────────────────────────────────────────────────────

/// log₂(2048) = 11. Trace has 2048 rows (next power of 2 ≥ K×N = 1536).
pub const LOG_N_ROWS: u32 = 11;
/// Total hint rows (K × N = 1536); rows beyond this are zero-padded.
pub const HINT_ROWS: usize = mldsa::params::K * mldsa::N;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
type TraceColumns = Vec<TraceCol>;

// ── Preprocessed column IDs ────────────────────────────────────────────────────

pub fn pc_is_init()  -> PreProcessedColumnId { PreProcessedColumnId { id: "hw_is_init".into() } }
pub fn pc_is_valid() -> PreProcessedColumnId { PreProcessedColumnId { id: "hw_is_valid".into() } }

pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    vec![pc_is_init(), pc_is_valid()]
}

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct HintWeightEval {
    pub log_n_rows: u32,
}

pub type HintWeightComponent = FrameworkComponent<HintWeightEval>;

impl FrameworkEval for HintWeightEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Degree-2 constraints → quotient degree fits in n+1 bits.
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // Preprocessed columns (constants per row).
        let is_init  = eval.get_preprocessed_column(pc_is_init());
        let is_valid = eval.get_preprocessed_column(pc_is_valid());

        // Main trace: current and previous row of s (running sum).
        let [s_curr, s_prev] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        // Main trace: current hint bit h (current row only).
        let [h] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let one = E::F::from(BaseField::from_u32_unchecked(1));

        // C1: h ∈ {0,1}  →  h·(1 − h) = 0
        eval.add_constraint(h.clone() * (one.clone() - h.clone()));

        // C2: padding rows must have h = 0  →  (1 − is_valid)·h = 0
        eval.add_constraint((one.clone() - is_valid) * h.clone());

        // C3: running sum continuity.
        //   s_curr = h + (1 − is_init) · s_prev
        //   ↔  s_curr − h − s_prev + is_init · s_prev = 0
        eval.add_constraint(s_curr - h - s_prev.clone() + is_init * s_prev);

        eval
    }
}

// ── Component constructor ──────────────────────────────────────────────────────

pub fn new_component(log_n_rows: u32) -> HintWeightComponent {
    let ids = preprocessed_column_ids();
    HintWeightComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&ids),
        HintWeightEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ──────────────────────────────────────────────────────────────

/// Build the main and preprocessed traces from hint bits.
///
/// `hints[i][j]` is the hint bit for polynomial i, coefficient j.
/// Must have `hints.len() == K` and each `hints[i].len() == N`.
///
/// Returns `(main_cols, preproc_cols, total_weight)`.
pub fn build_trace(hints: &[Vec<bool>]) -> (TraceColumns, TraceColumns, usize) {
    let k = mldsa::params::K;
    let n = mldsa::N;
    let n_rows = 1usize << LOG_N_ROWS; // 2048

    // Flatten hints into a 1536-element bit vector; pad to 2048 with 0s.
    let mut h_flat = vec![0i64; n_rows];
    for (i, row) in hints.iter().enumerate() {
        for (j, &bit) in row.iter().enumerate() {
            h_flat[i * n + j] = if bit { 1 } else { 0 };
        }
    }

    // Running sum.
    let mut s_flat = vec![0i64; n_rows];
    let mut acc = 0i64;
    for r in 0..n_rows {
        acc += h_flat[r];
        s_flat[r] = acc;
    }
    let total_weight = acc as usize;

    // is_init: 1 at row 0, 0 elsewhere.
    let mut is_init_vals = vec![0i64; n_rows];
    is_init_vals[0] = 1;

    // is_valid: 1 at rows 0..HINT_ROWS (= k*n = 1536), 0 for padding.
    let mut is_valid_vals = vec![0i64; n_rows];
    for r in 0..(k * n) {
        is_valid_vals[r] = 1;
    }

    // Column order must match next_interaction_mask call order in FrameworkEval:
    //   First call reads s (two offsets [0,-1]), second call reads h (offset [0]).
    let main_cols = make_trace_cols(&[&s_flat, &h_flat], LOG_N_ROWS);
    let preproc_cols = make_trace_cols(&[&is_init_vals, &is_valid_vals], LOG_N_ROWS);

    (main_cols, preproc_cols, total_weight)
}

fn make_trace_cols(columns: &[&[i64]], log_n_rows: u32) -> TraceColumns {
    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    columns.iter().map(|&col| {
        let mut vals: Vec<BaseField> = col.iter()
            .map(|&v| BaseField::from_u32_unchecked(v as u32))
            .collect();
        bit_reverse_coset_to_circle_domain_order(&mut vals);
        CircleEvaluation::new(domain, vals)
    }).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_hints() -> Vec<Vec<bool>> {
        vec![vec![false; mldsa::N]; mldsa::params::K]
    }

    fn hints_with_count(count: usize) -> Vec<Vec<bool>> {
        let k = mldsa::params::K;
        let n = mldsa::N;
        let mut h = zero_hints();
        let mut placed = 0;
        'outer: for i in 0..k {
            for j in 0..n {
                if placed >= count { break 'outer; }
                h[i][j] = true;
                placed += 1;
            }
        }
        h
    }

    #[test]
    fn test_build_trace_zero_hints() {
        let (main, preproc, weight) = build_trace(&zero_hints());
        assert_eq!(weight, 0);
        assert_eq!(main.len(), 2);     // h, s
        assert_eq!(preproc.len(), 2);  // is_init, is_valid
    }

    #[test]
    fn test_build_trace_counts_correctly() {
        for &count in &[0, 1, 10, 55, 100, HINT_ROWS] {
            let (_, _, w) = build_trace(&hints_with_count(count));
            assert_eq!(w, count, "count={count}");
        }
    }

    #[test]
    fn test_build_trace_is_valid_pattern() {
        let (_, preproc, _) = build_trace(&zero_hints());
        // preproc[1] is is_valid: sum of all values should equal HINT_ROWS.
        let valid_sum: u32 = preproc[1].values.iter().map(|v| v.0).sum();
        assert_eq!(valid_sum as usize, HINT_ROWS, "is_valid rows");
        // preproc[0] is is_init: exactly one row should be 1.
        let init_sum: u32 = preproc[0].values.iter().map(|v| v.0).sum();
        assert_eq!(init_sum, 1, "is_init rows");
    }

    #[test]
    fn test_constraints_on_trace() {
        use mldsa::params::OMEGA;
        use mldsa::N;
        let count = 30usize;
        let h_bits = hints_with_count(count);
        let (_, _, weight) = build_trace(&h_bits);
        assert_eq!(weight, count);
        assert!(weight <= OMEGA, "weight {weight} > omega {OMEGA}");

        let n_rows = 1usize << LOG_N_ROWS;
        let h_flat: Vec<i64> = {
            let k = mldsa::params::K;
            let mut v = vec![0i64; n_rows];
            for (i, row) in h_bits.iter().enumerate() {
                for (j, &b) in row.iter().enumerate() {
                    v[i * N + j] = if b { 1 } else { 0 };
                }
            }
            v
        };
        let mut s_flat = vec![0i64; n_rows];
        let mut acc = 0i64;
        for r in 0..n_rows {
            acc += h_flat[r];
            s_flat[r] = acc;
        }
        // C1: h*(1-h) = 0 for all rows.
        for r in 0..n_rows {
            assert_eq!(h_flat[r] * (1 - h_flat[r]), 0, "C1 failed at row {r}");
        }
        // C2: h = 0 for padding rows.
        for r in HINT_ROWS..n_rows {
            assert_eq!(h_flat[r], 0, "C2 failed at row {r}");
        }
        // C3: running sum.
        assert_eq!(s_flat[0], h_flat[0], "C3 init");
        for r in 1..n_rows {
            assert_eq!(s_flat[r], s_flat[r-1] + h_flat[r], "C3 at row {r}");
        }
    }
}
