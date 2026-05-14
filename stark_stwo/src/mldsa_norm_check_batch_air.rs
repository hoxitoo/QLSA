/// ML-DSA-65 batch norm-check AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves norm[j][p] = min(z[j][p], Q − z[j][p]) for ALL L=5 signature
/// polynomials simultaneously in a single STARK (L×3 = 15 columns, 256 rows):
///
///   norm[j][p] = min(z[j][p], Q − z[j][p])    ∀ j ∈ 0..L, p ∈ 0..N
///
/// This replaces L individual norm-check proofs with one compact proof,
/// saving L-1=4 STARK components in the full VerifyMldsaProofV6 pipeline.
///
/// # Trace layout  (L×3 = 15 columns, 256 rows)
///
/// Per row j = 0..L-1  (3 columns each):
///   col 3*j+0  z[j][p]    ∈ [0, Q)         input coefficient
///   col 3*j+1  sel[j][p]  ∈ {0,1}          1 iff z[j] > (Q−1)/2
///   col 3*j+2  norm[j][p] ∈ [0, (Q−1)/2]   output: min(z, Q−z)
///
/// # Constraints  (L×2 = 10 total, max degree 2)
///
/// Per row j in 0..L:
///   C1  sel[j]² − sel[j] = 0                         (boolean)
///   C2  norm[j] − z[j] + 2·sel[j]·z[j] − sel[j]·Q = 0  (norm def)
///
/// # Soundness
///
/// Same as single-row norm_check_air — constraints are fully sound for the
/// computational definition.  Range proofs for norm[j] ∈ [0, (Q−1)/2] and
/// the norm-bound assertion (norm < γ₁ − β = 524 092) are deferred to MVP-4.

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
use crate::mldsa::params::L;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub const LOG_N_ROWS: u32 = 8;

/// Columns per L-row block: z + sel + norm.
const COLS_PER_ROW: usize = 3;
/// Total columns: L × COLS_PER_ROW.
pub const N_COLS: usize = L * COLS_PER_ROW; // 15

/// Centered threshold: z[i] > HALF ⟹ sel = 1.
const HALF: i64 = (Q - 1) / 2; // 4 190 208

pub struct NormCheckBatchEval {
    pub log_n_rows: u32,
}

pub type NormCheckBatchComponent = FrameworkComponent<NormCheckBatchEval>;

impl FrameworkEval for NormCheckBatchEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        for _j in 0..L {
            let z    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let sel  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
            let norm = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();

            // C1: sel ∈ {0, 1}
            eval.add_constraint(sel.clone() * sel.clone() - sel.clone());

            // C2: norm − z + 2·sel·z − sel·Q = 0
            eval.add_constraint(
                norm - z.clone()
                    + sel.clone() * z.clone()
                    + sel.clone() * z
                    - sel * q,
            );
        }

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> NormCheckBatchComponent {
    NormCheckBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        NormCheckBatchEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the batch norm-check trace for L polynomials.
///
/// Returns `(columns, norm_out, max_norms)` where:
///   `norm_out[j][p]` = min(z[j][p], Q − z[j][p])
///   `max_norms[j]`   = max_p norm_out[j][p]  (the ||z[j]||_∞ value)
pub fn build_trace(
    z: &[[i64; N]; L],
) -> (TraceColumns, [[i64; N]; L], [i64; L]) {
    let n      = 1_usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);
    let bf0    = BaseField::from_u32_unchecked(0);

    let mut z_cols:    Vec<Vec<BaseField>> = vec![vec![bf0; n]; L];
    let mut sel_cols:  Vec<Vec<BaseField>> = vec![vec![bf0; n]; L];
    let mut norm_cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; L];

    let mut norm_out:  [[i64; N]; L] = [[0i64; N]; L];
    let mut max_norms: [i64; L]      = [0i64; L];

    for p in 0..N {
        for j in 0..L {
            let zv = z[j][p];
            let (sel, norm) = if zv > HALF { (1i64, Q - zv) } else { (0i64, zv) };
            norm_out[j][p] = norm;
            if norm > max_norms[j] { max_norms[j] = norm; }

            z_cols[j][p]    = bf(zv);
            sel_cols[j][p]  = bf(sel);
            norm_cols[j][p] = bf(norm);
        }
    }

    for j in 0..L {
        bit_reverse_coset_to_circle_domain_order(&mut z_cols[j]);
        bit_reverse_coset_to_circle_domain_order(&mut sel_cols[j]);
        bit_reverse_coset_to_circle_domain_order(&mut norm_cols[j]);
    }

    // Pack in evaluate() read order: per j: z, sel, norm.
    let mut columns: TraceColumns = Vec::with_capacity(N_COLS);
    for j in 0..L {
        columns.push(CircleEvaluation::new(domain, z_cols[j].clone()));
        columns.push(CircleEvaluation::new(domain, sel_cols[j].clone()));
        columns.push(CircleEvaluation::new(domain, norm_cols[j].clone()));
    }

    debug_assert_eq!(columns.len(), N_COLS);
    (columns, norm_out, max_norms)
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
        assert_eq!(N_COLS, 15);
        assert_eq!(COLS_PER_ROW, 3);
    }

    #[test]
    fn test_norm_batch_correctness() {
        let z: [[i64; N]; L] = std::array::from_fn(|j| random_poly(j as u64 * 7 + 1));
        let (_, norm_out, max_norms) = build_trace(&z);

        for j in 0..L {
            let mut expected_max = 0i64;
            for p in 0..N {
                let expected = if z[j][p] > HALF { Q - z[j][p] } else { z[j][p] };
                assert_eq!(norm_out[j][p], expected,
                    "norm[{j}][{p}]: expected {expected}, got {}", norm_out[j][p]);
                if expected > expected_max { expected_max = expected; }
            }
            assert_eq!(max_norms[j], expected_max, "max_norm[{j}] mismatch");
        }
    }

    #[test]
    fn test_norm_batch_zero_input() {
        let (_, norm_out, max_norms) = build_trace(&[[0i64; N]; L]);
        for j in 0..L {
            assert_eq!(norm_out[j], [0i64; N], "norm[{j}] must be zero for z=0");
            assert_eq!(max_norms[j], 0, "max_norm[{j}] must be zero");
        }
    }

    #[test]
    fn test_norm_batch_matches_single_per_row() {
        use crate::mldsa_norm_check_air;
        let z: [[i64; N]; L] = std::array::from_fn(|j| random_poly(j as u64 * 11 + 3));
        let (_, norm_batch, _) = build_trace(&z);

        for j in 0..L {
            let (_, norm_single) = mldsa_norm_check_air::build_trace(&z[j]);
            assert_eq!(norm_batch[j], norm_single, "row {j}: batch ≠ single");
        }
    }

    #[test]
    fn test_constraints_on_trace() {
        let z: [[i64; N]; L] = std::array::from_fn(|j| random_poly(j as u64 * 5 + 9));
        let (cols, _, _) = build_trace(&z);
        let col_vals: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vals.iter().collect();
        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], col_refs]);
        let evaluator = NormCheckBatchEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
