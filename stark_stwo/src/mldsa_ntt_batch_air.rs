/// ML-DSA-65 batch NTT butterfly AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves M independent forward NTT computations simultaneously in a single
/// STARK.  All M polynomials follow the same butterfly sequence (same ζ
/// twiddle per row), so one shared `zeta` column is sufficient — saving M-1
/// columns versus M independent NTTs.  M is supplied at construction time
/// via `NttBatchEval { n_polys: M }` (default K=6 for backward compat).
///
/// # Trace layout  (1 + M×54 columns, 1024 rows)
///
///   col 0        zeta             ∈ [0, Q)   shared CT twiddle ζ_k
///
///   Per polynomial j = 0..M-1  (54 columns each, base = 1 + j×54):
///     col base+0    a_in[j]      ∈ [0, Q)   input a
///     col base+1    b_in[j]      ∈ [0, Q)   input b
///     col base+2    t[j]         ∈ [0, Q)   ζ × b_in mod Q (witness)
///     col base+3    carry_t[j]   ∈ [0, Q)   ⌊ζ × b_in / Q⌋ (witness)
///     col base+4    a_out[j]     ∈ [0, Q)   (a_in + t) mod Q
///     col base+5    b_out[j]     ∈ [0, Q)   (a_in − t) mod Q
///     col base+6    carry_a[j]   ∈ {0,1}    1 iff a_in + t ≥ Q
///     col base+7    carry_b[j]   ∈ {0,1}    1 iff a_in < t
///     col base+8..30  t_bits[j][0..22]      23-bit decomp of t
///     col base+31..53 ct_bits[j][0..22]     23-bit decomp of carry_t
///
/// # Constraints  (53 × M total per row, max degree 2)
///
/// Per polynomial j in 0..M:
///   C1   zeta × b_in[j] − t[j] − carry_t[j] × Q = 0  (shared zeta, degree 2)
///   C2   a_out[j] − a_in[j] − t[j] + carry_a[j] × Q = 0
///   C3   carry_a[j]² − carry_a[j] = 0
///   C4   b_out[j] − a_in[j] + t[j] − carry_b[j] × Q = 0
///   C5   carry_b[j]² − carry_b[j] = 0
///   C6   t[j] − Σ t_bits[j][k]·2^k = 0
///   C7–C29   t_bits[j][k]² − t_bits[j][k] = 0,  k = 0..22
///   C30  carry_t[j] − Σ ct_bits[j][k]·2^k = 0
///   C31–C53  ct_bits[j][k]² − ct_bits[j][k] = 0,  k = 0..22

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

use crate::mldsa::{Q, N, ZETA};
use crate::mldsa::field;
use crate::mldsa::params::K;

/// Dynamic column count for a batch NTT with `n_polys` polynomials.
pub fn n_cols_for(n_polys: usize) -> usize {
    1 + n_polys * COLS_PER_POLY
}

// ── Type aliases ─────────────────────────────────────────────────────────────

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

// ── Constants ────────────────────────────────────────────────────────────────

const N_STAGES: usize = 8;
const BUTTERFLIES_PER_STAGE: usize = N / 2;
pub const N_BUTTERFLIES: usize = N_STAGES * BUTTERFLIES_PER_STAGE; // 1024
pub const LOG_N_ROWS: u32 = 10;

pub const N_BITS: usize = 23;
/// Columns per polynomial block: a_in, b_in, t, carry_t, a_out, b_out, carry_a, carry_b + 2×23 bits.
pub const COLS_PER_POLY: usize = 8 + 2 * N_BITS; // 54
/// Total columns: 1 shared zeta + K×54.
pub const N_COLS: usize = 1 + K * COLS_PER_POLY; // 325

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct NttBatchEval {
    pub log_n_rows: u32,
    /// Number of polynomials in this batch (default K=6; use L=5 for NTT-z).
    pub n_polys: usize,
}

pub type NttBatchComponent = FrameworkComponent<NttBatchEval>;

impl FrameworkEval for NttBatchEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        // Col 0: shared twiddle ζ_k.
        let [zeta] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        for _j in 0..self.n_polys {
            let [a_in]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [b_in]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [t]       = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [carry_t] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [a_out]   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [b_out]   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [carry_a] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [carry_b] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

            let t_bits: Vec<E::F> = (0..N_BITS)
                .map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone())
                .collect();
            let ct_bits: Vec<E::F> = (0..N_BITS)
                .map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone())
                .collect();

            // C1: zeta × b_in − t − carry_t × Q = 0  (degree 2; shared zeta)
            eval.add_constraint(zeta.clone() * b_in - t.clone() - carry_t.clone() * q);

            // C2: a_out − a_in − t + carry_a × Q = 0
            eval.add_constraint(a_out - a_in.clone() - t.clone() + carry_a.clone() * q);

            // C3: carry_a ∈ {0,1}
            eval.add_constraint(carry_a.clone() * carry_a.clone() - carry_a);

            // C4: b_out − a_in + t − carry_b × Q = 0
            eval.add_constraint(b_out - a_in + t.clone() - carry_b.clone() * q);

            // C5: carry_b ∈ {0,1}
            eval.add_constraint(carry_b.clone() * carry_b.clone() - carry_b);

            // C6: t = Σ t_bits[k] · 2^k
            let mut pow: u32 = 1;
            let mut t_sum = t_bits[0].clone();
            for k in 1..N_BITS {
                pow <<= 1;
                t_sum = t_sum + t_bits[k].clone() * E::F::from(BaseField::from_u32_unchecked(pow));
            }
            eval.add_constraint(t - t_sum);

            // C7–C29: t_bits[k] ∈ {0,1}
            for bit in &t_bits {
                eval.add_constraint(bit.clone() * bit.clone() - bit.clone());
            }

            // C30: carry_t = Σ ct_bits[k] · 2^k
            let mut pow: u32 = 1;
            let mut ct_sum = ct_bits[0].clone();
            for k in 1..N_BITS {
                pow <<= 1;
                ct_sum = ct_sum + ct_bits[k].clone() * E::F::from(BaseField::from_u32_unchecked(pow));
            }
            eval.add_constraint(carry_t - ct_sum);

            // C31–C53: ct_bits[k] ∈ {0,1}
            for bit in &ct_bits {
                eval.add_constraint(bit.clone() * bit.clone() - bit.clone());
            }
        }

        eval
    }
}

/// Create a K=6 batch NTT component (backward compat).
pub fn new_component(log_n_rows: u32) -> NttBatchComponent {
    new_component_m(log_n_rows, K)
}

/// Create a batch NTT component for an arbitrary number of polynomials.
pub fn new_component_m(log_n_rows: u32, n_polys: usize) -> NttBatchComponent {
    NttBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        NttBatchEval { log_n_rows, n_polys },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the batch NTT butterfly trace for M input polynomials.
///
/// Returns `(columns, outputs)` where:
/// - `columns`: `1 + M×54` columns in circle-domain bit-reversed order
/// - `outputs`: M NTT results (all coefficients in [0, Q))
pub fn build_trace(polys: &[[i64; N]]) -> (TraceColumns, Vec<[i64; N]>) {
    let n_polys = polys.len();

    // Forward twiddle table (same as single NTT AIR).
    let mut zeta_fwd = [0i64; 256];
    for k in 0u8..=255u8 {
        zeta_fwd[k as usize] = field::pow(ZETA, k.reverse_bits() as u64);
    }

    let n      = 1_usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf0    = BaseField::from_u32_unchecked(0);
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);

    let mut states: Vec<[i64; N]> = polys.iter().map(|p| *p).collect();

    let mut zeta_col: Vec<BaseField>                  = vec![bf0; n];
    let mut per_poly: Vec<Vec<Vec<BaseField>>> = (0..n_polys)
        .map(|_| vec![vec![bf0; n]; COLS_PER_POLY])
        .collect();

    let mut row_idx: usize = 0;
    let mut k_tbl: usize = 1;
    let mut len: usize = 128;

    // Mirror enumerate_ntt_butterflies from mldsa_ntt_air.rs.
    while len >= 1 {
        let mut start: usize = 0;
        while start < N {
            let zeta_k = zeta_fwd[k_tbl];
            k_tbl += 1;
            for j_coeff in start..start + len {
                zeta_col[row_idx] = bf(zeta_k);

                for poly_j in 0..n_polys {
                    let a_in = states[poly_j][j_coeff];
                    let b_in = states[poly_j][j_coeff + len];

                    let prod    = zeta_k * b_in;
                    let t       = prod % Q;
                    let carry_t = prod / Q;

                    let sum     = a_in + t;
                    let carry_a = if sum >= Q { 1_i64 } else { 0 };
                    let a_out   = sum - carry_a * Q;

                    let diff    = a_in - t;
                    let carry_b = if diff < 0 { 1_i64 } else { 0 };
                    let b_out   = diff + carry_b * Q;

                    states[poly_j][j_coeff]       = a_out;
                    states[poly_j][j_coeff + len] = b_out;

                    let pc = &mut per_poly[poly_j];
                    pc[0][row_idx] = bf(a_in);
                    pc[1][row_idx] = bf(b_in);
                    pc[2][row_idx] = bf(t);
                    pc[3][row_idx] = bf(carry_t);
                    pc[4][row_idx] = bf(a_out);
                    pc[5][row_idx] = bf(b_out);
                    pc[6][row_idx] = bf(carry_a);
                    pc[7][row_idx] = bf(carry_b);

                    let t_u  = t       as u32;
                    let ct_u = carry_t as u32;
                    for kb in 0..N_BITS {
                        pc[8      + kb][row_idx] = BaseField::from_u32_unchecked((t_u  >> kb) & 1);
                        pc[8 + N_BITS + kb][row_idx] = BaseField::from_u32_unchecked((ct_u >> kb) & 1);
                    }
                }

                row_idx += 1;
            }
            start += 2 * len;
        }
        len >>= 1;
    }

    debug_assert_eq!(row_idx, N_BUTTERFLIES);

    let outputs: Vec<[i64; N]> = states;

    bit_reverse_coset_to_circle_domain_order(&mut zeta_col);
    for pc in per_poly.iter_mut() {
        for col in pc.iter_mut() {
            bit_reverse_coset_to_circle_domain_order(col);
        }
    }

    let n_cols = n_cols_for(n_polys);
    let mut columns: TraceColumns = Vec::with_capacity(n_cols);
    columns.push(CircleEvaluation::new(domain, zeta_col));
    for pc in per_poly {
        for col in pc {
            columns.push(CircleEvaluation::new(domain, col));
        }
    }

    debug_assert_eq!(columns.len(), n_cols);
    (columns, outputs)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;
    use crate::mldsa::ntt::ntt;

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
        assert_eq!(COLS_PER_POLY, 54);
        assert_eq!(N_COLS, 1 + K * 54);
        assert_eq!(N_COLS, 325);
        assert_eq!(n_cols_for(K), 325);
        assert_eq!(n_cols_for(5), 1 + 5 * 54); // L=5 case
    }

    #[test]
    fn test_outputs_match_reference() {
        let polys: [[i64; N]; K] = std::array::from_fn(|j| random_poly(j as u64 + 1));
        let (_, outputs) = build_trace(&polys);

        for (j, poly) in polys.iter().enumerate() {
            let mut expected = *poly;
            ntt(&mut expected);
            assert_eq!(
                outputs[j], expected,
                "batch NTT output mismatch for poly j={j}"
            );
        }
    }

    #[test]
    fn test_outputs_match_reference_l5() {
        let polys: Vec<[i64; N]> = (0..5).map(|j| random_poly(j as u64 + 100)).collect();
        let (_, outputs) = build_trace(&polys);

        for (j, poly) in polys.iter().enumerate() {
            let mut expected = *poly;
            ntt(&mut expected);
            assert_eq!(outputs[j], expected, "L=5 batch NTT output mismatch for poly j={j}");
        }
    }

    #[test]
    fn test_constraints_on_trace() {
        let polys: [[i64; N]; K] = std::array::from_fn(|j| random_poly(j as u64 * 7 + 3));
        let (cols, _) = build_trace(&polys);

        assert_eq!(cols.len(), n_cols_for(K));
        let col_vecs: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vecs.iter().collect();
        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], col_refs]);
        let evaluator = NttBatchEval { log_n_rows: LOG_N_ROWS, n_polys: K };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn test_constraints_on_trace_l5() {
        let polys: Vec<[i64; N]> = (0..5).map(|j| random_poly(j as u64 * 7 + 200)).collect();
        let (cols, _) = build_trace(&polys);

        assert_eq!(cols.len(), n_cols_for(5));
        let col_vecs: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vecs.iter().collect();
        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], col_refs]);
        let evaluator = NttBatchEval { log_n_rows: LOG_N_ROWS, n_polys: 5 };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn test_matches_single_ntt() {
        use crate::mldsa_ntt_air;
        let polys: [[i64; N]; K] = std::array::from_fn(|j| random_poly(j as u64 * 11 + 5));
        let (_, batch_outputs) = build_trace(&polys);

        for j in 0..K {
            let (_, single_out) = mldsa_ntt_air::build_trace(&polys[j]);
            assert_eq!(
                batch_outputs[j], single_out,
                "batch vs single NTT output mismatch for poly j={j}"
            );
        }
    }
}
