/// ML-DSA-65 batch INTT butterfly AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves K=6 independent inverse NTT computations simultaneously in a
/// single STARK.  All K polynomials follow the same butterfly sequence
/// (same ζ^{-1} twiddle per row), so one shared `zeta_inv` column is
/// sufficient for the entire batch — saving K-1=5 columns versus K
/// independent INTTs, and more importantly collapsing K STARK instances
/// into one, reducing the sub-proof count by K-1=5.
///
/// # Trace layout  (1 + K×54 = 325 columns, 1024 rows)
///
///   col 0        zeta_inv         ∈ [0, Q)   shared GS twiddle ζ_k^{-1}
///
///   Per polynomial j = 0..K-1  (54 columns each, base = 1 + j×54):
///     col base+0    a_in[j]      ∈ [0, Q)   input a
///     col base+1    b_in[j]      ∈ [0, Q)   input b
///     col base+2    diff[j]      ∈ [0, Q)   (a_in − b_in) mod Q
///     col base+3    carry_d[j]   ∈ {0,1}    1 iff a_in < b_in
///     col base+4    a_out[j]     ∈ [0, Q)   (a_in + b_in) mod Q
///     col base+5    carry_a[j]   ∈ {0,1}    1 iff a_in + b_in ≥ Q
///     col base+6    b_out[j]     ∈ [0, Q)   ζ^{-1} × diff mod Q
///     col base+7    carry_b[j]   ∈ [0, Q)   ⌊ζ^{-1} × diff / Q⌋
///     col base+8..30  bo_bits[j][0..22]     23-bit decomp of b_out
///     col base+31..53 cb_bits[j][0..22]     23-bit decomp of carry_b
///
/// # Constraints  (53 × K = 318 total per row, max degree 2)
///
/// Per polynomial j in 0..K:
///   C1   diff[j] − a_in[j] + b_in[j] − carry_d[j] × Q = 0
///   C2   carry_d[j]² − carry_d[j] = 0
///   C3   a_out[j] − a_in[j] − b_in[j] + carry_a[j] × Q = 0
///   C4   carry_a[j]² − carry_a[j] = 0
///   C5   zeta_inv × diff[j] − b_out[j] − carry_b[j] × Q = 0  (shared zeta_inv)
///   C6   b_out[j] − Σ bo_bits[j][k]·2^k = 0
///   C7–C29   bo_bits[j][k]² − bo_bits[j][k] = 0,  k = 0..22
///   C30  carry_b[j] − Σ cb_bits[j][k]·2^k = 0
///   C31–C53  cb_bits[j][k]² − cb_bits[j][k] = 0,  k = 0..22
///
/// # N^{-1} scaling
///
/// The final N^{-1} = 256^{-1} mod Q multiplication is applied in the trace
/// builder and bound to the proof via the Fiat-Shamir output fingerprint (same
/// convention as the single-poly INTT AIR).

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

use crate::mldsa::{Q, N, ZETA, N_INV};
use crate::mldsa::field;
use crate::mldsa::params::K;

/// Dynamic column count for a batch INTT with `n_polys` polynomials.
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

/// Bit-width of the 23-bit range decompositions.
pub const N_BITS: usize = 23;
/// Columns per polynomial block: a_in, b_in, diff, carry_d, a_out, carry_a, b_out, carry_b + 2×23 bits.
pub const COLS_PER_POLY: usize = 8 + 2 * N_BITS; // 54
/// Total columns: 1 shared zeta_inv + K×54.
pub const N_COLS: usize = 1 + K * COLS_PER_POLY; // 325

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct InttBatchEval {
    pub log_n_rows: u32,
    /// Number of polynomials in this batch (default K=6).
    pub n_polys: usize,
}

pub type InttBatchComponent = FrameworkComponent<InttBatchEval>;

impl FrameworkEval for InttBatchEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        // Col 0: shared twiddle factor ζ_k^{-1}.
        let [zeta_inv] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        for _j in 0..self.n_polys {
            // Per-poly base columns.
            let [a_in]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [b_in]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [diff]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [carry_d] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [a_out]   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [carry_a] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [b_out]   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
            let [carry_b] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

            let bo_bits: Vec<E::F> = (0..N_BITS)
                .map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone())
                .collect();
            let cb_bits: Vec<E::F> = (0..N_BITS)
                .map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone())
                .collect();

            // C1: diff − a_in + b_in − carry_d × Q = 0  (sub mod Q)
            eval.add_constraint(
                diff.clone() - a_in.clone() + b_in.clone() - carry_d.clone() * q
            );
            // C2: carry_d ∈ {0,1}
            eval.add_constraint(carry_d.clone() * carry_d.clone() - carry_d);

            // C3: a_out − a_in − b_in + carry_a × Q = 0  (add mod Q)
            eval.add_constraint(
                a_out - a_in - b_in + carry_a.clone() * q
            );
            // C4: carry_a ∈ {0,1}
            eval.add_constraint(carry_a.clone() * carry_a.clone() - carry_a);

            // C5: zeta_inv × diff − b_out − carry_b × Q = 0  (degree 2; shared zeta_inv)
            eval.add_constraint(zeta_inv.clone() * diff - b_out.clone() - carry_b.clone() * q);

            // C6: b_out = Σ bo_bits[k] · 2^k
            let mut pow: u32 = 1;
            let mut bo_sum = bo_bits[0].clone();
            for k in 1..N_BITS {
                pow <<= 1;
                bo_sum = bo_sum + bo_bits[k].clone() * E::F::from(BaseField::from_u32_unchecked(pow));
            }
            eval.add_constraint(b_out - bo_sum);

            // C7–C29: bo_bits[k] ∈ {0,1}
            for bit in &bo_bits {
                eval.add_constraint(bit.clone() * bit.clone() - bit.clone());
            }

            // C30: carry_b = Σ cb_bits[k] · 2^k
            let mut pow: u32 = 1;
            let mut cb_sum = cb_bits[0].clone();
            for k in 1..N_BITS {
                pow <<= 1;
                cb_sum = cb_sum + cb_bits[k].clone() * E::F::from(BaseField::from_u32_unchecked(pow));
            }
            eval.add_constraint(carry_b - cb_sum);

            // C31–C53: cb_bits[k] ∈ {0,1}
            for bit in &cb_bits {
                eval.add_constraint(bit.clone() * bit.clone() - bit.clone());
            }
        }

        eval
    }
}

/// Create a K=6 batch INTT component (backward compat).
pub fn new_component(log_n_rows: u32) -> InttBatchComponent {
    new_component_m(log_n_rows, K)
}

/// Create a batch INTT component for an arbitrary number of polynomials.
pub fn new_component_m(log_n_rows: u32, n_polys: usize) -> InttBatchComponent {
    InttBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        InttBatchEval { log_n_rows, n_polys },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the batch INTT butterfly trace for M input polynomials.
///
/// Returns `(columns, outputs)` where:
/// - `columns`: `1 + M×54` columns in circle-domain bit-reversed order
/// - `outputs`: M INTT results with the N^{-1} scaling step applied
pub fn build_trace(polys: &[[i64; N]]) -> (TraceColumns, Vec<[i64; N]>) {
    let n_polys = polys.len();

    // Inverse twiddle table (same as single INTT AIR).
    let mut zeta_inv_tbl = [0i64; 256];
    for k in 0u8..=255u8 {
        let brv = k.reverse_bits() as u32;
        let exp = (512 - brv) % 512;
        zeta_inv_tbl[k as usize] = field::pow(ZETA, exp as u64);
    }

    let n      = 1_usize << LOG_N_ROWS; // 1024
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf0    = BaseField::from_u32_unchecked(0);
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);

    // Mutable working state for each polynomial.
    let mut states: Vec<[i64; N]> = polys.iter().map(|p| *p).collect();

    // Allocate output columns: [zeta_inv_col] + [per_poly_cols[j][c][row]].
    let mut zeta_inv_col: Vec<BaseField>              = vec![bf0; n];
    let mut per_poly: Vec<Vec<Vec<BaseField>>> = (0..n_polys)
        .map(|_| vec![vec![bf0; n]; COLS_PER_POLY])
        .collect();

    let mut row_idx: usize = 0;

    // Mirror enumerate_intt_butterflies from mldsa_intt_air.rs.
    let mut len: usize = 1;
    while len <= 128 {
        let k_start = N / (2 * len);
        let mut k_tbl = k_start;
        let mut start: usize = 0;
        while start < N {
            let zeta_inv_k = zeta_inv_tbl[k_tbl];
            k_tbl += 1;
            for j_coeff in start..start + len {
                // Fill shared column.
                zeta_inv_col[row_idx] = bf(zeta_inv_k);

                // For each polynomial, compute and store butterfly witness.
                for poly_j in 0..n_polys {
                    let a_in = states[poly_j][j_coeff];
                    let b_in = states[poly_j][j_coeff + len];

                    let raw_diff = a_in - b_in;
                    let carry_d  = if raw_diff < 0 { 1_i64 } else { 0 };
                    let diff     = raw_diff + carry_d * Q;

                    let raw_a   = a_in + b_in;
                    let carry_a = if raw_a >= Q { 1_i64 } else { 0 };
                    let a_out   = raw_a - carry_a * Q;

                    let prod    = zeta_inv_k * diff;
                    let carry_b = prod / Q;
                    let b_out   = prod % Q;

                    // Update state.
                    states[poly_j][j_coeff]       = a_out;
                    states[poly_j][j_coeff + len] = b_out;

                    let pc = &mut per_poly[poly_j];
                    pc[0][row_idx] = bf(a_in);
                    pc[1][row_idx] = bf(b_in);
                    pc[2][row_idx] = bf(diff);
                    pc[3][row_idx] = bf(carry_d);
                    pc[4][row_idx] = bf(a_out);
                    pc[5][row_idx] = bf(carry_a);
                    pc[6][row_idx] = bf(b_out);
                    pc[7][row_idx] = bf(carry_b);

                    let bo_u = b_out   as u32;
                    let cb_u = carry_b as u32;
                    for kb in 0..N_BITS {
                        pc[8      + kb][row_idx] = BaseField::from_u32_unchecked((bo_u >> kb) & 1);
                        pc[8 + N_BITS + kb][row_idx] = BaseField::from_u32_unchecked((cb_u >> kb) & 1);
                    }
                }

                row_idx += 1;
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    debug_assert_eq!(row_idx, N_BUTTERFLIES);

    // Apply N^{-1} scaling.
    let outputs: Vec<[i64; N]> = states.iter().map(|state| {
        let mut out = [0i64; N];
        for (p, &v) in state.iter().enumerate() {
            out[p] = field::mul(v, N_INV);
        }
        out
    }).collect();

    // Bit-reverse all columns.
    bit_reverse_coset_to_circle_domain_order(&mut zeta_inv_col);
    for pc in per_poly.iter_mut() {
        for col in pc.iter_mut() {
            bit_reverse_coset_to_circle_domain_order(col);
        }
    }

    // Assemble: [zeta_inv] then per-poly blocks in order.
    let n_cols = n_cols_for(n_polys);
    let mut columns: TraceColumns = Vec::with_capacity(n_cols);
    columns.push(CircleEvaluation::new(domain, zeta_inv_col));
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
    use crate::mldsa::ntt::{ntt, ntt_inv};

    fn random_poly_ntt(seed: u64) -> [i64; N] {
        let mut state = seed;
        let mut p = [0i64; N];
        for c in p.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *c = ((state >> 33) as i64).abs() % Q;
        }
        // Bring into NTT domain.
        ntt(&mut p);
        p
    }

    #[test]
    fn test_column_count() {
        assert_eq!(COLS_PER_POLY, 54);
        assert_eq!(N_COLS, 1 + K * 54);
        assert_eq!(N_COLS, 325);
        assert_eq!(n_cols_for(K), 325);
    }

    #[test]
    fn test_outputs_match_reference() {
        let polys: [[i64; N]; K] = std::array::from_fn(|j| random_poly_ntt(j as u64 + 1));
        let (_, outputs) = build_trace(&polys);

        for (j, poly) in polys.iter().enumerate() {
            let mut expected = *poly;
            ntt_inv(&mut expected);
            assert_eq!(
                outputs[j], expected,
                "batch INTT output mismatch for poly j={j}"
            );
        }
    }

    #[test]
    fn test_ntt_intt_roundtrip() {
        let mut originals: [[i64; N]; K] = [[0i64; N]; K];
        for j in 0..K {
            let mut state = (j as u64 + 99) * 7;
            for c in originals[j].iter_mut() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                *c = ((state >> 33) as i64).abs() % Q;
            }
        }

        let mut polys_ntt: [[i64; N]; K] = originals;
        for p in polys_ntt.iter_mut() { ntt(p); }

        let (_, outputs) = build_trace(&polys_ntt);
        let outputs_arr: [[i64; N]; K] = outputs.try_into().unwrap();
        assert_eq!(outputs_arr, originals, "INTT(NTT(f)) ≠ f for batch");
    }

    #[test]
    fn test_constraints_on_trace() {
        let polys: [[i64; N]; K] = std::array::from_fn(|j| random_poly_ntt(j as u64 * 7 + 3));
        let (cols, _) = build_trace(&polys);

        assert_eq!(cols.len(), n_cols_for(K));
        let col_vecs: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vecs.iter().collect();
        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], col_refs]);
        let evaluator = InttBatchEval { log_n_rows: LOG_N_ROWS, n_polys: K };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn test_matches_single_intt() {
        use crate::mldsa_intt_air;
        let polys: [[i64; N]; K] = std::array::from_fn(|j| random_poly_ntt(j as u64 * 11 + 5));
        let (_, batch_outputs) = build_trace(&polys);

        for j in 0..K {
            let (_, single_out) = mldsa_intt_air::build_trace(&polys[j]);
            assert_eq!(
                batch_outputs[j], single_out,
                "batch vs single INTT output mismatch for poly j={j}"
            );
        }
    }
}
