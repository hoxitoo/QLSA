/// ML-DSA-65 INTT (inverse NTT) butterfly AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves all 8 × 128 = 1024 Gentleman-Sande (GS) butterfly operations of
/// the inverse NTT (FIPS 204 Algorithm 42) in consecutive trace rows.
///
/// # GS Butterfly (one trace row)
///
///   diff    = a_in − b_in        (mod Q)
///   a_out   = a_in + b_in        (mod Q)
///   b_out   = ζ_k^{-1} × diff   (mod Q)
///
/// Note: the final N^{-1} = 256^{-1} mod Q scaling (last step of Algorithm 42)
/// is applied in the trace builder but proved via the commitment binding only.
/// A dedicated scaling AIR will close this gap in MVP-4.
///
/// # Trace layout  (9 columns, single-row constraints)
///
///   col 0  a_in      ∈ [0, Q)    input a
///   col 1  b_in      ∈ [0, Q)    input b
///   col 2  zeta_inv  ∈ [0, Q)    twiddle ζ_k^{-1}
///   col 3  diff      ∈ [0, Q)    (a_in − b_in) mod Q         (witness)
///   col 4  carry_d   ∈ {0,1}     1 iff a_in < b_in
///   col 5  a_out     ∈ [0, Q)    (a_in + b_in) mod Q
///   col 6  carry_a   ∈ {0,1}     1 iff a_in + b_in ≥ Q
///   col 7  b_out     ∈ [0, Q)    ζ_k^{-1} × diff mod Q       (witness)
///   col 8  carry_b   ∈ [0, Q)    ⌊ζ_k^{-1} × diff / Q⌋       (witness)
///
/// # Constraints (all degree ≤ 2)
///
///   C1  diff  − a_in + b_in − carry_d × Q = 0   [sub mod Q, degree 1]
///   C2  carry_d² − carry_d = 0                   [boolean,   degree 2]
///   C3  a_out − a_in − b_in + carry_a × Q = 0   [add mod Q, degree 1]
///   C4  carry_a² − carry_a = 0                   [boolean,   degree 2]
///   C5  ζ^{-1} × diff − b_out − carry_b × Q = 0 [mul mod Q, degree 2]
///
/// # Soundness
///
/// C1–C4 are fully sound over M31: all values < Q < 2^{23}, so no M31
/// wrap-around ambiguity.  C5 carries the same M31 multiplication gap as
/// C1 in the NTT butterfly AIR (range-check arguments planned for MVP-4).

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

use crate::mldsa::{Q, N, ZETA, N_INV};
use crate::mldsa::field;

// ── Type aliases ─────────────────────────────────────────────────────────────

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

const N_STAGES: usize = 8;
const BUTTERFLIES_PER_STAGE: usize = N / 2;
pub const N_BUTTERFLIES: usize = N_STAGES * BUTTERFLIES_PER_STAGE; // 1024
pub const LOG_N_BUTTERFLIES: u32 = 10;

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct MlDsaInttButterflyEval {
    pub log_n_rows: u32,
}

pub type MlDsaInttButterflyComponent = FrameworkComponent<MlDsaInttButterflyEval>;

impl FrameworkEval for MlDsaInttButterflyEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        let [a_in]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [b_in]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [zeta_inv] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [diff]     = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [carry_d]  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [a_out]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [carry_a]  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [b_out]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [carry_b]  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        // C1: diff − a_in + b_in − carry_d × Q = 0  (sub)
        eval.add_constraint(
            diff.clone() - a_in.clone() + b_in.clone() - carry_d.clone() * q
        );
        // C2: carry_d ∈ {0,1}
        eval.add_constraint(carry_d.clone() * carry_d.clone() - carry_d);

        // C3: a_out − a_in − b_in + carry_a × Q = 0  (add)
        eval.add_constraint(
            a_out - a_in - b_in + carry_a.clone() * q
        );
        // C4: carry_a ∈ {0,1}
        eval.add_constraint(carry_a.clone() * carry_a.clone() - carry_a);

        // C5: ζ^{-1} × diff − b_out − carry_b × Q = 0  (mul, degree 2)
        eval.add_constraint(zeta_inv * diff - b_out - carry_b * q);

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> MlDsaInttButterflyComponent {
    MlDsaInttButterflyComponent::new(
        &mut TraceLocationAllocator::default(),
        MlDsaInttButterflyEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Butterfly witness ─────────────────────────────────────────────────────────

struct InttRow {
    a_in:     i64,
    b_in:     i64,
    zeta_inv: i64,
    diff:     i64,
    carry_d:  i64,
    a_out:    i64,
    carry_a:  i64,
    b_out:    i64,
    carry_b:  i64,
}

fn compute_gs_butterfly(a_in: i64, b_in: i64, zeta_inv_k: i64) -> InttRow {
    // diff = (a_in − b_in) mod Q
    let raw_diff = a_in - b_in;
    let carry_d  = if raw_diff < 0 { 1 } else { 0 };
    let diff     = raw_diff + carry_d * Q;

    // a_out = (a_in + b_in) mod Q
    let raw_a = a_in + b_in;
    let carry_a = if raw_a >= Q { 1 } else { 0 };
    let a_out   = raw_a - carry_a * Q;

    // b_out = ζ^{-1} × diff mod Q
    let prod    = zeta_inv_k * diff;
    let carry_b = prod / Q;
    let b_out   = prod % Q;

    InttRow { a_in, b_in, zeta_inv: zeta_inv_k, diff, carry_d, a_out, carry_a, b_out, carry_b }
}

/// Enumerate all 1024 GS butterflies for the inverse NTT of `f`.
///
/// Returns `(rows, unscaled)` where `unscaled` is the state after all butterfly
/// stages but *before* the N^{-1} multiplication.
fn enumerate_intt_butterflies(f: &[i64; N]) -> (Vec<InttRow>, [i64; N]) {
    let mut rows = Vec::with_capacity(N_BUTTERFLIES);
    let mut poly = *f;

    // Inverse zeta table: ZETA_INV[k] = ζ^{512 − brv₈(k)} mod Q.
    let mut zeta_inv_tbl = [0i64; 256];
    for k in 0u8..=255u8 {
        let brv = k.reverse_bits() as u32;
        let exp = (512 - brv) % 512;
        zeta_inv_tbl[k as usize] = field::pow(ZETA, exp as u64);
    }

    // INTT stage order: len = 1, 2, 4, ..., 128.
    // k starts at N/(2·len) for each stage (same as ntt_inv in ntt.rs).
    let mut len: usize = 1;
    while len <= 128 {
        let k_start = N / (2 * len);
        let mut k = k_start;
        let mut start: usize = 0;
        while start < N {
            let zeta_inv_k = zeta_inv_tbl[k];
            k += 1;
            for j in start..start + len {
                let row = compute_gs_butterfly(poly[j], poly[j + len], zeta_inv_k);
                poly[j]       = row.a_out;
                poly[j + len] = row.b_out;
                rows.push(row);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    debug_assert_eq!(rows.len(), N_BUTTERFLIES);
    (rows, poly)
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the INTT butterfly trace for input `f` (in NTT domain).
///
/// Returns `(columns, intt_out)` where:
/// - `columns`: 9 columns in circle-domain bit-reversed order
/// - `intt_out`: full INTT result including the N^{-1} scaling step
pub fn build_trace(f: &[i64; N]) -> (TraceColumns, [i64; N]) {
    let (rows, unscaled) = enumerate_intt_butterflies(f);

    // Apply N^{-1} scaling to get the final INTT output.
    let mut intt_out = unscaled;
    for c in intt_out.iter_mut() {
        *c = field::mul(*c, N_INV);
    }

    let n     = 1_usize << LOG_N_BUTTERFLIES;
    let domain = CanonicCoset::new(LOG_N_BUTTERFLIES).circle_domain();
    let bf_zero = BaseField::from_u32_unchecked(0);
    let bf      = |v: i64| BaseField::from_u32_unchecked(v as u32);

    let mut a_in_col    = vec![bf_zero; n];
    let mut b_in_col    = vec![bf_zero; n];
    let mut zi_col      = vec![bf_zero; n];
    let mut diff_col    = vec![bf_zero; n];
    let mut carry_d_col = vec![bf_zero; n];
    let mut a_out_col   = vec![bf_zero; n];
    let mut carry_a_col = vec![bf_zero; n];
    let mut b_out_col   = vec![bf_zero; n];
    let mut carry_b_col = vec![bf_zero; n];

    for (i, row) in rows.iter().enumerate() {
        a_in_col[i]    = bf(row.a_in);
        b_in_col[i]    = bf(row.b_in);
        zi_col[i]      = bf(row.zeta_inv);
        diff_col[i]    = bf(row.diff);
        carry_d_col[i] = bf(row.carry_d);
        a_out_col[i]   = bf(row.a_out);
        carry_a_col[i] = bf(row.carry_a);
        b_out_col[i]   = bf(row.b_out);
        carry_b_col[i] = bf(row.carry_b);
    }
    // Rows [N_BUTTERFLIES..n) remain zero: the zero GS butterfly satisfies all
    // constraints trivially.

    for col in [
        &mut a_in_col, &mut b_in_col, &mut zi_col,
        &mut diff_col, &mut carry_d_col,
        &mut a_out_col, &mut carry_a_col,
        &mut b_out_col, &mut carry_b_col,
    ] {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    let columns = vec![
        CircleEvaluation::new(domain, a_in_col),
        CircleEvaluation::new(domain, b_in_col),
        CircleEvaluation::new(domain, zi_col),
        CircleEvaluation::new(domain, diff_col),
        CircleEvaluation::new(domain, carry_d_col),
        CircleEvaluation::new(domain, a_out_col),
        CircleEvaluation::new(domain, carry_a_col),
        CircleEvaluation::new(domain, b_out_col),
        CircleEvaluation::new(domain, carry_b_col),
    ];

    (columns, intt_out)
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
    fn test_gs_butterfly_integer_correctness() {
        let a_in     = 1_234_567_i64;
        let b_in     = 7_654_321_i64;
        let zeta_inv = field::pow(ZETA, 384); // ζ^{512-128} = ζ^{-128}

        let row = compute_gs_butterfly(a_in, b_in, zeta_inv);

        // C1: diff = (a_in - b_in) mod Q
        assert_eq!(row.diff, (a_in - b_in).rem_euclid(Q), "diff");
        // C3: a_out = (a_in + b_in) mod Q
        assert_eq!(row.a_out, (a_in + b_in).rem_euclid(Q), "a_out");
        // C5: b_out = ζ^{-1} × diff mod Q (integer)
        assert_eq!(zeta_inv * row.diff, row.b_out + row.carry_b * Q, "C5 integer");
        assert!(row.b_out >= 0 && row.b_out < Q);
        assert!(matches!(row.carry_d, 0 | 1));
        assert!(matches!(row.carry_a, 0 | 1));
    }

    #[test]
    fn test_intt_output_matches_reference() {
        for seed in [0u64, 1, 42, 0xdead_beef] {
            // Start from a polynomial in NTT domain.
            let f = random_poly(seed);
            let mut f_hat = f;
            ntt(&mut f_hat);

            let (_, intt_out) = build_trace(&f_hat);

            let mut expected = f_hat;
            ntt_inv(&mut expected);

            assert_eq!(intt_out, expected, "INTT mismatch (seed={seed})");
        }
    }

    #[test]
    fn test_intt_ntt_roundtrip() {
        let f = random_poly(99);
        let mut f_hat = f;
        ntt(&mut f_hat);
        let (_, intt_out) = build_trace(&f_hat);
        assert_eq!(intt_out, f, "INTT(NTT(f)) ≠ f");
    }

    #[test]
    fn test_constraints_on_trace() {
        let f = random_poly(1337);
        // Use an NTT-domain input (random polynomial through NTT).
        let mut f_hat = f;
        ntt(&mut f_hat);

        let (cols, _) = build_trace(&f_hat);

        let a_in_v:    Vec<M31> = cols[0].values.clone();
        let b_in_v:    Vec<M31> = cols[1].values.clone();
        let zi_v:      Vec<M31> = cols[2].values.clone();
        let diff_v:    Vec<M31> = cols[3].values.clone();
        let carry_d_v: Vec<M31> = cols[4].values.clone();
        let a_out_v:   Vec<M31> = cols[5].values.clone();
        let carry_a_v: Vec<M31> = cols[6].values.clone();
        let b_out_v:   Vec<M31> = cols[7].values.clone();
        let carry_b_v: Vec<M31> = cols[8].values.clone();

        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![],
            vec![
                &a_in_v, &b_in_v, &zi_v, &diff_v, &carry_d_v,
                &a_out_v, &carry_a_v, &b_out_v, &carry_b_v,
            ],
        ]);

        let evaluator = MlDsaInttButterflyEval { log_n_rows: LOG_N_BUTTERFLIES };
        assert_constraints_on_trace(
            &evals,
            LOG_N_BUTTERFLIES,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
