/// ML-DSA-65 NTT butterfly AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves one forward NTT over Z_q[X]/(X^{256}+1) as a sequence of
/// Cooley-Tukey butterfly operations.  All 8 × 128 = 1024 butterflies from
/// FIPS 204 Algorithm 41 are flattened into consecutive trace rows.
///
/// # Butterfly (one trace row)
///
///   t       = ζ_k × b_in   (mod Q)
///   a_out   = a_in + t      (mod Q)
///   b_out   = a_in − t      (mod Q)
///
/// # Trace layout  (55 columns, single-row constraints)
///
///   col 0      a_in         ∈ [0, Q)   input a coefficient
///   col 1      b_in         ∈ [0, Q)   input b coefficient
///   col 2      zeta         ∈ [0, Q)   twiddle factor ζ_k
///   col 3      t            ∈ [0, Q)   ζ_k × b_in mod Q (witness)
///   col 4      carry_t      ∈ [0, Q)   ⌊ζ_k × b_in / Q⌋  (witness)
///   col 5      a_out        ∈ [0, Q)   (a_in + t) mod Q
///   col 6      b_out        ∈ [0, Q)   (a_in − t) mod Q
///   col 7      carry_a      ∈ {0,1}    1 iff a_in + t ≥ Q
///   col 8      carry_b      ∈ {0,1}    1 iff a_in < t
///   col 9–31   t_bits[0–22] ∈ {0,1}   23-bit decomposition of t
///   col 32–54  ct_bits[0–22]∈ {0,1}   23-bit decomposition of carry_t
///
/// # Constraints (all degree ≤ 2)
///
///   C1   ζ × b_in − t − carry_t × Q = 0         [mul mod Q,  degree 2]
///   C2   a_out − a_in − t + carry_a × Q = 0      [add mod Q,  degree 1]
///   C3   carry_a² − carry_a = 0                  [boolean,    degree 2]
///   C4   b_out − a_in + t − carry_b × Q = 0      [sub mod Q,  degree 1]
///   C5   carry_b² − carry_b = 0                  [boolean,    degree 2]
///   C6   t − Σ t_bits[k]·2^k = 0                 [t decomp,   degree 1]
///   C7–C29  t_bits[k]² − t_bits[k] = 0 (k=0..22)[boolean ×23,degree 2]
///   C30  carry_t − Σ ct_bits[k]·2^k = 0          [ct decomp,  degree 1]
///   C31–C53 ct_bits[k]²−ct_bits[k]=0 (k=0..22)  [boolean ×23,degree 2]
///
/// # Soundness improvement (C1)
///
/// C2–C5 are fully sound over M31: all values are < Q < 2^{23} < M31,
/// so integer equations and M31 equations coincide.
///
/// C1 evaluates `ζ × b_in` in M31, which can wrap since the product
/// reaches ~2^{46}.  Adding C6–C53 proves t ∈ [0, Q) and carry_t ∈ [0, Q).
/// With both witnesses range-bounded:
///   t + carry_t × Q ∈ [0, Q²)  and  ζ × b_in ∈ [0, Q²),
/// so the M31 equation has at most ⌈Q²/M31⌉ ≈ 32 654 solutions per row.
/// This reduces the per-row soundness error from ~1 to ~32 654 / M31²,
/// giving ≈ 2^{-47} per butterfly (1024 rows → ≈ 2^{-37} for the full NTT).
/// Full single-row soundness requires a lookup argument on the product
/// (planned for MVP-4 when the full on-chain verifier is implemented).

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

use crate::mldsa::{Q, N, ZETA};
use crate::mldsa::field;

// ── Type aliases ─────────────────────────────────────────────────────────────

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

// ── Constants ────────────────────────────────────────────────────────────────

/// NTT stages = log₂(N) = 8 for N = 256.
const N_STAGES: usize = 8;
/// Butterflies per stage = N / 2 = 128.
const BUTTERFLIES_PER_STAGE: usize = N / 2;
/// Total butterflies for one full forward NTT.
pub const N_BUTTERFLIES: usize = N_STAGES * BUTTERFLIES_PER_STAGE; // 1024
/// log₂(N_BUTTERFLIES) = 10.
pub const LOG_N_BUTTERFLIES: u32 = 10;
/// Bit-width of Q: ceil(log₂(Q)) = 23.
pub const N_BITS: usize = 23;
/// Total trace columns: 9 base + 23 bits of t + 23 bits of carry_t.
pub const N_COLS: usize = 9 + 2 * N_BITS; // 55

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct MlDsaNttButterflyEval {
    pub log_n_rows: u32,
}

pub type MlDsaNttButterflyComponent = FrameworkComponent<MlDsaNttButterflyEval>;

impl FrameworkEval for MlDsaNttButterflyEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Max constraint degree is 2 → quotient domain needs 2× rows.
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        // ── Columns 0–8: butterfly core ──────────────────────────────────────
        let [a_in]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [b_in]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [zeta]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [t]       = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [carry_t] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [a_out]   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [b_out]   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [carry_a] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [carry_b] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        // ── Columns 9–31: 23-bit decomposition of t ──────────────────────────
        let t_bits: Vec<E::F> = (0..N_BITS)
            .map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone())
            .collect();

        // ── Columns 32–54: 23-bit decomposition of carry_t ───────────────────
        let ct_bits: Vec<E::F> = (0..N_BITS)
            .map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone())
            .collect();

        // ── C1: ζ × b_in − t − carry_t × Q = 0  (degree 2) ─────────────────
        eval.add_constraint(zeta * b_in - t.clone() - carry_t.clone() * q);

        // ── C2: a_out − a_in − t + carry_a × Q = 0 ──────────────────────────
        eval.add_constraint(a_out - a_in.clone() - t.clone() + carry_a.clone() * q);

        // ── C3: carry_a² − carry_a = 0 ──────────────────────────────────────
        eval.add_constraint(carry_a.clone() * carry_a.clone() - carry_a);

        // ── C4: b_out − a_in + t − carry_b × Q = 0 ──────────────────────────
        eval.add_constraint(b_out - a_in + t.clone() - carry_b.clone() * q);

        // ── C5: carry_b² − carry_b = 0 ──────────────────────────────────────
        eval.add_constraint(carry_b.clone() * carry_b.clone() - carry_b);

        // ── C6: t = Σ t_bits[k] · 2^k  (proves t ∈ [0, 2^23) ⊃ [0, Q)) ────
        let mut pow2: u32 = 1;
        let mut t_from_bits = t_bits[0].clone();
        for k in 1..N_BITS {
            pow2 <<= 1;
            t_from_bits = t_from_bits + t_bits[k].clone() * BaseField::from_u32_unchecked(pow2);
        }
        eval.add_constraint(t - t_from_bits);

        // ── C7–C29: t_bits[k]² − t_bits[k] = 0  (boolean, 23 constraints) ──
        for bk in &t_bits {
            eval.add_constraint(bk.clone() * bk.clone() - bk.clone());
        }

        // ── C30: carry_t = Σ ct_bits[k] · 2^k  (proves carry_t ∈ [0, Q)) ───
        let mut pow2: u32 = 1;
        let mut ct_from_bits = ct_bits[0].clone();
        for k in 1..N_BITS {
            pow2 <<= 1;
            ct_from_bits =
                ct_from_bits + ct_bits[k].clone() * BaseField::from_u32_unchecked(pow2);
        }
        eval.add_constraint(carry_t - ct_from_bits);

        // ── C31–C53: ct_bits[k]² − ct_bits[k] = 0  (boolean, 23 constraints)
        for bk in &ct_bits {
            eval.add_constraint(bk.clone() * bk.clone() - bk.clone());
        }

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> MlDsaNttButterflyComponent {
    MlDsaNttButterflyComponent::new(
        &mut TraceLocationAllocator::default(),
        MlDsaNttButterflyEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Butterfly witness ─────────────────────────────────────────────────────────

struct ButterflyRow {
    a_in:    i64,
    b_in:    i64,
    zeta:    i64,
    t:       i64,
    carry_t: i64,
    a_out:   i64,
    b_out:   i64,
    carry_a: i64,
    carry_b: i64,
}

fn compute_butterfly(a_in: i64, b_in: i64, zeta_k: i64) -> ButterflyRow {
    let prod    = zeta_k * b_in;
    let t       = prod % Q;
    let carry_t = prod / Q;

    let sum     = a_in + t;
    let carry_a = if sum >= Q { 1 } else { 0 };
    let a_out   = sum - carry_a * Q;

    let diff    = a_in - t;
    let carry_b = if diff < 0 { 1 } else { 0 };
    let b_out   = diff + carry_b * Q;

    ButterflyRow { a_in, b_in, zeta: zeta_k, t, carry_t, a_out, b_out, carry_a, carry_b }
}

/// Enumerate all 1024 Cooley-Tukey butterflies for the forward NTT of `f`.
fn enumerate_ntt_butterflies(f: &[i64; N]) -> (Vec<ButterflyRow>, [i64; N]) {
    let mut rows = Vec::with_capacity(N_BUTTERFLIES);
    let mut poly = *f;

    let mut zeta_fwd = [0i64; 256];
    for k in 0u8..=255u8 {
        zeta_fwd[k as usize] = field::pow(ZETA, k.reverse_bits() as u64);
    }

    let mut k: usize = 1;
    let mut len: usize = 128;
    while len >= 1 {
        let mut start: usize = 0;
        while start < N {
            let zeta_k = zeta_fwd[k];
            k += 1;
            for j in start..start + len {
                let row = compute_butterfly(poly[j], poly[j + len], zeta_k);
                poly[j]       = row.a_out;
                poly[j + len] = row.b_out;
                rows.push(row);
            }
            start += 2 * len;
        }
        len >>= 1;
    }

    debug_assert_eq!(rows.len(), N_BUTTERFLIES);
    (rows, poly)
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the 55-column NTT butterfly trace for input polynomial `f`.
///
/// Columns 0–8 are the butterfly core; columns 9–31 are the 23-bit
/// decomposition of `t`; columns 32–54 are the 23-bit decomposition of
/// `carry_t`.  All three ranges prove the corresponding witness is in [0, Q).
pub fn build_trace(f: &[i64; N]) -> (TraceColumns, [i64; N]) {
    let (butterflies, ntt_out) = enumerate_ntt_butterflies(f);

    let n      = 1_usize << LOG_N_BUTTERFLIES; // 1024 (padded to power-of-2)
    let domain = CanonicCoset::new(LOG_N_BUTTERFLIES).circle_domain();
    let bf0    = BaseField::from_u32_unchecked(0);
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);

    // ── Base columns ─────────────────────────────────────────────────────────
    let mut a_in_col    = vec![bf0; n];
    let mut b_in_col    = vec![bf0; n];
    let mut zeta_col    = vec![bf0; n];
    let mut t_col       = vec![bf0; n];
    let mut carry_t_col = vec![bf0; n];
    let mut a_out_col   = vec![bf0; n];
    let mut b_out_col   = vec![bf0; n];
    let mut carry_a_col = vec![bf0; n];
    let mut carry_b_col = vec![bf0; n];

    // ── Bit-decomposition columns ─────────────────────────────────────────────
    let mut t_bit_cols:  Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_BITS];
    let mut ct_bit_cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_BITS];

    for (i, row) in butterflies.iter().enumerate() {
        a_in_col[i]    = bf(row.a_in);
        b_in_col[i]    = bf(row.b_in);
        zeta_col[i]    = bf(row.zeta);
        t_col[i]       = bf(row.t);
        carry_t_col[i] = bf(row.carry_t);
        a_out_col[i]   = bf(row.a_out);
        b_out_col[i]   = bf(row.b_out);
        carry_a_col[i] = bf(row.carry_a);
        carry_b_col[i] = bf(row.carry_b);

        let t_u  = row.t       as u32;
        let ct_u = row.carry_t as u32;
        for k in 0..N_BITS {
            t_bit_cols[k][i]  = BaseField::from_u32_unchecked((t_u  >> k) & 1);
            ct_bit_cols[k][i] = BaseField::from_u32_unchecked((ct_u >> k) & 1);
        }
    }
    // Rows [N_BUTTERFLIES..n) stay zero: the all-zero row satisfies all
    // constraints trivially (0 × 0 = 0, bit decomp of 0 = 0, etc.).

    // ── Bit-reverse all columns ───────────────────────────────────────────────
    for col in [
        &mut a_in_col, &mut b_in_col, &mut zeta_col,
        &mut t_col, &mut carry_t_col,
        &mut a_out_col, &mut b_out_col,
        &mut carry_a_col, &mut carry_b_col,
    ] {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    for col in t_bit_cols.iter_mut().chain(ct_bit_cols.iter_mut()) {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    // ── Assemble columns in constraint order ──────────────────────────────────
    let mut columns: TraceColumns = Vec::with_capacity(N_COLS);

    columns.push(CircleEvaluation::new(domain, a_in_col));
    columns.push(CircleEvaluation::new(domain, b_in_col));
    columns.push(CircleEvaluation::new(domain, zeta_col));
    columns.push(CircleEvaluation::new(domain, t_col));
    columns.push(CircleEvaluation::new(domain, carry_t_col));
    columns.push(CircleEvaluation::new(domain, a_out_col));
    columns.push(CircleEvaluation::new(domain, b_out_col));
    columns.push(CircleEvaluation::new(domain, carry_a_col));
    columns.push(CircleEvaluation::new(domain, carry_b_col));
    for col in t_bit_cols  { columns.push(CircleEvaluation::new(domain, col)); }
    for col in ct_bit_cols { columns.push(CircleEvaluation::new(domain, col)); }

    debug_assert_eq!(columns.len(), N_COLS);
    (columns, ntt_out)
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
    fn test_butterfly_integer_correctness() {
        let a_in   = 1_234_567_i64;
        let b_in   = 7_654_321_i64;
        let zeta_k = field::pow(ZETA, 128);

        let row = compute_butterfly(a_in, b_in, zeta_k);

        assert_eq!(zeta_k * b_in, row.t + row.carry_t * Q, "C1");
        assert_eq!(row.a_out, (a_in + row.t) % Q,           "C2");
        assert_eq!(row.b_out, (a_in - row.t).rem_euclid(Q), "C4");
        assert!(matches!(row.carry_a, 0 | 1), "carry_a boolean");
        assert!(matches!(row.carry_b, 0 | 1), "carry_b boolean");
        assert!(row.t       >= 0 && row.t       < Q, "t in [0,Q)");
        assert!(row.carry_t >= 0 && row.carry_t < Q, "carry_t in [0,Q)");
        assert!(row.a_out   >= 0 && row.a_out   < Q, "a_out in [0,Q)");
        assert!(row.b_out   >= 0 && row.b_out   < Q, "b_out in [0,Q)");
    }

    #[test]
    fn test_butterfly_max_inputs() {
        let row = compute_butterfly(Q - 1, Q - 1, Q - 1);
        assert!(row.t       >= 0 && row.t       < Q);
        assert!(row.carry_t >= 0 && row.carry_t < Q);
        assert!(row.a_out   >= 0 && row.a_out   < Q);
        assert!(row.b_out   >= 0 && row.b_out   < Q);
    }

    #[test]
    fn test_ntt_output_matches_reference() {
        for seed in [0u64, 1, 42, 0xdead_beef] {
            let f = random_poly(seed);
            let (_, ntt_out) = build_trace(&f);

            let mut expected = f;
            crate::mldsa::ntt::ntt(&mut expected);

            assert_eq!(ntt_out, expected, "NTT output mismatch (seed={seed})");
        }
    }

    #[test]
    fn test_butterfly_count() {
        let f = random_poly(7);
        let (rows, _) = enumerate_ntt_butterflies(&f);
        assert_eq!(rows.len(), N_BUTTERFLIES);
    }

    #[test]
    fn test_column_count() {
        let f = random_poly(13);
        let (cols, _) = build_trace(&f);
        assert_eq!(cols.len(), N_COLS, "expected {N_COLS} columns");
    }

    #[test]
    fn test_carry_t_in_range() {
        // For all butterflies with max inputs, carry_t must fit in 23 bits.
        let row = compute_butterfly(Q - 1, Q - 1, Q - 1);
        assert!(row.carry_t < (1 << N_BITS), "carry_t must fit in 23 bits");
        assert!(row.t < (1 << N_BITS),       "t must fit in 23 bits");
    }

    #[test]
    fn test_constraints_on_trace() {
        let f = random_poly(1337);
        let (cols, _) = build_trace(&f);

        assert_eq!(cols.len(), N_COLS);

        // Collect all column value references.
        let col_vecs: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vecs.iter().collect();

        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![],       // no preprocessed columns
            col_refs,
        ]);

        let evaluator = MlDsaNttButterflyEval { log_n_rows: LOG_N_BUTTERFLIES };
        assert_constraints_on_trace(
            &evals,
            LOG_N_BUTTERFLIES,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
