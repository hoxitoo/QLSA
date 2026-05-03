/// Poseidon2-over-M31 AIR (Circle STARK — Stwo 2.2.0)
///
/// # Trace layout
///
/// Each Poseidon2 permutation takes N_ROUNDS = 8 rows (one per round).
/// Row `b*N_ROUNDS + r` belongs to block `b` (leaf `b`), round `r`.
///
/// Main trace (7 columns, in order):
///   0  s0    : state element 0 after this round
///   1  s1    : state element 1 after this round
///   2  t0    : (inp0 + rc0)^2  — SBox helper for s0
///   3  t1    : (inp1 + rc1)^2  — SBox helper for s1
///   4  inp0  : input to round for s0  =  (1-init_row)*s0[-1] + is_init*leaf
///   5  leaf  : leaf value (non-zero only on is_init rows, i.e. r == 0)
///   6  inp1  : input to round for s1  =  (1-init_row)*s1[-1]
///
/// Preprocessed trace (4 columns, in order):
///   0  rc0      : RC[r % N_ROUNDS][0]
///   1  rc1      : RC[r % N_ROUNDS][1]
///   2  is_init  : 1 if r % N_ROUNDS == 0, else 0
///   3  init_row : 1 if row index == 0, else 0
///
/// # Constraints (×6, all degree ≤ 3)
///
///   C1     inp0  − (1−init_row)·s0[−1] − is_init·leaf = 0       (degree 2)
///   C_inp1 inp1  − (1−init_row)·s1[−1]                = 0       (degree 2)
///   C2     t0    − (inp0 + rc0)²                       = 0       (degree 2)
///   C3     t1    − (inp1 + rc1)²                       = 0       (degree 2)
///   C4     s0    − (3·t0²·(inp0+rc0)  +  t1²·(inp1+rc1)) = 0    (degree 3)
///   C5     s1    − (  t0²·(inp0+rc0)  + 3·t1²·(inp1+rc1)) = 0   (degree 3)
///
/// # Wrap-around
///
/// Circle STARK evaluates constraints on all rows, including the wrap-around
/// row n−1 → 0.  At row 0:
///   init_row[0] = 1  →  (1−init_row)·s0[n−1] = 0,  (1−init_row)·s1[n−1] = 0
///   inp0[0] = is_init[0]·leaf[0] = leaf[0]   (initial state forced to 0)
///   inp1[0] = 0                               (initial s1=0)
///
/// Using inp1 as an explicit trace column (degree 1) keeps x1 = inp1 + rc1 at
/// degree 1, so all constraint degrees stay ≤ 3, satisfying the bound
/// max_constraint_log_degree_bound = log_n_rows + 1.
///
/// Padding rows (n_real..n−1) continue absorbing zero leaves — their constraints
/// hold by construction when the trace builder propagates the permutation.

use stwo::core::fields::m31::BaseField;
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
use stwo::core::fields::qm31::SecureField;

use crate::poseidon2::{M31_P, N_ROUNDS, RC, m31_add, m31_mul};

// ── Type aliases ─────────────────────────────────────────────────────────────

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

/// Minimum trace log2-size (Stwo requires ≥ 4 rows; we enforce ≥ 8 = 2^3).
pub const MIN_LOG_SIZE: u32 = 3;

// ── Preprocessed column IDs ───────────────────────────────────────────────────

pub fn pc_rc0()     -> PreProcessedColumnId { PreProcessedColumnId { id: "p2_rc0".into() } }
pub fn pc_rc1()     -> PreProcessedColumnId { PreProcessedColumnId { id: "p2_rc1".into() } }
pub fn pc_is_init() -> PreProcessedColumnId { PreProcessedColumnId { id: "p2_is_init".into() } }
pub fn pc_init_row()-> PreProcessedColumnId { PreProcessedColumnId { id: "p2_init_row".into() } }

pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    vec![pc_rc0(), pc_rc1(), pc_is_init(), pc_init_row()]
}

// ── Trace size helpers ────────────────────────────────────────────────────────

/// Total trace rows = smallest 2^k ≥ n_leaves·N_ROUNDS, with k ≥ MIN_LOG_SIZE.
pub fn compute_log_size(n_leaves: usize) -> u32 {
    // checked_mul prevents overflow for n_leaves > ~2^61; callers reject u32::MAX
    // because it exceeds MAX_LOG_SIZE (28).
    let n_real = match n_leaves.checked_mul(N_ROUNDS) {
        Some(v) => v,
        None => return u32::MAX,
    };
    let needed = n_real.max(1 << MIN_LOG_SIZE);
    let p2 = needed.next_power_of_two();
    p2.trailing_zeros().max(MIN_LOG_SIZE)
}

// ── FrameworkEval impl ────────────────────────────────────────────────────────

pub struct Poseidon2Eval {
    pub log_n_rows: u32,
}

pub type Poseidon2Component = FrameworkComponent<Poseidon2Eval>;

impl FrameworkEval for Poseidon2Eval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Degree-3 constraints: quotient has 2·2^n = 2^(n+1) coefficients.
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // ── Preprocessed columns (order must match trace builder) ─────────
        let rc0      = eval.get_preprocessed_column(pc_rc0());
        let rc1      = eval.get_preprocessed_column(pc_rc1());
        let is_init  = eval.get_preprocessed_column(pc_is_init());
        let init_row = eval.get_preprocessed_column(pc_init_row());

        // ── Main trace columns ─────────────────────────────────────────────
        let [s0_curr, s0_prev] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [s1_curr, s1_prev] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [t0]   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [t1]   = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [inp0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [leaf] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        // inp1 is an explicit trace column so that x1 = inp1 + rc1 is degree 1,
        // keeping all constraint degrees ≤ 3.
        let [inp1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        // ── Helpers ────────────────────────────────────────────────────────
        let one = E::F::from(BaseField::from_u32_unchecked(1));

        // (1 − init_row) gates the Circle-STARK wrap-around at row 0.
        let not_init_row = one - init_row.clone();
        let s0_prev_gated = not_init_row.clone() * s0_prev;
        let s1_prev_gated = not_init_row * s1_prev;

        // inp0_expected = (1−init_row)·s0[−1] + is_init·leaf
        let inp0_expected = s0_prev_gated + is_init.clone() * leaf;

        // x0 = inp0 + rc0  (degree 1)
        // x1 = inp1 + rc1  (degree 1, via explicit inp1 column)
        let x0 = inp0.clone() + rc0;
        let x1 = inp1.clone() + rc1;

        // SBox witnesses: t0 = x0^2,  t1 = x1^2  (degree 2 each)
        // x^5 = t^2 · x
        let sbox0 = t0.clone() * t0.clone() * x0.clone();  // degree 3
        let sbox1 = t1.clone() * t1.clone() * x1.clone();  // degree 3

        // MDS [[3,1],[1,3]]:
        //   s0_new = 3·sbox0 + sbox1
        //   s1_new = sbox0 + 3·sbox1
        let three = BaseField::from_u32_unchecked(3);
        let s0_expected = sbox0.clone() * three + sbox1.clone();
        let s1_expected = sbox0 + sbox1 * three;

        // ── Constraints ───────────────────────────────────────────────────
        // C1: inp0 = (1−init_row)·s0[−1] + is_init·leaf          (degree 2)
        eval.add_constraint(inp0.clone() - inp0_expected);
        // C_inp1: inp1 = (1−init_row)·s1[−1]                      (degree 2)
        eval.add_constraint(inp1 - s1_prev_gated);
        // C2: t0 = (inp0+rc0)²                                     (degree 2)
        eval.add_constraint(t0 - x0.clone() * x0);
        // C3: t1 = (inp1+rc1)²                                     (degree 2)
        eval.add_constraint(t1 - x1.clone() * x1);
        // C4: s0 update                                             (degree 3)
        eval.add_constraint(s0_curr - s0_expected);
        // C5: s1 update                                             (degree 3)
        eval.add_constraint(s1_curr - s1_expected);

        eval
    }
}

/// Create a Poseidon2Component with the correct preprocessed column allocator.
pub fn new_component(log_n_rows: u32) -> Poseidon2Component {
    let ids = preprocessed_column_ids();
    Poseidon2Component::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&ids),
        Poseidon2Eval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the execution trace for `n_leaves` Poseidon2 absorptions.
///
/// Returns `(main_columns, preprocessed_columns, commitment)` where:
///   - `main_columns`: 7 columns in circle-domain bit-reversed order
///   - `preprocessed_columns`: 4 columns in the same order
///   - `commitment`: s0 value at the last REAL row (row n_leaves·N_ROUNDS − 1)
pub fn build_trace(
    leaves: &[u64],
) -> (TraceColumns, TraceColumns, BaseField) {
    assert!(!leaves.is_empty(), "leaves must not be empty");

    let n_leaves = leaves.len();
    let log_size = compute_log_size(n_leaves);
    let n = 1_usize << log_size;
    let n_real = n_leaves * N_ROUNDS;
    let domain = CanonicCoset::new(log_size).circle_domain();

    let to_m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);
    let bf_one  = BaseField::from_u32_unchecked(1);
    let bf_zero = BaseField::from_u32_unchecked(0);

    // ── Allocate columns ─────────────────────────────────────────────────
    // Main (7 columns)
    let mut s0_col   = vec![bf_zero; n];
    let mut s1_col   = vec![bf_zero; n];
    let mut t0_col   = vec![bf_zero; n];
    let mut t1_col   = vec![bf_zero; n];
    let mut inp0_col = vec![bf_zero; n];
    let mut leaf_col = vec![bf_zero; n];
    let mut inp1_col = vec![bf_zero; n];

    // Preprocessed
    let mut rc0_col      = vec![bf_zero; n];
    let mut rc1_col      = vec![bf_zero; n];
    let mut is_init_col  = vec![bf_zero; n];
    let mut init_row_col = vec![bf_zero; n];

    // ── Fill preprocessed columns (depend only on row index) ─────────────
    for i in 0..n {
        let r = i % N_ROUNDS;
        rc0_col[i]      = to_m31(RC[r][0] as u64);
        rc1_col[i]      = to_m31(RC[r][1] as u64);
        is_init_col[i]  = if r == 0 { bf_one } else { bf_zero };
        init_row_col[i] = if i == 0 { bf_one } else { bf_zero };
    }

    // ── Fill main trace ───────────────────────────────────────────────────
    // `state` tracks (s0, s1) flowing through the sponge.  It starts at (0,0)
    // and is updated after every round.  Padding rows (i ≥ n_real) absorb
    // zero leaves, keeping the computation consistent with the constraints.
    //
    // inp1_col[row] = state[1] before the round = s1[row-1], except at row 0
    // where it is 0 (initial state).  This matches constraint C_inp1.
    let mut state = [0u64; 2];

    let leaf_at = |block: usize| -> u64 {
        if block < n_leaves { leaves[block] % M31_P } else { 0 }
    };

    for block in 0..(n / N_ROUNDS) {
        let lf = leaf_at(block);

        for r in 0..N_ROUNDS {
            let row = block * N_ROUNDS + r;

            // inp0: on round 0 of each block absorb the leaf.
            let inp0_val = if r == 0 {
                m31_add(state[0], lf)
            } else {
                state[0]
            };
            // inp1: state[1] before this round (= s1[row-1], or 0 at row 0).
            let inp1_val = state[1];

            let rc = [RC[r][0] as u64, RC[r][1] as u64];
            let x0 = m31_add(inp0_val, rc[0]);
            let x1 = m31_add(inp1_val, rc[1]);

            // t0 = x0^2,  t1 = x1^2
            let t0_val = m31_mul(x0, x0);
            let t1_val = m31_mul(x1, x1);

            // sbox(x) = t^2 · x = x^5
            let sbox0 = m31_mul(m31_mul(t0_val, t0_val), x0);
            let sbox1 = m31_mul(m31_mul(t1_val, t1_val), x1);

            // MDS [[3,1],[1,3]]
            let s0_new = m31_add(
                m31_add(m31_add(sbox0, sbox0), sbox0), // 3·sbox0
                sbox1,
            );
            let s1_new = m31_add(
                sbox0,
                m31_add(m31_add(sbox1, sbox1), sbox1), // 3·sbox1
            );

            // Write main trace
            inp0_col[row] = to_m31(inp0_val);
            inp1_col[row] = to_m31(inp1_val);
            leaf_col[row] = if r == 0 { to_m31(lf) } else { bf_zero };
            t0_col[row]   = to_m31(t0_val);
            t1_col[row]   = to_m31(t1_val);
            s0_col[row]   = to_m31(s0_new);
            s1_col[row]   = to_m31(s1_new);

            state[0] = s0_new;
            state[1] = s1_new;
        }
    }

    // Commitment = s0 at the last REAL row.
    let commitment = s0_col[n_real - 1];

    // ── Bit-reverse all columns to circle-domain storage order ────────────
    for col in [
        &mut s0_col, &mut s1_col, &mut t0_col, &mut t1_col,
        &mut inp0_col, &mut leaf_col, &mut inp1_col,
        &mut rc0_col, &mut rc1_col, &mut is_init_col, &mut init_row_col,
    ] {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    let main_cols = vec![
        CircleEvaluation::new(domain, s0_col),
        CircleEvaluation::new(domain, s1_col),
        CircleEvaluation::new(domain, t0_col),
        CircleEvaluation::new(domain, t1_col),
        CircleEvaluation::new(domain, inp0_col),
        CircleEvaluation::new(domain, leaf_col),
        CircleEvaluation::new(domain, inp1_col),
    ];
    let preproc_cols = vec![
        CircleEvaluation::new(domain, rc0_col),
        CircleEvaluation::new(domain, rc1_col),
        CircleEvaluation::new(domain, is_init_col),
        CircleEvaluation::new(domain, init_row_col),
    ];

    (main_cols, preproc_cols, commitment)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::{assert_constraints_on_trace, FrameworkEval};

    #[test]
    fn test_compute_log_size() {
        assert_eq!(compute_log_size(1), 3); // 8 rows → need 2^3 = 8
        assert_eq!(compute_log_size(4), 5); // 32 rows → need 2^5 = 32
        assert_eq!(compute_log_size(8), 6); // 64 rows → need 2^6 = 64
    }

    #[test]
    fn test_build_trace_commitment_matches_chain() {
        use crate::poseidon2::poseidon2_chain;

        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (_, _, commitment) = build_trace(&leaves);
        let (expected_s0, _) = poseidon2_chain(&leaves);

        assert_eq!(
            commitment,
            BaseField::from_u32_unchecked(expected_s0 as u32),
            "AIR commitment must match poseidon2_chain output"
        );
    }

    #[test]
    fn test_constraints_on_trace() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (main_cols, preproc_cols, _) = build_trace(&leaves);
        let log_size = compute_log_size(leaves.len());

        let s0_v:    Vec<M31> = main_cols[0].values.clone();
        let s1_v:    Vec<M31> = main_cols[1].values.clone();
        let t0_v:    Vec<M31> = main_cols[2].values.clone();
        let t1_v:    Vec<M31> = main_cols[3].values.clone();
        let inp0_v:  Vec<M31> = main_cols[4].values.clone();
        let leaf_v:  Vec<M31> = main_cols[5].values.clone();
        let inp1_v:  Vec<M31> = main_cols[6].values.clone();

        let rc0_v:      Vec<M31> = preproc_cols[0].values.clone();
        let rc1_v:      Vec<M31> = preproc_cols[1].values.clone();
        let is_init_v:  Vec<M31> = preproc_cols[2].values.clone();
        let init_row_v: Vec<M31> = preproc_cols[3].values.clone();

        // TreeVec order: [preprocessed, main]
        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![&rc0_v, &rc1_v, &is_init_v, &init_row_v],
            vec![&s0_v, &s1_v, &t0_v, &t1_v, &inp0_v, &leaf_v, &inp1_v],
        ]);

        let eval_obj = Poseidon2Eval { log_n_rows: log_size };
        assert_constraints_on_trace(
            &evals,
            log_size,
            |eval| { eval_obj.evaluate(eval); },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn test_build_trace_small() {
        // Smoke test: 1 leaf — should not panic and produce a valid commitment.
        let (_, _, commitment) = build_trace(&[42u64]);
        assert_ne!(commitment, BaseField::from_u32_unchecked(0));
    }
}
