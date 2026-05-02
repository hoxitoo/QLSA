/// Poseidon2 Merkle-tree AIR (compression-function mode, Stwo 2.2.0)
///
/// Proves that N leaves hash to a given Merkle root using Poseidon2 as the
/// 2-to-1 compression function:
///
///   H(left, right) = Poseidon2_permutation([left, right])[0]
///
/// # Trace layout
///
/// Each H(left, right) call takes N_ROUNDS = 8 rows (one per permutation round).
/// Row `node * N_ROUNDS + r` belongs to Merkle node `node`, round `r`.
/// Nodes are processed bottom-up, left-to-right:
///   - Level 1: hash(leaf[2i], leaf[2i+1]) for i = 0..N/2
///   - Level 2: hash(level1[2i], level1[2i+1]) …
///   - …until the root
///
/// Main trace (8 columns):
///   0  s0    : state[0] after round r
///   1  s1    : state[1] after round r
///   2  t0    : (inp0 + rc0)²  — SBox helper
///   3  t1    : (inp1 + rc1)²  — SBox helper
///   4  inp0  : is_init·left  + (1−is_init)·s0[−1]
///   5  left  : left child (non-zero only at is_init rows)
///   6  inp1  : is_init·right + (1−is_init)·s1[−1]
///   7  right : right child (non-zero only at is_init rows)
///
/// Preprocessed trace (3 columns):
///   0  rc0     : RC[r % N_ROUNDS][0]
///   1  rc1     : RC[r % N_ROUNDS][1]
///   2  is_init : 1 if r % N_ROUNDS == 0, else 0
///
/// # Constraints (×6, all degree ≤ 3)
///
///   C1     inp0 − is_init·left  − (1−is_init)·s0[−1] = 0    (degree 2)
///   C_inp1 inp1 − is_init·right − (1−is_init)·s1[−1] = 0    (degree 2)
///   C2     t0   − (inp0+rc0)²                         = 0    (degree 2)
///   C3     t1   − (inp1+rc1)²                         = 0    (degree 2)
///   C4     s0   − (3·t0²·(inp0+rc0) +   t1²·(inp1+rc1)) = 0 (degree 3)
///   C5     s1   − (  t0²·(inp0+rc0) + 3·t1²·(inp1+rc1)) = 0 (degree 3)
///
/// # Wrap-around
///
/// Circle STARK evaluates on all rows including row 0 → n−1 wrap.
/// At row 0: is_init[0] = 1, so (1−is_init)·s0[n−1] = 0 and
/// (1−is_init)·s1[n−1] = 0. Constraints reduce to inp0[0]=left[0],
/// inp1[0]=right[0]. No init_row column needed.

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

use crate::poseidon2::{M31_P, N_ROUNDS, RC, m31_add, m31_mul, permute};

// ── Type aliases ─────────────────────────────────────────────────────────────

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

/// Minimum trace log2-size (≥ 8 rows = 1 Merkle hash).
pub const MIN_LOG_SIZE: u32 = 3;

// ── Preprocessed column IDs ───────────────────────────────────────────────────

pub fn pc_rc0()     -> PreProcessedColumnId { PreProcessedColumnId { id: "p2m_rc0".into() } }
pub fn pc_rc1()     -> PreProcessedColumnId { PreProcessedColumnId { id: "p2m_rc1".into() } }
pub fn pc_is_init() -> PreProcessedColumnId { PreProcessedColumnId { id: "p2m_is_init".into() } }

pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    vec![pc_rc0(), pc_rc1(), pc_is_init()]
}

// ── Trace size helpers ────────────────────────────────────────────────────────

/// Returns the number of leaves padded to the next power of 2 ≥ 2.
pub fn padded_leaf_count(n_leaves: usize) -> usize {
    n_leaves.max(2).next_power_of_two()
}

/// Number of internal Merkle nodes for `n_leaves_padded` leaves (= n_padded − 1).
pub fn n_merkle_nodes(n_leaves_padded: usize) -> usize {
    n_leaves_padded - 1
}

/// Total real trace rows = n_nodes × N_ROUNDS.
pub fn compute_log_size(n_leaves: usize) -> u32 {
    let n_padded = padded_leaf_count(n_leaves);
    let n_real = n_merkle_nodes(n_padded) * N_ROUNDS;
    let needed = n_real.max(1 << MIN_LOG_SIZE);
    let p2 = needed.next_power_of_two();
    p2.trailing_zeros().max(MIN_LOG_SIZE)
}

// ── Poseidon2 compression (2-to-1 hash) ─────────────────────────────────────

/// Compute H(left, right) = Poseidon2([left, right])[0].
pub fn compress(left: u64, right: u64) -> u64 {
    let mut state = [left % M31_P, right % M31_P];
    permute(&mut state);
    state[0]
}

/// Build the full Merkle tree from leaves using Poseidon2 compression.
/// Returns all levels, starting from leaves (index 0) up to the root (last index).
pub fn build_merkle_tree(leaves: &[u64]) -> Vec<Vec<u64>> {
    let n_padded = padded_leaf_count(leaves.len());
    let mut level: Vec<u64> = (0..n_padded)
        .map(|i| if i < leaves.len() { leaves[i] % M31_P } else { 0 })
        .collect();
    let mut tree = vec![level.clone()];
    while level.len() > 1 {
        level = level.chunks(2).map(|pair| compress(pair[0], pair[1])).collect();
        tree.push(level.clone());
    }
    tree
}

/// Return the Merkle root for the given leaves.
pub fn merkle_root(leaves: &[u64]) -> u64 {
    let tree = build_merkle_tree(leaves);
    tree.last().unwrap()[0]
}

// ── FrameworkEval impl ────────────────────────────────────────────────────────

pub struct Poseidon2MerkleEval {
    pub log_n_rows: u32,
}

pub type Poseidon2MerkleComponent = FrameworkComponent<Poseidon2MerkleEval>;

impl FrameworkEval for Poseidon2MerkleEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Degree-3 constraints → degree-4 quotient: 2·2^n coefficients = 2^(n+1).
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // ── Preprocessed columns ─────────────────────────────────────────────
        let rc0      = eval.get_preprocessed_column(pc_rc0());
        let rc1      = eval.get_preprocessed_column(pc_rc1());
        let is_init  = eval.get_preprocessed_column(pc_is_init());

        // ── Main trace columns ───────────────────────────────────────────────
        let [s0_curr, s0_prev] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [s1_curr, s1_prev] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [t0]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [t1]    = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [inp0]  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [left]  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [inp1]  = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [right] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        // ── Helpers ──────────────────────────────────────────────────────────
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let not_init = one - is_init.clone();

        // inp0 = is_init*left + (1-is_init)*s0[-1]
        let inp0_expected = is_init.clone() * left + not_init.clone() * s0_prev;
        // inp1 = is_init*right + (1-is_init)*s1[-1]
        let inp1_expected = is_init * right + not_init * s1_prev;

        // x0 = inp0+rc0, x1 = inp1+rc1  (degree 1)
        let x0 = inp0.clone() + rc0;
        let x1 = inp1.clone() + rc1;

        // sbox(x) = t^2*x = x^5  where t = x^2
        let sbox0 = t0.clone() * t0.clone() * x0.clone(); // degree 3
        let sbox1 = t1.clone() * t1.clone() * x1.clone(); // degree 3

        // MDS [[3,1],[1,3]]
        let three = BaseField::from_u32_unchecked(3);
        let s0_expected = sbox0.clone() * three + sbox1.clone();
        let s1_expected = sbox0 + sbox1 * three;

        // ── Constraints ──────────────────────────────────────────────────────
        // C1:     inp0 initialization                         (degree 2)
        eval.add_constraint(inp0.clone() - inp0_expected);
        // C_inp1: inp1 initialization                         (degree 2)
        eval.add_constraint(inp1 - inp1_expected);
        // C2:     t0 = (inp0+rc0)²                           (degree 2)
        eval.add_constraint(t0 - x0.clone() * x0);
        // C3:     t1 = (inp1+rc1)²                           (degree 2)
        eval.add_constraint(t1 - x1.clone() * x1);
        // C4:     s0 update                                   (degree 3)
        eval.add_constraint(s0_curr - s0_expected);
        // C5:     s1 update                                   (degree 3)
        eval.add_constraint(s1_curr - s1_expected);

        eval
    }
}

/// Create a Poseidon2MerkleComponent with the correct preprocessed allocator.
pub fn new_component(log_n_rows: u32) -> Poseidon2MerkleComponent {
    let ids = preprocessed_column_ids();
    Poseidon2MerkleComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&ids),
        Poseidon2MerkleEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the Poseidon2 Merkle execution trace for `leaves`.
///
/// Returns `(main_columns, preprocessed_columns, root_commitment)` where:
///   - `main_columns`: 8 columns in circle-domain bit-reversed order
///   - `preprocessed_columns`: 3 columns in the same order
///   - `root_commitment`: the Merkle root as an M31 field element
pub fn build_trace(leaves: &[u64]) -> (TraceColumns, TraceColumns, BaseField) {
    assert!(!leaves.is_empty(), "leaves must not be empty");

    let n_padded  = padded_leaf_count(leaves.len());
    let log_size  = compute_log_size(leaves.len());
    let n         = 1_usize << log_size;
    let n_nodes   = n_merkle_nodes(n_padded);
    let n_real    = n_nodes * N_ROUNDS;
    let domain    = CanonicCoset::new(log_size).circle_domain();

    let to_m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);
    let bf_one  = BaseField::from_u32_unchecked(1);
    let bf_zero = BaseField::from_u32_unchecked(0);

    // ── Allocate columns ─────────────────────────────────────────────────────
    let mut s0_col    = vec![bf_zero; n];
    let mut s1_col    = vec![bf_zero; n];
    let mut t0_col    = vec![bf_zero; n];
    let mut t1_col    = vec![bf_zero; n];
    let mut inp0_col  = vec![bf_zero; n];
    let mut left_col  = vec![bf_zero; n];
    let mut inp1_col  = vec![bf_zero; n];
    let mut right_col = vec![bf_zero; n];

    let mut rc0_col      = vec![bf_zero; n];
    let mut rc1_col      = vec![bf_zero; n];
    let mut is_init_col  = vec![bf_zero; n];

    // ── Preprocessed: periodic by round ──────────────────────────────────────
    for i in 0..n {
        let r = i % N_ROUNDS;
        rc0_col[i]     = to_m31(RC[r][0] as u64);
        rc1_col[i]     = to_m31(RC[r][1] as u64);
        is_init_col[i] = if r == 0 { bf_one } else { bf_zero };
    }

    // ── Build the full Merkle tree ────────────────────────────────────────────
    let tree = build_merkle_tree(leaves);

    // ── Fill trace bottom-up, left-to-right ──────────────────────────────────
    // We walk through the tree levels and for each pair of children, record
    // the 8-round Poseidon2 permutation of [left, right].
    let mut node_idx = 0usize; // index into the trace (which block we're filling)

    for level in 0..tree.len() - 1 {
        let children = &tree[level];
        for pair in children.chunks(2) {
            let lv = pair[0];
            let rv = pair[1];

            let mut state = [lv, rv];
            for r in 0..N_ROUNDS {
                let row = node_idx * N_ROUNDS + r;
                let inp0_val = if r == 0 { lv } else { state[0] };
                let inp1_val = if r == 0 { rv } else { state[1] };

                let rc = [RC[r][0] as u64, RC[r][1] as u64];
                let x0 = m31_add(inp0_val, rc[0]);
                let x1 = m31_add(inp1_val, rc[1]);
                let t0v = m31_mul(x0, x0);
                let t1v = m31_mul(x1, x1);
                let sbox0 = m31_mul(m31_mul(t0v, t0v), x0);
                let sbox1 = m31_mul(m31_mul(t1v, t1v), x1);
                let s0_new = m31_add(m31_add(m31_add(sbox0, sbox0), sbox0), sbox1);
                let s1_new = m31_add(sbox0, m31_add(m31_add(sbox1, sbox1), sbox1));

                inp0_col[row]  = to_m31(inp0_val);
                inp1_col[row]  = to_m31(inp1_val);
                left_col[row]  = if r == 0 { to_m31(lv) } else { bf_zero };
                right_col[row] = if r == 0 { to_m31(rv) } else { bf_zero };
                t0_col[row]    = to_m31(t0v);
                t1_col[row]    = to_m31(t1v);
                s0_col[row]    = to_m31(s0_new);
                s1_col[row]    = to_m31(s1_new);

                state[0] = s0_new;
                state[1] = s1_new;
            }
            node_idx += 1;
        }
    }

    // Padding nodes: H(0, 0) — valid computation that keeps constraints satisfied.
    while node_idx * N_ROUNDS < n {
        let mut state = [0u64, 0u64];
        for r in 0..N_ROUNDS {
            let row = node_idx * N_ROUNDS + r;
            let inp0_val = if r == 0 { 0 } else { state[0] };
            let inp1_val = if r == 0 { 0 } else { state[1] };
            let rc = [RC[r][0] as u64, RC[r][1] as u64];
            let x0 = m31_add(inp0_val, rc[0]);
            let x1 = m31_add(inp1_val, rc[1]);
            let t0v = m31_mul(x0, x0);
            let t1v = m31_mul(x1, x1);
            let sbox0 = m31_mul(m31_mul(t0v, t0v), x0);
            let sbox1 = m31_mul(m31_mul(t1v, t1v), x1);
            let s0_new = m31_add(m31_add(m31_add(sbox0, sbox0), sbox0), sbox1);
            let s1_new = m31_add(sbox0, m31_add(m31_add(sbox1, sbox1), sbox1));

            inp0_col[row]  = to_m31(inp0_val);
            inp1_col[row]  = to_m31(inp1_val);
            left_col[row]  = bf_zero;
            right_col[row] = bf_zero;
            t0_col[row]    = to_m31(t0v);
            t1_col[row]    = to_m31(t1v);
            s0_col[row]    = to_m31(s0_new);
            s1_col[row]    = to_m31(s1_new);

            state[0] = s0_new;
            state[1] = s1_new;
        }
        node_idx += 1;
    }

    // Root commitment = s0 at the last round of the last REAL node.
    // IMPORTANT: this read MUST happen before bit_reverse_coset_to_circle_domain_order;
    // after bit-reversal s0_col[n_real-1] no longer corresponds to the final round output.
    let root_commitment = s0_col[n_real - 1];

    // ── Bit-reverse all columns ───────────────────────────────────────────────
    for col in [
        &mut s0_col, &mut s1_col, &mut t0_col, &mut t1_col,
        &mut inp0_col, &mut left_col, &mut inp1_col, &mut right_col,
        &mut rc0_col, &mut rc1_col, &mut is_init_col,
    ] {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    let main_cols = vec![
        CircleEvaluation::new(domain, s0_col),
        CircleEvaluation::new(domain, s1_col),
        CircleEvaluation::new(domain, t0_col),
        CircleEvaluation::new(domain, t1_col),
        CircleEvaluation::new(domain, inp0_col),
        CircleEvaluation::new(domain, left_col),
        CircleEvaluation::new(domain, inp1_col),
        CircleEvaluation::new(domain, right_col),
    ];
    let preproc_cols = vec![
        CircleEvaluation::new(domain, rc0_col),
        CircleEvaluation::new(domain, rc1_col),
        CircleEvaluation::new(domain, is_init_col),
    ];

    (main_cols, preproc_cols, root_commitment)
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
    fn test_compress_is_deterministic() {
        let h1 = compress(1, 2);
        let h2 = compress(1, 2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compress_is_not_symmetric() {
        // Poseidon2([a,b]) ≠ Poseidon2([b,a]) in general.
        let h_ab = compress(100, 200);
        let h_ba = compress(200, 100);
        assert_ne!(h_ab, h_ba, "compression must not be symmetric");
    }

    #[test]
    fn test_compress_output_in_m31() {
        let h = compress(0xDEAD_BEEF, 0x1234_5678);
        assert!(h < M31_P, "output must be in M31 range");
    }

    #[test]
    fn test_merkle_root_two_leaves() {
        let leaves = [10u64, 20];
        let root = merkle_root(&leaves);
        let expected = compress(10, 20);
        assert_eq!(root, expected, "root of 2 leaves = compress(l0, l1)");
    }

    #[test]
    fn test_merkle_root_four_leaves() {
        let leaves = [1u64, 2, 3, 4];
        let root = merkle_root(&leaves);
        let h01 = compress(1, 2);
        let h23 = compress(3, 4);
        let expected = compress(h01, h23);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_changes_with_leaf() {
        let leaves_a = [1u64, 2, 3, 4];
        let leaves_b = [1u64, 2, 3, 5]; // last leaf differs
        assert_ne!(merkle_root(&leaves_a), merkle_root(&leaves_b));
    }

    #[test]
    fn test_compute_log_size() {
        assert_eq!(compute_log_size(1), 3); //  1 node → 8 rows → 2^3
        assert_eq!(compute_log_size(2), 3); //  1 node → 8 rows → 2^3
        assert_eq!(compute_log_size(3), 5); //  3 nodes → 24 rows → 2^5
        assert_eq!(compute_log_size(4), 5); //  3 nodes → 24 rows → 2^5
        assert_eq!(compute_log_size(8), 6); //  7 nodes → 56 rows → 2^6
    }

    #[test]
    fn test_build_trace_root_matches_merkle_root() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (_, _, root_commit) = build_trace(&leaves);
        let expected = merkle_root(&leaves);
        assert_eq!(
            root_commit,
            BaseField::from_u32_unchecked(expected as u32),
            "trace commitment must equal direct merkle_root()"
        );
    }

    #[test]
    fn test_constraints_on_trace_small() {
        let leaves = vec![1u64, 2, 3, 4];
        let (main_cols, preproc_cols, _) = build_trace(&leaves);
        let log_size = compute_log_size(leaves.len());

        let s0_v:    Vec<M31> = main_cols[0].values.clone();
        let s1_v:    Vec<M31> = main_cols[1].values.clone();
        let t0_v:    Vec<M31> = main_cols[2].values.clone();
        let t1_v:    Vec<M31> = main_cols[3].values.clone();
        let inp0_v:  Vec<M31> = main_cols[4].values.clone();
        let left_v:  Vec<M31> = main_cols[5].values.clone();
        let inp1_v:  Vec<M31> = main_cols[6].values.clone();
        let right_v: Vec<M31> = main_cols[7].values.clone();

        let rc0_v:      Vec<M31> = preproc_cols[0].values.clone();
        let rc1_v:      Vec<M31> = preproc_cols[1].values.clone();
        let is_init_v:  Vec<M31> = preproc_cols[2].values.clone();

        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![&rc0_v, &rc1_v, &is_init_v],
            vec![&s0_v, &s1_v, &t0_v, &t1_v, &inp0_v, &left_v, &inp1_v, &right_v],
        ]);

        let eval_obj = Poseidon2MerkleEval { log_n_rows: log_size };
        assert_constraints_on_trace(
            &evals,
            log_size,
            |eval| { eval_obj.evaluate(eval); },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn test_constraints_on_trace_eight_leaves() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (main_cols, preproc_cols, _) = build_trace(&leaves);
        let log_size = compute_log_size(leaves.len());

        let s0_v:    Vec<M31> = main_cols[0].values.clone();
        let s1_v:    Vec<M31> = main_cols[1].values.clone();
        let t0_v:    Vec<M31> = main_cols[2].values.clone();
        let t1_v:    Vec<M31> = main_cols[3].values.clone();
        let inp0_v:  Vec<M31> = main_cols[4].values.clone();
        let left_v:  Vec<M31> = main_cols[5].values.clone();
        let inp1_v:  Vec<M31> = main_cols[6].values.clone();
        let right_v: Vec<M31> = main_cols[7].values.clone();

        let rc0_v:     Vec<M31> = preproc_cols[0].values.clone();
        let rc1_v:     Vec<M31> = preproc_cols[1].values.clone();
        let is_init_v: Vec<M31> = preproc_cols[2].values.clone();

        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![&rc0_v, &rc1_v, &is_init_v],
            vec![&s0_v, &s1_v, &t0_v, &t1_v, &inp0_v, &left_v, &inp1_v, &right_v],
        ]);

        let eval_obj = Poseidon2MerkleEval { log_n_rows: log_size };
        assert_constraints_on_trace(
            &evals,
            log_size,
            |eval| { eval_obj.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
