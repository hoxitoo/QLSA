//! Nonce-tree UPDATE AIR — two Poseidon2 t=8 lanes on ONE sibling path (A-4).
//!
//! An update to a sparse Merkle tree replaces one leaf. Its witness is ONE
//! sibling path: hashed up from the old leaf it must reach the old root, hashed
//! up from the new leaf it must reach the new root. Only the leaf and the nodes
//! above it change; the siblings hang off the path and do not.
//!
//! # Why a new AIR, and not two `merkle_path_t8_air` paths
//!
//! That is what `nonce_accumulator` did first: path `2i` (old leaf → pre-root)
//! and path `2i+1` (new leaf → post-root), each a separate path in the shared
//! Merkle component. The honest prover gave both the same siblings, but nothing
//! REQUIRED it — every row's `sib` is free witness. So a prover could take the
//! new path's siblings from a DIFFERENT tree, one where another sender's slot is
//! reset to 0, and claim that tree's root as `post_root`: every pinned leaf,
//! index and root still checks out, and the reset sender can replay. Shown by
//! test in `bafbcf8` (TECH_DEBT § A-4).
//!
//! Here one row carries BOTH lanes, and `sib`/`bit` are single columns read by
//! both. That the two lanes share their siblings is not a constraint a prover
//! could slip past — there is nothing to tell their siblings apart with.
//!
//! # Layout (85 main + 30 preprocessed columns)
//!
//! Update `u` of depth `D` occupies compressions `u·D .. u·D + D`, each 22 rows
//! (one t=8 round per row), exactly as a `merkle_path_t8_air` path does.
//!
//! ```text
//! Main:   lane A: in[8] sq[8] sbox[8] out[8] cur[4] leaf[4]     (old leaf → pre-root)
//!         lane B: in[8] sq[8] sbox[8] out[8] cur[4] leaf[4]     (new leaf → post-root)
//!         sib[4] bit                                            (SHARED)
//! Preproc: rc[8] is_ext is_int is_first_comp is_first_path idx_bit   (shared)
//!          leaf_a[4] leaf_b[4] is_root root_a[4] root_b[4]           (per-lane pins)
//! ```
//!
//! Each lane's constraints are `MerklePathT8Eval`'s, verbatim, written once in
//! [`constrain_lane`] and applied twice. Preprocessed ids carry the `nut8_`
//! prefix so this component can later sit beside `merkle_path_t8_air` (`mpt8_`)
//! in one tree node without the allocator conflating their columns.

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::CommitmentSchemeProver;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

use crate::poseidon2::{m31_add, m31_mul, sbox as sbox_ref, M31_P};
use crate::poseidon2_t8::{mat_external as mat_external_ref, mat_internal as mat_internal_ref, T};
use crate::recursive::poseidon2_t8_air::{
    mat_external_expr, mat_internal_expr, round_schedule, N_REAL_ROWS as N_ROUNDS,
};
use crate::{make_config, LOG_BLOWUP};

/// Columns per lane: in, sq, sbox, out (8 each), cur, leaf (4 each).
const LANE_COLS: usize = 4 * T + 8;
pub const N_MAIN_COLS: usize = 2 * LANE_COLS + 5;
pub const N_PREPROC_COLS: usize = T + 5 + 8 + 1 + 8;
pub const MIN_LOG_SIZE: u32 = 5;
pub const MAX_LOG_SIZE: u32 = 24;
/// Matches `merkle_path_t8_air::MAX_DEPTH`: the index is a u32.
pub const MAX_DEPTH: usize = 28;

// Offsets within a lane.
const L_IN: usize = 0;
const L_SQ: usize = T;
const L_SBOX: usize = 2 * T;
const L_OUT: usize = 3 * T;
const L_CUR: usize = 4 * T;
const L_LEAF: usize = 4 * T + 4;
// Shared columns, after both lanes.
const C_SIB: usize = 2 * LANE_COLS;
const C_BIT: usize = 2 * LANE_COLS + 4;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;
pub type NonceUpdateT8Component = FrameworkComponent<NonceUpdateT8Eval>;

/// The public part of one update: what both lanes are pinned to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedUpdate {
    pub old_leaf: [u64; 4],
    pub new_leaf: [u64; 4],
    pub index: u32,
    pub pre_root: [u64; 4],
    pub post_root: [u64; 4],
}

// ── Preprocessed column ids ─────────────────────────────────────────────────

fn pc(name: &str) -> PreProcessedColumnId {
    PreProcessedColumnId { id: format!("nut8_{name}") }
}
pub fn pc_rc(i: usize) -> PreProcessedColumnId { pc(&format!("rc{i}")) }
pub fn pc_is_ext() -> PreProcessedColumnId { pc("is_ext") }
pub fn pc_is_int() -> PreProcessedColumnId { pc("is_int") }
pub fn pc_is_first_comp() -> PreProcessedColumnId { pc("is_first_comp") }
pub fn pc_is_first_path() -> PreProcessedColumnId { pc("is_first_path") }
pub fn pc_idx_bit() -> PreProcessedColumnId { pc("idx_bit") }
pub fn pc_leaf_a(k: usize) -> PreProcessedColumnId { pc(&format!("leaf_a{k}")) }
pub fn pc_leaf_b(k: usize) -> PreProcessedColumnId { pc(&format!("leaf_b{k}")) }
pub fn pc_is_root() -> PreProcessedColumnId { pc("is_root") }
pub fn pc_root_a(k: usize) -> PreProcessedColumnId { pc(&format!("root_a{k}")) }
pub fn pc_root_b(k: usize) -> PreProcessedColumnId { pc(&format!("root_b{k}")) }

/// In the order [`build_preproc`] emits them.
pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    let mut ids: Vec<PreProcessedColumnId> = (0..T).map(pc_rc).collect();
    ids.extend([pc_is_ext(), pc_is_int(), pc_is_first_comp(), pc_is_first_path(), pc_idx_bit()]);
    ids.extend((0..4).map(pc_leaf_a));
    ids.extend((0..4).map(pc_leaf_b));
    ids.push(pc_is_root());
    ids.extend((0..4).map(pc_root_a));
    ids.extend((0..4).map(pc_root_b));
    debug_assert_eq!(ids.len(), N_PREPROC_COLS);
    ids
}

// ── AIR ─────────────────────────────────────────────────────────────────────

struct Lane<F> {
    inp: Vec<F>,
    sq: Vec<F>,
    sbox: Vec<F>,
    out: Vec<F>,
    out_prev: Vec<F>,
    cur: Vec<F>,
    leaf: Vec<F>,
}

/// Selectors and columns both lanes read.
struct Shared<F> {
    rc: Vec<F>,
    is_ext: F,
    is_int: F,
    is_first_comp: F,
    is_first_path: F,
    is_root: F,
    sib: Vec<F>,
    bit: F,
}

fn read_lane<E: EvalAtRow>(eval: &mut E) -> Lane<E::F> {
    let one = |eval: &mut E| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone();
    let inp = (0..T).map(|_| one(eval)).collect();
    let sq = (0..T).map(|_| one(eval)).collect();
    let sbox = (0..T).map(|_| one(eval)).collect();
    let mut out = Vec::with_capacity(T);
    let mut out_prev = Vec::with_capacity(T);
    for _ in 0..T {
        let [c, p] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        out.push(c);
        out_prev.push(p);
    }
    let cur = (0..4).map(|_| one(eval)).collect();
    let leaf = (0..4).map(|_| one(eval)).collect();
    Lane { inp, sq, sbox, out, out_prev, cur, leaf }
}

/// One lane's constraints — `MerklePathT8Eval::evaluate`'s, with `sib`/`bit`
/// taken from the shared columns.
fn constrain_lane<E: EvalAtRow>(
    eval: &mut E,
    l: &Lane<E::F>,
    s: &Shared<E::F>,
    leaf_pin: &[E::F],
    root_pin: &[E::F],
) {
    let one = E::F::from(BaseField::from_u32_unchecked(1));

    // Round core (every row).
    let y: Vec<E::F> = (0..T).map(|i| l.inp[i].clone() + s.rc[i].clone()).collect();
    for i in 0..T {
        eval.add_constraint(l.sq[i].clone() - y[i].clone() * y[i].clone());
    }
    for i in 0..T {
        eval.add_constraint(l.sbox[i].clone() - l.sq[i].clone() * l.sq[i].clone() * y[i].clone());
    }
    let sb_ext: [E::F; 8] = std::array::from_fn(|i| l.sbox[i].clone());
    let sb_int: [E::F; 8] =
        std::array::from_fn(|i| if i == 0 { l.sbox[0].clone() } else { l.inp[i].clone() });
    let me = mat_external_expr(&sb_ext);
    let mi = mat_internal_expr(&sb_int);
    for i in 0..T {
        let expected = s.is_ext.clone() * me[i].clone() + s.is_int.clone() * mi[i].clone();
        eval.add_constraint(l.out[i].clone() - expected);
    }

    // cur = leaf at the path start, else the previous compression's output.
    for k in 0..4 {
        let cur_expected = s.is_first_path.clone() * l.leaf[k].clone()
            + (one.clone() - s.is_first_path.clone()) * l.out_prev[k].clone();
        eval.add_constraint(s.is_first_comp.clone() * (l.cur[k].clone() - cur_expected));
    }
    for k in 0..4 {
        eval.add_constraint(s.is_first_path.clone() * (l.leaf[k].clone() - leaf_pin[k].clone()));
    }

    // Child selection from the SHARED sibling and bit.
    let raw8: [E::F; 8] = std::array::from_fn(|i| {
        if i < 4 {
            s.bit.clone() * s.sib[i].clone() + (one.clone() - s.bit.clone()) * l.cur[i].clone()
        } else {
            let k = i - 4;
            s.bit.clone() * l.cur[k].clone() + (one.clone() - s.bit.clone()) * s.sib[k].clone()
        }
    });
    let me_raw = mat_external_expr(&raw8);
    for i in 0..T {
        let expected = s.is_first_comp.clone() * me_raw[i].clone()
            + (one.clone() - s.is_first_comp.clone()) * l.out_prev[i].clone();
        eval.add_constraint(l.inp[i].clone() - expected);
    }

    for k in 0..4 {
        eval.add_constraint(s.is_root.clone() * (l.out[k].clone() - root_pin[k].clone()));
    }
}

pub struct NonceUpdateT8Eval {
    pub log_n_rows: u32,
}

impl FrameworkEval for NonceUpdateT8Eval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let rc: Vec<E::F> = (0..T).map(|i| eval.get_preprocessed_column(pc_rc(i))).collect();
        let is_ext = eval.get_preprocessed_column(pc_is_ext());
        let is_int = eval.get_preprocessed_column(pc_is_int());
        let is_first_comp = eval.get_preprocessed_column(pc_is_first_comp());
        let is_first_path = eval.get_preprocessed_column(pc_is_first_path());
        let idx_bit = eval.get_preprocessed_column(pc_idx_bit());
        let leaf_a: Vec<E::F> = (0..4).map(|k| eval.get_preprocessed_column(pc_leaf_a(k))).collect();
        let leaf_b: Vec<E::F> = (0..4).map(|k| eval.get_preprocessed_column(pc_leaf_b(k))).collect();
        let is_root = eval.get_preprocessed_column(pc_is_root());
        let root_a: Vec<E::F> = (0..4).map(|k| eval.get_preprocessed_column(pc_root_a(k))).collect();
        let root_b: Vec<E::F> = (0..4).map(|k| eval.get_preprocessed_column(pc_root_b(k))).collect();

        // Main columns in layout order: lane A, lane B, then the shared ones.
        let a = read_lane(&mut eval);
        let b = read_lane(&mut eval);
        let sib: Vec<E::F> = (0..4)
            .map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone())
            .collect();
        let [bit] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        // The index bit is shared too: boolean, and the pinned one.
        eval.add_constraint(is_first_comp.clone() * (bit.clone() * bit.clone() - bit.clone()));
        eval.add_constraint(is_first_comp.clone() * (bit.clone() - idx_bit));

        let s = Shared { rc, is_ext, is_int, is_first_comp, is_first_path, is_root, sib, bit };
        constrain_lane(&mut eval, &a, &s, &leaf_a, &root_a);
        constrain_lane(&mut eval, &b, &s, &leaf_b, &root_b);
        eval
    }
}

pub(crate) fn new_component(log_n_rows: u32) -> NonceUpdateT8Component {
    NonceUpdateT8Component::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_column_ids()),
        NonceUpdateT8Eval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Sizes ───────────────────────────────────────────────────────────────────

/// Smallest `log_size` holding `n_updates` updates of `depth`: `n·depth·22`
/// rows — half of what the same updates take as `2n` separate paths.
pub fn compute_log_size(n_updates: usize, depth: usize) -> u32 {
    let n_real = n_updates.max(1) * depth.max(1) * N_ROUNDS;
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < n_real {
        log += 1;
    }
    log
}

fn m31(v: u64) -> BaseField {
    BaseField::from_u32_unchecked((v % M31_P) as u32)
}

fn norm4(v: [u64; 4]) -> [u64; 4] {
    [v[0] % M31_P, v[1] % M31_P, v[2] % M31_P, v[3] % M31_P]
}

fn to_evals(mut cols: Vec<Vec<BaseField>>, log_size: u32) -> TraceColumns {
    let domain = CanonicCoset::new(log_size).circle_domain();
    for col in cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    cols.into_iter().map(|c| CircleEvaluation::new(domain, c)).collect()
}

// ── Preprocessed columns (canonical source, C1/C2) ──────────────────────────

/// The whole preprocessed tree, from PUBLIC data alone.
pub fn build_preproc(updates: &[PinnedUpdate], depth: usize, log_size: u32) -> TraceColumns {
    let n = 1usize << log_size;
    assert!(depth >= 1, "depth must be ≥ 1");
    assert!(updates.len() * depth * N_ROUNDS <= n, "updates exceed trace capacity");
    let bf0 = BaseField::from_u32_unchecked(0);
    let one = BaseField::from_u32_unchecked(1);
    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_PREPROC_COLS];
    let (is_ext_c, is_int_c, first_comp_c, first_path_c, idx_bit_c) = (T, T + 1, T + 2, T + 3, T + 4);
    let (leaf_a_c, leaf_b_c, is_root_c, root_a_c, root_b_c) = (T + 5, T + 9, T + 13, T + 14, T + 18);

    for (u, up) in updates.iter().enumerate() {
        for j in 0..depth {
            let comp = u * depth + j;
            for r in 0..N_ROUNDS {
                let row = comp * N_ROUNDS + r;
                let (is_ext, rc) = round_schedule(r);
                for i in 0..T {
                    cols[i][row] = m31(rc[i]);
                }
                cols[if is_ext { is_ext_c } else { is_int_c }][row] = one;
            }
            let first = comp * N_ROUNDS;
            cols[first_comp_c][first] = one;
            cols[idx_bit_c][first] = m31(((up.index >> j) & 1) as u64);
            if j == 0 {
                cols[first_path_c][first] = one;
                for k in 0..4 {
                    cols[leaf_a_c + k][first] = m31(up.old_leaf[k]);
                    cols[leaf_b_c + k][first] = m31(up.new_leaf[k]);
                }
            }
            if j == depth - 1 {
                let root_row = first + N_ROUNDS - 1;
                cols[is_root_c][root_row] = one;
                for k in 0..4 {
                    cols[root_a_c + k][root_row] = m31(up.pre_root[k]);
                    cols[root_b_c + k][root_row] = m31(up.post_root[k]);
                }
            }
        }
    }
    to_evals(cols, log_size)
}

/// The C2 pin: the commitment root of [`build_preproc`].
pub(crate) fn canonical_preproc_root(
    updates: &[PinnedUpdate],
    depth: usize,
    log_size: u32,
) -> <Blake2sM31MerkleHasher as stwo::core::vcs_lifted::MerkleHasherLifted>::Hash {
    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();
    let mut throwaway = Blake2sM31Channel::default();
    let mut tree = scheme.tree_builder();
    tree.extend_evals(build_preproc(updates, depth, log_size));
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

// ── Main trace ──────────────────────────────────────────────────────────────

/// The 22 rows of one t=8 compression of `raw8`: `(in, sq, sbox, out)` per row.
fn fill_compression(raw8: [u64; T]) -> Vec<([u64; T], [u64; T], [u64; T], [u64; T])> {
    let mut state = raw8;
    mat_external_ref(&mut state);
    let mut rows = Vec::with_capacity(N_ROUNDS);
    for r in 0..N_ROUNDS {
        let (is_ext, rc) = round_schedule(r);
        let inp = state;
        let mut sq = [0u64; T];
        let mut sbx = [0u64; T];
        for i in 0..T {
            let yi = m31_add(inp[i], rc[i]);
            sq[i] = m31_mul(yi, yi);
            sbx[i] = sbox_ref(yi);
        }
        let mut lin = inp;
        if is_ext {
            lin = sbx;
            mat_external_ref(&mut lin);
        } else {
            lin[0] = sbx[0];
            mat_internal_ref(&mut lin);
        }
        rows.push((inp, sq, sbx, lin));
        state = lin;
    }
    rows
}

/// Natural-order main columns, plus the `(pre, post)` roots each update's two
/// lanes reach. `sibs[u]`/`bits[u]` are update `u`'s ONE path, used by both.
pub(crate) fn build_trace_raw(
    old_leaves: &[[u64; 4]],
    new_leaves: &[[u64; 4]],
    sibs: &[Vec<[u64; 4]>],
    bits: &[Vec<bool>],
    log_size: u32,
) -> (Vec<Vec<BaseField>>, Vec<([u64; 4], [u64; 4])>) {
    let n_up = old_leaves.len();
    assert!(n_up >= 1, "need ≥ 1 update");
    assert!(new_leaves.len() == n_up && sibs.len() == n_up && bits.len() == n_up);
    let depth = sibs[0].len();
    assert!(depth >= 1, "depth must be ≥ 1");
    assert!(
        sibs.iter().zip(bits).all(|(s, b)| s.len() == depth && b.len() == depth),
        "every update's path must be depth {depth}",
    );
    let n = 1usize << log_size;
    assert!(n_up * depth * N_ROUNDS <= n, "updates exceed trace capacity");

    let bf0 = BaseField::from_u32_unchecked(0);
    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];
    let mut reached = Vec::with_capacity(n_up);
    let mut carry = [[0u64; T]; 2]; // each lane's last `out`, for the padding chain

    for u in 0..n_up {
        let mut cur = [norm4(old_leaves[u]), norm4(new_leaves[u])];
        for j in 0..depth {
            let comp = u * depth + j;
            let sib = norm4(sibs[u][j]);
            let bit = bits[u][j];
            for lane in 0..2 {
                let base = lane * LANE_COLS;
                let c = cur[lane];
                let (l, r) = if bit { (sib, c) } else { (c, sib) };
                let raw8 = [l[0], l[1], l[2], l[3], r[0], r[1], r[2], r[3]];
                for (rr, (inp, sq, sbx, out)) in fill_compression(raw8).into_iter().enumerate() {
                    let row = comp * N_ROUNDS + rr;
                    for i in 0..T {
                        cols[base + L_IN + i][row] = m31(inp[i]);
                        cols[base + L_SQ + i][row] = m31(sq[i]);
                        cols[base + L_SBOX + i][row] = m31(sbx[i]);
                        cols[base + L_OUT + i][row] = m31(out[i]);
                    }
                    if rr == 0 {
                        for k in 0..4 {
                            cols[base + L_CUR + k][row] = m31(c[k]);
                        }
                        if j == 0 {
                            let leaf = if lane == 0 { old_leaves[u] } else { new_leaves[u] };
                            for k in 0..4 {
                                cols[base + L_LEAF + k][row] = m31(leaf[k]);
                            }
                        }
                    }
                    carry[lane] = out;
                }
                cur[lane] = [carry[lane][0], carry[lane][1], carry[lane][2], carry[lane][3]];
            }
            let row0 = comp * N_ROUNDS;
            for k in 0..4 {
                cols[C_SIB + k][row0] = m31(sib[k]);
            }
            cols[C_BIT][row0] = if bit { m31(1) } else { bf0 };
        }
        reached.push((cur[0], cur[1]));
    }

    // Padding: each lane continues its round chain with out = 0, as in
    // `merkle_path_t8_air` (all selectors are 0 there).
    for row in (n_up * depth * N_ROUNDS)..n {
        for lane in 0..2 {
            let base = lane * LANE_COLS;
            for i in 0..T {
                let v = carry[lane][i];
                cols[base + L_IN + i][row] = m31(v);
                cols[base + L_SQ + i][row] = m31(m31_mul(v, v));
                cols[base + L_SBOX + i][row] = m31(sbox_ref(v));
            }
            carry[lane] = [0u64; T];
        }
    }
    (cols, reached)
}

/// [`build_trace_raw`] in the bit-reversed circle-domain order the prover takes.
pub fn build_trace(
    old_leaves: &[[u64; 4]],
    new_leaves: &[[u64; 4]],
    sibs: &[Vec<[u64; 4]>],
    bits: &[Vec<bool>],
    log_size: u32,
) -> (TraceColumns, Vec<([u64; 4], [u64; 4])>) {
    let (cols, reached) = build_trace_raw(old_leaves, new_leaves, sibs, bits, log_size);
    (to_evals(cols, log_size), reached)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursive::merkle_path_t8_air::merkle_path_root_t8;

    fn rand_m31(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) % M31_P
    }
    fn rand_node(seed: &mut u64) -> [u64; 4] {
        [rand_m31(seed), rand_m31(seed), rand_m31(seed), rand_m31(seed)]
    }

    #[test]
    fn both_lanes_reach_the_reference_roots_over_one_path() {
        let mut s = 0x4E55_u64;
        for (n_up, depth) in [(1usize, 1usize), (2, 3), (3, 5)] {
            let old: Vec<_> = (0..n_up).map(|_| rand_node(&mut s)).collect();
            let new: Vec<_> = (0..n_up).map(|_| rand_node(&mut s)).collect();
            let sibs: Vec<Vec<_>> =
                (0..n_up).map(|_| (0..depth).map(|_| rand_node(&mut s)).collect()).collect();
            let bits: Vec<Vec<_>> =
                (0..n_up).map(|_| (0..depth).map(|_| rand_m31(&mut s) & 1 == 1).collect()).collect();
            let log = compute_log_size(n_up, depth);
            let (cols, reached) = build_trace(&old, &new, &sibs, &bits, log);
            assert_eq!(cols.len(), N_MAIN_COLS);
            for u in 0..n_up {
                assert_eq!(reached[u].0, merkle_path_root_t8(old[u], &sibs[u], &bits[u]));
                assert_eq!(reached[u].1, merkle_path_root_t8(new[u], &sibs[u], &bits[u]));
            }
        }
    }

    #[test]
    fn the_layout_constants_agree() {
        assert_eq!(N_MAIN_COLS, 85);
        assert_eq!(N_PREPROC_COLS, 30);
        assert_eq!(preprocessed_column_ids().len(), N_PREPROC_COLS);
        let up = PinnedUpdate {
            old_leaf: [1; 4], new_leaf: [2; 4], index: 5, pre_root: [3; 4], post_root: [4; 4],
        };
        assert_eq!(build_preproc(&[up], 3, compute_log_size(1, 3)).len(), N_PREPROC_COLS);
        // Half the rows of 2N separate paths.
        assert_eq!(compute_log_size(25, 8), 13); // 25·8·22 = 4400 → 2^13
    }
}
