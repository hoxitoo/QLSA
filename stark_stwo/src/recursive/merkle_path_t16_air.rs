//! Poseidon2 **t=16** Merkle authentication-path AIR — the 128-bit recursion inner hash (R3.18).
//!
//! The wide analogue of [`super::merkle_path_air`] (t=2, 31-bit nodes): proves a
//! Merkle authentication path over **8-word (248-bit) M31 nodes** using the
//! Poseidon2 t=16 2-to-1 compression [`crate::poseidon2_t16::compress_t16`] (node
//! collision ~2^124 ≈ 128-bit — the ladder's target level).  This is the hash a **VFRI11** inner proof's
//! FRI-layer Merkle trees use, so it is the path the recursion must replicate to
//! verify a real VFRI11 decommitment.
//!
//! It is to [`super::poseidon2_t16_air`] (single t=8 compression) exactly what
//! `merkle_path_air` is to `poseidon2_merkle_air`: the same round arithmetization,
//! chained across `depth` compressions with per-compression child selection.
//!
//! # Path semantics (8-word nodes)
//!
//! For depth `D`, `cur₀ = leaf` (∈ M31⁸) and index bits `b₀ … b_{D-1}` (LSB first):
//!
//! ```text
//! (left_i, right_i) = b_i ? (sib_i, cur_i) : (cur_i, sib_i)   // each ∈ M31⁸
//! cur_{i+1}         = compress_t16(left_i, right_i)
//! root              = cur_D
//! ```
//!
//! # Trace layout (89 main columns + 38 preprocessed)
//!
//! Each compression takes `N_ROUNDS = 22` rows (one t=16 permutation round each);
//! compression `c` occupies rows `c·22 .. c·22+22`.  The round state chains
//! *within* a compression via the `in = out[-1]` round chain, and the path chains
//! *across* compressions because a compression's output lands on its last round
//! row — immediately before the next compression's first row (`out[-1]`, the same
//! trick as the t=2 path).
//!
//! ```text
//! Main (per row):
//!   in[0..8] sq[0..8] sbox[0..8] out[0..8]   — the t=16 round columns (64)
//!   cur[0..8]  — chained current node (leaf at path start, else prev comp output)
//!   sib[0..8]  — sibling node       (meaningful on each compression's row 0)
//!   bit        — index bit b_i       (meaningful on each compression's row 0)
//!   leaf[0..8] — the path leaf        (meaningful on the path's very first row)
//!
//! Preprocessed (verifier-pinned canonical source, C1/C2):
//!   rc[0..16]       — round constants (period 22; cell 0 only on internal rounds)
//!   is_ext, is_int  — round type
//!   is_first_comp   — 1 on each compression's row 0     (child-selection wiring)
//!   is_first_path   — 1 on the path's very first row      (cur = leaf reset)
//!   idx_bit         — verifier-fixed index bit per compression (C1 index binding)
//!   leaf_pin[0..8]  — verifier-fixed leaf                  (C1 leaf binding)
//!   is_root         — 1 on the last real compression's last round row
//!   root_pin[0..8]  — verifier-fixed root                  (C1 root binding)
//! ```
//!
//! # Soundness
//!
//! - **[C2]** the whole preprocessed tree (round constants, selectors, pinned
//!   index/leaf/root) is the single canonical source [`build_preproc`]; the
//!   verifier recomputes its commitment root and rejects a mismatch.
//! - **[C1]** `index`, `leaf`, and `root` are all bound in-circuit (pinned columns
//!   + gated equality constraints), matching the on-chain
//!   `the (future) t=16 on-chain analogue of Poseidon2MerkleVerifierT8.verify(root, leaf, index, depth, siblings)`.

use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

use crate::poseidon2::{m31_add, m31_mul, sbox as sbox_ref, M31_P};
use crate::poseidon2_t16::{compress_t16, mat_external as mat_external_ref, mat_internal as mat_internal_ref, T};
use crate::recursive::poseidon2_t16_air::{
    mat_external16_expr as mat_external_expr, mat_internal16_expr as mat_internal_expr,
    round_schedule, N_REAL_ROWS as N_ROUNDS,
};
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub const N_MAIN_COLS: usize = 89;
pub const MIN_LOG_SIZE: u32 = 5; // ≥ 32 rows = 1 compression (22 rounds)
pub const MAX_LOG_SIZE: u32 = 24;
/// Maximum supported path depth (index fits in u32; trace depth bounded).
pub const MAX_DEPTH: usize = 28;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;
pub type MerklePathT16Component = FrameworkComponent<MerklePathT16Eval>;

// ── Column offsets ───────────────────────────────────────────────────────────
const C_IN: usize = 0; // 0..16
const C_SQ: usize = 16; // 16..32
const C_SBOX: usize = 32; // 32..48
const C_OUT: usize = 48; // 48..64
const C_CUR: usize = 64; // 64..72
const C_SIB: usize = 72; // 72..80
const C_BIT: usize = 80; // 80
const C_LEAF: usize = 81; // 81..89

// ── Preprocessed column IDs ───────────────────────────────────────────────────

pub fn pc_rc(i: usize) -> PreProcessedColumnId {
    PreProcessedColumnId { id: format!("mpt16_rc{i}") }
}
pub fn pc_is_ext() -> PreProcessedColumnId { PreProcessedColumnId { id: "mpt16_is_ext".into() } }
pub fn pc_is_int() -> PreProcessedColumnId { PreProcessedColumnId { id: "mpt16_is_int".into() } }
pub fn pc_is_first_comp() -> PreProcessedColumnId { PreProcessedColumnId { id: "mpt16_is_first_comp".into() } }
pub fn pc_is_first_path() -> PreProcessedColumnId { PreProcessedColumnId { id: "mpt16_is_first_path".into() } }
pub fn pc_idx_bit() -> PreProcessedColumnId { PreProcessedColumnId { id: "mpt16_idx_bit".into() } }
pub fn pc_leaf(k: usize) -> PreProcessedColumnId { PreProcessedColumnId { id: format!("mpt16_leaf{k}") } }
pub fn pc_is_root() -> PreProcessedColumnId { PreProcessedColumnId { id: "mpt16_is_root".into() } }
pub fn pc_root(k: usize) -> PreProcessedColumnId { PreProcessedColumnId { id: format!("mpt16_root{k}") } }

pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    let mut ids: Vec<PreProcessedColumnId> = (0..T).map(pc_rc).collect();
    ids.push(pc_is_ext());
    ids.push(pc_is_int());
    ids.push(pc_is_first_comp());
    ids.push(pc_is_first_path());
    ids.push(pc_idx_bit());
    for k in 0..8 {
        ids.push(pc_leaf(k));
    }
    ids.push(pc_is_root());
    for k in 0..8 {
        ids.push(pc_root(k));
    }
    ids
}

// ── Reference path hash ────────────────────────────────────────────────────────

/// Compute the Merkle root reached by hashing the 4-word `leaf` up through
/// `sibs` using the index `bits` (LSB first), via `compress_t16`.
pub fn merkle_path_root_t16(leaf: [u64; 8], sibs: &[[u64; 8]], bits: &[bool]) -> [u64; 8] {
    assert_eq!(sibs.len(), bits.len(), "sibs/bits length mismatch");
    let mut cur = norm8(leaf);
    for i in 0..sibs.len() {
        let s = norm8(sibs[i]);
        let (l, r) = if bits[i] { (s, cur) } else { (cur, s) };
        cur = compress_t16(l, r);
    }
    cur
}

fn norm8(v: [u64; 8]) -> [u64; 8] {
    std::array::from_fn(|i| v[i] % M31_P)
}

/// Pack index bits (LSB first) into a u32 index.
pub fn bits_to_index(bits: &[bool]) -> u32 {
    assert!(bits.len() <= 32, "depth {} exceeds 32-bit index", bits.len());
    let mut idx = 0u32;
    for (i, &b) in bits.iter().enumerate() {
        if b {
            idx |= 1u32 << i;
        }
    }
    idx
}

// ── AIR ──────────────────────────────────────────────────────────────────────

pub struct MerklePathT16Eval {
    pub log_n_rows: u32,
}

impl FrameworkEval for MerklePathT16Eval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        // sbox = sq²·y (degree 3) is the highest; every other constraint ≤ 3.
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let rc: Vec<E::F> = (0..T).map(|i| eval.get_preprocessed_column(pc_rc(i))).collect();
        let is_ext = eval.get_preprocessed_column(pc_is_ext());
        let is_int = eval.get_preprocessed_column(pc_is_int());
        let is_first_comp = eval.get_preprocessed_column(pc_is_first_comp());
        let is_first_path = eval.get_preprocessed_column(pc_is_first_path());
        let idx_bit = eval.get_preprocessed_column(pc_idx_bit());
        let leaf_pin: Vec<E::F> = (0..8).map(|k| eval.get_preprocessed_column(pc_leaf(k))).collect();
        let is_root = eval.get_preprocessed_column(pc_is_root());
        let root_pin: Vec<E::F> = (0..8).map(|k| eval.get_preprocessed_column(pc_root(k))).collect();

        // Main columns. `out` needs previous-row access for the round + path chain.
        let inp: Vec<E::F> =
            (0..T).map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()).collect();
        let sq: Vec<E::F> =
            (0..T).map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()).collect();
        let sbox: Vec<E::F> =
            (0..T).map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()).collect();
        let mut out: Vec<E::F> = Vec::with_capacity(T);
        let mut out_prev: Vec<E::F> = Vec::with_capacity(T);
        for _ in 0..T {
            let [c, p] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
            out.push(c);
            out_prev.push(p);
        }
        let cur: Vec<E::F> =
            (0..8).map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()).collect();
        let sib: Vec<E::F> =
            (0..8).map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()).collect();
        let [bit] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let leaf: Vec<E::F> =
            (0..8).map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()).collect();

        let one = E::F::from(BaseField::from_u32_unchecked(1));

        // ── Round core (every row) — identical to poseidon2_t8_air ───────────────
        let y: Vec<E::F> = (0..T).map(|i| inp[i].clone() + rc[i].clone()).collect();
        for i in 0..T {
            eval.add_constraint(sq[i].clone() - y[i].clone() * y[i].clone()); // C_sq (deg 2)
        }
        for i in 0..T {
            eval.add_constraint(sbox[i].clone() - sq[i].clone() * sq[i].clone() * y[i].clone()); // C_sbox (deg 3)
        }
        let sb_ext: [E::F; 16] = std::array::from_fn(|i| sbox[i].clone());
        let sb_int: [E::F; 16] =
            std::array::from_fn(|i| if i == 0 { sbox[0].clone() } else { inp[i].clone() });
        let me = mat_external_expr(&sb_ext);
        let mi = mat_internal_expr(&sb_int);
        for i in 0..T {
            let expected = is_ext.clone() * me[i].clone() + is_int.clone() * mi[i].clone();
            eval.add_constraint(out[i].clone() - expected); // C_out (deg 2)
        }

        // ── Path node wiring (compression-first rows, gated by is_first_comp) ─────
        // cur = is_first_path·leaf + (1−is_first_path)·out_prev[0..4]
        for k in 0..8 {
            let cur_expected = is_first_path.clone() * leaf[k].clone()
                + (one.clone() - is_first_path.clone()) * out_prev[k].clone();
            eval.add_constraint(is_first_comp.clone() * (cur[k].clone() - cur_expected));
        }
        // bit boolean + index binding (C1).
        eval.add_constraint(is_first_comp.clone() * (bit.clone() * bit.clone() - bit.clone()));
        eval.add_constraint(is_first_comp.clone() * (bit.clone() - idx_bit));
        // leaf binding (C1): the path leaf equals the pinned leaf on the first row.
        for k in 0..8 {
            eval.add_constraint(is_first_path.clone() * (leaf[k].clone() - leaf_pin[k].clone()));
        }

        // ── in wiring: comp-first row injects mat_external(child-selected raw);
        //    every other row chains the round input from the previous output ──────
        // left  = bit·sib + (1−bit)·cur ; right = bit·cur + (1−bit)·sib  (each 4-word)
        let raw16: [E::F; 16] = std::array::from_fn(|i| {
            if i < 8 {
                bit.clone() * sib[i].clone() + (one.clone() - bit.clone()) * cur[i].clone()
            } else {
                let k = i - 8;
                bit.clone() * cur[k].clone() + (one.clone() - bit.clone()) * sib[k].clone()
            }
        });
        let me_raw = mat_external_expr(&raw16);
        for i in 0..T {
            let expected = is_first_comp.clone() * me_raw[i].clone()
                + (one.clone() - is_first_comp.clone()) * out_prev[i].clone();
            eval.add_constraint(inp[i].clone() - expected); // C_in (deg 3)
        }

        // ── C1 root binding: out[0..4] on the last real compression's last round ─
        for k in 0..8 {
            eval.add_constraint(is_root.clone() * (out[k].clone() - root_pin[k].clone()));
        }

        eval
    }
}

fn new_component(log_n_rows: u32) -> MerklePathT16Component {
    MerklePathT16Component::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_column_ids()),
        MerklePathT16Eval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace size ───────────────────────────────────────────────────────────────

pub fn compute_log_size(depth: usize) -> u32 {
    let n_real = depth.max(1) * N_ROUNDS;
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < n_real {
        log += 1;
    }
    log
}

// ── Preprocessed columns (canonical source, C1/C2) ──────────────────────────────

pub fn build_preproc(
    leaf: [u64; 8],
    index: u32,
    root: [u64; 8],
    depth: usize,
    log_size: u32,
) -> TraceColumns {
    let n = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let one = BaseField::from_u32_unchecked(1);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut rc_cols: Vec<Vec<BaseField>> = (0..T).map(|_| vec![bf0; n]).collect();
    let mut is_ext_c = vec![bf0; n];
    let mut is_int_c = vec![bf0; n];
    let mut first_comp_c = vec![bf0; n];
    let mut first_path_c = vec![bf0; n];
    let mut idx_bit_c = vec![bf0; n];
    let mut leaf_cols: Vec<Vec<BaseField>> = (0..8).map(|_| vec![bf0; n]).collect();
    let mut is_root_c = vec![bf0; n];
    let mut root_cols: Vec<Vec<BaseField>> = (0..8).map(|_| vec![bf0; n]).collect();

    let n_comp_real = depth.min(n / N_ROUNDS);
    for c in 0..n_comp_real {
        for r in 0..N_ROUNDS {
            let row = c * N_ROUNDS + r;
            let (is_ext, rc) = round_schedule(r);
            for i in 0..T {
                rc_cols[i][row] = m31(rc[i]);
            }
            if is_ext {
                is_ext_c[row] = one;
            } else {
                is_int_c[row] = one;
            }
        }
        let first = c * N_ROUNDS;
        first_comp_c[first] = one;
        // index bit for compression c on its first row (C1).
        let bit = if c < 32 { (index >> c) & 1 } else { 0 };
        idx_bit_c[first] = m31(bit as u64);
        if c == 0 {
            first_path_c[first] = one;
            for k in 0..8 {
                leaf_cols[k][first] = m31(leaf[k]);
            }
        }
    }
    // Root pinned on the last real compression's last round row (C1 root binding).
    if depth >= 1 && depth * N_ROUNDS <= n {
        let root_row = (depth - 1) * N_ROUNDS + (N_ROUNDS - 1);
        is_root_c[root_row] = one;
        for k in 0..8 {
            root_cols[k][root_row] = m31(root[k]);
        }
    }

    let mut all = rc_cols;
    all.push(is_ext_c);
    all.push(is_int_c);
    all.push(first_comp_c);
    all.push(first_path_c);
    all.push(idx_bit_c);
    all.extend(leaf_cols);
    all.push(is_root_c);
    all.extend(root_cols);
    for col in all.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    all.into_iter().map(|col| CircleEvaluation::new(domain, col)).collect()
}

fn canonical_preproc_root(
    leaf: [u64; 8],
    index: u32,
    root: [u64; 8],
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
    tree.extend_evals(build_preproc(leaf, index, root, depth, log_size));
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

// ── Trace builder ────────────────────────────────────────────────────────────────

/// Build the main trace. Returns `(main_columns, root)`. The first `depth`
/// compressions are the real path; padding rows continue the round chain with
/// zero output (both selectors 0 → out = 0).
pub fn build_trace(
    leaf: [u64; 8],
    sibs: &[[u64; 8]],
    bits: &[bool],
    log_size: u32,
) -> (TraceColumns, [u64; 8]) {
    assert_eq!(sibs.len(), bits.len(), "sibs/bits length mismatch");
    let depth = sibs.len();
    let n = 1usize << log_size;
    debug_assert!(depth * N_ROUNDS <= n, "path exceeds trace capacity");
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];

    let mut cur = norm8(leaf);
    let mut root = cur;
    let mut carry_state = [0u64; T]; // out of the previous row (for padding chain)

    for c in 0..depth {
        let sib = norm8(sibs[c]);
        let bit = bits[c];
        let (left, right) = if bit { (sib, cur) } else { (cur, sib) };
        let raw16 = [
            left[0], left[1], left[2], left[3], left[4], left[5], left[6], left[7],
            right[0], right[1], right[2], right[3], right[4], right[5], right[6], right[7],
        ];

        // in[row0] = mat_external(raw8).
        let mut state = raw16;
        mat_external_ref(&mut state);

        for r in 0..N_ROUNDS {
            let row = c * N_ROUNDS + r;
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
                for i in 0..T {
                    lin[i] = sbx[i];
                }
                mat_external_ref(&mut lin);
            } else {
                lin[0] = sbx[0];
                mat_internal_ref(&mut lin);
            }
            let out = lin;

            for i in 0..T {
                cols[C_IN + i][row] = m31(inp[i]);
                cols[C_SQ + i][row] = m31(sq[i]);
                cols[C_SBOX + i][row] = m31(sbx[i]);
                cols[C_OUT + i][row] = m31(out[i]);
            }
            if r == 0 {
                for k in 0..8 {
                    cols[C_CUR + k][row] = m31(cur[k]);
                    cols[C_SIB + k][row] = m31(sib[k]);
                }
                cols[C_BIT][row] = if bit { m31(1) } else { bf0 };
                if c == 0 {
                    for k in 0..8 {
                        cols[C_LEAF + k][row] = m31(leaf[k]);
                    }
                }
            }
            state = out;
            carry_state = out;
        }
        // Node = out[0..8] of this compression's last round.
        cur = [state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]];
        if c + 1 == depth {
            root = cur;
        }
    }

    // Padding rows: continue the round chain (in = out_prev); both selectors are 0
    // so C_out forces out = 0; C_sq/C_sbox derived so the ungated constraints hold.
    for row in (depth * N_ROUNDS)..n {
        for i in 0..T {
            let inp_i = carry_state[i];
            cols[C_IN + i][row] = m31(inp_i);
            cols[C_SQ + i][row] = m31(m31_mul(inp_i, inp_i));
            cols[C_SBOX + i][row] = m31(sbox_ref(inp_i));
            // out = 0 (already zero-initialised)
        }
        carry_state = [0u64; T];
    }

    let mut main = cols;
    for col in main.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    let main_cols: TraceColumns = main.into_iter().map(|col| CircleEvaluation::new(domain, col)).collect();
    (main_cols, root)
}

// ── Multi-path builders (N independent paths in one component) ───────────────────
//
// The AIR is unchanged — `is_first_path` gates each path's `cur = leaf` reset and
// leaf pinning, `is_root` gates each path's root pinning, so N paths of uniform
// `depth` lay out in consecutive blocks of `depth` compressions (22 rows each).

/// Smallest `log_size` fitting `num_paths` paths of `depth` compressions.
pub fn compute_log_size_multi(num_paths: usize, depth: usize) -> u32 {
    let comps = num_paths.max(1) * depth.max(1);
    let n_real = comps * N_ROUNDS;
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < n_real {
        log += 1;
    }
    log
}

/// Canonical preprocessed columns for `num_paths` paths of uniform `depth`:
/// per-round rc/is_ext/is_int, per-compression `is_first_comp`, per-path
/// `is_first_path`/`idx_bit`/`leaf_pin`/`is_root`/`root_pin`. Single source of
/// truth for the preprocessed tree (C1/C2).
pub fn build_preproc_multi(
    leaves: &[[u64; 8]],
    indices: &[u32],
    roots: &[[u64; 8]],
    depth: usize,
    log_size: u32,
) -> TraceColumns {
    assert_eq!(leaves.len(), indices.len(), "leaves/indices length mismatch");
    assert_eq!(leaves.len(), roots.len(), "leaves/roots length mismatch");
    assert!(depth >= 1, "depth must be ≥ 1");
    let n = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let one = BaseField::from_u32_unchecked(1);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut rc_cols: Vec<Vec<BaseField>> = (0..T).map(|_| vec![bf0; n]).collect();
    let mut is_ext_c = vec![bf0; n];
    let mut is_int_c = vec![bf0; n];
    let mut first_comp_c = vec![bf0; n];
    let mut first_path_c = vec![bf0; n];
    let mut idx_bit_c = vec![bf0; n];
    let mut leaf_cols: Vec<Vec<BaseField>> = (0..8).map(|_| vec![bf0; n]).collect();
    let mut is_root_c = vec![bf0; n];
    let mut root_cols: Vec<Vec<BaseField>> = (0..8).map(|_| vec![bf0; n]).collect();

    let n_comp = n / N_ROUNDS;
    for comp in 0..n_comp {
        let path = comp / depth;
        let j = comp % depth; // compression within the path
        if path >= leaves.len() {
            break; // padding rows: all selectors stay zero
        }
        for r in 0..N_ROUNDS {
            let row = comp * N_ROUNDS + r;
            let (is_ext, rc) = round_schedule(r);
            for i in 0..T {
                rc_cols[i][row] = m31(rc[i]);
            }
            if is_ext {
                is_ext_c[row] = one;
            } else {
                is_int_c[row] = one;
            }
        }
        let first = comp * N_ROUNDS;
        first_comp_c[first] = one;
        let bit = if j < 32 { (indices[path] >> j) & 1 } else { 0 };
        idx_bit_c[first] = m31(bit as u64);
        if j == 0 {
            first_path_c[first] = one; // path start: cur = leaf reset + leaf pin
            for k in 0..8 {
                leaf_cols[k][first] = m31(leaves[path][k]);
            }
        }
        if j == depth - 1 {
            // Path root pinned on its last compression's last round row (C1).
            let root_row = comp * N_ROUNDS + (N_ROUNDS - 1);
            is_root_c[root_row] = one;
            for k in 0..8 {
                root_cols[k][root_row] = m31(roots[path][k]);
            }
        }
    }

    let mut all = rc_cols;
    all.push(is_ext_c);
    all.push(is_int_c);
    all.push(first_comp_c);
    all.push(first_path_c);
    all.push(idx_bit_c);
    all.extend(leaf_cols);
    all.push(is_root_c);
    all.extend(root_cols);
    for col in all.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    all.into_iter().map(|col| CircleEvaluation::new(domain, col)).collect()
}

/// Build the multi-path main trace. `leaves[p]`, `sibs[p]`, `bits[p]` describe
/// path `p` (all of uniform `depth`). Returns `(main_columns, roots)`.
pub fn build_trace_multi(
    leaves: &[[u64; 8]],
    sibs: &[Vec<[u64; 8]>],
    bits: &[Vec<bool>],
    log_size: u32,
) -> (TraceColumns, Vec<[u64; 8]>) {
    let num_paths = leaves.len();
    assert!(num_paths >= 1, "need ≥ 1 path");
    assert_eq!(sibs.len(), num_paths);
    assert_eq!(bits.len(), num_paths);
    let depth = sibs[0].len();
    assert!(depth >= 1, "depth must be ≥ 1");
    assert!(sibs.iter().all(|s| s.len() == depth), "paths must share depth");
    assert!(bits.iter().all(|b| b.len() == depth), "paths must share depth");

    let n = 1usize << log_size;
    debug_assert!(num_paths * depth * N_ROUNDS <= n, "paths exceed trace capacity");
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];
    let mut roots = Vec::with_capacity(num_paths);
    let mut carry_state = [0u64; T]; // previous row's out (for chains)

    let n_comp_real = num_paths * depth;
    let mut cur = [0u64; 8];
    for comp in 0..n_comp_real {
        let path = comp / depth;
        let j = comp % depth;
        if j == 0 {
            cur = norm8(leaves[path]); // path start: cur = its leaf
        }
        let sib = norm8(sibs[path][j]);
        let bit = bits[path][j];
        let (left, right) = if bit { (sib, cur) } else { (cur, sib) };
        let raw16 = [
            left[0], left[1], left[2], left[3], left[4], left[5], left[6], left[7],
            right[0], right[1], right[2], right[3], right[4], right[5], right[6], right[7],
        ];

        let mut state = raw16;
        mat_external_ref(&mut state);

        for r in 0..N_ROUNDS {
            let row = comp * N_ROUNDS + r;
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
                for i in 0..T {
                    lin[i] = sbx[i];
                }
                mat_external_ref(&mut lin);
            } else {
                lin[0] = sbx[0];
                mat_internal_ref(&mut lin);
            }
            let out = lin;

            for i in 0..T {
                cols[C_IN + i][row] = m31(inp[i]);
                cols[C_SQ + i][row] = m31(sq[i]);
                cols[C_SBOX + i][row] = m31(sbx[i]);
                cols[C_OUT + i][row] = m31(out[i]);
            }
            if r == 0 {
                for k in 0..8 {
                    cols[C_CUR + k][row] = m31(cur[k]);
                    cols[C_SIB + k][row] = m31(sib[k]);
                }
                cols[C_BIT][row] = if bit { m31(1) } else { bf0 };
                if j == 0 {
                    for k in 0..8 {
                        cols[C_LEAF + k][row] = m31(leaves[path][k]);
                    }
                }
            }
            state = out;
            carry_state = out;
        }
        cur = [state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]];
        if j == depth - 1 {
            roots.push(cur); // path `path`'s root
        }
    }

    // Padding rows: continue the round chain (in = out_prev); selectors are 0 so
    // C_out forces out = 0; sq/sbox derived so the ungated constraints hold.
    for row in (n_comp_real * N_ROUNDS)..n {
        for i in 0..T {
            let inp_i = carry_state[i];
            cols[C_IN + i][row] = m31(inp_i);
            cols[C_SQ + i][row] = m31(m31_mul(inp_i, inp_i));
            cols[C_SBOX + i][row] = m31(sbox_ref(inp_i));
        }
        carry_state = [0u64; T];
    }

    let mut main = cols;
    for col in main.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    let main_cols: TraceColumns = main.into_iter().map(|col| CircleEvaluation::new(domain, col)).collect();
    (main_cols, roots)
}

// ── Prove / verify roundtrip ────────────────────────────────────────────────────

fn mix_public(channel: &mut Blake2sM31Channel, leaf: [u64; 8], index: u32, root: [u64; 8]) {
    let w = |v: u64| (v % M31_P) as u32;
    let mut words = Vec::with_capacity(17);
    words.extend(leaf.iter().map(|&v| w(v)));
    words.push(index);
    words.extend(root.iter().map(|&v| w(v)));
    channel.mix_u32s(&words);
}

/// Prove a t=16 Merkle authentication path. Returns `(proof_bytes, log_size, root)`.
pub fn prove_merkle_path_t16(
    leaf: [u64; 8],
    sibs: &[[u64; 8]],
    bits: &[bool],
) -> Result<(Vec<u8>, u32, [u64; 8]), String> {
    if sibs.len() != bits.len() {
        return Err("sibs/bits length mismatch".into());
    }
    if sibs.is_empty() {
        return Err("path must have depth ≥ 1".into());
    }
    if sibs.len() > MAX_DEPTH {
        return Err(format!("path depth {} exceeds MAX_DEPTH {MAX_DEPTH}", sibs.len()));
    }
    let log_size = compute_log_size(sibs.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("log_size {log_size} exceeds {MAX_LOG_SIZE}"));
    }
    let (main_cols, root) = build_trace(leaf, sibs, bits, log_size);
    let index = bits_to_index(bits);
    let preproc = build_preproc(leaf, index, root, sibs.len(), log_size);

    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree = commitment_scheme.tree_builder();
    tree.extend_evals(preproc);
    tree.commit(channel);
    let mut tree = commitment_scheme.tree_builder();
    tree.extend_evals(main_cols);
    tree.commit(channel);

    mix_public(channel, leaf, index, root);

    let component = new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("t16 merkle-path proving error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("t16 merkle-path serialize error: {e:?}"))?;
    Ok((bytes, log_size, root))
}

/// Verify a proof from [`prove_merkle_path_t16`] against `(depth, leaf, index, root)`.
pub fn verify_merkle_path_t16(
    proof_bytes: &[u8],
    log_size: u32,
    depth: usize,
    leaf: [u64; 8],
    index: u32,
    root: [u64; 8],
) -> Result<bool, String> {
    if !(MIN_LOG_SIZE..=MAX_LOG_SIZE).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range [{MIN_LOG_SIZE}, {MAX_LOG_SIZE}]"));
    }
    if !(1..=MAX_DEPTH).contains(&depth) {
        return Err(format!("depth {depth} out of range [1, {MAX_DEPTH}]"));
    }
    if depth * N_ROUNDS > (1usize << log_size) {
        return Err(format!("depth {depth} exceeds trace capacity at log_size {log_size}"));
    }

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("t16 merkle-path deserialize error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let component = new_component(log_size);
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    // C1 + C2: pin the preprocessed tree (round constants, selectors, pinned
    // index/leaf/root) to its canonical value.
    if proof.commitments[0] != canonical_preproc_root(leaf, index, root, depth, log_size) {
        return Ok(false);
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    mix_public(verifier_channel, leaf, index, root);

    let result = verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof);
    Ok(result.is_ok())
}

// ── Tests ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_m31(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) % M31_P
    }
    fn rand_node(seed: &mut u64) -> [u64; 8] {
        std::array::from_fn(|_| rand_m31(seed))
    }
    fn rand_path(seed: &mut u64, depth: usize) -> ([u64; 8], Vec<[u64; 8]>, Vec<bool>) {
        let leaf = rand_node(seed);
        let sibs: Vec<[u64; 8]> = (0..depth).map(|_| rand_node(seed)).collect();
        let bits: Vec<bool> = (0..depth).map(|_| rand_m31(seed) & 1 == 1).collect();
        (leaf, sibs, bits)
    }

    // Reference root vs direct compress_t16 chaining, both bit orderings.
    #[test]
    fn test_path_root_matches_manual_compress() {
        let leaf = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let s0 = [10u64, 11, 12, 13, 14, 15, 16, 17];
        let s1 = [20u64, 21, 22, 23, 24, 25, 26, 27];
        // bits [false, true]: h1 = compress_t16(leaf, s0); root = compress_t16(s1, h1)
        let h1 = compress_t16(leaf, s0);
        let expected = compress_t16(s1, h1);
        assert_eq!(merkle_path_root_t16(leaf, &[s0, s1], &[false, true]), expected);
    }

    // The AIR trace root matches the reference for random paths.
    #[test]
    fn test_build_trace_root_matches_reference() {
        let mut seed = 0x1111_u64;
        for depth in [1usize, 2, 3, 5] {
            let (leaf, sibs, bits) = rand_path(&mut seed, depth);
            let log = compute_log_size(depth);
            let (main, root) = build_trace(leaf, &sibs, &bits, log);
            assert_eq!(main.len(), N_MAIN_COLS);
            assert_eq!(root, merkle_path_root_t16(leaf, &sibs, &bits), "trace root must match reference");
        }
    }

    #[test]
    fn test_roundtrip_depth1() {
        let mut seed = 0xA1_u64;
        let (leaf, sibs, bits) = rand_path(&mut seed, 1);
        let (proof, log, root) = prove_merkle_path_t16(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        assert!(verify_merkle_path_t16(&proof, log, sibs.len(), leaf, idx, root).expect("verify"));
    }

    #[test]
    fn test_roundtrip_depth3() {
        let mut seed = 0xB2_u64;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let (proof, log, root) = prove_merkle_path_t16(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        assert!(verify_merkle_path_t16(&proof, log, sibs.len(), leaf, idx, root).expect("verify"), "valid path must verify");
    }

    #[test]
    fn test_roundtrip_depth5() {
        let mut seed = 0xC3_u64;
        let (leaf, sibs, bits) = rand_path(&mut seed, 5);
        let (proof, log, root) = prove_merkle_path_t16(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        assert!(verify_merkle_path_t16(&proof, log, sibs.len(), leaf, idx, root).expect("verify"));
    }

    #[test]
    fn test_wrong_root_rejected() {
        let mut seed = 0xD4_u64;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let (proof, log, root) = prove_merkle_path_t16(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        let mut bad = root;
        bad[0] ^= 1;
        assert!(!verify_merkle_path_t16(&proof, log, sibs.len(), leaf, idx, bad).unwrap_or(false), "wrong root must not verify");
    }

    #[test]
    fn test_wrong_index_rejected() {
        let mut seed = 0xE5_u64;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let (proof, log, root) = prove_merkle_path_t16(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        assert!(!verify_merkle_path_t16(&proof, log, sibs.len(), leaf, idx ^ 1, root).unwrap_or(false), "wrong index must not verify");
    }

    #[test]
    fn test_wrong_leaf_rejected() {
        let mut seed = 0xE6_u64;
        let (leaf, sibs, bits) = rand_path(&mut seed, 2);
        let (proof, log, root) = prove_merkle_path_t16(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        let mut bad = leaf;
        bad[0] ^= 1;
        assert!(!verify_merkle_path_t16(&proof, log, sibs.len(), bad, idx, root).unwrap_or(false), "wrong leaf must not verify");
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let mut seed = 0xF6_u64;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let (proof, log, root) = prove_merkle_path_t16(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        let mut bad = proof.clone();
        bad[proof.len() / 2] ^= 0xFF;
        assert!(!verify_merkle_path_t16(&bad, log, sibs.len(), leaf, idx, root).unwrap_or(false), "tampered proof must not verify");
    }

    // C1 root-binding regression: a malicious prover with an internally-valid trace
    // (honest siblings → real root R) who pins a DIFFERENT root cannot build a proof.
    #[test]
    fn test_forged_root_cannot_prove() {
        let mut seed = 0xC1_007_u64;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let log = compute_log_size(sibs.len());
        let (main, root) = build_trace(leaf, &sibs, &bits, log);
        let idx = bits_to_index(&bits);
        let mut bad_root = root;
        bad_root[0] ^= 1;
        let forged = build_preproc(leaf, idx, bad_root, sibs.len(), log);

        let config = make_config(log);
        let twiddles = CpuBackend::precompute_twiddles(
            CanonicCoset::new(log + LOG_BLOWUP + 1).circle_domain().half_coset,
        );
        let channel = &mut Blake2sM31Channel::default();
        let mut scheme =
            CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
        scheme.set_store_polynomials_coefficients();
        let mut tree = scheme.tree_builder();
        tree.extend_evals(forged);
        tree.commit(channel);
        let mut tree = scheme.tree_builder();
        tree.extend_evals(main);
        tree.commit(channel);
        mix_public(channel, leaf, idx, bad_root);
        let component = new_component(log);
        let res = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, scheme);
        assert!(res.is_err(), "trace root ≠ pinned root must violate the root-binding constraint (C1)");
    }

    // C2 regression: a forged preprocessed selector (is_first_comp → 0) must not
    // verify — the verifier pins the canonical preprocessed root.
    #[test]
    fn test_forged_preproc_rejected() {
        let mut seed = 0xC2_u64;
        let (leaf, sibs, bits) = rand_path(&mut seed, 2);
        let log = compute_log_size(sibs.len());
        let (main, root) = build_trace(leaf, &sibs, &bits, log);
        let idx = bits_to_index(&bits);
        let mut preproc = build_preproc(leaf, idx, root, sibs.len(), log);
        let domain = CanonicCoset::new(log).circle_domain();
        let n = 1usize << log;
        // is_first_comp is preproc index T+2 (rc[0..8], is_ext, is_int, is_first_comp).
        preproc[T + 2] = CircleEvaluation::new(domain, vec![BaseField::from_u32_unchecked(0); n]);

        let config = make_config(log);
        let twiddles = CpuBackend::precompute_twiddles(
            CanonicCoset::new(log + LOG_BLOWUP + 1).circle_domain().half_coset,
        );
        let channel = &mut Blake2sM31Channel::default();
        let mut scheme =
            CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
        scheme.set_store_polynomials_coefficients();
        let mut tree = scheme.tree_builder();
        tree.extend_evals(preproc);
        tree.commit(channel);
        let mut tree = scheme.tree_builder();
        tree.extend_evals(main);
        tree.commit(channel);
        mix_public(channel, leaf, idx, root);
        let component = new_component(log);
        if let Ok(proof) = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, scheme) {
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            assert!(!verify_merkle_path_t16(&bytes, log, sibs.len(), leaf, idx, root).unwrap_or(false), "forged preproc must not verify (C2)");
        }
    }
}
