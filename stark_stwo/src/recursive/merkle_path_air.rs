//! Poseidon2 Merkle authentication-path AIR — recursive-verifier gadget (R2).
//!
//! Proves a Merkle **authentication path**: that a `leaf` at a given `index`,
//! together with prover-committed sibling values, hashes up to a claimed `root`
//! using Poseidon2 (t=2) 2-to-1 compression.  This is the on-chain
//! `MerkleVerifier.verify(root, leaf, index, depth, siblings)` translated into
//! AIR constraints — the most-repeated (and most expensive) operation of the
//! recursive FRI verifier (one path per query per FRI layer).
//!
//! The existing [`crate::poseidon2_merkle_air`] proves a *whole tree* (all
//! leaves → root, for committing).  This gadget proves a *single path* (one
//! leaf + log₂N siblings → root, for verifying), which is the dual operation.
//!
//! # Path semantics
//!
//! For depth `D`, with `cur₀ = leaf` and index bits `b₀ … b_{D-1}` (LSB first):
//!
//! ```text
//! (left_i, right_i) = b_i ? (sib_i, cur_i) : (cur_i, sib_i)
//! cur_{i+1}         = compress(left_i, right_i)
//! root              = cur_D
//! ```
//!
//! `compress(l, r) = Poseidon2_t2([l, r])[0]` (identical to
//! `poseidon2_merkle_air::compress`).
//!
//! # Trace layout
//!
//! Each compression takes `N_ROUNDS = 8` rows (one Poseidon2 round each); row
//! `i·8 + r` is compression `i`, round `r`.  The state chains *within* a
//! compression via `[-1]` masks (as in `poseidon2_merkle_air`), and the path
//! chains *across* compressions because compression `i`'s init row reads
//! `cur = s0[-1]` (the previous compression's output) — except the very first,
//! which reads the `leaf`.
//!
//! Main trace (10 columns):
//! ```text
//! 0 s0   1 s1   2 t0   3 t1   4 inp0  5 inp1
//! 6 cur  (chained current node: leaf at row 0, else prev compression output)
//! 7 sib  (sibling value; meaningful on init rows)
//! 8 bit  (index bit b_i; boolean; meaningful on init rows)
//! 9 leaf (the leaf value; meaningful on row 0 only — the path input)
//! ```
//!
//! Preprocessed trace (4 columns): `rc0, rc1, is_init (r==0), is_first (row 0)`.
//!
//! # Public-input binding
//!
//! `(leaf, index, root)` are mixed into the Fiat-Shamir channel after the trace
//! commitment (the codebase convention for sub-proof gadgets), so the proof is
//! *specific to* one mixed `(leaf, index, root)` triple.
//!
//! Soundness (audit 2026-06-17):
//! - **[C2 — fixed]** the preprocessed tree (round constants + selectors + the
//!   claimed-index bits) is pinned by the verifier via `canonical_preproc_root`.
//! - **[C1 index + leaf binding — fixed]** `index` and `leaf` are bound in-circuit:
//!   the pinned `idx_bit` column carries the verifier-fixed index (one bit per
//!   compression) with `is_init·(bit − idx_bit) = 0`, and the pinned `leaf` column
//!   carries the verifier-fixed leaf with `is_first·(leaf − leaf_pinned) = 0`. A
//!   claimed `index`/`leaf` that disagrees with the committed path can't be proven
//!   (`test_forged_index_bits_cannot_prove`, `test_forged_leaf_cannot_prove`).
//! - **[C1 root binding — deferred]** `root` is still bound via Fiat-Shamir
//!   `mix_public`; the full in-circuit `(computed_root − root) = 0` binding is
//!   tightened at the recursive-verifier composition (where the root is a committed
//!   FRI-layer root and the leaf is the pinned per-query fold output).

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

use crate::poseidon2::{m31_add, m31_mul, M31_P, N_ROUNDS, RC};
use crate::poseidon2_merkle_air::compress;
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub const N_MAIN_COLS: usize = 10;
pub const MIN_LOG_SIZE: u32 = 3; // ≥ 8 rows = 1 compression
pub const MAX_LOG_SIZE: u32 = 24;
/// Maximum supported path depth (index fits in u32; trace depth bounded).
pub const MAX_DEPTH: usize = 28;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub type MerklePathComponent = FrameworkComponent<MerklePathEval>;

// ── Preprocessed column IDs ───────────────────────────────────────────────────

pub fn pc_rc0() -> PreProcessedColumnId { PreProcessedColumnId { id: "rmp_rc0".into() } }
pub fn pc_rc1() -> PreProcessedColumnId { PreProcessedColumnId { id: "rmp_rc1".into() } }
pub fn pc_is_init() -> PreProcessedColumnId { PreProcessedColumnId { id: "rmp_is_init".into() } }
pub fn pc_is_first() -> PreProcessedColumnId { PreProcessedColumnId { id: "rmp_is_first".into() } }
/// `idx_bit` carries the verifier-fixed claimed `index`, one bit per compression
/// on its init row (`(index >> i) & 1`); the AIR pins the trace's index bits to it
/// so `index` is bound in-circuit, not just via Fiat-Shamir (audit gap C1).
pub fn pc_idx_bit() -> PreProcessedColumnId { PreProcessedColumnId { id: "rmp_idx_bit".into() } }
/// `leaf_val` carries the verifier-fixed claimed `leaf` (row 0 only); the AIR pins
/// the trace's leaf to it so `leaf` is bound in-circuit (audit gap C1). In the
/// recursive composition this is the per-query fold output hashed to a leaf.
pub fn pc_leaf() -> PreProcessedColumnId { PreProcessedColumnId { id: "rmp_leaf".into() } }

pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    vec![pc_rc0(), pc_rc1(), pc_is_init(), pc_is_first(), pc_idx_bit(), pc_leaf()]
}

// ── Reference path hash ────────────────────────────────────────────────────────

/// Compute the Merkle root reached by hashing `leaf` up through `sibs` using the
/// index `bits` (LSB first). Mirrors the on-chain `MerkleVerifier.verify` fold.
pub fn merkle_path_root(leaf: u64, sibs: &[u64], bits: &[bool]) -> u64 {
    assert_eq!(sibs.len(), bits.len(), "sibs/bits length mismatch");
    let mut cur = leaf % M31_P;
    for i in 0..sibs.len() {
        let s = sibs[i] % M31_P;
        let (l, r) = if bits[i] { (s, cur) } else { (cur, s) };
        cur = compress(l, r);
    }
    cur
}

/// Pack index bits (LSB first) into a u32 index.
///
/// Panics if `bits.len() > 32` (a u32 index cannot hold more) — callers cap at
/// [`MAX_DEPTH`] (≤ 28), so this only guards direct misuse of this `pub` helper.
pub fn bits_to_index(bits: &[bool]) -> u32 {
    assert!(bits.len() <= 32, "bits_to_index: depth {} exceeds 32-bit index", bits.len());
    let mut idx = 0u32;
    for (i, &b) in bits.iter().enumerate() {
        if b {
            idx |= 1u32 << i;
        }
    }
    idx
}

// ── AIR ──────────────────────────────────────────────────────────────────────

pub struct MerklePathEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for MerklePathEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // max constraint degree is 3
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let rc0 = eval.get_preprocessed_column(pc_rc0());
        let rc1 = eval.get_preprocessed_column(pc_rc1());
        let is_init = eval.get_preprocessed_column(pc_is_init());
        let is_first = eval.get_preprocessed_column(pc_is_first());
        let idx_bit = eval.get_preprocessed_column(pc_idx_bit());
        let leaf_pinned = eval.get_preprocessed_column(pc_leaf());

        let [s0_curr, s0_prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [s1_curr, s1_prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [t0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [t1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [inp0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [inp1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [cur] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [sib] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [bit] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [leaf] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let not_init = one.clone() - is_init.clone();
        let not_first = one - is_first.clone();

        // ── Poseidon2 round core (identical to poseidon2_merkle_air) ──────────
        let x0 = inp0.clone() + rc0;
        let x1 = inp1.clone() + rc1;
        let sbox0 = t0.clone() * t0.clone() * x0.clone(); // x0^5
        let sbox1 = t1.clone() * t1.clone() * x1.clone(); // x1^5
        let three = BaseField::from_u32_unchecked(3);
        eval.add_constraint(t0 - x0.clone() * x0); // C_t0: t0 = (inp0+rc0)²
        eval.add_constraint(t1 - x1.clone() * x1); // C_t1
        eval.add_constraint(s0_curr - (sbox0.clone() * three + sbox1.clone())); // C_s0: MDS row0
        eval.add_constraint(s1_curr - (sbox0 + sbox1 * three)); // C_s1: MDS row1

        // ── cur helper: chained current node ─────────────────────────────────
        // cur = is_first·leaf + (1−is_first)·s0[-1]    (only meaningful on init rows)
        let cur_expected = is_first.clone() * leaf.clone() + not_first * s0_prev.clone();
        eval.add_constraint(is_init.clone() * (cur.clone() - cur_expected));

        // ── Init-row wiring: index-bit child selection ───────────────────────
        // left  = bit·sib + (1−bit)·cur ;  right = bit·cur + (1−bit)·sib
        let left = bit.clone() * sib.clone() + (one_minus(&bit)) * cur.clone();
        let right = bit.clone() * cur + (one_minus(&bit)) * sib;
        eval.add_constraint(is_init.clone() * (inp0.clone() - left)); // C_inp0_init
        eval.add_constraint(is_init.clone() * (inp1.clone() - right)); // C_inp1_init
        eval.add_constraint(is_init.clone() * (bit.clone() * bit.clone() - bit.clone())); // C_bit boolean
        // C_idx: the trace's index bit equals the pinned claimed-index bit on each
        // init row — binds `index` in-circuit to the path bits (audit gap C1).
        eval.add_constraint(is_init.clone() * (bit - idx_bit));
        // C_leaf: the trace's leaf equals the pinned verifier-fixed leaf (row 0) —
        // binds `leaf` in-circuit (audit gap C1). In the recursive composition the
        // pinned leaf is the per-query fold output hashed via hashLeaf.
        eval.add_constraint(is_first.clone() * (leaf.clone() - leaf_pinned));

        // ── Non-init chaining: state carries within a compression ────────────
        eval.add_constraint(not_init.clone() * (inp0 - s0_prev)); // C_inp0_chain
        eval.add_constraint(not_init * (inp1 - s1_prev)); // C_inp1_chain

        eval
    }
}

/// `1 − x` for an `E::F` term (avoids needing a standalone `one` clone chain).
#[inline]
fn one_minus<F: Clone + std::ops::Sub<Output = F> + From<BaseField>>(x: &F) -> F {
    F::from(BaseField::from_u32_unchecked(1)) - x.clone()
}

fn new_component(log_n_rows: u32) -> MerklePathComponent {
    MerklePathComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_column_ids()),
        MerklePathEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace size helpers ─────────────────────────────────────────────────────────

pub fn compute_log_size(depth: usize) -> u32 {
    let n_real = depth.max(1) * N_ROUNDS;
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < n_real {
        log += 1;
    }
    log
}

// ── Preprocessed columns (witness-free canonical source) ───────────────────────

/// Build the canonical preprocessed columns `[rc0, rc1, is_init, is_first]` from
/// `log_size` alone (no witness): Poseidon2 round constants keyed by the in-round
/// index, `is_init = 1` on each compression's row 0, `is_first = 1` on row 0.
///
/// This is the single source of truth for the preprocessed tree — [`build_trace`]
/// commits exactly these, and [`verify_merkle_path`] recomputes their commitment
/// root to PIN them (audit gap C2), so a prover cannot forge `is_init`/`is_first`
/// (to break the sponge/leaf wiring) or `rc0`/`rc1` (to swap the hash function).
pub fn build_preproc(leaf: u64, index: u32, log_size: u32) -> TraceColumns {
    let n = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let to_m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut rc0_c = vec![bf0; n];
    let mut rc1_c = vec![bf0; n];
    let mut init_c = vec![bf0; n];
    let mut first_c = vec![bf0; n];
    let mut idx_bit_c = vec![bf0; n];
    let mut leaf_c = vec![bf0; n];
    leaf_c[0] = to_m31(leaf); // verifier-fixed leaf, row 0 only

    let n_comp = n / N_ROUNDS;
    for i in 0..n_comp {
        // Bit `i` of the claimed index on compression `i`'s init row. A valid path
        // has index < 2^depth, so bits at i ≥ depth (and i ≥ 32) are 0 — matching
        // the trace's padding-compression bits.
        let idx_bit = if i < 32 { (index >> i) & 1 } else { 0 };
        for r in 0..N_ROUNDS {
            let row = i * N_ROUNDS + r;
            rc0_c[row] = to_m31(RC[r][0] as u64);
            rc1_c[row] = to_m31(RC[r][1] as u64);
            init_c[row] = if r == 0 { to_m31(1) } else { bf0 };
            first_c[row] = if row == 0 { to_m31(1) } else { bf0 };
            idx_bit_c[row] = if r == 0 { to_m31(idx_bit as u64) } else { bf0 };
        }
    }
    for c in [&mut rc0_c, &mut rc1_c, &mut init_c, &mut first_c, &mut idx_bit_c, &mut leaf_c] {
        bit_reverse_coset_to_circle_domain_order(c);
    }
    [rc0_c, rc1_c, init_c, first_c, idx_bit_c, leaf_c]
        .into_iter()
        .map(|c| CircleEvaluation::new(domain, c))
        .collect()
}

/// Recompute the canonical preprocessed-tree commitment root, mirroring the
/// prover's Tree 0 commit. The verifier pins `proof.commitments[0]` to this.
/// `leaf`/`index` are verifier-fixed public inputs carried in the pinned columns.
fn canonical_preproc_root(
    leaf: u64,
    index: u32,
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
    tree.extend_evals(build_preproc(leaf, index, log_size));
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

// ── Trace builder ──────────────────────────────────────────────────────────────

/// Build the Merkle-path trace. Returns `(main_columns, preprocessed_columns,
/// root)`. The first `sibs.len()` compressions are the real path; remaining rows
/// are padded with valid `H(cur, 0)` compressions (constraints stay satisfied).
/// The preprocessed columns come from [`build_preproc`] (the canonical source).
pub fn build_trace(
    leaf: u64,
    sibs: &[u64],
    bits: &[bool],
    log_size: u32,
) -> (TraceColumns, TraceColumns, u64) {
    assert_eq!(sibs.len(), bits.len(), "sibs/bits length mismatch");
    let depth = sibs.len();
    let n = 1usize << log_size;
    debug_assert!(depth * N_ROUNDS <= n, "path exceeds trace capacity");
    let domain = CanonicCoset::new(log_size).circle_domain();

    let to_m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);
    let bf0 = BaseField::from_u32_unchecked(0);

    let mut col: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];

    let n_comp = n / N_ROUNDS;
    let mut prev_out = 0u64; // s0 output of the previous compression
    let mut path_root = leaf % M31_P;

    for i in 0..n_comp {
        // cur node: leaf for the first compression, else the previous output.
        let cur_val = if i == 0 { leaf % M31_P } else { prev_out };
        // Sibling / bit: real path values for i < depth, padding zeros otherwise.
        let sib_val = if i < depth { sibs[i] % M31_P } else { 0 };
        let bit_val = if i < depth { bits[i] } else { false };
        let (lv, rv) = if bit_val { (sib_val, cur_val) } else { (cur_val, sib_val) };

        let mut state = [lv, rv];
        for r in 0..N_ROUNDS {
            let row = i * N_ROUNDS + r;
            let inp0v = if r == 0 { lv } else { state[0] };
            let inp1v = if r == 0 { rv } else { state[1] };
            let x0 = m31_add(inp0v, RC[r][0] as u64);
            let x1 = m31_add(inp1v, RC[r][1] as u64);
            let t0v = m31_mul(x0, x0);
            let t1v = m31_mul(x1, x1);
            let sbox0 = m31_mul(m31_mul(t0v, t0v), x0);
            let sbox1 = m31_mul(m31_mul(t1v, t1v), x1);
            let s0n = m31_add(m31_add(m31_add(sbox0, sbox0), sbox0), sbox1);
            let s1n = m31_add(sbox0, m31_add(m31_add(sbox1, sbox1), sbox1));

            col[0][row] = to_m31(s0n);
            col[1][row] = to_m31(s1n);
            col[2][row] = to_m31(t0v);
            col[3][row] = to_m31(t1v);
            col[4][row] = to_m31(inp0v);
            col[5][row] = to_m31(inp1v);
            if r == 0 {
                col[6][row] = to_m31(cur_val); // cur
                col[7][row] = to_m31(sib_val); // sib
                col[8][row] = if bit_val { to_m31(1) } else { bf0 }; // bit
                col[9][row] = if i == 0 { to_m31(leaf) } else { bf0 }; // leaf
            }

            state = [s0n, s1n];
        }
        prev_out = state[0];
        if i + 1 == depth.max(1) {
            path_root = prev_out; // capture root at the last REAL compression
        }
    }

    let mut main = col;
    for c in main.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(c);
    }

    let main_cols: TraceColumns = main.into_iter().map(|c| CircleEvaluation::new(domain, c)).collect();
    let preproc = build_preproc(leaf, bits_to_index(bits), log_size); // single canonical source (C1/C2)
    (main_cols, preproc, path_root)
}

// ── Multi-path builders (N independent paths in one component) ───────────────────
//
// The AIR is unchanged — it is per-row with `is_first` gating each path's reset
// (`cur = is_first·leaf + (1−is_first)·s0[-1]`). N paths of uniform `depth` are laid
// out in consecutive blocks of `depth` compressions; `is_first`/`idx_bit`/`leaf` are
// set per path. All paths authenticate their leaf into their own root (in the
// recursive composition, all into the same committed FRI-layer root).

/// Smallest `log_size` fitting `num_paths` paths of `depth` compressions.
pub fn compute_log_size_multi(num_paths: usize, depth: usize) -> u32 {
    let comps = num_paths.max(1) * depth.max(1);
    compute_log_size(comps) // reuses: smallest 2^k ≥ comps·N_ROUNDS
}

/// Canonical preprocessed columns for `num_paths` paths of uniform `depth`:
/// per-compression rc/is_init, `is_first` at each path's first compression, and
/// the pinned `idx_bit`/`leaf` per path. Single source of truth (C1/C2).
pub fn build_preproc_multi(
    leaves: &[u64],
    indices: &[u32],
    depth: usize,
    log_size: u32,
) -> TraceColumns {
    assert_eq!(leaves.len(), indices.len(), "leaves/indices length mismatch");
    let n = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let to_m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut rc0_c = vec![bf0; n];
    let mut rc1_c = vec![bf0; n];
    let mut init_c = vec![bf0; n];
    let mut first_c = vec![bf0; n];
    let mut idx_bit_c = vec![bf0; n];
    let mut leaf_c = vec![bf0; n];

    let n_comp = n / N_ROUNDS;
    for comp in 0..n_comp {
        // Which path/compression is this? (paths laid out in blocks of `depth`.)
        let path = comp / depth;
        let j = comp % depth; // compression within the path
        let is_real = path < leaves.len();
        for r in 0..N_ROUNDS {
            let row = comp * N_ROUNDS + r;
            rc0_c[row] = to_m31(RC[r][0] as u64);
            rc1_c[row] = to_m31(RC[r][1] as u64);
            init_c[row] = if r == 0 { to_m31(1) } else { bf0 };
            if r == 0 && is_real {
                if j == 0 {
                    first_c[row] = to_m31(1); // path start
                    leaf_c[row] = to_m31(leaves[path]);
                }
                let bit = if j < 32 { (indices[path] >> j) & 1 } else { 0 };
                idx_bit_c[row] = to_m31(bit as u64);
            }
        }
    }
    for c in [&mut rc0_c, &mut rc1_c, &mut init_c, &mut first_c, &mut idx_bit_c, &mut leaf_c] {
        bit_reverse_coset_to_circle_domain_order(c);
    }
    [rc0_c, rc1_c, init_c, first_c, idx_bit_c, leaf_c]
        .into_iter()
        .map(|c| CircleEvaluation::new(domain, c))
        .collect()
}

/// Build the multi-path main trace. `leaves[p]`, `sibs[p]`, `bits[p]` describe path
/// `p` (all of uniform `depth`). Returns `(main_columns, preproc_columns, roots)`.
pub fn build_trace_multi(
    leaves: &[u64],
    sibs: &[Vec<u64>],
    bits: &[Vec<bool>],
    log_size: u32,
) -> (TraceColumns, TraceColumns, Vec<u64>) {
    let num_paths = leaves.len();
    assert!(num_paths >= 1, "need ≥ 1 path");
    assert_eq!(sibs.len(), num_paths);
    assert_eq!(bits.len(), num_paths);
    let depth = sibs[0].len();
    assert!(sibs.iter().all(|s| s.len() == depth), "paths must share depth");
    assert!(bits.iter().all(|b| b.len() == depth), "paths must share depth");

    let n = 1usize << log_size;
    debug_assert!(num_paths * depth * N_ROUNDS <= n, "paths exceed trace capacity");
    let domain = CanonicCoset::new(log_size).circle_domain();
    let to_m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);
    let bf0 = BaseField::from_u32_unchecked(0);

    let mut col: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];
    let mut roots = Vec::with_capacity(num_paths);

    let n_comp = n / N_ROUNDS;
    let mut prev_out = 0u64;
    for comp in 0..n_comp {
        let path = comp / depth;
        let j = comp % depth;
        let is_real = path < num_paths;
        let (leaf, sib_val, bit_val) = if is_real {
            let leaf = leaves[path] % M31_P;
            (leaf, sibs[path][j] % M31_P, bits[path][j])
        } else {
            (0, 0, false) // padding: H(cur, 0)
        };
        // cur: leaf at each path's first compression, else the previous output.
        let cur_val = if is_real && j == 0 { leaf } else { prev_out };
        let (lv, rv) = if bit_val { (sib_val, cur_val) } else { (cur_val, sib_val) };

        let mut state = [lv, rv];
        for r in 0..N_ROUNDS {
            let row = comp * N_ROUNDS + r;
            let inp0v = if r == 0 { lv } else { state[0] };
            let inp1v = if r == 0 { rv } else { state[1] };
            let x0 = m31_add(inp0v, RC[r][0] as u64);
            let x1 = m31_add(inp1v, RC[r][1] as u64);
            let t0v = m31_mul(x0, x0);
            let t1v = m31_mul(x1, x1);
            let sbox0 = m31_mul(m31_mul(t0v, t0v), x0);
            let sbox1 = m31_mul(m31_mul(t1v, t1v), x1);
            let s0n = m31_add(m31_add(m31_add(sbox0, sbox0), sbox0), sbox1);
            let s1n = m31_add(sbox0, m31_add(m31_add(sbox1, sbox1), sbox1));

            col[0][row] = to_m31(s0n);
            col[1][row] = to_m31(s1n);
            col[2][row] = to_m31(t0v);
            col[3][row] = to_m31(t1v);
            col[4][row] = to_m31(inp0v);
            col[5][row] = to_m31(inp1v);
            if r == 0 {
                col[6][row] = to_m31(cur_val);
                col[7][row] = to_m31(sib_val);
                col[8][row] = if bit_val { to_m31(1) } else { bf0 };
                col[9][row] = if is_real && j == 0 { to_m31(leaf) } else { bf0 };
            }
            state = [s0n, s1n];
        }
        prev_out = state[0];
        if is_real && j == depth - 1 {
            roots.push(prev_out); // path `path`'s root at its last compression
        }
    }

    for c in col.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(c);
    }
    let main_cols: TraceColumns = col.into_iter().map(|c| CircleEvaluation::new(domain, c)).collect();
    let indices: Vec<u32> = bits.iter().map(|b| bits_to_index(b)).collect();
    let preproc = build_preproc_multi(leaves, &indices, depth, log_size);
    (main_cols, preproc, roots)
}

// ── Prove / verify roundtrip ────────────────────────────────────────────────────

fn mix_public(channel: &mut Blake2sM31Channel, leaf: u64, index: u32, root: u64) {
    channel.mix_u32s(&[(leaf % M31_P) as u32, index, (root % M31_P) as u32]);
}

/// Prove a Merkle authentication path. Returns `(proof_bytes, log_size, root)`.
pub fn prove_merkle_path(leaf: u64, sibs: &[u64], bits: &[bool]) -> Result<(Vec<u8>, u32, u64), String> {
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
    let (main_cols, preproc, root) = build_trace(leaf, sibs, bits, log_size);
    let index = bits_to_index(bits);
    let proof = prove_columns(main_cols, preproc, log_size, leaf, index, root)?;
    Ok((proof, log_size, root))
}

fn prove_columns(
    main_cols: TraceColumns,
    preproc: TraceColumns,
    log_size: u32,
    leaf: u64,
    index: u32,
    root: u64,
) -> Result<Vec<u8>, String> {
    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preproc); // Tree 0: preprocessed (rc0, rc1, is_init, is_first)
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_cols); // Tree 1: main trace (10 columns)
    tree_builder.commit(channel);

    mix_public(channel, leaf, index, root);

    let component = new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;
    bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))
}

/// Verify a proof produced by [`prove_merkle_path`] against the claimed
/// `(leaf, index, root)`.
pub fn verify_merkle_path(
    proof_bytes: &[u8],
    log_size: u32,
    leaf: u64,
    index: u32,
    root: u64,
) -> Result<bool, String> {
    if !(MIN_LOG_SIZE..=MAX_LOG_SIZE).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range [{MIN_LOG_SIZE}, {MAX_LOG_SIZE}]"));
    }

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

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

    // C2 + C1: pin the preprocessed tree (round constants, selectors, AND the
    // claimed-index bits) to its canonical value — a forged rc/is_init/is_first
    // tree, or a claimed `index` that disagrees with the committed path bits, no
    // longer verifies (the `idx_bit` constraint ties trace bits to this index).
    if proof.commitments[0] != canonical_preproc_root(leaf, index, log_size) {
        return Ok(false);
    }

    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    mix_public(verifier_channel, leaf, index, root);

    let result = verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof);
    Ok(result.is_ok())
}

// ── Multi-path prove / verify ────────────────────────────────────────────────────

fn canonical_preproc_root_multi(
    leaves: &[u64],
    indices: &[u32],
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
    tree.extend_evals(build_preproc_multi(leaves, indices, depth, log_size));
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

fn mix_public_multi(channel: &mut Blake2sM31Channel, leaves: &[u64], indices: &[u32], roots: &[u64]) {
    let mut words = Vec::with_capacity(leaves.len() * 3);
    for p in 0..leaves.len() {
        words.push((leaves[p] % M31_P) as u32);
        words.push(indices[p]);
        words.push((roots[p] % M31_P) as u32);
    }
    channel.mix_u32s(&words);
}

/// Prove `N` independent Merkle paths (uniform depth) in ONE component.
/// Returns `(proof, log_size, roots)`.
pub fn prove_paths_multi(
    leaves: &[u64],
    sibs: &[Vec<u64>],
    bits: &[Vec<bool>],
) -> Result<(Vec<u8>, u32, Vec<u64>), String> {
    if leaves.is_empty() {
        return Err("need ≥ 1 path".into());
    }
    let depth = sibs.first().map(|s| s.len()).unwrap_or(0);
    if depth == 0 {
        return Err("path depth must be ≥ 1".into());
    }
    let log_size = compute_log_size_multi(leaves.len(), depth);
    if log_size > MAX_LOG_SIZE {
        return Err(format!("multi-path log_size {log_size} exceeds {MAX_LOG_SIZE}"));
    }
    let (main_cols, preproc, roots) = build_trace_multi(leaves, sibs, bits, log_size);
    let indices: Vec<u32> = bits.iter().map(|b| bits_to_index(b)).collect();

    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let channel = &mut Blake2sM31Channel::default();
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    let mut tree = scheme.tree_builder();
    tree.extend_evals(preproc);
    tree.commit(channel);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(main_cols);
    tree.commit(channel);

    mix_public_multi(channel, leaves, &indices, &roots);

    let component = new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, scheme)
        .map_err(|e| format!("multi-path prove error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("multi-path serialize error: {e:?}"))?;
    Ok((bytes, log_size, roots))
}

/// Verify a multi-path proof against the claimed `(depth, leaves, indices, roots)`.
pub fn verify_paths_multi(
    proof_bytes: &[u8],
    log_size: u32,
    depth: usize,
    leaves: &[u64],
    indices: &[u32],
    roots: &[u64],
) -> Result<bool, String> {
    if !(MIN_LOG_SIZE..=MAX_LOG_SIZE).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range"));
    }
    if leaves.len() != indices.len() || leaves.len() != roots.len() {
        return Err("leaves/indices/roots length mismatch".into());
    }

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("multi-path deserialize error: {e:?}"))?;

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
    if proof.commitments[0] != canonical_preproc_root_multi(leaves, indices, depth, log_size) {
        return Ok(false);
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    mix_public_multi(verifier_channel, leaves, indices, roots);

    let result = verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof);
    Ok(result.is_ok())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_m31(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) % M31_P
    }

    fn rand_path(seed: &mut u64, depth: usize) -> (u64, Vec<u64>, Vec<bool>) {
        let leaf = rand_m31(seed);
        let sibs: Vec<u64> = (0..depth).map(|_| rand_m31(seed)).collect();
        let bits: Vec<bool> = (0..depth).map(|_| rand_m31(seed) & 1 == 1).collect();
        (leaf, sibs, bits)
    }

    #[test]
    fn test_path_root_matches_manual_compress() {
        // Depth 2, both bit orderings, checked against direct compress calls.
        let leaf = 12345u64;
        let s0 = 6789u64;
        let s1 = 222u64;
        // bits [false, true]: h1 = compress(leaf, s0); root = compress(s1, h1)
        let h1 = compress(leaf, s0);
        let expected = compress(s1, h1);
        assert_eq!(merkle_path_root(leaf, &[s0, s1], &[false, true]), expected);
    }

    #[test]
    fn test_build_trace_root_matches_reference() {
        let mut seed = 0x1111;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let log = compute_log_size(sibs.len());
        let (main, preproc, root) = build_trace(leaf, &sibs, &bits, log);
        assert_eq!(main.len(), N_MAIN_COLS);
        assert_eq!(preproc.len(), 6); // rc0, rc1, is_init, is_first, idx_bit, leaf
        assert_eq!(root, merkle_path_root(leaf, &sibs, &bits), "trace root must match reference");
    }

    #[test]
    fn test_bits_to_index() {
        assert_eq!(bits_to_index(&[true, false, true, true]), 0b1101);
        assert_eq!(bits_to_index(&[false, false]), 0);
    }

    #[test]
    fn test_roundtrip_depth1() {
        let mut seed = 0xA1;
        let (leaf, sibs, bits) = rand_path(&mut seed, 1);
        let (proof, log, root) = prove_merkle_path(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        assert!(verify_merkle_path(&proof, log, leaf, idx, root).expect("verify"));
    }

    #[test]
    fn test_roundtrip_depth3() {
        let mut seed = 0xB2;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let (proof, log, root) = prove_merkle_path(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        assert!(verify_merkle_path(&proof, log, leaf, idx, root).expect("verify"), "valid path must verify");
    }

    #[test]
    fn test_roundtrip_depth5() {
        let mut seed = 0xC3;
        let (leaf, sibs, bits) = rand_path(&mut seed, 5);
        let (proof, log, root) = prove_merkle_path(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        assert!(verify_merkle_path(&proof, log, leaf, idx, root).expect("verify"));
    }

    #[test]
    fn test_wrong_root_rejected() {
        // A different claimed root changes the mixed transcript → verify fails.
        let mut seed = 0xD4;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let (proof, log, root) = prove_merkle_path(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        assert!(
            !verify_merkle_path(&proof, log, leaf, idx, root ^ 1).unwrap_or(false),
            "a wrong root must not verify",
        );
    }

    #[test]
    fn test_wrong_index_rejected() {
        let mut seed = 0xE5;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let (proof, log, root) = prove_merkle_path(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        assert!(
            !verify_merkle_path(&proof, log, leaf, idx ^ 1, root).unwrap_or(false),
            "a wrong index must not verify",
        );
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let mut seed = 0xF6;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let (proof, log, root) = prove_merkle_path(leaf, &sibs, &bits).expect("prove");
        let idx = bits_to_index(&bits);
        let mut bad = proof.clone();
        bad[proof.len() / 2] ^= 0xFF;
        assert!(!verify_merkle_path(&bad, log, leaf, idx, root).unwrap_or(false), "tampered proof must not verify");
    }

    #[test]
    fn test_corrupted_trace_rejected() {
        // Corrupt the s0 column → the Poseidon2 round constraints reject it.
        let mut seed = 0x77;
        let (leaf, sibs, bits) = rand_path(&mut seed, 2);
        let log = compute_log_size(sibs.len());
        let (mut main, preproc, root) = build_trace(leaf, &sibs, &bits, log);
        let domain = CanonicCoset::new(log).circle_domain();
        let mut vals = main[0].values.clone(); // column 0 = s0
        vals[1] = vals[1] + BaseField::from_u32_unchecked(1);
        main[0] = CircleEvaluation::new(domain, vals);
        let idx = bits_to_index(&bits);
        match prove_columns(main, preproc, log, leaf, idx, root) {
            Ok(proof) => assert!(
                !verify_merkle_path(&proof, log, leaf, idx, root).unwrap_or(false),
                "a corrupted trace must not yield a verifying proof",
            ),
            Err(_) => {}
        }
    }

    // C2 regression: a prover that forges the `is_init` preprocessed selector to
    // all-zero must not verify — the verifier pins the canonical preprocessed root.
    #[test]
    fn test_forged_preproc_rejected() {
        let mut seed = 0xC2;
        let (leaf, sibs, bits) = rand_path(&mut seed, 2);
        let log = compute_log_size(sibs.len());
        let (main, mut preproc, root) = build_trace(leaf, &sibs, &bits, log);
        let idx = bits_to_index(&bits);
        let domain = CanonicCoset::new(log).circle_domain();
        let n = 1usize << log;

        // Forge is_init (preproc[2]) → all-zero (would disable the absorb wiring).
        preproc[2] = CircleEvaluation::new(domain, vec![BaseField::from_u32_unchecked(0); n]);

        // The forged trace may or may not still satisfy the (now differently-gated)
        // constraints, but its preprocessed root ≠ canonical → verify must reject.
        if let Ok(proof) = prove_columns(main, preproc, log, leaf, idx, root) {
            assert!(
                !verify_merkle_path(&proof, log, leaf, idx, root).unwrap_or(false),
                "a forged preprocessed tree must not verify (C2 pinned)",
            );
        }
    }

    // C1 regression: a prover whose trace path bits are for index X but whose
    // `idx_bit` preprocessed column claims a different index cannot even build a
    // valid proof — the in-circuit `is_init·(bit − idx_bit)=0` constraint fails.
    #[test]
    fn test_forged_index_bits_cannot_prove() {
        let mut seed = 0xC1;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let log = compute_log_size(sibs.len());
        let (main, _canonical, root) = build_trace(leaf, &sibs, &bits, log);
        let idx = bits_to_index(&bits);

        // Preprocessed idx_bit for a DIFFERENT index (flip bit 0) — inconsistent
        // with the trace's committed path bits.
        let forged_preproc = build_preproc(leaf, idx ^ 1, log);
        let res = prove_columns(main, forged_preproc, log, leaf, idx ^ 1, root);
        assert!(
            res.is_err(),
            "trace bits ≠ claimed idx_bit must violate the index-binding constraint (C1)",
        );
    }

    // Multi-path: N independent paths of uniform depth in ONE component.
    #[test]
    fn test_multi_path_roundtrip() {
        let mut seed = 0x3a7f_u64;
        let num_paths = 3;
        let depth = 2;
        let leaves: Vec<u64> = (0..num_paths).map(|_| rand_m31(&mut seed)).collect();
        let sibs: Vec<Vec<u64>> = (0..num_paths)
            .map(|_| (0..depth).map(|_| rand_m31(&mut seed)).collect())
            .collect();
        let bits: Vec<Vec<bool>> = (0..num_paths)
            .map(|_| (0..depth).map(|_| rand_m31(&mut seed) & 1 == 1).collect())
            .collect();

        let (proof, log, roots) = prove_paths_multi(&leaves, &sibs, &bits).unwrap();
        // Each returned root matches the single-path reference.
        for p in 0..num_paths {
            assert_eq!(roots[p], merkle_path_root(leaves[p], &sibs[p], &bits[p]));
        }
        let indices: Vec<u32> = bits.iter().map(|b| bits_to_index(b)).collect();
        assert!(verify_paths_multi(&proof, log, depth, &leaves, &indices, &roots).unwrap());
        // A wrong claimed root for one path must fail.
        let mut bad = roots.clone();
        bad[1] ^= 1;
        assert!(!verify_paths_multi(&proof, log, depth, &leaves, &indices, &bad).unwrap_or(false));
    }

    // C1 regression: a trace whose committed leaf is X but whose pinned `leaf`
    // preprocessed column claims Y ≠ X cannot be proven — the is_first-gated
    // leaf-equality constraint is violated.
    #[test]
    fn test_forged_leaf_cannot_prove() {
        let mut seed = 0xC1_1eaf;
        let (leaf, sibs, bits) = rand_path(&mut seed, 3);
        let log = compute_log_size(sibs.len());
        let (main, _canonical, root) = build_trace(leaf, &sibs, &bits, log);
        let idx = bits_to_index(&bits);
        // Pinned leaf claims a different value than the trace's committed leaf.
        let forged_preproc = build_preproc(leaf ^ 1, idx, log);
        let res = prove_columns(main, forged_preproc, log, leaf ^ 1, idx, root);
        assert!(
            res.is_err(),
            "trace leaf ≠ pinned leaf must violate the leaf-binding constraint (C1)",
        );
    }
}
