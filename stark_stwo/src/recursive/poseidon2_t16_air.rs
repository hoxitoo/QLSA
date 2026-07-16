//! Poseidon2 **t=16** compression AIR — the 128-bit recursion inner-hash primitive.
//!
//! Proves one 2-to-1 compression `node = compress_t16(left, right)` where each
//! node is an **8-word (248-bit) M31 value** (`left`/`right`/`node ∈ M31⁸`):
//!
//! ```text
//! state = (l0..l7, r0..r7) → permute_t16 → node = state[0..8]
//! ```
//!
//! The FINAL rung of the inner-hash ladder (t=2 → t=8 → **t=16**): 8-word nodes
//! raise node-collision cost to ~2^124 ≈ **128-bit** — the target soundness level
//! and the width of Stwo's native Poseidon2-16.  Per the path decision
//! (2026-06-17), t=16's value is *inside* the recursion (constant on-chain gas),
//! never as a standalone verifier (~400M+ gas).  This AIR is the direct t=16
//! analogue of [`super::poseidon2_t8_air`]: the same one-round-per-row layout and
//! S-box helper pattern, with 16-cell linear layers.
//!
//! # Trace layout (80 main columns + 43 preprocessed)
//!
//! ```text
//! Main (one round per row):
//!   in[0..16]   — state entering the round (before AddRC)
//!   sq[0..16]   — S-box square helper: sq[i] = (in[i]+rc[i])²
//!   sbox[0..16] — S-box output: sbox[i] = sq[i]²·(in[i]+rc[i])  (keeps out linear)
//!   out[0..16]  — state after the round's linear layer
//!   raw[0..16]  — compression input (l0..7, r0..7); meaningful on row 0 only
//!
//! Preprocessed (verifier-pinned canonical source, C2):
//!   rc[0..16]   — round constants (cell 0 only on internal rounds)
//!   is_ext / is_int / is_first — as in the t=8 AIR
//! ```
//!
//! Row map: rows 0..4 external (K_RC[0..64]), rows 4..18 internal (K_RC[128..142]
//! on cell 0), rows 18..22 external (K_RC[64..128]), rows 22.. zero padding.
//! Node = `out[0..8]` on row 21.  Same 22-round schedule as t=8 (R_F=8, R_P=14).

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

use crate::poseidon2::{m31_add, m31_mul, M31_P};
use crate::poseidon2_t16::{compress_t16, K_RC, R_F, R_P, T};
use crate::recursive::poseidon2_t8_air::m4_expr;
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub const N_MAIN_COLS: usize = 80;
/// 22 permutation rounds (R_F=8 + R_P=14) → the trace needs ≥ 32 rows.
pub const N_REAL_ROWS: usize = R_F + R_P; // 22
pub const LOG_SIZE: u32 = 5; // 32 rows ≥ 22

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;
pub type Poseidon2T16Component = FrameworkComponent<Poseidon2T16Eval>;

// ── Preprocessed column IDs ───────────────────────────────────────────────────

pub fn pc_rc(i: usize) -> PreProcessedColumnId {
    PreProcessedColumnId { id: format!("p2t16_rc{i}") }
}
pub fn pc_is_ext() -> PreProcessedColumnId {
    PreProcessedColumnId { id: "p2t16_is_ext".into() }
}
pub fn pc_is_int() -> PreProcessedColumnId {
    PreProcessedColumnId { id: "p2t16_is_int".into() }
}
pub fn pc_is_first() -> PreProcessedColumnId {
    PreProcessedColumnId { id: "p2t16_is_first".into() }
}
/// `raw_pin[0..T]` — verifier-fixed compression input (left‖right), pinned to the
/// trace's `raw` (row 0) so `(left, right)` are bound in-circuit (C1).
pub fn pc_raw(i: usize) -> PreProcessedColumnId {
    PreProcessedColumnId { id: format!("p2t16_raw{i}") }
}
/// `node_pin[0..T/2]` — verifier-fixed output node, pinned to the trace's output
/// row (C1). `is_node` marks the last real round row.
pub fn pc_node(k: usize) -> PreProcessedColumnId {
    PreProcessedColumnId { id: format!("p2t16_node{k}") }
}
pub fn pc_is_node() -> PreProcessedColumnId {
    PreProcessedColumnId { id: "p2t16_is_node".into() }
}
pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    let mut ids: Vec<PreProcessedColumnId> = (0..T).map(pc_rc).collect();
    ids.push(pc_is_ext());
    ids.push(pc_is_int());
    ids.push(pc_is_first());
    for i in 0..T {
        ids.push(pc_raw(i));
    }
    for k in 0..(T / 2) {
        ids.push(pc_node(k));
    }
    ids.push(pc_is_node());
    ids
}

// ── Linear layers as generic expressions ───────────────────────────────────────

use std::ops::Mul;

/// External linear layer `M_E = circ(2·M4, M4, M4, M4)` on a 16-vector:
/// apply M4 to each 4-cell block (→ v0..v3), then out_block_b = v_b + Σ_j v_j.
pub(crate) fn mat_external16_expr<F>(a: &[F; 16]) -> [F; 16]
where
    F: Clone + std::ops::Add<Output = F> + Mul<BaseField, Output = F>,
{
    let v: [[F; 4]; 4] = std::array::from_fn(|b| {
        m4_expr(&std::array::from_fn(|k| a[4 * b + k].clone()))
    });
    std::array::from_fn(|i| {
        let b = i / 4;
        let k = i % 4;
        let sigma = v[0][k].clone() + v[1][k].clone() + v[2][k].clone() + v[3][k].clone();
        v[b][k].clone() + sigma
    })
}

/// Internal linear layer `M_I = J + diag(1..16)`: `out_i = Σ_j a_j + (i+1)·a_i`.
pub(crate) fn mat_internal16_expr<F>(a: &[F; 16]) -> [F; 16]
where
    F: Clone + std::ops::Add<Output = F> + Mul<BaseField, Output = F>,
{
    let mut sum = a[0].clone();
    for j in 1..16 {
        sum = sum + a[j].clone();
    }
    std::array::from_fn(|i| {
        sum.clone() + a[i].clone() * BaseField::from_u32_unchecked((i + 1) as u32)
    })
}

// ── AIR ────────────────────────────────────────────────────────────────────────

pub struct Poseidon2T16Eval {
    pub log_n_rows: u32,
}

impl FrameworkEval for Poseidon2T16Eval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        // sbox = sq²·y (degree 3) is the highest; linear layers keep out ≤ deg 2.
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let rc: Vec<E::F> = (0..T).map(|i| eval.get_preprocessed_column(pc_rc(i))).collect();
        let is_ext = eval.get_preprocessed_column(pc_is_ext());
        let is_int = eval.get_preprocessed_column(pc_is_int());
        let is_first = eval.get_preprocessed_column(pc_is_first());
        let raw_pin: Vec<E::F> = (0..T).map(|i| eval.get_preprocessed_column(pc_raw(i))).collect();
        let node_pin: Vec<E::F> = (0..(T / 2)).map(|k| eval.get_preprocessed_column(pc_node(k))).collect();
        let is_node = eval.get_preprocessed_column(pc_is_node());

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
        let raw: Vec<E::F> =
            (0..T).map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()).collect();

        // y[i] = in[i] + rc[i]  (round input after AddRC).
        let y: Vec<E::F> = (0..T).map(|i| inp[i].clone() + rc[i].clone()).collect();

        // ── C_sq: sq[i] = y[i]²  (deg 2); C_sbox: sbox[i] = sq[i]²·y[i] (deg 3) ──
        for i in 0..T {
            eval.add_constraint(sq[i].clone() - y[i].clone() * y[i].clone());
        }
        for i in 0..T {
            eval.add_constraint(sbox[i].clone() - sq[i].clone() * sq[i].clone() * y[i].clone());
        }

        // External S-boxed state (all 16) / internal (cell 0 only) — degree-1 refs.
        let sb_ext: [E::F; 16] = std::array::from_fn(|i| sbox[i].clone());
        let sb_int: [E::F; 16] =
            std::array::from_fn(|i| if i == 0 { sbox[0].clone() } else { inp[i].clone() });
        let me = mat_external16_expr(&sb_ext);
        let mi = mat_internal16_expr(&sb_int);

        // ── C_out: out[i] = is_ext·ME[i] + is_int·MI[i]  (deg 2) ─────────────────
        for i in 0..T {
            let expected = is_ext.clone() * me[i].clone() + is_int.clone() * mi[i].clone();
            eval.add_constraint(out[i].clone() - expected);
        }

        // ── C_in: in[i] = is_first·ME(raw)[i] + (1−is_first)·out_prev[i] (deg 2) ─
        let me_raw = mat_external16_expr(&std::array::from_fn::<E::F, 16, _>(|i| raw[i].clone()));
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        for i in 0..T {
            let expected =
                is_first.clone() * me_raw[i].clone() + (one.clone() - is_first.clone()) * out_prev[i].clone();
            eval.add_constraint(inp[i].clone() - expected);
        }

        // ── C1: pin the compression input (row 0) and output node (last row) ─────
        for i in 0..T {
            eval.add_constraint(is_first.clone() * (raw[i].clone() - raw_pin[i].clone()));
        }
        for k in 0..(T / 2) {
            eval.add_constraint(is_node.clone() * (out[k].clone() - node_pin[k].clone()));
        }

        eval
    }
}

fn new_component(log_n_rows: u32) -> Poseidon2T16Component {
    Poseidon2T16Component::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_column_ids()),
        Poseidon2T16Eval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Round schedule (shared by trace + preproc) ───────────────────────────────────

/// For trace row `row < N_REAL_ROWS`, return `(is_ext, rc[0..16])`.
pub(crate) fn round_schedule(row: usize) -> (bool, [u64; T]) {
    let mut rc = [0u64; T];
    if row < R_F / 2 {
        for i in 0..T {
            rc[i] = K_RC[T * row + i] as u64;
        }
        (true, rc)
    } else if row < R_F / 2 + R_P {
        let j = row - R_F / 2;
        rc[0] = K_RC[T * R_F + j] as u64;
        (false, rc)
    } else {
        let r = R_F / 2 + (row - R_F / 2 - R_P);
        for i in 0..T {
            rc[i] = K_RC[T * r + i] as u64;
        }
        (true, rc)
    }
}

// ── Preprocessed columns (witness-free canonical source, C2) ────────────────────

pub fn build_preproc(left: [u64; 8], right: [u64; 8], node: [u64; 8], log_size: u32) -> TraceColumns {
    let n = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let one = BaseField::from_u32_unchecked(1);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut rc_cols: Vec<Vec<BaseField>> = (0..T).map(|_| vec![bf0; n]).collect();
    let mut is_ext_c = vec![bf0; n];
    let mut is_int_c = vec![bf0; n];
    let mut is_first_c = vec![bf0; n];
    let mut raw_cols: Vec<Vec<BaseField>> = (0..T).map(|_| vec![bf0; n]).collect();
    let mut node_cols: Vec<Vec<BaseField>> = (0..(T / 2)).map(|_| vec![bf0; n]).collect();
    let mut is_node_c = vec![bf0; n];

    for row in 0..N_REAL_ROWS.min(n) {
        let (is_ext, rc) = round_schedule(row);
        for i in 0..T {
            rc_cols[i][row] = m31(rc[i]);
        }
        if is_ext {
            is_ext_c[row] = one;
        } else {
            is_int_c[row] = one;
        }
    }
    if n > 0 {
        is_first_c[0] = one;
        for i in 0..(T / 2) {
            raw_cols[i][0] = m31(left[i]);
            raw_cols[(T / 2) + i][0] = m31(right[i]);
        }
    }
    if N_REAL_ROWS <= n {
        let node_row = N_REAL_ROWS - 1;
        is_node_c[node_row] = one;
        for k in 0..(T / 2) {
            node_cols[k][node_row] = m31(node[k]);
        }
    }

    let mut all = rc_cols;
    all.push(is_ext_c);
    all.push(is_int_c);
    all.push(is_first_c);
    all.extend(raw_cols);
    all.extend(node_cols);
    all.push(is_node_c);
    for c in all.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(c);
    }
    all.into_iter().map(|c| CircleEvaluation::new(domain, c)).collect()
}

fn canonical_preproc_root(
    left: [u64; 8],
    right: [u64; 8],
    node: [u64; 8],
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
    tree.extend_evals(build_preproc(left, right, node, log_size));
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

// ── Trace builder ────────────────────────────────────────────────────────────────

/// Build the main trace for one `compress_t16(left, right)`; returns
/// `(main_columns, node)` where `node = state[0..8]` after the permutation.
pub fn build_trace(left: [u64; 8], right: [u64; 8], log_size: u32) -> (TraceColumns, [u64; 8]) {
    let n = 1usize << log_size;
    debug_assert!(N_REAL_ROWS <= n, "rounds exceed trace capacity");
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];

    let mut raw = [0u64; T];
    for i in 0..8 {
        raw[i] = left[i] % M31_P;
        raw[8 + i] = right[i] % M31_P;
    }
    // in[row 0] = mat_external(raw)  (the permutation's initial pre-mix).
    let mut state = raw;
    crate::poseidon2_t16::mat_external(&mut state);

    for row in 0..N_REAL_ROWS {
        let (is_ext, rc) = round_schedule(row);
        let inp = state;
        let mut sq = [0u64; T];
        let mut sbx = [0u64; T];
        for i in 0..T {
            let yi = m31_add(inp[i], rc[i]);
            sq[i] = m31_mul(yi, yi);
            sbx[i] = crate::poseidon2::sbox(yi);
        }
        let mut lin = inp;
        if is_ext {
            for i in 0..T {
                lin[i] = sbx[i];
            }
            crate::poseidon2_t16::mat_external(&mut lin);
        } else {
            lin[0] = sbx[0];
            crate::poseidon2_t16::mat_internal(&mut lin);
        }
        let out = lin;

        // Columns: in=0..16, sq=16..32, sbox=32..48, out=48..64, raw=64..80.
        for i in 0..T {
            cols[i][row] = m31(inp[i]);
            cols[T + i][row] = m31(sq[i]);
            cols[2 * T + i][row] = m31(sbx[i]);
            cols[3 * T + i][row] = m31(out[i]);
        }
        if row == 0 {
            for i in 0..T {
                cols[4 * T + i][row] = m31(raw[i]);
            }
        }
        state = out;
    }

    let node = [
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    ];

    // Padding rows: continue the round chain (in = out_prev); selectors are 0 so
    // C_out forces out = 0; sq/sbox derived so the ungated constraints hold.
    for row in N_REAL_ROWS..n {
        for i in 0..T {
            let inp_i = state[i];
            cols[i][row] = m31(inp_i);
            cols[T + i][row] = m31(m31_mul(inp_i, inp_i));
            cols[2 * T + i][row] = m31(crate::poseidon2::sbox(inp_i));
        }
        state = [0u64; T];
    }

    let mut main = cols;
    for c in main.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(c);
    }
    let main_cols: TraceColumns = main.into_iter().map(|c| CircleEvaluation::new(domain, c)).collect();
    (main_cols, node)
}

// ── Prove / verify roundtrip ────────────────────────────────────────────────────

fn mix_public(channel: &mut Blake2sM31Channel, left: [u64; 8], right: [u64; 8], node: [u64; 8]) {
    let w = |v: u64| (v % M31_P) as u32;
    let mut words = Vec::with_capacity(24);
    words.extend(left.iter().map(|&v| w(v)));
    words.extend(right.iter().map(|&v| w(v)));
    words.extend(node.iter().map(|&v| w(v)));
    channel.mix_u32s(&words);
}

/// Prove `node = compress_t16(left, right)`. Returns `(proof_bytes, log_size, node)`.
pub fn prove_compress(left: [u64; 8], right: [u64; 8]) -> Result<(Vec<u8>, u32, [u64; 8]), String> {
    let log_size = LOG_SIZE;
    let (main_trace, node) = build_trace(left, right, log_size);
    debug_assert_eq!(node, compress_t16(left, right), "trace node must match reference");
    let preproc = build_preproc(left, right, node, log_size);

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
    tree.extend_evals(main_trace);
    tree.commit(channel);

    mix_public(channel, left, right, node);

    let component = new_component(log_size);
    let proof =
        prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
            .map_err(|e| format!("t16 compress proving error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("t16 compress serialize error: {e:?}"))?;
    Ok((bytes, log_size, node))
}

/// Verify a proof from [`prove_compress`] against the claimed `(left, right, node)`.
pub fn verify_compress(
    proof_bytes: &[u8],
    log_size: u32,
    left: [u64; 8],
    right: [u64; 8],
    node: [u64; 8],
) -> Result<bool, String> {
    if log_size != LOG_SIZE {
        return Err(format!("log_size {log_size} != {LOG_SIZE}"));
    }
    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("t16 compress deserialize error: {e:?}"))?;

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
    // C2: pin the preprocessed tree (round constants + selectors) to canonical.
    if proof.commitments[0] != canonical_preproc_root(left, right, node, log_size) {
        return Ok(false);
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    mix_public(verifier_channel, left, right, node);

    let result = verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof);
    Ok(result.is_ok())
}

// ── Tests ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2_t16::permute_t16;

    fn rand_m31(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) % M31_P
    }
    fn rand_node(seed: &mut u64) -> [u64; 8] {
        std::array::from_fn(|_| rand_m31(seed))
    }

    // The trace's node must equal the reference compress_t16 for random inputs.
    #[test]
    fn test_trace_node_matches_reference() {
        let mut s = 0x7e16_u64;
        for _ in 0..8 {
            let l = rand_node(&mut s);
            let r = rand_node(&mut s);
            let (_main, node) = build_trace(l, r, LOG_SIZE);
            assert_eq!(node, compress_t16(l, r), "AIR trace node must match compress_t16");
        }
    }

    // The AIR's generic linear-layer expressions must agree with the reference
    // (evaluated over BaseField).
    #[test]
    fn test_expr_layers_match_reference() {
        let mut s = 0x11f_u64;
        let vals: [u64; 16] = std::array::from_fn(|_| rand_m31(&mut s));
        let bf: [BaseField; 16] =
            std::array::from_fn(|i| BaseField::from_u32_unchecked(vals[i] as u32));

        let mut ext_ref = vals;
        crate::poseidon2_t16::mat_external(&mut ext_ref);
        let ext_expr = mat_external16_expr(&bf);
        for i in 0..16 {
            assert_eq!(ext_expr[i].0 as u64 % M31_P, ext_ref[i] % M31_P, "mat_external cell {i}");
        }

        let mut int_ref = vals;
        crate::poseidon2_t16::mat_internal(&mut int_ref);
        let int_expr = mat_internal16_expr(&bf);
        for i in 0..16 {
            assert_eq!(int_expr[i].0 as u64 % M31_P, int_ref[i] % M31_P, "mat_internal cell {i}");
        }
    }

    // Round-by-round schedule must reproduce permute_t16.
    #[test]
    fn test_round_schedule_reproduces_permutation() {
        let mut s = 0xabc16_u64;
        let raw: [u64; 16] = std::array::from_fn(|_| rand_m31(&mut s));
        let mut ref_state = raw;
        permute_t16(&mut ref_state);

        let mut state = raw;
        crate::poseidon2_t16::mat_external(&mut state);
        for row in 0..N_REAL_ROWS {
            let (is_ext, rc) = round_schedule(row);
            let mut sb = state;
            if is_ext {
                for i in 0..T {
                    sb[i] = crate::poseidon2::sbox(m31_add(state[i], rc[i]));
                }
                crate::poseidon2_t16::mat_external(&mut sb);
            } else {
                sb[0] = crate::poseidon2::sbox(m31_add(state[0], rc[0]));
                crate::poseidon2_t16::mat_internal(&mut sb);
            }
            state = sb;
        }
        assert_eq!(state, ref_state, "round schedule must reproduce permute_t16");
    }

    // Honest prove → verify roundtrip.
    #[test]
    fn test_roundtrip() {
        let mut s = 0xc0de16_u64;
        let l = rand_node(&mut s);
        let r = rand_node(&mut s);
        let (proof, log, node) = prove_compress(l, r).expect("prove");
        assert_eq!(node, compress_t16(l, r));
        assert!(verify_compress(&proof, log, l, r, node).expect("verify"), "honest proof must verify");
    }

    // A wrong claimed node / input changes the mixed transcript → verify fails.
    #[test]
    fn test_wrong_node_rejected() {
        let mut s = 0xbad16_u64;
        let l = rand_node(&mut s);
        let r = rand_node(&mut s);
        let (proof, log, node) = prove_compress(l, r).expect("prove");
        let mut wrong = node;
        wrong[0] ^= 1;
        assert!(!verify_compress(&proof, log, l, r, wrong).unwrap_or(false), "wrong node must not verify");
        let mut wrong_l = l;
        wrong_l[0] ^= 1;
        assert!(!verify_compress(&proof, log, wrong_l, r, node).unwrap_or(false), "wrong input must not verify");
    }

    // C1 regression: pinning a DIFFERENT (FAKE) input than the trace's committed
    // raw makes the is_first-gated raw-binding constraint unsatisfiable.
    #[test]
    fn test_forged_input_cannot_prove() {
        let mut s = 0xF00_C1_16_u64;
        let l = rand_node(&mut s);
        let r = rand_node(&mut s);
        let log = LOG_SIZE;
        let (main, node) = build_trace(l, r, log);
        let mut fake_l = l;
        fake_l[0] ^= 1;
        let forged = build_preproc(fake_l, r, node, log);
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
        mix_public(channel, fake_l, r, node);
        let component = new_component(log);
        let res = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, scheme);
        assert!(res.is_err(), "trace raw != pinned raw_pin must violate the input-binding constraint (C1)");
    }

    // A corrupted trace (perturbed out[0]) must not yield a verifying proof.
    #[test]
    fn test_corrupted_trace_rejected() {
        let mut s = 0x9916_u64;
        let l = rand_node(&mut s);
        let r = rand_node(&mut s);
        let log = LOG_SIZE;
        let (mut main, node) = build_trace(l, r, log);
        let domain = CanonicCoset::new(log).circle_domain();
        let mut vals = main[3 * T].values.clone(); // out[0] column
        vals[1] = vals[1] + BaseField::from_u32_unchecked(1);
        main[3 * T] = CircleEvaluation::new(domain, vals);

        let preproc = build_preproc(l, r, node, log);
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
        mix_public(channel, l, r, node);
        let component = new_component(log);
        match prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, scheme) {
            Ok(proof) => {
                let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                assert!(!verify_compress(&bytes, log, l, r, node).unwrap_or(false), "corrupted trace must not verify");
            }
            Err(_) => {}
        }
    }

    // C2 regression: a forged preprocessed selector (is_ext → all-zero) must not
    // verify — the verifier pins the canonical preprocessed root.
    #[test]
    fn test_forged_preproc_rejected() {
        let mut s = 0xC216_u64;
        let l = rand_node(&mut s);
        let r = rand_node(&mut s);
        let log = LOG_SIZE;
        let (main, node) = build_trace(l, r, log);
        let mut preproc = build_preproc(l, r, node, log);
        let domain = CanonicCoset::new(log).circle_domain();
        let n = 1usize << log;
        preproc[T] = CircleEvaluation::new(domain, vec![BaseField::from_u32_unchecked(0); n]);

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
        mix_public(channel, l, r, node);
        let component = new_component(log);
        if let Ok(proof) = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, scheme) {
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            assert!(!verify_compress(&bytes, log, l, r, node).unwrap_or(false), "forged preproc must not verify (C2)");
        }
    }
}
