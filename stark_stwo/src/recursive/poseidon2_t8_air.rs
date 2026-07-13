//! Poseidon2 **t=8** compression AIR — recursion inner-hash primitive (R2 wide).
//!
//! Proves one 2-to-1 compression `node = compress_t8(left, right)` where each
//! node is a **4-word (124-bit) M31 value** (`left`/`right`/`node ∈ M31⁴`):
//!
//! ```text
//! state = (l0..l3, r0..r3) → permute_t8 → node = state[0..4]
//! ```
//!
//! This is the wide analogue of [`crate::poseidon2_merkle_air`] (t=2, 31-bit
//! nodes → 2^15.5 collision).  The t=8 permutation carries 4-word nodes, raising
//! node-collision cost to ~2^62 — the next rung on the 128-bit ladder (limitation
//! #6) and the hash the recursion must replicate to verify a **VFRI11** inner
//! proof (whose FRI-layer Merkle trees use the t=8 backend).  The reference
//! permutation [`crate::poseidon2_t8::permute_t8`] is already cross-checked
//! bit-exact against the on-chain `Poseidon2M31T8.sol`; this AIR arithmetizes it
//! and is validated by rebuilding the honest trace from that reference (a wrong
//! constraint makes the honest proof fail, not silently pass).
//!
//! # Permutation structure (see `poseidon2_t8.rs`)
//!
//! `mat_external` (pre-mix) → 4 external rounds (AddRC, S-box all 8, `mat_external`)
//! → 14 internal rounds (AddRC cell 0, S-box cell 0, `mat_internal`) → 4 external
//! rounds.  22 rounds total; one round per trace row.
//!
//! # Trace layout (32 main columns + 11 preprocessed)
//!
//! ```text
//! Main (one round per row):
//!   in[0..8]   — state entering the round (before AddRC)
//!   sq[0..8]   — S-box square helper: sq[i] = (in[i]+rc[i])²
//!   sbox[0..8] — S-box output: sbox[i] = sq[i]²·(in[i]+rc[i])  (keeps out linear)
//!   out[0..8]  — state after the round's linear layer
//!   raw[0..8]  — compression input (l0..3, r0..3); meaningful on row 0 only
//!
//! Preprocessed (verifier-pinned canonical source, C2):
//!   rc[0..8]   — round constants for this row (cell 0 only on internal rounds)
//!   is_ext     — 1 on external-round rows       (S-box all 8 + mat_external)
//!   is_int     — 1 on internal-round rows        (S-box cell 0 + mat_internal)
//!   is_first   — 1 on row 0 (injects the initial mat_external of the raw input)
//! ```
//!
//! Row map: rows 0..4 = external rounds 0..3 (`K_RC[0..32]`), rows 4..18 =
//! internal rounds 0..13 (`K_RC[64..78]` on cell 0), rows 18..22 = external rounds
//! 4..7 (`K_RC[32..64]`), rows 22.. = zero padding.  Node = `out[0..4]` on row 21.
//!
//! # Soundness
//!
//! - **[C2]** the preprocessed tree (round constants + selectors) is the single
//!   canonical source [`build_preproc`]; the verifier recomputes its commitment
//!   root ([`canonical_preproc_root`]) and rejects a mismatch — a forged selector
//!   or swapped constant no longer verifies (`test_forged_preproc_rejected`).
//! - The S-box helper (`sq = y²`, `sbox = sq²·y`) + the exact linear layers make
//!   every constraint satisfiable only by the true permutation trace.

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
use crate::poseidon2_t8::{compress_t8, K_RC, R_F, R_P, T};
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub const N_MAIN_COLS: usize = 40;
/// 22 permutation rounds → the trace needs ≥ 32 rows (2^5).
pub const N_REAL_ROWS: usize = R_F + R_P; // 8 + 14 = 22
pub const LOG_SIZE: u32 = 5; // 32 rows ≥ 22

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub type Poseidon2T8Component = FrameworkComponent<Poseidon2T8Eval>;

// ── Preprocessed column IDs ───────────────────────────────────────────────────

pub fn pc_rc(i: usize) -> PreProcessedColumnId {
    PreProcessedColumnId { id: format!("p2t8_rc{i}") }
}
pub fn pc_is_ext() -> PreProcessedColumnId {
    PreProcessedColumnId { id: "p2t8_is_ext".into() }
}
pub fn pc_is_int() -> PreProcessedColumnId {
    PreProcessedColumnId { id: "p2t8_is_int".into() }
}
pub fn pc_is_first() -> PreProcessedColumnId {
    PreProcessedColumnId { id: "p2t8_is_first".into() }
}
pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    let mut ids: Vec<PreProcessedColumnId> = (0..T).map(pc_rc).collect();
    ids.push(pc_is_ext());
    ids.push(pc_is_int());
    ids.push(pc_is_first());
    ids
}

// ── Linear layers as generic expressions ───────────────────────────────────────

/// `m4(s)[i] = Σ_j M4[i][j]·s[j]`, M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]].
pub(crate) fn m4_expr<F>(s: &[F; 4]) -> [F; 4]
where
    F: Clone + std::ops::Add<Output = F> + Mul<BaseField, Output = F>,
{
    let m = |v: u32| BaseField::from_u32_unchecked(v);
    [
        s[0].clone() * m(5) + s[1].clone() * m(7) + s[2].clone() * m(1) + s[3].clone() * m(3),
        s[0].clone() * m(4) + s[1].clone() * m(6) + s[2].clone() * m(1) + s[3].clone() * m(1),
        s[0].clone() * m(1) + s[1].clone() * m(3) + s[2].clone() * m(5) + s[3].clone() * m(7),
        s[0].clone() * m(1) + s[1].clone() * m(1) + s[2].clone() * m(4) + s[3].clone() * m(6),
    ]
}

use std::ops::Mul;

/// External linear layer `M_E = [[2·M4, M4],[M4, 2·M4]]` on an 8-vector.
pub(crate) fn mat_external_expr<F>(a: &[F; 8]) -> [F; 8]
where
    F: Clone + std::ops::Add<Output = F> + Mul<BaseField, Output = F>,
{
    let v0 = m4_expr(&[a[0].clone(), a[1].clone(), a[2].clone(), a[3].clone()]);
    let v1 = m4_expr(&[a[4].clone(), a[5].clone(), a[6].clone(), a[7].clone()]);
    let two = BaseField::from_u32_unchecked(2);
    let mut out: [F; 8] = [
        v0[0].clone(), v0[1].clone(), v0[2].clone(), v0[3].clone(),
        v1[0].clone(), v1[1].clone(), v1[2].clone(), v1[3].clone(),
    ];
    for k in 0..4 {
        // out[k]   = 2·v0[k] + v1[k]; out[4+k] = v0[k] + 2·v1[k]
        out[k] = v0[k].clone() * two + v1[k].clone();
        out[4 + k] = v0[k].clone() + v1[k].clone() * two;
    }
    out
}

/// Internal linear layer `M_I = J + diag(1..8)`: `out_i = Σ_j a_j + (i+1)·a_i`.
pub(crate) fn mat_internal_expr<F>(a: &[F; 8]) -> [F; 8]
where
    F: Clone + std::ops::Add<Output = F> + Mul<BaseField, Output = F>,
{
    // sum = Σ a_j
    let mut sum = a[0].clone();
    for j in 1..8 {
        sum = sum + a[j].clone();
    }
    let mut out: [F; 8] = [
        a[0].clone(), a[1].clone(), a[2].clone(), a[3].clone(),
        a[4].clone(), a[5].clone(), a[6].clone(), a[7].clone(),
    ];
    for i in 0..8 {
        out[i] = sum.clone() + a[i].clone() * BaseField::from_u32_unchecked((i + 1) as u32);
    }
    out
}

// ── AIR ────────────────────────────────────────────────────────────────────────

pub struct Poseidon2T8Eval {
    pub log_n_rows: u32,
}

impl FrameworkEval for Poseidon2T8Eval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Highest-degree constraint: sbox[i] = sq[i]²·y[i] (degree 3); the linear
        // layers and out/in constraints are ≤ degree 2. Matches the codebase's
        // twiddle setup (log + 1), as in the t=2 Merkle AIR.
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let rc: Vec<E::F> = (0..T).map(|i| eval.get_preprocessed_column(pc_rc(i))).collect();
        let is_ext = eval.get_preprocessed_column(pc_is_ext());
        let is_int = eval.get_preprocessed_column(pc_is_int());
        let is_first = eval.get_preprocessed_column(pc_is_first());

        // Main columns. `out` needs previous-row access for the round chain.
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

        // ── C_sq: sq[i] = y[i]²  (all cells, all rows; deg 2) ────────────────────
        for i in 0..T {
            eval.add_constraint(sq[i].clone() - y[i].clone() * y[i].clone());
        }
        // ── C_sbox: sbox[i] = sq[i]²·y[i]  (all cells, all rows; deg 3) ──────────
        for i in 0..T {
            eval.add_constraint(sbox[i].clone() - sq[i].clone() * sq[i].clone() * y[i].clone());
        }

        // External S-boxed state (all 8) and internal S-boxed state (cell 0 only) —
        // now degree-1 references to the `sbox`/`in` columns, so out stays linear.
        let sb_ext: [E::F; 8] = std::array::from_fn(|i| sbox[i].clone());
        let sb_int: [E::F; 8] =
            std::array::from_fn(|i| if i == 0 { sbox[0].clone() } else { inp[i].clone() });

        let me = mat_external_expr(&sb_ext);
        let mi = mat_internal_expr(&sb_int);

        // ── C_out: out[i] = is_ext·ME(sb_ext)[i] + is_int·MI(sb_int)[i] (deg 4) ──
        for i in 0..T {
            let expected = is_ext.clone() * me[i].clone() + is_int.clone() * mi[i].clone();
            eval.add_constraint(out[i].clone() - expected);
        }

        // ── C_in: in[i] = is_first·ME(raw)[i] + (1−is_first)·out_prev[i] (deg 2) ─
        // Row 0 injects the initial mat_external of the raw compression input;
        // every other row chains from the previous round's output.
        let me_raw = mat_external_expr(&std::array::from_fn::<E::F, 8, _>(|i| raw[i].clone()));
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        for i in 0..T {
            let expected =
                is_first.clone() * me_raw[i].clone() + (one.clone() - is_first.clone()) * out_prev[i].clone();
            eval.add_constraint(inp[i].clone() - expected);
        }

        eval
    }
}

fn new_component(log_n_rows: u32) -> Poseidon2T8Component {
    Poseidon2T8Component::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_column_ids()),
        Poseidon2T8Eval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Round schedule (shared by trace + preproc so they never drift) ──────────────

/// For trace row `row < N_REAL_ROWS`, return `(is_ext, rc[0..8])`.
/// External rounds S-box all 8 cells; internal rounds add/S-box cell 0 only.
pub(crate) fn round_schedule(row: usize) -> (bool, [u64; T]) {
    let mut rc = [0u64; T];
    if row < R_F / 2 {
        // external rounds 0..4 → K_RC[8*row .. +8]
        for i in 0..T {
            rc[i] = K_RC[T * row + i] as u64;
        }
        (true, rc)
    } else if row < R_F / 2 + R_P {
        // internal rounds 0..R_P → K_RC[T*R_F + j] on cell 0
        let j = row - R_F / 2;
        rc[0] = K_RC[T * R_F + j] as u64;
        (false, rc)
    } else {
        // external rounds R_F/2..R_F → K_RC[8*r .. +8], r = R_F/2 + (row - R_F/2 - R_P)
        let r = R_F / 2 + (row - R_F / 2 - R_P);
        for i in 0..T {
            rc[i] = K_RC[T * r + i] as u64;
        }
        (true, rc)
    }
}

// ── Preprocessed columns (witness-free canonical source, C2) ────────────────────

pub fn build_preproc(log_size: u32) -> TraceColumns {
    let n = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let one = BaseField::from_u32_unchecked(1);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut rc_cols: Vec<Vec<BaseField>> = (0..T).map(|_| vec![bf0; n]).collect();
    let mut is_ext_c = vec![bf0; n];
    let mut is_int_c = vec![bf0; n];
    let mut is_first_c = vec![bf0; n];

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
    }

    let mut all = rc_cols;
    all.push(is_ext_c);
    all.push(is_int_c);
    all.push(is_first_c);
    for c in all.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(c);
    }
    all.into_iter().map(|c| CircleEvaluation::new(domain, c)).collect()
}

fn canonical_preproc_root(
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
    tree.extend_evals(build_preproc(log_size));
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

// ── Trace builder ────────────────────────────────────────────────────────────────

/// Build the main trace for one `compress_t8(left, right)` and return
/// `(main_columns, node)` where `node = state[0..4]` after the permutation.
pub fn build_trace(left: [u64; 4], right: [u64; 4], log_size: u32) -> (TraceColumns, [u64; 4]) {
    let n = 1usize << log_size;
    debug_assert!(N_REAL_ROWS <= n, "rounds exceed trace capacity");
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];

    // Reference state evolution, checkpointed per round.
    let raw = [
        left[0] % M31_P, left[1] % M31_P, left[2] % M31_P, left[3] % M31_P,
        right[0] % M31_P, right[1] % M31_P, right[2] % M31_P, right[3] % M31_P,
    ];
    // in[row 0] = mat_external(raw)  (the permutation's initial pre-mix).
    let mut state = raw;
    crate::poseidon2_t8::mat_external(&mut state);

    for row in 0..N_REAL_ROWS {
        let (is_ext, rc) = round_schedule(row);
        // in = state entering the round; sq = (in+rc)²; out = linear_layer(sbox).
        let inp = state;
        let mut sq = [0u64; T];
        for i in 0..T {
            let y = m31_add(inp[i], rc[i]);
            sq[i] = m31_mul(y, y);
        }
        // S-box output for EVERY cell (used by external rounds; internal rounds
        // use only sbox[0] but must still satisfy the ungated C_sbox constraint).
        let mut sbox = [0u64; T];
        for i in 0..T {
            sbox[i] = crate::poseidon2::sbox(m31_add(inp[i], rc[i]));
        }
        // Compute out via the reference operations (guarantees trace ≡ reference).
        let mut lin = inp;
        if is_ext {
            for i in 0..T {
                lin[i] = sbox[i];
            }
            crate::poseidon2_t8::mat_external(&mut lin);
        } else {
            lin[0] = sbox[0];
            // cells 1..8 unchanged
            crate::poseidon2_t8::mat_internal(&mut lin);
        }
        let out = lin;

        // Columns: in=0..8, sq=8..16, sbox=16..24, out=24..32, raw=32..40.
        for i in 0..T {
            cols[i][row] = m31(inp[i]);
            cols[T + i][row] = m31(sq[i]);
            cols[2 * T + i][row] = m31(sbox[i]);
            cols[3 * T + i][row] = m31(out[i]);
        }
        if row == 0 {
            for i in 0..T {
                cols[4 * T + i][row] = m31(raw[i]);
            }
        }
        state = out;
    }

    // Node = out[0..4] on the last real round row (state after final mat_external).
    let node = [state[0], state[1], state[2], state[3]];

    // Padding rows: selectors are 0 (C_out forces out = 0), but the chain
    // constraint C_in still binds in[row] = out[row−1]. Continue the fill so the
    // first padding row chains from the node state and then decays to zero; sq/sbox
    // are derived so the ungated C_sq/C_sbox constraints stay satisfied.
    for row in N_REAL_ROWS..n {
        for i in 0..T {
            let inp_i = state[i]; // = previous row's out (0 after the first pad row)
            cols[i][row] = m31(inp_i);
            let y = inp_i; // rc = 0 on padding rows
            cols[T + i][row] = m31(m31_mul(y, y));
            cols[2 * T + i][row] = m31(crate::poseidon2::sbox(y));
            // out = 0 (both selectors 0); cols already zero-initialised.
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

fn mix_public(channel: &mut Blake2sM31Channel, left: [u64; 4], right: [u64; 4], node: [u64; 4]) {
    let w = |v: u64| (v % M31_P) as u32;
    channel.mix_u32s(&[
        w(left[0]), w(left[1]), w(left[2]), w(left[3]),
        w(right[0]), w(right[1]), w(right[2]), w(right[3]),
        w(node[0]), w(node[1]), w(node[2]), w(node[3]),
    ]);
}

/// Prove `node = compress_t8(left, right)`. Returns `(proof_bytes, log_size, node)`.
pub fn prove_compress(left: [u64; 4], right: [u64; 4]) -> Result<(Vec<u8>, u32, [u64; 4]), String> {
    let log_size = LOG_SIZE;
    let (main_trace, node) = build_trace(left, right, log_size);
    debug_assert_eq!(node, compress_t8(left, right), "trace node must match reference");
    let preproc = build_preproc(log_size);

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
            .map_err(|e| format!("t8 compress proving error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("t8 compress serialize error: {e:?}"))?;
    Ok((bytes, log_size, node))
}

/// Verify a proof from [`prove_compress`] against the claimed `(left, right, node)`.
pub fn verify_compress(
    proof_bytes: &[u8],
    log_size: u32,
    left: [u64; 4],
    right: [u64; 4],
    node: [u64; 4],
) -> Result<bool, String> {
    if log_size != LOG_SIZE {
        return Err(format!("log_size {log_size} != {LOG_SIZE}"));
    }
    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("t8 compress deserialize error: {e:?}"))?;

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
    if proof.commitments[0] != canonical_preproc_root(log_size) {
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
    use crate::poseidon2_t8::permute_t8;

    fn rand_m31(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) % M31_P
    }
    fn rand_node(seed: &mut u64) -> [u64; 4] {
        [rand_m31(seed), rand_m31(seed), rand_m31(seed), rand_m31(seed)]
    }

    // The trace's node must equal the reference compress_t8 for random inputs.
    #[test]
    fn test_trace_node_matches_reference() {
        let mut s = 0x7ea8_u64;
        for _ in 0..8 {
            let l = rand_node(&mut s);
            let r = rand_node(&mut s);
            let (_main, node) = build_trace(l, r, LOG_SIZE);
            assert_eq!(node, compress_t8(l, r), "AIR trace node must match compress_t8");
        }
    }

    // The reference permutation checkpoints (in[row] chain) must line up: rebuilding
    // the state via round_schedule reproduces permute_t8's final state.
    #[test]
    fn test_round_schedule_reproduces_permutation() {
        let mut s = 0xabc_u64;
        let raw: [u64; 8] = std::array::from_fn(|_| rand_m31(&mut s));
        let mut ref_state = raw;
        permute_t8(&mut ref_state);

        let mut state = raw;
        crate::poseidon2_t8::mat_external(&mut state);
        for row in 0..N_REAL_ROWS {
            let (is_ext, rc) = round_schedule(row);
            let mut sb = state;
            if is_ext {
                for i in 0..T {
                    sb[i] = crate::poseidon2::sbox(m31_add(state[i], rc[i]));
                }
                crate::poseidon2_t8::mat_external(&mut sb);
            } else {
                sb[0] = crate::poseidon2::sbox(m31_add(state[0], rc[0]));
                crate::poseidon2_t8::mat_internal(&mut sb);
            }
            state = sb;
        }
        assert_eq!(state, ref_state, "round-by-round schedule must reproduce permute_t8");
    }

    // Honest prove → verify roundtrip.
    #[test]
    fn test_roundtrip() {
        let mut s = 0xc0de_u64;
        let l = rand_node(&mut s);
        let r = rand_node(&mut s);
        let (proof, log, node) = prove_compress(l, r).expect("prove");
        assert_eq!(node, compress_t8(l, r));
        assert!(verify_compress(&proof, log, l, r, node).expect("verify"), "honest proof must verify");
    }

    // A wrong claimed node changes the mixed transcript → verify fails.
    #[test]
    fn test_wrong_node_rejected() {
        let mut s = 0xbad_u64;
        let l = rand_node(&mut s);
        let r = rand_node(&mut s);
        let (proof, log, node) = prove_compress(l, r).expect("prove");
        let mut wrong = node;
        wrong[0] ^= 1;
        assert!(!verify_compress(&proof, log, l, r, wrong).unwrap_or(false), "a wrong node must not verify");
    }

    // A wrong claimed input (left) changes the transcript → verify fails.
    #[test]
    fn test_wrong_input_rejected() {
        let mut s = 0xf00d_u64;
        let l = rand_node(&mut s);
        let r = rand_node(&mut s);
        let (proof, log, node) = prove_compress(l, r).expect("prove");
        let mut wrong_l = l;
        wrong_l[0] ^= 1;
        assert!(!verify_compress(&proof, log, wrong_l, r, node).unwrap_or(false), "a wrong input must not verify");
    }

    // A corrupted trace (perturbed s0 output) must not yield a verifying proof.
    #[test]
    fn test_corrupted_trace_rejected() {
        let mut s = 0x99_u64;
        let l = rand_node(&mut s);
        let r = rand_node(&mut s);
        let log = LOG_SIZE;
        let (mut main, node) = build_trace(l, r, log);
        let domain = CanonicCoset::new(log).circle_domain();
        let mut vals = main[3 * T].values.clone(); // out[0] column (in=0,sq=8,sbox=16,out=24)
        vals[1] = vals[1] + BaseField::from_u32_unchecked(1);
        main[3 * T] = CircleEvaluation::new(domain, vals);

        let preproc = build_preproc(log);
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
            Err(_) => {} // constraint failure at prove time is also acceptable
        }
    }

    // C2 regression: a forged preprocessed selector (is_ext → all-zero) must not
    // verify — the verifier pins the canonical preprocessed root.
    #[test]
    fn test_forged_preproc_rejected() {
        let mut s = 0xC2_u64;
        let l = rand_node(&mut s);
        let r = rand_node(&mut s);
        let log = LOG_SIZE;
        let (main, node) = build_trace(l, r, log);
        let mut preproc = build_preproc(log);
        let domain = CanonicCoset::new(log).circle_domain();
        let n = 1usize << log;
        // Forge is_ext (index T = 8) → all-zero.
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
