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
//! ⚠ Soundness (audit 2026-06-17): Fiat-Shamir mixing does NOT prove the trace
//! computed that `root` — a malicious prover can mix (and claim) a `root` that
//! differs from the trace's real output (gap **C1** in `super`'s module docs).
//! Likewise `index` is not constrained to equal `bits_to_index(trace bits)`.
//! A verifier-fixed public input + an in-circuit `(computed_root − root) = 0`
//! constraint (and an index↔bits binding) are required before this gadget's
//! `(leaf, index, root)` can be trusted; that binding is deferred to the
//! recursive-verifier composition (R3.7).

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

pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    vec![pc_rc0(), pc_rc1(), pc_is_init(), pc_is_first()]
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
        let cur_expected = is_first * leaf + not_first * s0_prev.clone();
        eval.add_constraint(is_init.clone() * (cur.clone() - cur_expected));

        // ── Init-row wiring: index-bit child selection ───────────────────────
        // left  = bit·sib + (1−bit)·cur ;  right = bit·cur + (1−bit)·sib
        let left = bit.clone() * sib.clone() + (one_minus(&bit)) * cur.clone();
        let right = bit.clone() * cur + (one_minus(&bit)) * sib;
        eval.add_constraint(is_init.clone() * (inp0.clone() - left)); // C_inp0_init
        eval.add_constraint(is_init.clone() * (inp1.clone() - right)); // C_inp1_init
        eval.add_constraint(is_init.clone() * (bit.clone() * bit.clone() - bit)); // C_bit boolean

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

// ── Trace builder ──────────────────────────────────────────────────────────────

/// Build the Merkle-path trace. Returns `(main_columns, preprocessed_columns,
/// root)`. The first `sibs.len()` compressions are the real path; remaining rows
/// are padded with valid `H(cur, 0)` compressions (constraints stay satisfied).
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
    let mut rc0_c = vec![bf0; n];
    let mut rc1_c = vec![bf0; n];
    let mut init_c = vec![bf0; n];
    let mut first_c = vec![bf0; n];

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
            rc0_c[row] = to_m31(RC[r][0] as u64);
            rc1_c[row] = to_m31(RC[r][1] as u64);
            init_c[row] = if r == 0 { to_m31(1) } else { bf0 };
            first_c[row] = if row == 0 { to_m31(1) } else { bf0 };

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
    for c in [&mut rc0_c, &mut rc1_c, &mut init_c, &mut first_c] {
        bit_reverse_coset_to_circle_domain_order(c);
    }

    let main_cols: TraceColumns = main.into_iter().map(|c| CircleEvaluation::new(domain, c)).collect();
    let preproc: TraceColumns = [rc0_c, rc1_c, init_c, first_c]
        .into_iter()
        .map(|c| CircleEvaluation::new(domain, c))
        .collect();
    (main_cols, preproc, path_root)
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
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    mix_public(verifier_channel, leaf, index, root);

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
        assert_eq!(preproc.len(), 4);
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
}
