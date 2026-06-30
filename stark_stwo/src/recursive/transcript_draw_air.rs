//! Poseidon2 Fiat-Shamir transcript **draw** (squeeze) AIR — recursive-verifier
//! gadget (R3.6).
//!
//! The dual of [`super::channel_air`] (which proves *absorb* / `mixU32s`): this
//! proves a sequence of Poseidon2 (t=2) duplex-sponge **draws**, the squeeze
//! operation `Poseidon2Channel.drawSecureFelt` / `drawQueries` are built from.
//! The recursive verifier must replay draws in-circuit to prove that the FRI
//! folding challenges and query indices were honestly *derived* from the
//! committed transcript digest — not cherry-picked by the prover.
//!
//! One draw from state `(s0, s1)` with counter `d` (matching `P2Channel::draw_pair`
//! in `vfri2_bridge.rs`):
//!
//! ```text
//! (w0, w1) ← (s0, s1)              // squeeze the rate cells BEFORE mutating
//! s0 ← (s0 + d) mod P              // mix the draw counter
//! (s0, s1) ← Poseidon2_t2(s0, s1)  // permute
//! d ← d + 1
//! ```
//!
//! Starting from a committed `digest` with `d = 0` (a freshly-mixed channel), the
//! `i`-th draw uses counter `i` and squeezes the state at the *start* of draw `i`:
//! `start₀ = digest`, `startᵢ₊₁ = Poseidon2(startᵢ.0 + i, startᵢ.1)`,
//! `drawᵢ = startᵢ`.  A `drawSecureFelt` is two draws → QM31; `drawQueries`
//! takes the low bits of each squeezed word.
//!
//! # Trace layout
//!
//! Each draw takes `N_ROUNDS = 8` rows (one Poseidon2 round each). Main trace
//! (8 columns):
//! ```text
//! 0 s0   1 s1   2 t0   3 t1   4 inp0  5 inp1
//! 6 w0   7 w1   (squeezed rate cells; meaningful on init rows only)
//! ```
//! Preprocessed (7 columns):
//! `rc0, rc1, is_init (r==0), is_first (row 0), ndraws (draw index i, init rows),
//!  dig0, dig1 (the committed starting digest, broadcast on every row)`.
//!
//! On draw `i`'s init row the squeezed value is `cur = is_first ? digest : s[-1]`
//! (the previous draw's permute output), the squeeze constrains `(w0,w1)=cur`,
//! and the permutation input is `inp0 = cur.0 + ndraws`, `inp1 = cur.1`.

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
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub const N_MAIN_COLS: usize = 8;
pub const MIN_LOG_SIZE: u32 = 3; // ≥ 8 rows = 1 draw
pub const MAX_LOG_SIZE: u32 = 24;
pub const MAX_DRAWS: usize = 1 << 18;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub type TranscriptDrawComponent = FrameworkComponent<TranscriptDrawEval>;

// ── Preprocessed column IDs ───────────────────────────────────────────────────

pub fn pc_rc0() -> PreProcessedColumnId { PreProcessedColumnId { id: "rtd_rc0".into() } }
pub fn pc_rc1() -> PreProcessedColumnId { PreProcessedColumnId { id: "rtd_rc1".into() } }
pub fn pc_is_init() -> PreProcessedColumnId { PreProcessedColumnId { id: "rtd_is_init".into() } }
pub fn pc_is_first() -> PreProcessedColumnId { PreProcessedColumnId { id: "rtd_is_first".into() } }
pub fn pc_ndraws() -> PreProcessedColumnId { PreProcessedColumnId { id: "rtd_ndraws".into() } }
pub fn pc_dig0() -> PreProcessedColumnId { PreProcessedColumnId { id: "rtd_dig0".into() } }
pub fn pc_dig1() -> PreProcessedColumnId { PreProcessedColumnId { id: "rtd_dig1".into() } }

pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    vec![pc_rc0(), pc_rc1(), pc_is_init(), pc_is_first(), pc_ndraws(), pc_dig0(), pc_dig1()]
}

// ── Reference draw chain ───────────────────────────────────────────────────────

/// Draw `m` pairs from a Poseidon2 t=2 duplex sponge starting at `digest` with
/// counter 0. Returns `(squeezed_pairs, final_state)`. Mirrors `P2Channel`
/// (`draw_pair`) in `vfri2_bridge.rs`.
pub fn draw_chain(digest: (u64, u64), m: usize) -> (Vec<(u64, u64)>, (u64, u64)) {
    let mut s = [digest.0 % M31_P, digest.1 % M31_P];
    let mut out = Vec::with_capacity(m);
    for i in 0..m {
        out.push((s[0], s[1])); // squeeze BEFORE mutating
        s[0] = m31_add(s[0], i as u64); // mix counter d = i
        crate::poseidon2::permute(&mut s);
    }
    (out, (s[0], s[1]))
}

/// `drawSecureFelt` = two draws packed into a QM31 (`c0 = (w0,w1)`, `c1 = (w2,w3)`).
/// `draw_chain(digest, 2)` provides the four words.
pub fn draw_secure_felt(digest: (u64, u64)) -> u128 {
    let (pairs, _) = draw_chain(digest, 2);
    let (w0, w1) = pairs[0];
    let (w2, w3) = pairs[1];
    ((w0 as u128) << 96) | ((w1 as u128) << 64) | ((w2 as u128) << 32) | (w3 as u128)
}

// ── AIR ──────────────────────────────────────────────────────────────────────

pub struct TranscriptDrawEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for TranscriptDrawEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // max constraint degree is 3 (Poseidon2 round core)
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let rc0 = eval.get_preprocessed_column(pc_rc0());
        let rc1 = eval.get_preprocessed_column(pc_rc1());
        let is_init = eval.get_preprocessed_column(pc_is_init());
        let is_first = eval.get_preprocessed_column(pc_is_first());
        let ndraws = eval.get_preprocessed_column(pc_ndraws());
        let dig0 = eval.get_preprocessed_column(pc_dig0());
        let dig1 = eval.get_preprocessed_column(pc_dig1());

        let [s0_curr, s0_prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [s1_curr, s1_prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [t0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [t1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [inp0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [inp1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [w0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [w1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let not_init = one.clone() - is_init.clone();
        let not_first = one - is_first.clone();

        // ── Poseidon2 round core (identical to channel_air / Merkle / base AIRs) ─
        let x0 = inp0.clone() + rc0;
        let x1 = inp1.clone() + rc1;
        let sbox0 = t0.clone() * t0.clone() * x0.clone(); // x0^5
        let sbox1 = t1.clone() * t1.clone() * x1.clone(); // x1^5
        let three = BaseField::from_u32_unchecked(3);
        eval.add_constraint(t0 - x0.clone() * x0); // C_t0
        eval.add_constraint(t1 - x1.clone() * x1); // C_t1
        eval.add_constraint(s0_curr - (sbox0.clone() * three + sbox1.clone())); // C_s0
        eval.add_constraint(s1_curr - (sbox0 + sbox1 * three)); // C_s1

        // ── Init-row wiring: squeeze, then mix the counter ───────────────────
        // cur = is_first ? digest : s[-1]   (first draw starts from the digest)
        let cur0 = is_first.clone() * dig0 + not_first.clone() * s0_prev.clone();
        let cur1 = is_first * dig1 + not_first * s1_prev.clone();
        // Squeeze: the drawn words equal the state at the start of the draw.
        eval.add_constraint(is_init.clone() * (w0 - cur0.clone())); // C_squeeze0
        eval.add_constraint(is_init.clone() * (w1 - cur1.clone())); // C_squeeze1
        // Permutation input: inp0 = cur0 + ndraws ; inp1 = cur1.
        eval.add_constraint(is_init.clone() * (inp0.clone() - (cur0 + ndraws))); // C_inp0_init
        eval.add_constraint(is_init * (inp1.clone() - cur1)); // C_inp1_init

        // ── Non-init chaining: state carries within a permutation ────────────
        eval.add_constraint(not_init.clone() * (inp0 - s0_prev)); // C_inp0_chain
        eval.add_constraint(not_init * (inp1 - s1_prev)); // C_inp1_chain

        eval
    }
}

fn new_component(log_n_rows: u32) -> TranscriptDrawComponent {
    TranscriptDrawComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_column_ids()),
        TranscriptDrawEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace size helpers ─────────────────────────────────────────────────────────

pub fn compute_log_size(n_draws: usize) -> u32 {
    let n_real = n_draws.max(1) * N_ROUNDS;
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < n_real {
        log += 1;
    }
    log
}

// ── Trace builder ──────────────────────────────────────────────────────────────

/// Build the draw trace. Returns `(main_columns, preprocessed_columns,
/// squeezed_pairs, final_state)`. The first `m` draws are real; remaining rows
/// continue the sponge (constraints stay satisfied) and are not returned.
pub fn build_trace(
    digest: (u64, u64),
    m: usize,
    log_size: u32,
) -> (TraceColumns, TraceColumns, Vec<(u64, u64)>, (u64, u64)) {
    let n = 1usize << log_size;
    debug_assert!(m * N_ROUNDS <= n, "draws exceed trace capacity");
    let domain = CanonicCoset::new(log_size).circle_domain();

    let to_m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);
    let bf0 = BaseField::from_u32_unchecked(0);

    let mut col: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];
    let mut rc0_c = vec![bf0; n];
    let mut rc1_c = vec![bf0; n];
    let mut init_c = vec![bf0; n];
    let mut first_c = vec![bf0; n];
    let mut ndraws_c = vec![bf0; n];
    let dig0 = to_m31(digest.0);
    let dig1 = to_m31(digest.1);
    let dig0_c = vec![dig0; n];
    let dig1_c = vec![dig1; n];

    let n_draw_blocks = n / N_ROUNDS;
    let mut cur = [digest.0 % M31_P, digest.1 % M31_P];
    let mut squeezed: Vec<(u64, u64)> = Vec::with_capacity(m);
    let mut final_state = (cur[0], cur[1]);

    for i in 0..n_draw_blocks {
        // Squeeze the state at the start of this draw.
        let (w0, w1) = (cur[0], cur[1]);
        if i < m {
            squeezed.push((w0, w1));
        }
        let inp0_init = m31_add(cur[0], i as u64); // counter d = i
        let inp1_init = cur[1];

        let mut state = [inp0_init, inp1_init];
        for r in 0..N_ROUNDS {
            let row = i * N_ROUNDS + r;
            let inp0v = if r == 0 { inp0_init } else { state[0] };
            let inp1v = if r == 0 { inp1_init } else { state[1] };
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
                col[6][row] = to_m31(w0);
                col[7][row] = to_m31(w1);
            }
            rc0_c[row] = to_m31(RC[r][0] as u64);
            rc1_c[row] = to_m31(RC[r][1] as u64);
            init_c[row] = if r == 0 { to_m31(1) } else { bf0 };
            first_c[row] = if row == 0 { to_m31(1) } else { bf0 };
            ndraws_c[row] = if r == 0 { to_m31(i as u64) } else { bf0 };

            state = [s0n, s1n];
        }
        cur = state; // start of the next draw
        if i + 1 == m {
            final_state = (state[0], state[1]); // state after the last REAL draw's permute
        }
    }

    let mut main = col;
    for c in main.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(c);
    }
    let mut preproc_cols = [rc0_c, rc1_c, init_c, first_c, ndraws_c, dig0_c, dig1_c];
    for c in preproc_cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(c);
    }

    let main_cols: TraceColumns = main.into_iter().map(|c| CircleEvaluation::new(domain, c)).collect();
    let preproc: TraceColumns = preproc_cols
        .into_iter()
        .map(|c| CircleEvaluation::new(domain, c))
        .collect();
    (main_cols, preproc, squeezed, final_state)
}

// ── Prove / verify roundtrip ────────────────────────────────────────────────────

fn mix_public(channel: &mut Blake2sM31Channel, m: u32, digest: (u64, u64)) {
    channel.mix_u32s(&[m, (digest.0 % M31_P) as u32, (digest.1 % M31_P) as u32]);
}

/// Prove a draw chain of `m` draws from `digest`. Returns
/// `(proof, log_size, squeezed_pairs, final_state)`.
pub fn prove_draws(
    digest: (u64, u64),
    m: usize,
) -> Result<(Vec<u8>, u32, Vec<(u64, u64)>, (u64, u64)), String> {
    if m == 0 {
        return Err("must draw ≥ 1 pair".into());
    }
    if m > MAX_DRAWS {
        return Err(format!("draw count {m} exceeds MAX_DRAWS {MAX_DRAWS}"));
    }
    let log_size = compute_log_size(m);
    let (main_cols, preproc, squeezed, final_state) = build_trace(digest, m, log_size);
    let proof = prove_columns(main_cols, preproc, log_size, m as u32, digest)?;
    Ok((proof, log_size, squeezed, final_state))
}

fn prove_columns(
    main_cols: TraceColumns,
    preproc: TraceColumns,
    log_size: u32,
    m: u32,
    digest: (u64, u64),
) -> Result<Vec<u8>, String> {
    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preproc);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_cols);
    tree_builder.commit(channel);

    mix_public(channel, m, digest);

    let component = new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;
    bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))
}

/// Verify a proof from [`prove_draws`] against the claimed `(m, digest)`.
pub fn verify_draws(
    proof_bytes: &[u8],
    log_size: u32,
    m: u32,
    digest: (u64, u64),
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

    mix_public(verifier_channel, m, digest);

    let result = verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof);
    Ok(result.is_ok())
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_m31(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) % M31_P
    }

    // draw_chain's first draw squeezes the digest verbatim; the state then evolves.
    #[test]
    fn test_draw_chain_first_is_digest() {
        let digest = (12345u64, 67890u64);
        let (pairs, _) = draw_chain(digest, 3);
        assert_eq!(pairs[0], digest, "draw 0 squeezes the digest state");
        // Draw 1 squeezes permute(digest.0 + 0, digest.1).
        let mut s = [digest.0, digest.1];
        s[0] = m31_add(s[0], 0);
        crate::poseidon2::permute(&mut s);
        assert_eq!(pairs[1], (s[0], s[1]));
    }

    // draw_secure_felt packs the first two draws into a QM31.
    #[test]
    fn test_draw_secure_felt_packs_two_draws() {
        let digest = (111u64, 222u64);
        let (pairs, _) = draw_chain(digest, 2);
        let felt = draw_secure_felt(digest);
        assert_eq!((felt >> 96) as u64 & 0xffff_ffff, pairs[0].0);
        assert_eq!((felt >> 64) as u64 & 0xffff_ffff, pairs[0].1);
        assert_eq!((felt >> 32) as u64 & 0xffff_ffff, pairs[1].0);
        assert_eq!(felt as u64 & 0xffff_ffff, pairs[1].1);
    }

    // build_trace's squeezed pairs and final state match the reference.
    #[test]
    fn test_build_trace_matches_reference() {
        let mut seed = 0x9999;
        let digest = (rand_m31(&mut seed), rand_m31(&mut seed));
        let m = 4;
        let log = compute_log_size(m);
        let (main, preproc, squeezed, final_state) = build_trace(digest, m, log);
        assert_eq!(main.len(), N_MAIN_COLS);
        assert_eq!(preproc.len(), 7);
        let (ref_pairs, ref_final) = draw_chain(digest, m);
        assert_eq!(squeezed, ref_pairs, "trace squeezed pairs must match reference");
        assert_eq!(final_state, ref_final, "trace final state must match reference");
    }

    // Roundtrip: a single draw.
    #[test]
    fn test_roundtrip_one_draw() {
        let digest = (42u64, 99u64);
        let (proof, log, squeezed, _) = prove_draws(digest, 1).unwrap();
        assert_eq!(squeezed[0], digest);
        assert!(verify_draws(&proof, log, 1, digest).unwrap());
    }

    // Roundtrip: many draws (drawQueries-scale).
    #[test]
    fn test_roundtrip_many_draws() {
        let mut seed = 0x1357;
        let digest = (rand_m31(&mut seed), rand_m31(&mut seed));
        let (proof, log, squeezed, _) = prove_draws(digest, 10).unwrap();
        assert_eq!(squeezed.len(), 10);
        assert!(
            verify_draws(&proof, log, 10, digest).unwrap(),
            "a valid draw chain must verify",
        );
    }

    // The drawn pairs equal a drawSecureFelt over the same digest.
    #[test]
    fn test_proof_draws_match_secure_felt() {
        let digest = (0x1234u64, 0x5678u64);
        let (_proof, _log, squeezed, _) = prove_draws(digest, 2).unwrap();
        let felt = draw_secure_felt(digest);
        let expect = (
            (felt >> 96) as u64 & 0xffff_ffff,
            (felt >> 64) as u64 & 0xffff_ffff,
        );
        assert_eq!(squeezed[0], expect);
    }

    // Rejection: a wrong claimed digest replays a different transcript.
    #[test]
    fn test_wrong_digest_rejected() {
        let mut seed = 0x2468;
        let digest = (rand_m31(&mut seed), rand_m31(&mut seed));
        let (proof, log, _, _) = prove_draws(digest, 4).unwrap();
        assert!(
            !verify_draws(&proof, log, 4, (digest.0 ^ 1, digest.1)).unwrap_or(false),
            "a wrong digest must not verify",
        );
    }

    // Rejection: a wrong claimed draw count.
    #[test]
    fn test_wrong_count_rejected() {
        let mut seed = 0x3690;
        let digest = (rand_m31(&mut seed), rand_m31(&mut seed));
        let (proof, log, _, _) = prove_draws(digest, 4).unwrap();
        assert!(!verify_draws(&proof, log, 5, digest).unwrap_or(false));
    }

    // Rejection: tampered proof bytes.
    #[test]
    fn test_tampered_proof_rejected() {
        let digest = (7u64, 8u64);
        let (mut proof, log, _, _) = prove_draws(digest, 3).unwrap();
        let n = proof.len();
        proof[n / 3] ^= 0xff;
        assert!(!verify_draws(&proof, log, 3, digest).unwrap_or(false));
    }

    // Rejection: corrupted squeeze column (claims a wrong drawn word).
    #[test]
    fn test_corrupted_squeeze_rejected() {
        let digest = (55u64, 66u64);
        let m = 3;
        let log = compute_log_size(m);
        let (mut main, preproc, _, _) = build_trace(digest, m, log);
        {
            let col = &mut main[6]; // w0 (squeezed) column
            let mut vals: Vec<BaseField> = col.values.to_vec();
            vals[0] = BaseField::from_u32_unchecked(123456);
            let domain = CanonicCoset::new(log).circle_domain();
            *col = CircleEvaluation::new(domain, vals);
        }
        assert!(prove_columns(main, preproc, log, m as u32, digest).is_err());
    }

    // Error on zero draws.
    #[test]
    fn test_zero_draws_error() {
        assert!(prove_draws((1, 2), 0).is_err());
    }
}
