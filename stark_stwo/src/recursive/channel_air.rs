//! Poseidon2 Fiat-Shamir transcript (sponge-absorb) AIR — recursive-verifier
//! gadget (R2/R3).
//!
//! Proves a Poseidon2 (t=2) duplex-sponge absorption: that absorbing a sequence
//! of prover-committed words into the rate cell and permuting after each one
//! yields a claimed digest `(s0, s1)`.  This is the `mixU32s` core of
//! `Poseidon2Channel` / `P2T8Channel` — the Fiat-Shamir transcript engine the
//! recursive verifier must replay in-circuit to prove it derived the folding
//! challenges and FRI query positions honestly (rather than cherry-picking them).
//!
//! Absorption (rate-1 sponge, matching the on-chain channel):
//!
//! ```text
//! s ← (0, 0)
//! for each word w:  s0 ← (s0 + w) mod P;  s ← Poseidon2_t2(s)
//! digest ← s
//! ```
//!
//! A `draw` (squeeze) reads the rate cells of the resulting state; that thin
//! layer is composed on top at the recursive-verifier level (R3).  This gadget
//! establishes the absorb/permute transcript structure, hash-width-independent
//! (the permutation core swaps to t=8/t=16 the same way VFRI10→VFRI11 did).
//!
//! # Trace layout
//!
//! Each absorb-and-permute takes `N_ROUNDS = 8` rows.  Main trace (7 columns):
//! ```text
//! 0 s0   1 s1   2 t0   3 t1   4 inp0  5 inp1
//! 6 word (absorbed word; meaningful on init rows only)
//! ```
//! Preprocessed (4 columns): `rc0, rc1, is_init (r==0), is_first (row 0)`.
//!
//! On each compression's init row the permutation input is
//! `inp0 = prev_s0 + word`, `inp1 = prev_s1`, where `prev_s = is_first ? 0 : s[-1]`
//! (the first absorb starts from the zero state).

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

pub const N_MAIN_COLS: usize = 7;
pub const MIN_LOG_SIZE: u32 = 3; // ≥ 8 rows = 1 absorb
pub const MAX_LOG_SIZE: u32 = 24;
pub const MAX_WORDS: usize = 1 << 18;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub type ChannelComponent = FrameworkComponent<ChannelEval>;

// ── Preprocessed column IDs ───────────────────────────────────────────────────

pub fn pc_rc0() -> PreProcessedColumnId { PreProcessedColumnId { id: "rch_rc0".into() } }
pub fn pc_rc1() -> PreProcessedColumnId { PreProcessedColumnId { id: "rch_rc1".into() } }
pub fn pc_is_init() -> PreProcessedColumnId { PreProcessedColumnId { id: "rch_is_init".into() } }
pub fn pc_is_first() -> PreProcessedColumnId { PreProcessedColumnId { id: "rch_is_first".into() } }

pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    vec![pc_rc0(), pc_rc1(), pc_is_init(), pc_is_first()]
}

// ── Reference sponge ───────────────────────────────────────────────────────────

/// Absorb `words` into a Poseidon2 t=2 duplex sponge (rate-1) and return the
/// resulting `(s0, s1)` digest. Matches the on-chain channel's `mixU32s` core.
pub fn sponge_absorb(words: &[u64]) -> (u64, u64) {
    let mut s = [0u64, 0u64];
    for &w in words {
        s[0] = m31_add(s[0], w % M31_P);
        crate::poseidon2::permute(&mut s);
    }
    (s[0], s[1])
}

// ── AIR ──────────────────────────────────────────────────────────────────────

pub struct ChannelEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for ChannelEval {
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
        let [word] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let not_init = one.clone() - is_init.clone();
        let not_first = one - is_first;

        // ── Poseidon2 round core (identical to the Merkle / base AIRs) ────────
        let x0 = inp0.clone() + rc0;
        let x1 = inp1.clone() + rc1;
        let sbox0 = t0.clone() * t0.clone() * x0.clone(); // x0^5
        let sbox1 = t1.clone() * t1.clone() * x1.clone(); // x1^5
        let three = BaseField::from_u32_unchecked(3);
        eval.add_constraint(t0 - x0.clone() * x0); // C_t0
        eval.add_constraint(t1 - x1.clone() * x1); // C_t1
        eval.add_constraint(s0_curr - (sbox0.clone() * three + sbox1.clone())); // C_s0
        eval.add_constraint(s1_curr - (sbox0 + sbox1 * three)); // C_s1

        // ── Init-row wiring: absorb word into the rate cell ──────────────────
        // prev_s = is_first ? 0 : s[-1]   (first absorb starts from zero state)
        let prev_s0 = not_first.clone() * s0_prev.clone();
        let prev_s1 = not_first * s1_prev.clone();
        // inp0 = prev_s0 + word ;  inp1 = prev_s1
        eval.add_constraint(is_init.clone() * (inp0.clone() - (prev_s0 + word))); // C_inp0_init
        eval.add_constraint(is_init.clone() * (inp1.clone() - prev_s1)); // C_inp1_init

        // ── Non-init chaining: state carries within a permutation ────────────
        eval.add_constraint(not_init.clone() * (inp0 - s0_prev)); // C_inp0_chain
        eval.add_constraint(not_init * (inp1 - s1_prev)); // C_inp1_chain

        eval
    }
}

fn new_component(log_n_rows: u32) -> ChannelComponent {
    ChannelComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_column_ids()),
        ChannelEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace size helpers ─────────────────────────────────────────────────────────

pub fn compute_log_size(n_words: usize) -> u32 {
    let n_real = n_words.max(1) * N_ROUNDS;
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < n_real {
        log += 1;
    }
    log
}

// ── Trace builder ──────────────────────────────────────────────────────────────

/// Build the sponge-absorb trace. Returns `(main_columns, preprocessed_columns,
/// digest)`. The first `words.len()` absorbs are real; remaining rows are padded
/// with `absorb(0)` (the sponge keeps running; constraints stay satisfied).
pub fn build_trace(words: &[u64], log_size: u32) -> (TraceColumns, TraceColumns, (u64, u64)) {
    let n_words = words.len();
    let n = 1usize << log_size;
    debug_assert!(n_words * N_ROUNDS <= n, "transcript exceeds trace capacity");
    let domain = CanonicCoset::new(log_size).circle_domain();

    let to_m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);
    let bf0 = BaseField::from_u32_unchecked(0);

    let mut col: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];
    let mut rc0_c = vec![bf0; n];
    let mut rc1_c = vec![bf0; n];
    let mut init_c = vec![bf0; n];
    let mut first_c = vec![bf0; n];

    let n_absorb = n / N_ROUNDS;
    let mut prev = [0u64, 0u64];
    let mut digest = (0u64, 0u64);

    for i in 0..n_absorb {
        let w = if i < n_words { words[i] % M31_P } else { 0 };
        let inp0_init = m31_add(prev[0], w);
        let inp1_init = prev[1];

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
                col[6][row] = to_m31(w); // word
            }
            rc0_c[row] = to_m31(RC[r][0] as u64);
            rc1_c[row] = to_m31(RC[r][1] as u64);
            init_c[row] = if r == 0 { to_m31(1) } else { bf0 };
            first_c[row] = if row == 0 { to_m31(1) } else { bf0 };

            state = [s0n, s1n];
        }
        prev = state;
        if i + 1 == n_words.max(1) {
            digest = (state[0], state[1]); // digest after the last REAL absorb
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
    (main_cols, preproc, digest)
}

// ── Prove / verify roundtrip ────────────────────────────────────────────────────

fn mix_digest(channel: &mut Blake2sM31Channel, n_words: u32, digest: (u64, u64)) {
    channel.mix_u32s(&[n_words, (digest.0 % M31_P) as u32, (digest.1 % M31_P) as u32]);
}

/// Prove a Fiat-Shamir transcript absorption. Returns `(proof, log_size, digest)`.
pub fn prove_channel(words: &[u64]) -> Result<(Vec<u8>, u32, (u64, u64)), String> {
    if words.is_empty() {
        return Err("transcript must have ≥ 1 word".into());
    }
    if words.len() > MAX_WORDS {
        return Err(format!("transcript length {} exceeds MAX_WORDS {MAX_WORDS}", words.len()));
    }
    let log_size = compute_log_size(words.len());
    let (main_cols, preproc, digest) = build_trace(words, log_size);
    let proof = prove_columns(main_cols, preproc, log_size, words.len() as u32, digest)?;
    Ok((proof, log_size, digest))
}

fn prove_columns(
    main_cols: TraceColumns,
    preproc: TraceColumns,
    log_size: u32,
    n_words: u32,
    digest: (u64, u64),
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
    tree_builder.extend_evals(preproc); // Tree 0: preprocessed
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_cols); // Tree 1: main trace (7 columns)
    tree_builder.commit(channel);

    mix_digest(channel, n_words, digest);

    let component = new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;
    bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))
}

/// Verify a proof produced by [`prove_channel`] against the claimed
/// `(n_words, digest)`.
pub fn verify_channel(
    proof_bytes: &[u8],
    log_size: u32,
    n_words: u32,
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

    mix_digest(verifier_channel, n_words, digest);

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

    #[test]
    fn test_sponge_absorb_matches_manual_permute() {
        // Single word: digest = permute([w, 0]).
        let w = 98765u64;
        let mut s = [w % M31_P, 0u64];
        crate::poseidon2::permute(&mut s);
        assert_eq!(sponge_absorb(&[w]), (s[0], s[1]));
    }

    #[test]
    fn test_sponge_absorb_two_words() {
        let (a, b) = (111u64, 222u64);
        let mut s = [a, 0u64];
        crate::poseidon2::permute(&mut s);
        s[0] = m31_add(s[0], b);
        crate::poseidon2::permute(&mut s);
        assert_eq!(sponge_absorb(&[a, b]), (s[0], s[1]));
    }

    #[test]
    fn test_build_trace_digest_matches_reference() {
        let mut seed = 0x2222;
        let words: Vec<u64> = (0..4).map(|_| rand_m31(&mut seed)).collect();
        let log = compute_log_size(words.len());
        let (main, preproc, digest) = build_trace(&words, log);
        assert_eq!(main.len(), N_MAIN_COLS);
        assert_eq!(preproc.len(), 4);
        assert_eq!(digest, sponge_absorb(&words), "trace digest must match reference");
    }

    #[test]
    fn test_roundtrip_one_word() {
        let words = vec![42u64];
        let (proof, log, digest) = prove_channel(&words).expect("prove");
        assert!(verify_channel(&proof, log, words.len() as u32, digest).expect("verify"));
    }

    #[test]
    fn test_roundtrip_many_words() {
        let mut seed = 0x3333;
        let words: Vec<u64> = (0..8).map(|_| rand_m31(&mut seed)).collect();
        let (proof, log, digest) = prove_channel(&words).expect("prove");
        assert!(
            verify_channel(&proof, log, words.len() as u32, digest).expect("verify"),
            "a valid transcript must verify",
        );
    }

    #[test]
    fn test_wrong_digest_rejected() {
        let mut seed = 0x4444;
        let words: Vec<u64> = (0..5).map(|_| rand_m31(&mut seed)).collect();
        let (proof, log, digest) = prove_channel(&words).expect("prove");
        assert!(
            !verify_channel(&proof, log, words.len() as u32, (digest.0 ^ 1, digest.1)).unwrap_or(false),
            "a wrong digest must not verify",
        );
    }

    #[test]
    fn test_wrong_word_count_rejected() {
        let mut seed = 0x5555;
        let words: Vec<u64> = (0..5).map(|_| rand_m31(&mut seed)).collect();
        let (proof, log, digest) = prove_channel(&words).expect("prove");
        assert!(
            !verify_channel(&proof, log, words.len() as u32 + 1, digest).unwrap_or(false),
            "a wrong word count must not verify",
        );
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let mut seed = 0x6666;
        let words: Vec<u64> = (0..5).map(|_| rand_m31(&mut seed)).collect();
        let (proof, log, digest) = prove_channel(&words).expect("prove");
        let mut bad = proof.clone();
        bad[proof.len() / 2] ^= 0xFF;
        assert!(
            !verify_channel(&bad, log, words.len() as u32, digest).unwrap_or(false),
            "tampered proof must not verify",
        );
    }

    #[test]
    fn test_corrupted_trace_rejected() {
        // Corrupt the absorbed-word column → the absorb-wiring constraints reject.
        let mut seed = 0x7777;
        let words: Vec<u64> = (0..3).map(|_| rand_m31(&mut seed)).collect();
        let log = compute_log_size(words.len());
        let (mut main, preproc, digest) = build_trace(&words, log);
        let domain = CanonicCoset::new(log).circle_domain();
        let mut vals = main[6].values.clone(); // column 6 = word
        vals[0] = vals[0] + BaseField::from_u32_unchecked(1);
        main[6] = CircleEvaluation::new(domain, vals);
        match prove_columns(main, preproc, log, words.len() as u32, digest) {
            Ok(proof) => assert!(
                !verify_channel(&proof, log, words.len() as u32, digest).unwrap_or(false),
                "a corrupted transcript trace must not yield a verifying proof",
            ),
            Err(_) => {}
        }
    }
}
