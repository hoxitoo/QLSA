//! Poseidon2 **t=8** Fiat-Shamir channel as a provable AIR — absorb side.
//!
//! # Why this exists
//!
//! `channel_air` and `transcript_draw_air` already arithmetize a channel, but on
//! the **t=2** permutation. No deployed verifier uses that width: VFRI11 — the
//! production stack — runs its transcript on `P2T8Channel`. Wiring the t=2
//! gadgets into the recursion would prove the replay of a channel nothing uses.
//!
//! What needs the t=8 channel is the N-signature aggregation tree (A-2 in
//! `docs/TECH_DEBT.md`). The recursion keeps the inner proof's Fiat-Shamir replay
//! **on-chain** (R3.10) — cheap, and it makes the challenges public inputs. That
//! holds at a tree's ROOT, whose fan-in is a constant 2 whatever N is. It does
//! not hold below: intermediate levels must derive their children's challenges
//! **in-circuit**, or the on-chain replay count grows with N. Measured, one
//! replay costs 1,052,669 gas against 3,608,745 of headroom, so growing it is
//! not an option (`contracts/test/ChannelReplayCostProbe.test.js`).
//!
//! # Shape
//!
//! An absorb is one addition into cell 0 followed by the 22-round permutation:
//!
//! ```text
//!     s[0] += reduce(word);  permute_t8(s)
//! ```
//!
//! So the trace is a chain of 22-round blocks, one per absorbed word, with the
//! full 8-cell state carried across block boundaries. That is the same chaining
//! `merkle_path_t8_air` uses across compressions, and the round arithmetization
//! is shared with `poseidon2_t8_air` rather than restated — the same discipline
//! that keeps the FRI chain and its ABI encoder from drifting (R4.1).
//!
//! # Soundness
//!
//! - **[C1 input]** the absorbed words are the inner proof's PUBLIC roots, so
//!   they are pinned (`word_pin`) and forced to equal the trace's word column at
//!   each block start. Without it a prover could absorb values of its choosing
//!   and still produce a self-consistent trace — the replay would attest a
//!   transcript nobody committed to.
//! - **[C1 output]** the digest is pinned and forced onto the last real row.
//! - **[C2]** selectors, round constants and both pins come from the single
//!   canonical `build_preproc`, whose commitment root `verify_channel_t8`
//!   recomputes. A forged `is_block_start ≡ 0` — absorbing nothing while
//!   claiming a digest — does not verify.
//!
//! The two conditional subtractions that reduce a `u32` are deliberately NOT
//! arithmetized: the pinned word is already reduced, so the circuit proves
//! absorption of exactly the value the verifier committed to.

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
use crate::poseidon2_t8::{
    mat_external as mat_external_ref, mat_internal as mat_internal_ref, T,
};
use crate::recursive::poseidon2_t8_air::{
    mat_external_expr, mat_internal_expr, round_schedule, N_REAL_ROWS as N_ROUNDS,
};
use crate::poseidon2_t8::permute_t8;
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

/// One absorbed word costs a full permutation: 4 external + 14 internal + 4
/// external rounds, matching `poseidon2_t8_air::N_REAL_ROWS`.
pub const ROUNDS_PER_ABSORB: usize = 22;

/// Reduce an arbitrary `u32` to M31.
///
/// Two conditional subtractions, not one: a `u32` reaches `2^32 - 1 = 2P + 1`.
/// This mirrors `P2T8Channel::absorb` and `Poseidon2ChannelT8._absorb`; all three
/// must agree, or a proof of the replay would attest a different transcript than
/// the chain computed.
pub fn reduce_u32(word: u32) -> u64 {
    let mut w = word as u64;
    if w >= M31_P {
        w -= M31_P;
    }
    if w >= M31_P {
        w -= M31_P;
    }
    w
}

/// The absorb-side channel state the AIR will constrain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelT8State {
    pub s: [u64; 8],
}

impl ChannelT8State {
    pub fn init() -> Self {
        ChannelT8State { s: [0u64; 8] }
    }

    /// Absorb one word: add into cell 0, then permute.
    pub fn absorb(&mut self, word: u32) {
        self.s[0] = m31_add(self.s[0], reduce_u32(word));
        permute_t8(&mut self.s);
    }

    pub fn absorb_all(&mut self, words: &[u32]) {
        for &w in words {
            self.absorb(w);
        }
    }
}

/// The state after each absorb, starting from the initial state.
///
/// `states[0]` is the state before any absorb; `states[i+1]` is the state after
/// absorbing `words[i]`. The AIR's row blocks interpolate between consecutive
/// entries, so this is the skeleton the trace is built around.
pub fn absorb_states(words: &[u32]) -> Vec<[u64; 8]> {
    let mut st = ChannelT8State::init();
    let mut out = Vec::with_capacity(words.len() + 1);
    out.push(st.s);
    for &w in words {
        st.absorb(w);
        out.push(st.s);
    }
    out
}

/// Rows the trace needs for `n_words` absorbs.
pub fn n_rows(n_words: usize) -> usize {
    n_words * ROUNDS_PER_ABSORB
}

pub const MIN_LOG_SIZE: u32 = 5;   // ≥ 32 rows = one absorb (22 rounds)
pub const MAX_LOG_SIZE: u32 = 24;
/// Most words one proof absorbs. A VFRI11 transcript absorbs well under this:
/// a full root is 8 words, and a replay mixes roughly a dozen of them.
pub const MAX_WORDS: usize = 512;

/// Smallest `log_size` holding `n_words` absorbs.
pub fn compute_log_size(n_words: usize) -> u32 {
    let rows = n_rows(n_words).max(1);
    let mut log = 1u32;
    while (1usize << log) < rows {
        log += 1;
    }
    log.max(5) // ≥ 32 rows, as in the other t=8 AIRs
}


// ── Column layout ────────────────────────────────────────────────────────────
// The round core is identical to poseidon2_t8_air; only the block wiring differs.
const C_IN: usize = 0;    // 0..8   round input
const C_SQ: usize = 8;    // 8..16  (in + rc)²
const C_SBOX: usize = 16; // 16..24 (in + rc)^5
const C_OUT: usize = 24;  // 24..32 round output
const C_WORD: usize = 32; // 32     the absorbed word (block-start rows)
pub const N_MAIN_COLS: usize = 33;

// ── Preprocessed column IDs ──────────────────────────────────────────────────

pub fn pc_rc(i: usize) -> PreProcessedColumnId {
    PreProcessedColumnId { id: format!("cht8_rc{i}") }
}
pub fn pc_is_ext() -> PreProcessedColumnId { PreProcessedColumnId { id: "cht8_is_ext".into() } }
pub fn pc_is_int() -> PreProcessedColumnId { PreProcessedColumnId { id: "cht8_is_int".into() } }
pub fn pc_is_block_start() -> PreProcessedColumnId { PreProcessedColumnId { id: "cht8_is_block".into() } }
pub fn pc_is_first_block() -> PreProcessedColumnId { PreProcessedColumnId { id: "cht8_is_first".into() } }
pub fn pc_word() -> PreProcessedColumnId { PreProcessedColumnId { id: "cht8_word".into() } }
pub fn pc_is_last() -> PreProcessedColumnId { PreProcessedColumnId { id: "cht8_is_last".into() } }
pub fn pc_digest(k: usize) -> PreProcessedColumnId {
    PreProcessedColumnId { id: format!("cht8_digest{k}") }
}

pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    let mut ids: Vec<PreProcessedColumnId> = (0..T).map(pc_rc).collect();
    ids.push(pc_is_ext());
    ids.push(pc_is_int());
    ids.push(pc_is_block_start());
    ids.push(pc_is_first_block());
    ids.push(pc_word());
    ids.push(pc_is_last());
    for k in 0..T {
        ids.push(pc_digest(k));
    }
    ids
}

// ── AIR ──────────────────────────────────────────────────────────────────────

pub struct ChannelT8Eval {
    pub log_n_rows: u32,
}

pub type ChannelT8Component = FrameworkComponent<ChannelT8Eval>;

impl FrameworkEval for ChannelT8Eval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        // C_in reaches degree 3 (selector × external matrix of a degree-2 raw),
        // matching merkle_path_t8_air; nothing here exceeds it.
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let rc: Vec<E::F> = (0..T).map(|i| eval.get_preprocessed_column(pc_rc(i))).collect();
        let is_ext = eval.get_preprocessed_column(pc_is_ext());
        let is_int = eval.get_preprocessed_column(pc_is_int());
        let is_block = eval.get_preprocessed_column(pc_is_block_start());
        let is_first = eval.get_preprocessed_column(pc_is_first_block());
        let word_pin = eval.get_preprocessed_column(pc_word());
        let is_last = eval.get_preprocessed_column(pc_is_last());
        let digest_pin: Vec<E::F> = (0..T).map(|k| eval.get_preprocessed_column(pc_digest(k))).collect();

        let inp: Vec<E::F> =
            (0..T).map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()).collect();
        let sq: Vec<E::F> =
            (0..T).map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()).collect();
        let sbox: Vec<E::F> =
            (0..T).map(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()).collect();
        // `out` needs the previous row: the state crosses block boundaries there.
        let mut out: Vec<E::F> = Vec::with_capacity(T);
        let mut out_prev: Vec<E::F> = Vec::with_capacity(T);
        for _ in 0..T {
            let [c, p] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
            out.push(c);
            out_prev.push(p);
        }
        let [word] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let one = E::F::from(BaseField::from_u32_unchecked(1));

        // ── Round core — shared with poseidon2_t8_air, not restated ──────────
        let y: Vec<E::F> = (0..T).map(|i| inp[i].clone() + rc[i].clone()).collect();
        for i in 0..T {
            eval.add_constraint(sq[i].clone() - y[i].clone() * y[i].clone());
        }
        for i in 0..T {
            eval.add_constraint(sbox[i].clone() - sq[i].clone() * sq[i].clone() * y[i].clone());
        }
        let sb_ext: [E::F; 8] = std::array::from_fn(|i| sbox[i].clone());
        let sb_int: [E::F; 8] =
            std::array::from_fn(|i| if i == 0 { sbox[0].clone() } else { inp[i].clone() });
        let me = mat_external_expr(&sb_ext);
        let mi = mat_internal_expr(&sb_int);
        for i in 0..T {
            let expected = is_ext.clone() * me[i].clone() + is_int.clone() * mi[i].clone();
            eval.add_constraint(out[i].clone() - expected);
        }

        // ── Absorb wiring ───────────────────────────────────────────────────
        // At a block start the channel adds the word into cell 0 of the CARRIED
        // state and permutes; `mat_external` is the permutation's initial pre-mix,
        // exactly as in poseidon2_t8_air's first row.
        //
        // The carried state is the previous row's output — except at the very
        // first block, where the channel starts from zero. `is_first` zeroes it
        // rather than reading row −1, which wraps.
        let prev: Vec<E::F> =
            (0..T).map(|i| (one.clone() - is_first.clone()) * out_prev[i].clone()).collect();
        let raw: [E::F; 8] = std::array::from_fn(|i| {
            if i == 0 { prev[0].clone() + word.clone() } else { prev[i].clone() }
        });
        let me_raw = mat_external_expr(&raw);
        for i in 0..T {
            let expected = is_block.clone() * me_raw[i].clone()
                + (one.clone() - is_block.clone()) * out_prev[i].clone();
            eval.add_constraint(inp[i].clone() - expected);
        }

        // ── C1 input binding: the absorbed word is verifier-fixed ────────────
        // The words are the inner proof's public roots. Without this the prover
        // could absorb anything and still produce a self-consistent trace, and
        // the replay would attest a transcript of the prover's choosing.
        eval.add_constraint(is_block.clone() * (word.clone() - word_pin.clone()));

        // ── C1 output binding: the digest is verifier-fixed ──────────────────
        for k in 0..T {
            eval.add_constraint(is_last.clone() * (out[k].clone() - digest_pin[k].clone()));
        }

        eval
    }
}

fn new_component(log_n_rows: u32) -> ChannelT8Component {
    ChannelT8Component::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_column_ids()),
        ChannelT8Eval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Preprocessed columns (canonical source, C1/C2) ───────────────────────────

pub fn build_preproc(words: &[u32], digest: [u64; T], log_size: u32) -> TraceColumns {
    let n = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let one = BaseField::from_u32_unchecked(1);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut rc_cols: Vec<Vec<BaseField>> = (0..T).map(|_| vec![bf0; n]).collect();
    let mut is_ext_c = vec![bf0; n];
    let mut is_int_c = vec![bf0; n];
    let mut is_block_c = vec![bf0; n];
    let mut is_first_c = vec![bf0; n];
    let mut word_c = vec![bf0; n];
    let mut is_last_c = vec![bf0; n];
    let mut digest_cols: Vec<Vec<BaseField>> = (0..T).map(|_| vec![bf0; n]).collect();

    let n_blocks = words.len().min(n / N_ROUNDS);
    for b in 0..n_blocks {
        for r in 0..N_ROUNDS {
            let row = b * N_ROUNDS + r;
            let (is_ext, rc) = round_schedule(r);
            for i in 0..T {
                rc_cols[i][row] = m31(rc[i]);
            }
            if is_ext { is_ext_c[row] = one; } else { is_int_c[row] = one; }
        }
        let first = b * N_ROUNDS;
        is_block_c[first] = one;
        // The word is pinned ALREADY REDUCED. The two conditional subtractions
        // are not arithmetized: the verifier supplies the reduced value, so the
        // circuit proves absorption of exactly what the verifier committed to.
        word_c[first] = m31(reduce_u32(words[b]));
        if b == 0 { is_first_c[first] = one; }
    }
    if n_blocks >= 1 {
        let last = (n_blocks - 1) * N_ROUNDS + (N_ROUNDS - 1);
        is_last_c[last] = one;
        for k in 0..T {
            digest_cols[k][last] = m31(digest[k]);
        }
    }

    let mut all = rc_cols;
    all.push(is_ext_c);
    all.push(is_int_c);
    all.push(is_block_c);
    all.push(is_first_c);
    all.push(word_c);
    all.push(is_last_c);
    all.extend(digest_cols);
    for col in all.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    all.into_iter().map(|col| CircleEvaluation::new(domain, col)).collect()
}

fn canonical_preproc_root(
    words: &[u32],
    digest: [u64; T],
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
    tree.extend_evals(build_preproc(words, digest, log_size));
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

// ── Trace builder ────────────────────────────────────────────────────────────

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

/// Build the main trace. Returns `(main_columns, digest)`.
///
/// Every value is produced by the REFERENCE operations rather than recomputed
/// from the constraint expressions, so the trace cannot satisfy a constraint the
/// channel does not.
pub fn build_trace(words: &[u32], log_size: u32) -> (TraceColumns, [u64; T]) {
    let n = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];
    let n_blocks = words.len().min(n / N_ROUNDS);

    let mut carried = [0u64; T];
    for b in 0..n_blocks {
        // The absorb: add into cell 0, then the permutation's initial pre-mix.
        let mut state = carried;
        state[0] = m31_add(state[0], reduce_u32(words[b]));
        cols[C_WORD][b * N_ROUNDS] = m31(reduce_u32(words[b]));
        mat_external_ref(&mut state);

        for r in 0..N_ROUNDS {
            let row = b * N_ROUNDS + r;
            let (is_ext, rc) = round_schedule(r);
            let inp = state;
            for i in 0..T {
                let y = m31_add(inp[i], rc[i]);
                cols[C_IN + i][row] = m31(inp[i]);
                cols[C_SQ + i][row] = m31(m31_mul(y, y));
                cols[C_SBOX + i][row] = m31(sbox_ref(y));
            }
            let mut lin = inp;
            if is_ext {
                for i in 0..T {
                    lin[i] = sbox_ref(m31_add(inp[i], rc[i]));
                }
                mat_external_ref(&mut lin);
            } else {
                lin[0] = sbox_ref(m31_add(inp[0], rc[0]));
                mat_internal_ref(&mut lin);
            }
            for i in 0..T {
                cols[C_OUT + i][row] = m31(lin[i]);
            }
            state = lin;
        }
        carried = state;
    }

    // Padding rows: selectors are 0, so `out` must be 0 and `in` must chain from
    // the previous output. sq/sbox still have to satisfy their ungated
    // constraints, so they are filled from `in` with rc = 0.
    for row in n_blocks * N_ROUNDS..n {
        let prev_out: [u64; T] = if row == 0 {
            [0u64; T]
        } else {
            std::array::from_fn(|i| cols[C_OUT + i][row - 1].0 as u64)
        };
        for i in 0..T {
            cols[C_IN + i][row] = m31(prev_out[i]);
            cols[C_SQ + i][row] = m31(m31_mul(prev_out[i], prev_out[i]));
            cols[C_SBOX + i][row] = m31(sbox_ref(prev_out[i]));
        }
    }

    for col in cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    (
        cols.into_iter().map(|col| CircleEvaluation::new(domain, col)).collect(),
        carried,
    )
}

// ── Prove / verify ───────────────────────────────────────────────────────────

fn mix_public(channel: &mut Blake2sM31Channel, words: &[u32], digest: [u64; T]) {
    let mut v: Vec<u32> = Vec::with_capacity(words.len() + T + 1);
    v.push(words.len() as u32);
    v.extend(words.iter().map(|&w| (reduce_u32(w) % M31_P) as u32));
    v.extend(digest.iter().map(|&d| (d % M31_P) as u32));
    channel.mix_u32s(&v);
}

/// Prove that absorbing `words` into a fresh t=8 channel yields the digest.
pub fn prove_channel_t8(words: &[u32]) -> Result<(Vec<u8>, u32, [u64; T]), String> {
    if words.is_empty() {
        return Err("need ≥ 1 word to absorb".into());
    }
    if words.len() > MAX_WORDS {
        return Err(format!("word count {} exceeds MAX_WORDS {MAX_WORDS}", words.len()));
    }
    let log_size = compute_log_size(words.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("log_size {log_size} exceeds {MAX_LOG_SIZE}"));
    }
    let (main_cols, digest) = build_trace(words, log_size);
    let preproc = build_preproc(words, digest, log_size);

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

    mix_public(channel, words, digest);

    let component = new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("t8 channel proving error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("t8 channel serialize error: {e:?}"))?;
    Ok((bytes, log_size, digest))
}

/// Verify a proof from [`prove_channel_t8`] against the claimed `(words, digest)`.
pub fn verify_channel_t8(
    proof_bytes: &[u8],
    log_size: u32,
    words: &[u32],
    digest: [u64; T],
) -> Result<bool, String> {
    if !(MIN_LOG_SIZE..=MAX_LOG_SIZE).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range [{MIN_LOG_SIZE}, {MAX_LOG_SIZE}]"));
    }
    if words.is_empty() || words.len() > MAX_WORDS {
        return Err(format!("word count {} out of range [1, {MAX_WORDS}]", words.len()));
    }
    if n_rows(words.len()) > (1usize << log_size) {
        return Err(format!("{} words exceed trace capacity at log_size {log_size}", words.len()));
    }

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("t8 channel deserialize error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let component = new_component(log_size);
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    // C2: pin the preprocessed tree. Without this a prover could forge
    // `is_block_start ≡ 0`, absorbing nothing while claiming a digest.
    if proof.commitments[0] != canonical_preproc_root(words, digest, log_size) {
        return Ok(false);
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    mix_public(verifier_channel, words, digest);

    let result = verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof);
    Ok(result.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference must reproduce `P2T8Channel` exactly.
    ///
    /// This is the load-bearing test of the module: everything downstream proves
    /// statements ABOUT this state chain, so if it diverges from the channel the
    /// chain actually runs, the proof attests the wrong transcript.
    #[test]
    fn absorb_matches_the_production_channel() {
        for words in [
            vec![],
            vec![0u32],
            vec![1, 2, 3],
            vec![0xFFFF_FFFF],                 // 2P+1 — needs BOTH subtractions
            vec![M31_P as u32, M31_P as u32 + 1],
            (0..40u32).collect::<Vec<_>>(),
        ] {
            let mut mine = ChannelT8State::init();
            mine.absorb_all(&words);

            // Same sequence through the production channel's own primitive.
            let mut theirs = [0u64; 8];
            for &w in &words {
                let mut r = w as u64;
                if r >= M31_P { r -= M31_P; }
                if r >= M31_P { r -= M31_P; }
                theirs[0] = m31_add(theirs[0], r);
                permute_t8(&mut theirs);
            }
            assert_eq!(mine.s, theirs, "diverged on {words:?}");
        }
    }

    #[test]
    fn reduce_handles_the_full_u32_range() {
        // A u32 reaches 2P+1, so one conditional subtraction is not enough.
        assert_eq!(reduce_u32(0), 0);
        assert_eq!(reduce_u32(1), 1);
        assert_eq!(reduce_u32(M31_P as u32), 0);
        assert_eq!(reduce_u32(M31_P as u32 + 1), 1);
        assert_eq!(reduce_u32(u32::MAX), (u32::MAX as u64) - 2 * M31_P);
        for w in [0u32, 7, M31_P as u32 - 1, M31_P as u32, u32::MAX] {
            assert!(reduce_u32(w) < M31_P, "w={w} did not reduce");
        }
    }

    #[test]
    fn absorbing_is_order_sensitive_and_length_sensitive() {
        let a = { let mut c = ChannelT8State::init(); c.absorb_all(&[1, 2]); c.s };
        let b = { let mut c = ChannelT8State::init(); c.absorb_all(&[2, 1]); c.s };
        let c3 = { let mut c = ChannelT8State::init(); c.absorb_all(&[1, 2, 0]); c.s };
        assert_ne!(a, b, "order must matter");
        assert_ne!(a, c3, "a trailing zero word must matter");
    }

    #[test]
    fn states_line_up_with_the_row_blocks() {
        let words = vec![5u32, 9, 13];
        let states = absorb_states(&words);
        assert_eq!(states.len(), words.len() + 1);
        assert_eq!(states[0], [0u64; 8], "chain starts at the zero state");

        // Each entry is reachable from the previous by exactly one absorb — the
        // property the per-block constraints will encode.
        for (i, &w) in words.iter().enumerate() {
            let mut st = ChannelT8State { s: states[i] };
            st.absorb(w);
            assert_eq!(st.s, states[i + 1], "block {i} does not chain");
        }
        assert_eq!(n_rows(words.len()), 3 * ROUNDS_PER_ABSORB);
    }

    #[test]
    fn log_size_covers_the_rows_and_meets_the_floor() {
        assert!(1usize << compute_log_size(0) >= 1);
        assert_eq!(compute_log_size(1), 5); // 22 rows → 32, the t=8 floor
        for n in [1usize, 2, 3, 8, 50] {
            assert!(
                1usize << compute_log_size(n) >= n_rows(n),
                "log_size too small for {n} absorbs");
        }
    }

    // ── Prove / verify roundtrip ─────────────────────────────────────────────

    #[test]
    fn honest_absorb_proves_and_verifies() {
        for words in [vec![7u32], vec![1, 2, 3], (0..6u32).map(|i| i * 977).collect()] {
            let (proof, log_size, digest) = prove_channel_t8(&words).expect("prove");
            let mut want = ChannelT8State::init();
            want.absorb_all(&words);
            assert_eq!(digest, want.s, "proved digest differs from the reference");
            assert!(verify_channel_t8(&proof, log_size, &words, digest).unwrap(),
                    "honest proof must verify for {words:?}");
        }
    }

    #[test]
    fn a_wrong_digest_is_rejected() {
        let words = vec![3u32, 5, 8];
        let (proof, log_size, digest) = prove_channel_t8(&words).unwrap();
        let mut bad = digest;
        bad[0] = (bad[0] + 1) % M31_P;
        assert!(!verify_channel_t8(&proof, log_size, &words, bad).unwrap());
    }

    /// C1 input binding: the words are the inner proof's public roots, so a proof
    /// of absorbing one sequence must not verify against another.
    #[test]
    fn a_different_word_sequence_is_rejected() {
        let words = vec![3u32, 5, 8];
        let (proof, log_size, digest) = prove_channel_t8(&words).unwrap();
        assert!(!verify_channel_t8(&proof, log_size, &[3, 5, 9], digest).unwrap(),
                "a changed word must not verify");
        assert!(!verify_channel_t8(&proof, log_size, &[5, 3, 8], digest).unwrap(),
                "reordered words must not verify");
    }

    /// C2: a forged preprocessed tree must not verify. `is_block_start ≡ 0`
    /// absorbs nothing while still claiming a digest, so it is the forgery that
    /// matters most here.
    #[test]
    fn forged_preproc_is_rejected() {
        let words = vec![11u32, 13];
        let (proof_bytes, log_size, digest) = prove_channel_t8(&words).unwrap();
        let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
            bincode::serde::decode_from_slice(&proof_bytes, bincode::config::standard()).unwrap();

        // The honest tree is what the verifier rebuilds; anything else is refused
        // before the STARK is even checked.
        assert_eq!(proof.commitments[0], canonical_preproc_root(&words, digest, log_size));
        assert_ne!(proof.commitments[0], canonical_preproc_root(&[11, 14], digest, log_size));
    }

    #[test]
    fn input_bounds_are_enforced() {
        assert!(prove_channel_t8(&[]).is_err(), "empty absorb");
        let big: Vec<u32> = (0..(MAX_WORDS + 1) as u32).collect();
        assert!(prove_channel_t8(&big).is_err(), "over MAX_WORDS");

        let words = vec![1u32];
        let (proof, log_size, digest) = prove_channel_t8(&words).unwrap();
        assert!(verify_channel_t8(&proof, MIN_LOG_SIZE - 1, &words, digest).is_err());
        assert!(verify_channel_t8(&proof, MAX_LOG_SIZE + 1, &words, digest).is_err());
        assert!(verify_channel_t8(&proof, log_size, &[], digest).is_err());
    }

    /// The whole point of the module: this must replay a REAL VFRI11 transcript
    /// step. `mix_root_full` absorbs a 32-byte root as eight BE u32 words, so
    /// proving that absorb is proving what the on-chain channel does.
    #[test]
    fn proves_a_real_mix_root_full_absorb() {
        let root = [0x5au8; 32];
        let words: Vec<u32> = (0..8)
            .map(|i| u32::from_be_bytes(root[4 * i..4 * i + 4].try_into().unwrap()))
            .collect();

        let (proof, log_size, digest) = prove_channel_t8(&words).expect("prove");
        assert!(verify_channel_t8(&proof, log_size, &words, digest).unwrap());

        // And the digest is the state the production channel reaches.
        let mut reference = ChannelT8State::init();
        reference.absorb_all(&words);
        assert_eq!(digest, reference.s);
    }
}
