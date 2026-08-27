//! Poseidon2 **t=8** Fiat-Shamir channel as a provable AIR — absorb AND draw.
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
//! Absorb and draw are the SAME operation on the state — add a value into cell 0
//! and permute — differing only in what is added and whether anything is read
//! out:
//!
//! ```text
//!     absorb(w):  s[0] += reduce(w);  permute_t8(s);  nDraws = 0
//!     draw():     read (s[0], s[1]);  s[0] += nDraws;  permute_t8(s);  nDraws += 1
//! ```
//!
//! So ONE AIR covers both: the trace is a chain of 22-round blocks with the full
//! 8-cell state carried across block boundaries, and a preprocessed column says
//! what each block adds. A second, near-identical AIR for draws is exactly the
//! duplication that lets two implementations drift. That is the same chaining
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
//! - **[C1 draw]** each drawn pair is pinned and forced to equal the CARRIED
//!   state's first two cells — the values the channel reads before mixing the
//!   counter in. An unpinned draw would let the prover claim any challenge it
//!   liked, which is the cherry-pick the recursion exists to prevent.
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

/// One transcript step.
///
/// Absorb and draw are the SAME operation on the state — add a value into cell 0
/// and permute — differing only in what is added and whether anything is read
/// out. Modelling them as one step keeps the AIR single: a second, near-identical
/// AIR for draws is exactly the duplication that lets two implementations drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Absorb a transcript word (`mixU32s` / `mixRoot*`).
    Absorb(u32),
    /// Draw one pair (`drawSecureFelt` is two of these; `drawQueries` repeats).
    Draw,
}

/// The channel state the AIR constrains, matching `P2T8Channel`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelT8State {
    pub s: [u64; 8],
    /// Squeeze counter. Reset to 0 by every absorb, exactly as on-chain — that
    /// reset is what stops two draws at the same state from colliding.
    pub n_draws: u32,
}

impl ChannelT8State {
    pub fn init() -> Self {
        ChannelT8State { s: [0u64; 8], n_draws: 0 }
    }

    /// Absorb one word: add into cell 0, permute, reset the draw counter.
    pub fn absorb(&mut self, word: u32) {
        self.s[0] = m31_add(self.s[0], reduce_u32(word));
        permute_t8(&mut self.s);
        self.n_draws = 0;
    }

    /// Draw one pair: read cells 0 and 1 BEFORE mixing the counter in.
    pub fn draw_pair(&mut self) -> (u32, u32) {
        let w0 = self.s[0] as u32;
        let w1 = self.s[1] as u32;
        self.s[0] = m31_add(self.s[0], self.n_draws as u64);
        permute_t8(&mut self.s);
        self.n_draws += 1;
        (w0, w1)
    }

    pub fn absorb_all(&mut self, words: &[u32]) {
        for &w in words {
            self.absorb(w);
        }
    }

    /// Run a transcript, returning the pairs each `Draw` produced.
    pub fn run(&mut self, steps: &[Step]) -> Vec<(u32, u32)> {
        let mut drawn = Vec::new();
        for &st in steps {
            match st {
                Step::Absorb(w) => self.absorb(w),
                Step::Draw => drawn.push(self.draw_pair()),
            }
        }
        drawn
    }
}

/// The value each step adds into cell 0, and the counter state it runs at.
///
/// This is what the preprocessed columns carry: the verifier knows the whole
/// transcript, so both the absorbed words and the draw counters are public.
pub fn step_addends(steps: &[Step]) -> Vec<u64> {
    let mut n_draws = 0u32;
    let mut out = Vec::with_capacity(steps.len());
    for &st in steps {
        match st {
            Step::Absorb(w) => {
                out.push(reduce_u32(w));
                n_draws = 0;
            }
            Step::Draw => {
                out.push(n_draws as u64);
                n_draws += 1;
            }
        }
    }
    out
}

/// The state after each step, starting from the initial state.
///
/// `states[0]` precedes every step; `states[i+1]` follows step `i`. The AIR's
/// row blocks interpolate between consecutive entries, so this is the skeleton
/// the trace is built around.
pub fn step_states(steps: &[Step]) -> Vec<[u64; 8]> {
    let mut st = ChannelT8State::init();
    let mut out = Vec::with_capacity(steps.len() + 1);
    out.push(st.s);
    for &sp in steps {
        match sp {
            Step::Absorb(w) => st.absorb(w),
            Step::Draw => { st.draw_pair(); }
        }
        out.push(st.s);
    }
    out
}

/// Rows the trace needs for `n_steps` steps.
pub fn n_rows(n_steps: usize) -> usize {
    n_steps * ROUNDS_PER_ABSORB
}

pub const MIN_LOG_SIZE: u32 = 5;   // ≥ 32 rows = one absorb (22 rounds)
pub const MAX_LOG_SIZE: u32 = 24;
/// Most steps one proof covers. A VFRI11 replay absorbs roughly a dozen roots
/// (8 words each) and draws a few dozen pairs, so this leaves ample room.
pub const MAX_STEPS: usize = 512;

/// Smallest `log_size` holding `n_steps` steps.
pub fn compute_log_size(n_steps: usize) -> u32 {
    let rows = n_rows(n_steps).max(1);
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
/// The value each step adds into cell 0: an absorbed word, or the draw counter.
pub fn pc_word() -> PreProcessedColumnId { PreProcessedColumnId { id: "cht8_word".into() } }
/// 1 on a DRAW block's first row; the pinned pair is read there.
pub fn pc_is_draw() -> PreProcessedColumnId { PreProcessedColumnId { id: "cht8_is_draw".into() } }
pub fn pc_drawn(k: usize) -> PreProcessedColumnId {
    PreProcessedColumnId { id: format!("cht8_drawn{k}") }
}
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
    ids.push(pc_is_draw());
    ids.push(pc_drawn(0));
    ids.push(pc_drawn(1));
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
        let is_draw = eval.get_preprocessed_column(pc_is_draw());
        let drawn: Vec<E::F> = (0..2).map(|k| eval.get_preprocessed_column(pc_drawn(k))).collect();
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

        // ── C1 draw binding: a drawn pair is the state BEFORE the counter is
        //    mixed in, so it reads off the CARRIED state, not this row's output.
        //    Pinning it is what makes the squeeze usable: an unpinned draw would
        //    let the prover claim any challenge it liked.
        for k in 0..2 {
            eval.add_constraint(is_draw.clone() * (prev[k].clone() - drawn[k].clone()));
        }

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

pub fn build_preproc(
    steps: &[Step],
    drawn: &[(u32, u32)],
    digest: [u64; T],
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
    let mut is_block_c = vec![bf0; n];
    let mut is_first_c = vec![bf0; n];
    let mut word_c = vec![bf0; n];
    let mut is_draw_c = vec![bf0; n];
    let mut drawn_cols: Vec<Vec<BaseField>> = (0..2).map(|_| vec![bf0; n]).collect();
    let mut is_last_c = vec![bf0; n];
    let mut digest_cols: Vec<Vec<BaseField>> = (0..T).map(|_| vec![bf0; n]).collect();

    let addends = step_addends(steps);
    let n_blocks = steps.len().min(n / N_ROUNDS);
    let mut draw_i = 0usize;
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
        // Pinned ALREADY REDUCED: for an absorb the reduced word, for a draw the
        // counter. The two conditional subtractions are not arithmetized — the
        // verifier supplies the reduced value, so the circuit proves the step it
        // committed to.
        word_c[first] = m31(addends[b]);
        if b == 0 { is_first_c[first] = one; }
        if matches!(steps[b], Step::Draw) {
            is_draw_c[first] = one;
            if let Some(&(w0, w1)) = drawn.get(draw_i) {
                drawn_cols[0][first] = m31(w0 as u64);
                drawn_cols[1][first] = m31(w1 as u64);
            }
            draw_i += 1;
        }
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
    all.push(is_draw_c);
    all.extend(drawn_cols);
    all.push(is_last_c);
    all.extend(digest_cols);
    for col in all.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    all.into_iter().map(|col| CircleEvaluation::new(domain, col)).collect()
}

fn canonical_preproc_root(
    steps: &[Step],
    drawn: &[(u32, u32)],
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
    tree.extend_evals(build_preproc(steps, drawn, digest, log_size));
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
pub fn build_trace(
    steps: &[Step],
    log_size: u32,
) -> (TraceColumns, [u64; T], Vec<(u32, u32)>) {
    let n = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];
    let n_blocks = steps.len().min(n / N_ROUNDS);

    // Drive the trace from the REFERENCE channel, so the trace cannot satisfy a
    // constraint the channel does not.
    let mut ch = ChannelT8State::init();
    let mut drawn: Vec<(u32, u32)> = Vec::new();

    for b in 0..n_blocks {
        let carried = ch.s;
        let addend = match steps[b] {
            Step::Absorb(w) => reduce_u32(w),
            Step::Draw => ch.n_draws as u64,
        };
        cols[C_WORD][b * N_ROUNDS] = m31(addend);

        // Advance the reference; a draw also records its pair.
        match steps[b] {
            Step::Absorb(w) => ch.absorb(w),
            Step::Draw => drawn.push(ch.draw_pair()),
        }

        // Replay the same permutation round by round into the trace.
        let mut state = carried;
        state[0] = m31_add(state[0], addend);
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
        debug_assert_eq!(state, ch.s, "trace block {b} diverged from the reference");
    }

    // Padding rows: selectors are 0, so `out` must be 0 and `in` chains from the
    // previous output. sq/sbox still have to satisfy their ungated constraints.
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
        ch.s,
        drawn,
    )
}

// ── Multiple independent transcripts in one trace ────────────────────────────
//
// A two-child aggregation node derives BOTH children's challenges, so one proof
// must carry two channel runs that each start from the zero state. The AIR
// already expresses that: `is_first_block` zeroes the carried state, so marking
// it at the start of EVERY transcript — rather than only at row 0 — gives
// independent runs laid out back to back. Same trick `merkle_path_t8_air` uses
// for multiple paths; the AIR itself is unchanged.

/// Blocks a list of transcripts occupies.
pub fn total_blocks(transcripts: &[Vec<Step>]) -> usize {
    transcripts.iter().map(|t| t.len()).sum()
}

/// Smallest `log_size` holding every transcript.
pub fn compute_log_size_multi(transcripts: &[Vec<Step>]) -> u32 {
    compute_log_size(total_blocks(transcripts))
}

/// Per-transcript results of a multi-run trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelRun {
    pub digest: [u64; T],
    pub drawn: Vec<(u32, u32)>,
}

/// Run several independent transcripts in one trace.
///
/// Each starts from the zero state; blocks are laid out in order.
pub fn build_trace_multi(
    transcripts: &[Vec<Step>],
    log_size: u32,
) -> (TraceColumns, Vec<ChannelRun>) {
    let (mut cols, runs) = build_trace_multi_raw(transcripts, log_size);
    let domain = CanonicCoset::new(log_size).circle_domain();
    for col in cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    (
        cols.into_iter().map(|col| CircleEvaluation::new(domain, col)).collect(),
        runs,
    )
}

/// The same trace, in natural row order and without the circle-domain wrapper.
///
/// A tree level feeds the node's columns to the NEXT level as its inner
/// statement, and that path wants raw values — the same split
/// `merkle_path_t8_air` and `recursive_verifier` already make.
pub fn build_trace_multi_raw(
    transcripts: &[Vec<Step>],
    log_size: u32,
) -> (Vec<Vec<BaseField>>, Vec<ChannelRun>) {
    let n = 1usize << log_size;
    let bf0 = BaseField::from_u32_unchecked(0);
    let m31 = |v: u64| BaseField::from_u32_unchecked((v % M31_P) as u32);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];
    let mut runs: Vec<ChannelRun> = Vec::with_capacity(transcripts.len());
    let mut block = 0usize;
    let cap = n / N_ROUNDS;

    for steps in transcripts {
        let mut ch = ChannelT8State::init();
        let mut drawn = Vec::new();
        for &sp in steps.iter() {
            if block >= cap {
                break;
            }
            let carried = ch.s;
            let addend = match sp {
                Step::Absorb(w) => reduce_u32(w),
                Step::Draw => ch.n_draws as u64,
            };
            cols[C_WORD][block * N_ROUNDS] = m31(addend);
            match sp {
                Step::Absorb(w) => ch.absorb(w),
                Step::Draw => drawn.push(ch.draw_pair()),
            }

            let mut state = carried;
            state[0] = m31_add(state[0], addend);
            mat_external_ref(&mut state);
            for r in 0..N_ROUNDS {
                let row = block * N_ROUNDS + r;
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
            debug_assert_eq!(state, ch.s, "multi-trace block {block} diverged");
            block += 1;
        }
        runs.push(ChannelRun { digest: ch.s, drawn });
    }

    for row in block * N_ROUNDS..n {
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

    (cols, runs)
}

/// Preprocessed columns for several independent transcripts.
pub fn build_preproc_multi(
    transcripts: &[Vec<Step>],
    runs: &[ChannelRun],
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
    let mut is_block_c = vec![bf0; n];
    let mut is_first_c = vec![bf0; n];
    let mut word_c = vec![bf0; n];
    let mut is_draw_c = vec![bf0; n];
    let mut drawn_cols: Vec<Vec<BaseField>> = (0..2).map(|_| vec![bf0; n]).collect();
    let mut is_last_c = vec![bf0; n];
    let mut digest_cols: Vec<Vec<BaseField>> = (0..T).map(|_| vec![bf0; n]).collect();

    let cap = n / N_ROUNDS;
    let mut block = 0usize;
    for (t, steps) in transcripts.iter().enumerate() {
        let addends = step_addends(steps);
        let mut draw_i = 0usize;
        let first_block_of_run = block;
        let mut placed = 0usize;
        for (b, sp) in steps.iter().enumerate() {
            if block >= cap {
                break;
            }
            for r in 0..N_ROUNDS {
                let row = block * N_ROUNDS + r;
                let (is_ext, rc) = round_schedule(r);
                for i in 0..T {
                    rc_cols[i][row] = m31(rc[i]);
                }
                if is_ext { is_ext_c[row] = one; } else { is_int_c[row] = one; }
            }
            let first = block * N_ROUNDS;
            is_block_c[first] = one;
            word_c[first] = m31(addends[b]);
            if block == first_block_of_run {
                is_first_c[first] = one;
            }
            if matches!(sp, Step::Draw) {
                is_draw_c[first] = one;
                if let Some(run) = runs.get(t) {
                    if let Some(&(w0, w1)) = run.drawn.get(draw_i) {
                        drawn_cols[0][first] = m31(w0 as u64);
                        drawn_cols[1][first] = m31(w1 as u64);
                    }
                }
                draw_i += 1;
            }
            block += 1;
            placed += 1;
        }
        // Each run pins its OWN digest on its own last row.
        if placed > 0 {
            if let Some(run) = runs.get(t) {
                let last = (block - 1) * N_ROUNDS + (N_ROUNDS - 1);
                is_last_c[last] = one;
                for k in 0..T {
                    digest_cols[k][last] = m31(run.digest[k]);
                }
            }
        }
    }

    let mut all = rc_cols;
    all.push(is_ext_c);
    all.push(is_int_c);
    all.push(is_block_c);
    all.push(is_first_c);
    all.push(word_c);
    all.push(is_draw_c);
    all.extend(drawn_cols);
    all.push(is_last_c);
    all.extend(digest_cols);
    for col in all.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    all.into_iter().map(|col| CircleEvaluation::new(domain, col)).collect()
}

// ── Prove / verify ───────────────────────────────────────────────────────────

fn mix_public(
    channel: &mut Blake2sM31Channel,
    steps: &[Step],
    drawn: &[(u32, u32)],
    digest: [u64; T],
) {
    let mut v: Vec<u32> = Vec::with_capacity(steps.len() * 2 + drawn.len() * 2 + T + 2);
    v.push(steps.len() as u32);
    for (st, add) in steps.iter().zip(step_addends(steps)) {
        v.push(match st { Step::Absorb(_) => 0, Step::Draw => 1 });
        v.push((add % M31_P) as u32);
    }
    v.push(drawn.len() as u32);
    for &(a, b) in drawn {
        v.push((a as u64 % M31_P) as u32);
        v.push((b as u64 % M31_P) as u32);
    }
    v.extend(digest.iter().map(|&d| (d % M31_P) as u32));
    channel.mix_u32s(&v);
}

/// Prove a transcript: absorbs and draws through a fresh t=8 channel.
///
/// Returns the proof, its `log_size`, the final digest, and the pairs the draws
/// produced — the challenges an intermediate tree level needs.
pub fn prove_channel_t8(steps: &[Step]) -> Result<(Vec<u8>, u32, [u64; T], Vec<(u32, u32)>), String> {
    if steps.is_empty() {
        return Err("need ≥ 1 step".into());
    }
    if steps.len() > MAX_STEPS {
        return Err(format!("step count {} exceeds MAX_STEPS {MAX_STEPS}", steps.len()));
    }
    let log_size = compute_log_size(steps.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("log_size {log_size} exceeds {MAX_LOG_SIZE}"));
    }
    let (main_cols, digest, drawn) = build_trace(steps, log_size);
    let preproc = build_preproc(steps, &drawn, digest, log_size);

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

    mix_public(channel, steps, &drawn, digest);

    let component = new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("t8 channel proving error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("t8 channel serialize error: {e:?}"))?;
    Ok((bytes, log_size, digest, drawn))
}

/// Verify a proof from [`prove_channel_t8`] against the claimed transcript.
pub fn verify_channel_t8(
    proof_bytes: &[u8],
    log_size: u32,
    steps: &[Step],
    drawn: &[(u32, u32)],
    digest: [u64; T],
) -> Result<bool, String> {
    if !(MIN_LOG_SIZE..=MAX_LOG_SIZE).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range [{MIN_LOG_SIZE}, {MAX_LOG_SIZE}]"));
    }
    if steps.is_empty() || steps.len() > MAX_STEPS {
        return Err(format!("step count {} out of range [1, {MAX_STEPS}]", steps.len()));
    }
    if drawn.len() != steps.iter().filter(|s| matches!(s, Step::Draw)).count() {
        return Err("drawn pairs do not match the number of Draw steps".into());
    }
    if n_rows(steps.len()) > (1usize << log_size) {
        return Err(format!("{} steps exceed trace capacity at log_size {log_size}", steps.len()));
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
    // C2: pin the preprocessed tree. Without it a prover could forge
    // `is_block_start ≡ 0`, running no steps while claiming a digest.
    if proof.commitments[0] != canonical_preproc_root(steps, drawn, digest, log_size) {
        return Ok(false);
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    mix_public(verifier_channel, steps, drawn, digest);

    let result = verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof);
    Ok(result.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absorbs(words: &[u32]) -> Vec<Step> {
        words.iter().map(|&w| Step::Absorb(w)).collect()
    }

    /// The reference must reproduce `P2T8Channel` exactly — both sides.
    ///
    /// This is the load-bearing test: everything downstream proves statements
    /// ABOUT this state chain, so a divergence here means attesting a transcript
    /// the chain never computed.
    #[test]
    fn reference_matches_the_production_channel() {
        for words in [
            vec![],
            vec![0u32],
            vec![1, 2, 3],
            vec![0xFFFF_FFFF],                       // 2P+1 — needs BOTH subtractions
            vec![M31_P as u32, M31_P as u32 + 1],
            (0..40u32).collect::<Vec<_>>(),
        ] {
            let mut mine = ChannelT8State::init();
            mine.absorb_all(&words);

            let mut theirs = [0u64; 8];
            for &w in &words {
                let mut r = w as u64;
                if r >= M31_P { r -= M31_P; }
                if r >= M31_P { r -= M31_P; }
                theirs[0] = m31_add(theirs[0], r);
                permute_t8(&mut theirs);
            }
            assert_eq!(mine.s, theirs, "absorb diverged on {words:?}");
        }

        // Draw side: read cells 0,1 BEFORE mixing the counter, then permute.
        let mut mine = ChannelT8State::init();
        mine.absorb_all(&[7, 9]);
        let got: Vec<(u32, u32)> = (0..3).map(|_| mine.draw_pair()).collect();

        let mut theirs = [0u64; 8];
        for &w in &[7u64, 9] {
            theirs[0] = m31_add(theirs[0], w);
            permute_t8(&mut theirs);
        }
        let mut n_draws = 0u64;
        let want: Vec<(u32, u32)> = (0..3).map(|_| {
            let pair = (theirs[0] as u32, theirs[1] as u32);
            theirs[0] = m31_add(theirs[0], n_draws);
            permute_t8(&mut theirs);
            n_draws += 1;
            pair
        }).collect();
        assert_eq!(got, want, "draw diverged");
        assert_eq!(mine.s, theirs);
    }

    #[test]
    fn an_absorb_resets_the_draw_counter() {
        // The reset is what stops two draws at the same state from colliding.
        let mut a = ChannelT8State::init();
        a.absorb(1);
        a.draw_pair();
        assert_eq!(a.n_draws, 1);
        a.absorb(2);
        assert_eq!(a.n_draws, 0, "an absorb must reset the counter");
    }

    #[test]
    fn reduce_handles_the_full_u32_range() {
        assert_eq!(reduce_u32(0), 0);
        assert_eq!(reduce_u32(M31_P as u32), 0);
        assert_eq!(reduce_u32(M31_P as u32 + 1), 1);
        assert_eq!(reduce_u32(u32::MAX), (u32::MAX as u64) - 2 * M31_P);
        for w in [0u32, 7, M31_P as u32 - 1, M31_P as u32, u32::MAX] {
            assert!(reduce_u32(w) < M31_P, "w={w} did not reduce");
        }
    }

    #[test]
    fn step_addends_track_the_counter() {
        let steps = vec![
            Step::Absorb(5), Step::Draw, Step::Draw, Step::Absorb(6), Step::Draw,
        ];
        // Absorbs contribute their reduced word; draws contribute the counter,
        // which the preceding absorb reset.
        assert_eq!(step_addends(&steps), vec![5, 0, 1, 6, 0]);
    }

    #[test]
    fn states_line_up_with_the_row_blocks() {
        let steps = vec![Step::Absorb(5), Step::Draw, Step::Absorb(13)];
        let states = step_states(&steps);
        assert_eq!(states.len(), steps.len() + 1);
        assert_eq!(states[0], [0u64; 8], "chain starts at the zero state");
        assert_eq!(n_rows(steps.len()), 3 * ROUNDS_PER_ABSORB);
    }

    #[test]
    fn log_size_covers_the_rows_and_meets_the_floor() {
        assert_eq!(compute_log_size(1), 5); // 22 rows → 32, the t=8 floor
        for n in [1usize, 2, 3, 8, 50] {
            assert!(1usize << compute_log_size(n) >= n_rows(n), "too small for {n}");
        }
    }

    // ── Prove / verify roundtrip ─────────────────────────────────────────────

    #[test]
    fn an_honest_transcript_proves_and_verifies() {
        for steps in [
            absorbs(&[7]),
            absorbs(&[1, 2, 3]),
            vec![Step::Absorb(11), Step::Draw, Step::Draw],
            vec![Step::Absorb(3), Step::Draw, Step::Absorb(5), Step::Draw],
        ] {
            let (proof, log_size, digest, drawn) = prove_channel_t8(&steps).expect("prove");

            let mut want = ChannelT8State::init();
            let want_drawn = want.run(&steps);
            assert_eq!(digest, want.s, "proved digest differs from the reference");
            assert_eq!(drawn, want_drawn, "proved draws differ from the reference");

            assert!(verify_channel_t8(&proof, log_size, &steps, &drawn, digest).unwrap(),
                    "honest proof must verify for {steps:?}");
        }
    }

    #[test]
    fn a_wrong_digest_is_rejected() {
        let steps = absorbs(&[3, 5, 8]);
        let (proof, log_size, digest, drawn) = prove_channel_t8(&steps).unwrap();
        let mut bad = digest;
        bad[0] = (bad[0] + 1) % M31_P;
        assert!(!verify_channel_t8(&proof, log_size, &steps, &drawn, bad).unwrap());
    }

    /// C1 input binding: the words are the inner proof's public roots, so a proof
    /// of one transcript must not verify against another.
    #[test]
    fn a_different_transcript_is_rejected() {
        let steps = absorbs(&[3, 5, 8]);
        let (proof, log_size, digest, drawn) = prove_channel_t8(&steps).unwrap();
        for other in [absorbs(&[3, 5, 9]), absorbs(&[5, 3, 8])] {
            assert!(!verify_channel_t8(&proof, log_size, &other, &drawn, digest).unwrap(),
                    "{other:?} must not verify against a proof of {steps:?}");
        }
    }

    /// C1 draw binding — the point of the squeeze side. An unpinned draw would
    /// let the prover claim any challenge it liked, which is exactly the
    /// cherry-pick the recursion exists to prevent.
    #[test]
    fn a_forged_drawn_pair_is_rejected() {
        let steps = vec![Step::Absorb(11), Step::Draw, Step::Draw];
        let (proof, log_size, digest, drawn) = prove_channel_t8(&steps).unwrap();
        assert_eq!(drawn.len(), 2);

        let mut bad = drawn.clone();
        bad[0].0 = bad[0].0.wrapping_add(1);
        assert!(!verify_channel_t8(&proof, log_size, &steps, &bad, digest).unwrap(),
                "a tampered challenge must not verify");

        let swapped = vec![drawn[1], drawn[0]];
        assert!(!verify_channel_t8(&proof, log_size, &steps, &swapped, digest).unwrap(),
                "reordered challenges must not verify");
    }

    /// C2: `is_block_start ≡ 0` runs no steps while claiming a digest, so it is
    /// the forgery that matters most; the pinned tree refuses it.
    #[test]
    fn a_forged_preproc_is_rejected() {
        let steps = absorbs(&[11, 13]);
        let (proof_bytes, log_size, digest, drawn) = prove_channel_t8(&steps).unwrap();
        let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
            bincode::serde::decode_from_slice(&proof_bytes, bincode::config::standard()).unwrap();

        assert_eq!(proof.commitments[0],
                   canonical_preproc_root(&steps, &drawn, digest, log_size));
        assert_ne!(proof.commitments[0],
                   canonical_preproc_root(&absorbs(&[11, 14]), &drawn, digest, log_size));
    }

    #[test]
    fn input_bounds_are_enforced() {
        assert!(prove_channel_t8(&[]).is_err(), "empty transcript");
        let big: Vec<Step> = (0..(MAX_STEPS + 1) as u32).map(Step::Absorb).collect();
        assert!(prove_channel_t8(&big).is_err(), "over MAX_STEPS");

        let steps = absorbs(&[1]);
        let (proof, log_size, digest, drawn) = prove_channel_t8(&steps).unwrap();
        assert!(verify_channel_t8(&proof, MIN_LOG_SIZE - 1, &steps, &drawn, digest).is_err());
        assert!(verify_channel_t8(&proof, MAX_LOG_SIZE + 1, &steps, &drawn, digest).is_err());
        assert!(verify_channel_t8(&proof, log_size, &[], &drawn, digest).is_err());
        // A drawn-pair count that disagrees with the Draw steps is a caller bug.
        assert!(verify_channel_t8(&proof, log_size, &steps, &[(1, 2)], digest).is_err());
    }

    /// The whole point: this replays a REAL VFRI11 transcript fragment.
    /// `mix_root_full` absorbs a 32-byte root as eight BE u32 words, and
    /// `drawSecureFelt` is two draws — so proving this is proving what the
    /// on-chain channel does.
    #[test]
    fn proves_a_real_mix_root_full_then_draw_secure_felt() {
        let root = [0x5au8; 32];
        let mut steps: Vec<Step> = (0..8)
            .map(|i| Step::Absorb(u32::from_be_bytes(root[4 * i..4 * i + 4].try_into().unwrap())))
            .collect();
        steps.push(Step::Draw);
        steps.push(Step::Draw);

        let (proof, log_size, digest, drawn) = prove_channel_t8(&steps).expect("prove");
        assert!(verify_channel_t8(&proof, log_size, &steps, &drawn, digest).unwrap());

        let mut reference = ChannelT8State::init();
        let want = reference.run(&steps);
        assert_eq!(digest, reference.s);
        assert_eq!(drawn, want, "the drawn challenges must be the channel's own");
    }

    // ── Multiple independent transcripts ─────────────────────────────────────

    #[test]
    fn multi_runs_are_independent_and_match_the_reference() {
        // Two DIFFERENT transcripts: aggregating two copies of one would prove
        // nothing about independence.
        let a = vec![Step::Absorb(11), Step::Draw, Step::Draw];
        let b = vec![Step::Absorb(11), Step::Absorb(29), Step::Draw];
        let transcripts = vec![a.clone(), b.clone()];

        let log_size = compute_log_size_multi(&transcripts);
        let (_cols, runs) = build_trace_multi(&transcripts, log_size);
        assert_eq!(runs.len(), 2);

        for (run, steps) in runs.iter().zip([&a, &b]) {
            let mut want = ChannelT8State::init();
            let drawn = want.run(steps);
            assert_eq!(run.digest, want.s, "digest for {steps:?}");
            assert_eq!(run.drawn, drawn, "draws for {steps:?}");
        }
        // The runs must not have leaked into one another: the second starts from
        // zero, not from the first's digest.
        assert_ne!(runs[0].digest, runs[1].digest);
    }

    #[test]
    fn a_multi_run_equals_the_single_run_it_contains() {
        let steps = vec![Step::Absorb(5), Step::Draw, Step::Absorb(9)];
        let log_size = compute_log_size_multi(std::slice::from_ref(&steps));
        let (_c, runs) = build_trace_multi(std::slice::from_ref(&steps), log_size);
        let (_c1, digest, drawn) = build_trace(&steps, log_size);
        assert_eq!(runs[0].digest, digest);
        assert_eq!(runs[0].drawn, drawn);
    }

    #[test]
    fn multi_preproc_pins_each_run_s_own_digest() {
        // A single shared digest column would let one run's digest stand for the
        // other's; each must be pinned on its own last row.
        let a = vec![Step::Absorb(3), Step::Draw];
        let b = vec![Step::Absorb(4), Step::Draw];
        let ts = vec![a, b];
        let log_size = compute_log_size_multi(&ts);
        let (_c, runs) = build_trace_multi(&ts, log_size);
        assert_ne!(runs[0].digest, runs[1].digest);

        let honest = build_preproc_multi(&ts, &runs, log_size);
        // Swapping the two runs' results changes the tree, so the pins are
        // per-run rather than shared.
        let swapped = vec![runs[1].clone(), runs[0].clone()];
        let other = build_preproc_multi(&ts, &swapped, log_size);
        let differs = honest.iter().zip(other.iter()).any(|(x, y)| x.values != y.values);
        assert!(differs, "swapping run results must change the preprocessed columns");
    }

    #[test]
    fn multi_sizing_accounts_for_every_transcript() {
        let ts = vec![
            vec![Step::Absorb(1); 3],
            vec![Step::Absorb(2); 5],
        ];
        assert_eq!(total_blocks(&ts), 8);
        assert!(1usize << compute_log_size_multi(&ts) >= n_rows(8));
    }
}
