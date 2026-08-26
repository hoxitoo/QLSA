//! An aggregation node: the Fiat-Shamir channel and a fold chain, in ONE proof.
//!
//! # What this is for
//!
//! Aggregating N signatures needs a tree, and a tree needs each level to justify
//! the challenges the level below ran under. Today those challenges are public
//! inputs, replayed **on-chain** (R3.10) — sound, cheap, and constant only while
//! there is one inner statement. Measured, a replay costs 1,052,669 gas against
//! 3,608,745 of headroom, so a single level holds about four signatures
//! (`contracts/test/ChannelReplayCostProbe.test.js`).
//!
//! The resolution is not to replay more on-chain but to move the derivation into
//! the circuit — and, importantly, into the PARENT's circuit rather than the
//! child's. Each node proves "the challenges my children ran under are the ones
//! their public roots produce", and passes its own challenges up as public inputs
//! for its own parent to justify. At the root the on-chain verifier replays once.
//! Constant on-chain work, whatever N is; the depth is absorbed by the circuit,
//! and depth was measured to be free — the recursion is a fixed point at 87
//! columns, log 14 (`probe_recursion_self_composition`).
//!
//! This module is one such derivation bound to one fold chain. A two-child node
//! is this twice.
//!
//! # How the binding works
//!
//! Stwo components cannot reference each other's columns, so the connection is
//! made the way `composition_t8` already makes it: both components' pinned values
//! come from ONE canonical preprocessed source, committed as a single Tree 0
//! whose root the verifier recomputes. A prover cannot run the fold chain under
//! challenges other than the transcript's, because both pins live in one tree and
//! the root is checked.
//!
//! # Where the transcript structure lives
//!
//! Deliberately not here. The caller supplies the step list and a
//! [`ChallengeLayout`] saying which draws yield which challenge, so this module
//! stays a generic "channel bound to a fold chain" and the VFRI11-specific
//! knowledge stays with `vfri11_transcript_steps`, next to the replay it must
//! agree with.

use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::TraceLocationAllocator;

use crate::poseidon2::M31_P;
use crate::recursive::channel_t8_air as channel;
use crate::recursive::qm31_mul_air::pack;
use crate::recursive::recursive_verifier as rv;
use crate::recursive::recursive_verifier::FoldRound;

/// One query's OODS + circle-fold step, as `composition_t8` names it.
pub type QueryStep = rv::StepOp;
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

/// Which draws in a transcript produce which challenge.
///
/// A QM31 felt is two consecutive draws, so each field is the index of the FIRST
/// of the pair. Keeping this explicit rather than hard-coding the VFRI11 order
/// leaves the transcript's shape in one place — beside the replay it mirrors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeLayout {
    /// First draw of the OODS point `z_x`.
    pub z_x_at: usize,
    /// First draw of each fold challenge: `friAlpha`, then one per fold round.
    pub alpha_at: Vec<usize>,
}

impl ChallengeLayout {
    /// Highest draw index this layout reads, for bounds checking.
    fn max_draw(&self) -> usize {
        let mut m = self.z_x_at + 1;
        for &a in &self.alpha_at {
            m = m.max(a + 1);
        }
        m
    }
}

/// Rebuild a QM31 felt from the pair at `i` and the pair at `i + 1`.
///
/// The limb order matches `qm31_mul_air::pack` and the channel's
/// `draw_secure_felt`, which is why the two agree without conversion.
fn felt_from(drawn: &[(u32, u32)], i: usize) -> u128 {
    pack([
        drawn[i].0 as u64,
        drawn[i].1 as u64,
        drawn[i + 1].0 as u64,
        drawn[i + 1].1 as u64,
    ])
}

/// The challenges a transcript produces, in the shape `recursive_verifier` wants.
#[derive(Clone, Debug)]
pub struct DerivedChallenges {
    pub z_x: u128,
    /// `friAlpha` followed by one alpha per fold round.
    pub alphas: Vec<u128>,
    pub drawn: Vec<(u32, u32)>,
    pub digest: [u64; 8],
}

/// Run the transcript and read the challenges out of it.
pub fn derive_challenges(
    steps: &[channel::Step],
    layout: &ChallengeLayout,
) -> Result<DerivedChallenges, String> {
    if steps.is_empty() {
        return Err("transcript must have ≥ 1 step".into());
    }
    if steps.len() > channel::MAX_STEPS {
        return Err(format!("transcript length {} exceeds MAX_STEPS {}", steps.len(), channel::MAX_STEPS));
    }
    let mut ch = channel::ChannelT8State::init();
    let drawn = ch.run(steps);
    // Every felt is two consecutive draws, so `max_draw` is the highest index
    // read and must be in range. A layout pointing past the draws is a caller
    // error worth naming, not something to meet as an index panic.
    if layout.max_draw() >= drawn.len() {
        return Err(format!(
            "layout reads draw {} but the transcript makes only {}",
            layout.max_draw(), drawn.len()));
    }
    Ok(DerivedChallenges {
        z_x: felt_from(&drawn, layout.z_x_at),
        alphas: layout.alpha_at.iter().map(|&i| felt_from(&drawn, i)).collect(),
        drawn,
        digest: ch.s,
    })
}

// ── Sizing ───────────────────────────────────────────────────────────────────

/// Both components share one `log_size`, as `composition_t8` does — the larger
/// of the two requirements.
pub fn node_log_size(n_steps: usize, num_folds: usize) -> u32 {
    channel::compute_log_size(n_steps).max(rv::compute_log_size(1 + num_folds))
}

fn combined_preproc_ids() -> Vec<PreProcessedColumnId> {
    let mut ids = rv::preprocessed_column_ids();
    ids.extend(channel::preprocessed_column_ids());
    ids
}

fn combined_preproc(
    final_fold: u128,
    challenges: &rv::QueryChallenges,
    num_folds: usize,
    steps: &[channel::Step],
    drawn: &[(u32, u32)],
    digest: [u64; 8],
    log_size: u32,
) -> Vec<
    stwo::prover::poly::circle::CircleEvaluation<
        CpuBackend,
        stwo::core::fields::m31::BaseField,
        stwo::prover::poly::BitReversedOrder,
    >,
> {
    let mut cols =
        rv::build_preproc(&[final_fold], std::slice::from_ref(challenges), num_folds, log_size);
    cols.extend(channel::build_preproc(steps, drawn, digest, log_size));
    cols
}

#[allow(clippy::too_many_arguments)]
fn canonical_node_preproc_root(
    final_fold: u128,
    challenges: &rv::QueryChallenges,
    num_folds: usize,
    steps: &[channel::Step],
    drawn: &[(u32, u32)],
    digest: [u64; 8],
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
    tree.extend_evals(combined_preproc(
        final_fold, challenges, num_folds, steps, drawn, digest, log_size));
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

fn mix_public(
    ch: &mut Blake2sM31Channel,
    px: u32,
    final_fold: u128,
    digest: [u64; 8],
    n_steps: usize,
) {
    let l = crate::recursive::qm31_mul_air::limbs(final_fold);
    let mut v = vec![px, n_steps as u32];
    v.extend(l.iter().map(|&x| x as u32));
    v.extend(digest.iter().map(|&d| (d % M31_P) as u32));
    ch.mix_u32s(&v);
}

// ── Prove / verify ───────────────────────────────────────────────────────────

pub struct ChannelBoundQueryResult {
    pub proof: Vec<u8>,
    pub log_size: u32,
    pub num_folds: usize,
    pub challenges: rv::QueryChallenges,
    pub final_fold: u128,
    pub digest: [u64; 8],
    pub drawn: Vec<(u32, u32)>,
}

/// Prove that a fold chain ran under the challenges its transcript produces.
///
/// Fails if the supplied `(step, rounds)` disagree with the transcript. That is a
/// caller error rather than an attack — but catching it here is the difference
/// between a proof that is merely self-consistent and one that is bound to a
/// transcript, and the whole point of the node is the latter.
pub fn prove_channel_bound_query(
    steps: &[channel::Step],
    layout: &ChallengeLayout,
    step: &QueryStep,
    rounds: &[FoldRound],
) -> Result<ChannelBoundQueryResult, String> {
    let num_folds = rounds.len();
    if num_folds > rv::MAX_NUM_FOLDS {
        return Err(format!("num_folds {num_folds} exceeds MAX_NUM_FOLDS {}", rv::MAX_NUM_FOLDS));
    }
    if layout.alpha_at.len() != 1 + num_folds {
        return Err(format!(
            "layout names {} alphas but the chain has {} rounds (expect 1 + rounds)",
            layout.alpha_at.len(), num_folds));
    }

    let derived = derive_challenges(steps, layout)?;
    let challenges = rv::query_challenges(step, rounds);

    // The binding, checked before it is proved: a mismatch here would produce a
    // proof about challenges nobody derived.
    if challenges.z_x != derived.z_x {
        return Err("z_x does not match the transcript's".into());
    }
    if challenges.alphas != derived.alphas {
        return Err("fold challenges do not match the transcript's".into());
    }

    let log_size = node_log_size(steps.len(), num_folds);
    if log_size > rv::MAX_LOG_SIZE.min(channel::MAX_LOG_SIZE) {
        return Err(format!("node log_size {log_size} too large"));
    }

    let final_fold = rv::recursive_query_final(step, rounds);
    let px = step.2;

    let (rv_main, rv_preproc) = rv::build_trace(step, rounds, log_size);
    let (chan_main, digest, drawn) = channel::build_trace(steps, log_size);
    debug_assert_eq!(digest, derived.digest);
    let chan_preproc = channel::build_preproc(steps, &drawn, digest, log_size);

    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let fs = &mut Blake2sM31Channel::default();
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    let mut preproc_cols = rv_preproc;
    preproc_cols.extend(chan_preproc);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(preproc_cols);
    tree.commit(fs);

    let mut main_cols = rv_main;
    main_cols.extend(chan_main);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(main_cols);
    tree.commit(fs);

    mix_public(fs, px, final_fold, digest, steps.len());

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&combined_preproc_ids());
    let rv_comp = rv::RecursiveVerifierComponent::new(
        &mut alloc,
        rv::RecursiveVerifierEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let chan_comp = channel::ChannelT8Component::new(
        &mut alloc,
        channel::ChannelT8Eval { log_n_rows: log_size },
        SecureField::from(0u32),
    );

    let proof =
        prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&rv_comp, &chan_comp], fs, scheme)
            .map_err(|e| format!("channel-bound node prove error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("channel-bound node serialize error: {e:?}"))?;

    Ok(ChannelBoundQueryResult {
        proof: bytes,
        log_size,
        num_folds,
        challenges,
        final_fold,
        digest,
        drawn,
    })
}

/// Verify a proof from [`prove_channel_bound_query`].
///
/// The verifier is given the TRANSCRIPT, not the challenges: it derives them
/// itself and rebuilds the pinned tree from the result. So a proof only verifies
/// against the transcript it was actually bound to.
#[allow(clippy::too_many_arguments)]
pub fn verify_channel_bound_query(
    proof_bytes: &[u8],
    log_size: u32,
    steps: &[channel::Step],
    layout: &ChallengeLayout,
    num_folds: usize,
    px: u32,
    final_fold: u128,
    comp_pos: u128,
    comp_neg: u128,
    invs: &[u32],
) -> Result<bool, String> {
    if num_folds > rv::MAX_NUM_FOLDS {
        return Err(format!("num_folds {num_folds} exceeds MAX_NUM_FOLDS {}", rv::MAX_NUM_FOLDS));
    }
    if invs.len() != 1 + num_folds {
        return Err(format!("expected {} twiddle inverses, got {}", 1 + num_folds, invs.len()));
    }
    if log_size != node_log_size(steps.len(), num_folds) {
        return Err(format!("log_size {log_size} is not the canonical size for this shape"));
    }

    let derived = derive_challenges(steps, layout)?;
    if derived.alphas.len() != 1 + num_folds {
        return Err("layout does not name one alpha per round plus friAlpha".into());
    }

    // Rebuilt from the TRANSCRIPT — the challenges are not taken on trust.
    let challenges = rv::QueryChallenges {
        px,
        z_x: derived.z_x,
        alphas: derived.alphas.clone(),
        invs: invs.to_vec(),
        comp_pos,
        comp_neg,
    };

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("channel-bound node deserialize error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&combined_preproc_ids());
    let rv_comp = rv::RecursiveVerifierComponent::new(
        &mut alloc,
        rv::RecursiveVerifierEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let chan_comp = channel::ChannelT8Component::new(
        &mut alloc,
        channel::ChannelT8Eval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let components: [&dyn Component; 2] = [&rv_comp, &chan_comp];

    let fs = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = rv_comp
        .trace_log_degree_bounds()
        .iter()
        .zip(chan_comp.trace_log_degree_bounds().iter())
        .map(|(a, b)| {
            let mut v = a.clone();
            v.extend(b.iter().copied());
            v
        })
        .collect::<Vec<_>>();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    // C2 — and the binding: the pinned tree carries BOTH the transcript and the
    // challenges, so a proof under different challenges has a different root.
    if proof.commitments[0]
        != canonical_node_preproc_root(
            final_fold, &challenges, num_folds, steps, &derived.drawn, derived.digest, log_size)
    {
        return Ok(false);
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], fs);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], fs);

    mix_public(fs, px, final_fold, derived.digest, steps.len());

    let result = verify::<Blake2sM31MerkleChannel>(&components, fs, commitment_scheme, proof);
    Ok(result.is_ok())
}

// ── The two-child (in general N-child) aggregation node ──────────────────────

/// One child of an aggregation node.
///
/// `steps`/`layout` are the child's transcript and where its challenges sit in
/// it; `step`/`rounds` are the fold chain the child ran. The node proves the
/// latter used exactly the challenges the former produces.
#[derive(Clone)]
pub struct Child {
    pub steps: Vec<channel::Step>,
    pub layout: ChallengeLayout,
    pub step: QueryStep,
    pub rounds: Vec<FoldRound>,
}

pub struct AggregationNodeResult {
    pub proof: Vec<u8>,
    pub log_size: u32,
    pub num_folds: usize,
    pub challenges: Vec<rv::QueryChallenges>,
    pub finals: Vec<u128>,
    pub runs: Vec<channel::ChannelRun>,
}

/// `log_size` a node of this shape uses. Both components share it, as elsewhere
/// in the composition family.
pub fn aggregation_node_log_size(children: &[Child]) -> u32 {
    let transcripts: Vec<Vec<channel::Step>> = children.iter().map(|c| c.steps.clone()).collect();
    let num_folds = children.first().map(|c| c.rounds.len()).unwrap_or(0);
    channel::compute_log_size_multi(&transcripts)
        .max(rv::compute_log_size(children.len() * (1 + num_folds)))
}

fn check_children(children: &[Child]) -> Result<(Vec<rv::QueryChallenges>, usize), String> {
    if children.is_empty() {
        return Err("a node needs ≥ 1 child".into());
    }
    let num_folds = children[0].rounds.len();
    if num_folds > rv::MAX_NUM_FOLDS {
        return Err(format!("num_folds {num_folds} exceeds MAX_NUM_FOLDS {}", rv::MAX_NUM_FOLDS));
    }
    let mut out = Vec::with_capacity(children.len());
    for (i, c) in children.iter().enumerate() {
        // `rv::build_preproc` takes ONE fold count for every query, so a node's
        // children must share a shape. In a tree they do; saying so here beats
        // a mismatch surfacing as a malformed trace.
        if c.rounds.len() != num_folds {
            return Err(format!(
                "child {i} has {} fold rounds, child 0 has {num_folds}", c.rounds.len()));
        }
        if c.layout.alpha_at.len() != 1 + num_folds {
            return Err(format!(
                "child {i}'s layout names {} alphas, expected {}",
                c.layout.alpha_at.len(), 1 + num_folds));
        }
        let derived = derive_challenges(&c.steps, &c.layout)?;
        let ch = rv::query_challenges(&c.step, &c.rounds);
        if ch.z_x != derived.z_x {
            return Err(format!("child {i}: z_x does not match its transcript's"));
        }
        if ch.alphas != derived.alphas {
            return Err(format!("child {i}: fold challenges do not match its transcript's"));
        }
        out.push(ch);
    }
    Ok((out, num_folds))
}

/// Prove an aggregation node: every child's fold chain ran under the challenges
/// its OWN transcript produces.
///
/// This is the tree's internal node. Two children is the binary case; the
/// function takes N because the shape is the same and a wider node is
/// occasionally useful at the bottom.
pub fn prove_aggregation_node(children: &[Child]) -> Result<AggregationNodeResult, String> {
    let (challenges, num_folds) = check_children(children)?;

    let log_size = aggregation_node_log_size(children);
    if log_size > rv::MAX_LOG_SIZE.min(channel::MAX_LOG_SIZE) {
        return Err(format!("node log_size {log_size} too large"));
    }

    let queries: Vec<(QueryStep, Vec<FoldRound>)> =
        children.iter().map(|c| (c.step, c.rounds.clone())).collect();
    let transcripts: Vec<Vec<channel::Step>> = children.iter().map(|c| c.steps.clone()).collect();

    let finals = rv::recursive_queries_final(&queries);
    let (rv_main, rv_preproc) = rv::build_trace_multi(&queries, log_size);
    let (chan_main, runs) = channel::build_trace_multi(&transcripts, log_size);
    let chan_preproc = channel::build_preproc_multi(&transcripts, &runs, log_size);

    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let fs = &mut Blake2sM31Channel::default();
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    let mut preproc_cols = rv_preproc;
    preproc_cols.extend(chan_preproc);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(preproc_cols);
    tree.commit(fs);

    let mut main_cols = rv_main;
    main_cols.extend(chan_main);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(main_cols);
    tree.commit(fs);

    mix_public_node(fs, children, &finals, &runs);

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&combined_preproc_ids());
    let rv_comp = rv::RecursiveVerifierComponent::new(
        &mut alloc,
        rv::RecursiveVerifierEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let chan_comp = channel::ChannelT8Component::new(
        &mut alloc,
        channel::ChannelT8Eval { log_n_rows: log_size },
        SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&rv_comp, &chan_comp], fs, scheme)
        .map_err(|e| format!("aggregation node prove error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("aggregation node serialize error: {e:?}"))?;

    Ok(AggregationNodeResult {
        proof: bytes,
        log_size,
        num_folds,
        challenges,
        finals,
        runs,
    })
}

fn mix_public_node(
    ch: &mut Blake2sM31Channel,
    children: &[Child],
    finals: &[u128],
    runs: &[channel::ChannelRun],
) {
    let mut v = vec![children.len() as u32];
    for c in children {
        v.push(c.step.2);
        v.push(c.steps.len() as u32);
    }
    for f in finals {
        v.extend(crate::recursive::qm31_mul_air::limbs(*f).iter().map(|&x| x as u32));
    }
    for r in runs {
        v.extend(r.digest.iter().map(|&d| (d % M31_P) as u32));
    }
    ch.mix_u32s(&v);
}

fn canonical_node_root(
    children: &[Child],
    challenges: &[rv::QueryChallenges],
    finals: &[u128],
    runs: &[channel::ChannelRun],
    num_folds: usize,
    log_size: u32,
) -> <Blake2sM31MerkleHasher as stwo::core::vcs_lifted::MerkleHasherLifted>::Hash {
    let transcripts: Vec<Vec<channel::Step>> = children.iter().map(|c| c.steps.clone()).collect();
    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();
    let mut throwaway = Blake2sM31Channel::default();
    let mut cols = rv::build_preproc(finals, challenges, num_folds, log_size);
    cols.extend(channel::build_preproc_multi(&transcripts, runs, log_size));
    let mut tree = scheme.tree_builder();
    tree.extend_evals(cols);
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

/// Verify an aggregation node.
///
/// The verifier is handed the CHILDREN — transcripts and fold-chain inputs — and
/// re-derives every challenge itself, so a proof only verifies against the
/// children it was actually built from.
pub fn verify_aggregation_node(
    proof_bytes: &[u8],
    log_size: u32,
    children: &[Child],
) -> Result<bool, String> {
    let (challenges, num_folds) = check_children(children)?;
    if log_size != aggregation_node_log_size(children) {
        return Err(format!("log_size {log_size} is not canonical for this node"));
    }

    let queries: Vec<(QueryStep, Vec<FoldRound>)> =
        children.iter().map(|c| (c.step, c.rounds.clone())).collect();
    let transcripts: Vec<Vec<channel::Step>> = children.iter().map(|c| c.steps.clone()).collect();
    let finals = rv::recursive_queries_final(&queries);
    let (_, runs) = channel::build_trace_multi(&transcripts, log_size);

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("aggregation node deserialize error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&combined_preproc_ids());
    let rv_comp = rv::RecursiveVerifierComponent::new(
        &mut alloc,
        rv::RecursiveVerifierEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let chan_comp = channel::ChannelT8Component::new(
        &mut alloc,
        channel::ChannelT8Eval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let components: [&dyn Component; 2] = [&rv_comp, &chan_comp];

    let fs = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = rv_comp
        .trace_log_degree_bounds()
        .iter()
        .zip(chan_comp.trace_log_degree_bounds().iter())
        .map(|(a, b)| {
            let mut v = a.clone();
            v.extend(b.iter().copied());
            v
        })
        .collect::<Vec<_>>();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    if proof.commitments[0]
        != canonical_node_root(children, &challenges, &finals, &runs, num_folds, log_size)
    {
        return Ok(false);
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], fs);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], fs);

    mix_public_node(fs, children, &finals, &runs);

    let result = verify::<Blake2sM31MerkleChannel>(&components, fs, commitment_scheme, proof);
    Ok(result.is_ok())
}

// ── The complete tree node: channel + fold chain + Merkle membership ─────────
//
// `prove_aggregation_node` above proves the channel binding alone, which is the
// unit worth testing in isolation but NOT a tree node: it does not tie a child's
// fold-chain output to the FRI layer that child committed to. A node that
// omitted that would let a prover fold to whatever it liked and still be
// "bound to the transcript".
//
// The complete node is three components over one Tree 0 — the two of
// `composition_t8` plus the channel — so a child is: its transcript, its fold
// chain, and the membership paths that anchor both ends.

use crate::recursive::composition_t8::{path_depths, CompMembership};
use crate::recursive::integration::qm31_leaf_hash_t8;
use crate::recursive::merkle_path_t8_air as merkle;

/// One child STATEMENT of a tree node.
///
/// A child is a whole inner proof, not one of its queries. Its transcript is a
/// property of the proof — `z_x` and the fold challenges are drawn once and every
/// query runs under them — so grouping this way runs each transcript ONCE.
///
/// The first shape I wrote here was per-query, and it was both wasteful and
/// wrong-headed: at the production 20 queries a transcript would have been
/// replayed twenty times, taking the node's trace from log 14 to log 17 to prove
/// the same thing repeatedly.
#[derive(Clone)]
pub struct TreeStatement {
    /// The child proof's transcript and where its challenges sit in it.
    pub steps: Vec<channel::Step>,
    pub layout: ChallengeLayout,
    /// The child's FRI queries, all running under the transcript's challenges.
    pub queries: Vec<(QueryStep, Vec<FoldRound>)>,
    /// Per query: the final fold's path into the child's committed last FRI layer.
    pub paths: Vec<(Vec<[u64; 4]>, Vec<bool>)>,
    /// Per query: the two composition-value paths into the child's compRoot.
    pub comp_paths: Vec<CompMembership>,
}

pub struct TreeNodeResult {
    pub proof: Vec<u8>,
    pub log_size: u32,
    pub num_folds: usize,
    pub depth: usize,
    pub comp_depth: usize,
    /// Flattened across statements, in statement order.
    pub challenges: Vec<rv::QueryChallenges>,
    pub finals: Vec<u128>,
    /// One per statement.
    pub runs: Vec<channel::ChannelRun>,
    /// Per-path roots, in `path_depths` order: Q final-fold, Q comp, Q compNeg,
    /// where Q is the TOTAL query count across statements.
    pub roots: Vec<[u64; 4]>,
}

/// Everything a tree node's inputs are derived from, gathered once so prove and
/// verify cannot disagree about the ordering.
struct NodeShape {
    num_folds: usize,
    depth: usize,
    comp_depth: usize,
    log_size: u32,
    challenges: Vec<rv::QueryChallenges>,
    finals: Vec<u128>,
    leaves: Vec<[u64; 4]>,
    sibs: Vec<Vec<[u64; 4]>>,
    bits: Vec<Vec<bool>>,
    indices: Vec<u32>,
    depths: Vec<usize>,
    transcripts: Vec<Vec<channel::Step>>,
    queries: Vec<(QueryStep, Vec<FoldRound>)>,
    /// Queries per statement, so `mix_public` can describe the grouping.
    counts: Vec<usize>,
}

fn node_shape(statements: &[TreeStatement]) -> Result<NodeShape, String> {
    if statements.is_empty() {
        return Err("a node needs ≥ 1 child statement".into());
    }
    if statements[0].queries.is_empty() {
        return Err("a statement needs ≥ 1 query".into());
    }
    let num_folds = statements[0].queries[0].1.len();
    if num_folds > rv::MAX_NUM_FOLDS {
        return Err(format!("num_folds {num_folds} exceeds MAX_NUM_FOLDS {}", rv::MAX_NUM_FOLDS));
    }
    let depth = statements[0].paths[0].0.len();
    let comp_depth = statements[0].comp_paths[0].0.len();
    if depth == 0 || comp_depth == 0 {
        return Err("both path depths must be ≥ 1".into());
    }
    if depth > merkle::MAX_DEPTH || comp_depth > merkle::MAX_DEPTH {
        return Err(format!("a path depth exceeds MAX_DEPTH {}", merkle::MAX_DEPTH));
    }

    let mut challenges = Vec::new();
    let mut queries: Vec<(QueryStep, Vec<FoldRound>)> = Vec::new();
    let mut transcripts: Vec<Vec<channel::Step>> = Vec::new();
    let mut counts = Vec::with_capacity(statements.len());

    for (i, st) in statements.iter().enumerate() {
        if st.queries.is_empty() {
            return Err(format!("statement {i} has no queries"));
        }
        if st.paths.len() != st.queries.len() || st.comp_paths.len() != st.queries.len() {
            return Err(format!("statement {i}: paths/comp_paths do not match its query count"));
        }
        if st.layout.alpha_at.len() != 1 + num_folds {
            return Err(format!(
                "statement {i}'s layout names {} alphas, expected {}",
                st.layout.alpha_at.len(), 1 + num_folds));
        }

        // One transcript per STATEMENT: `z_x` and the fold challenges are drawn
        // once for the whole proof, so every query must run under them. A query
        // that does not is the cherry-pick this node exists to prevent.
        let derived = derive_challenges(&st.steps, &st.layout)?;
        for (q, (step, rounds)) in st.queries.iter().enumerate() {
            if rounds.len() != num_folds {
                return Err(format!(
                    "statement {i} query {q} has {} fold rounds, expected {num_folds}",
                    rounds.len()));
            }
            if st.paths[q].0.len() != depth || st.paths[q].1.len() != depth {
                return Err(format!("statement {i} query {q}: final-fold path is not depth {depth}"));
            }
            let (ps, pb, ns, nb) = &st.comp_paths[q];
            if ps.len() != comp_depth || pb.len() != comp_depth
                || ns.len() != comp_depth || nb.len() != comp_depth
            {
                return Err(format!(
                    "statement {i} query {q}: composition paths are not depth {comp_depth}"));
            }
            let ch = rv::query_challenges(step, rounds);
            if ch.z_x != derived.z_x {
                return Err(format!("statement {i} query {q}: z_x does not match its transcript's"));
            }
            if ch.alphas != derived.alphas {
                return Err(format!(
                    "statement {i} query {q}: fold challenges do not match its transcript's"));
            }
            challenges.push(ch);
            queries.push((*step, rounds.clone()));
        }
        counts.push(st.queries.len());
        transcripts.push(st.steps.clone());
    }

    if queries.len() > rv::MAX_QUERIES {
        return Err(format!(
            "total query count {} exceeds MAX_QUERIES {}", queries.len(), rv::MAX_QUERIES));
    }

    let finals = rv::recursive_queries_final(&queries);

    // Path order is `composition_t8`'s, reused rather than restated: Q
    // final-fold, then Q compValue, then Q compValueNeg.
    let mut leaves: Vec<[u64; 4]> = finals.iter().map(|&f| qm31_leaf_hash_t8(f)).collect();
    leaves.extend(challenges.iter().map(|c| qm31_leaf_hash_t8(c.comp_pos)));
    leaves.extend(challenges.iter().map(|c| qm31_leaf_hash_t8(c.comp_neg)));

    let mut sibs: Vec<Vec<[u64; 4]>> = Vec::new();
    let mut bits: Vec<Vec<bool>> = Vec::new();
    for st in statements {
        sibs.extend(st.paths.iter().map(|(s, _)| s.clone()));
        bits.extend(st.paths.iter().map(|(_, b)| b.clone()));
    }
    for st in statements {
        sibs.extend(st.comp_paths.iter().map(|(ps, _, _, _)| ps.clone()));
        bits.extend(st.comp_paths.iter().map(|(_, pb, _, _)| pb.clone()));
    }
    for st in statements {
        sibs.extend(st.comp_paths.iter().map(|(_, _, ns, _)| ns.clone()));
        bits.extend(st.comp_paths.iter().map(|(_, _, _, nb)| nb.clone()));
    }

    let indices: Vec<u32> = bits.iter().map(|b| merkle::bits_to_index(b)).collect();
    let depths = path_depths(queries.len(), depth, comp_depth);

    let log_size = channel::compute_log_size_multi(&transcripts)
        .max(rv::compute_log_size(queries.len() * (1 + num_folds)))
        .max(merkle::compute_log_size_multi_var(&depths));

    Ok(NodeShape {
        num_folds, depth, comp_depth, log_size,
        challenges, finals, leaves, sibs, bits, indices, depths,
        transcripts, queries, counts,
    })
}

/// `log_size` a tree node of this shape uses.
pub fn tree_node_log_size(statements: &[TreeStatement]) -> Result<u32, String> {
    Ok(node_shape(statements)?.log_size)
}

fn mix_public_tree(
    ch: &mut Blake2sM31Channel,
    sh: &NodeShape,
    runs: &[channel::ChannelRun],
    roots: &[[u64; 4]],
) {
    let w = |v: u64| (v % M31_P) as u32;
    let mut v = vec![sh.queries.len() as u32, sh.depth as u32, sh.comp_depth as u32];
    // The GROUPING is public too: the same queries split differently across
    // statements would be a different claim.
    v.push(sh.counts.len() as u32);
    for (c, t) in sh.counts.iter().zip(sh.transcripts.iter()) {
        v.push(*c as u32);
        v.push(t.len() as u32);
    }
    for (s, _) in sh.queries.iter() {
        v.push(s.2);
    }
    for f in &sh.finals {
        v.extend(crate::recursive::qm31_mul_air::limbs(*f).iter().map(|&x| x as u32));
    }
    for l in &sh.leaves {
        v.extend(l.iter().map(|&x| w(x)));
    }
    v.extend(sh.indices.iter().copied());
    for r in roots {
        v.extend(r.iter().map(|&x| w(x)));
    }
    for r in runs {
        v.extend(r.digest.iter().map(|&d| w(d)));
    }
    ch.mix_u32s(&v);
}

fn tree_preproc_ids() -> Vec<PreProcessedColumnId> {
    let mut ids = rv::preprocessed_column_ids();
    ids.extend(merkle::preprocessed_column_ids());
    ids.extend(channel::preprocessed_column_ids());
    ids
}

fn canonical_tree_root(
    sh: &NodeShape,
    runs: &[channel::ChannelRun],
    roots: &[[u64; 4]],
) -> <Blake2sM31MerkleHasher as stwo::core::vcs_lifted::MerkleHasherLifted>::Hash {
    let config = make_config(sh.log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(sh.log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();
    let mut throwaway = Blake2sM31Channel::default();
    let mut cols = rv::build_preproc(&sh.finals, &sh.challenges, sh.num_folds, sh.log_size);
    cols.extend(merkle::build_preproc_multi_var(
        &sh.leaves, &sh.indices, roots, &sh.depths, sh.log_size));
    cols.extend(channel::build_preproc_multi(&sh.transcripts, runs, sh.log_size));
    let mut tree = scheme.tree_builder();
    tree.extend_evals(cols);
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

fn tree_components(
    log_size: u32,
) -> (rv::RecursiveVerifierComponent, merkle::MerklePathT8Component, channel::ChannelT8Component) {
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&tree_preproc_ids());
    let rv_comp = rv::RecursiveVerifierComponent::new(
        &mut alloc,
        rv::RecursiveVerifierEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let merkle_comp = merkle::MerklePathT8Component::new(
        &mut alloc,
        merkle::MerklePathT8Eval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let chan_comp = channel::ChannelT8Component::new(
        &mut alloc,
        channel::ChannelT8Eval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    (rv_comp, merkle_comp, chan_comp)
}

/// Prove a complete tree node.
///
/// For each child: its fold chain ran under the challenges its own transcript
/// produces (the channel component), its final fold is a member of the FRI layer
/// it committed to, and its composition values are members of its compRoot (the
/// Merkle component). Value-bound end to end, in one proof.
pub fn prove_tree_node(statements: &[TreeStatement]) -> Result<TreeNodeResult, String> {
    let sh = node_shape(statements)?;
    if sh.log_size > rv::MAX_LOG_SIZE.min(merkle::MAX_LOG_SIZE).min(channel::MAX_LOG_SIZE) {
        return Err(format!("tree node log_size {} too large", sh.log_size));
    }

    let (rv_main, rv_preproc) = rv::build_trace_multi(&sh.queries, sh.log_size);
    let (merkle_main, roots) =
        merkle::build_trace_multi(&sh.leaves, &sh.sibs, &sh.bits, sh.log_size);
    let merkle_preproc = merkle::build_preproc_multi_var(
        &sh.leaves, &sh.indices, &roots, &sh.depths, sh.log_size);
    let (chan_main, runs) = channel::build_trace_multi(&sh.transcripts, sh.log_size);
    let chan_preproc = channel::build_preproc_multi(&sh.transcripts, &runs, sh.log_size);

    let config = make_config(sh.log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(sh.log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let fs = &mut Blake2sM31Channel::default();
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    let mut preproc = rv_preproc;
    preproc.extend(merkle_preproc);
    preproc.extend(chan_preproc);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(preproc);
    tree.commit(fs);

    let mut main = rv_main;
    main.extend(merkle_main);
    main.extend(chan_main);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(main);
    tree.commit(fs);

    mix_public_tree(fs, &sh, &runs, &roots);

    let (rv_comp, merkle_comp, chan_comp) = tree_components(sh.log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&rv_comp, &merkle_comp, &chan_comp], fs, scheme)
        .map_err(|e| format!("tree node prove error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("tree node serialize error: {e:?}"))?;

    Ok(TreeNodeResult {
        proof: bytes,
        log_size: sh.log_size,
        num_folds: sh.num_folds,
        depth: sh.depth,
        comp_depth: sh.comp_depth,
        challenges: sh.challenges,
        finals: sh.finals,
        runs,
        roots,
    })
}

/// Verify a tree node against the children it claims.
///
/// The verifier re-derives every challenge and re-hashes every leaf, so a proof
/// verifies only against the children it was built from.
pub fn verify_tree_node(
    proof_bytes: &[u8],
    log_size: u32,
    statements: &[TreeStatement],
    roots: &[[u64; 4]],
) -> Result<bool, String> {
    let sh = node_shape(statements)?;
    if log_size != sh.log_size {
        return Err(format!("log_size {log_size} is not canonical for this node"));
    }
    if roots.len() != sh.depths.len() {
        return Err(format!("expected {} roots, got {}", sh.depths.len(), roots.len()));
    }
    let (_, runs) = channel::build_trace_multi(&sh.transcripts, sh.log_size);

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("tree node deserialize error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let (rv_comp, merkle_comp, chan_comp) = tree_components(log_size);
    let components: [&dyn Component; 3] = [&rv_comp, &merkle_comp, &chan_comp];

    let fs = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let mut sizes: Vec<Vec<u32>> = rv_comp.trace_log_degree_bounds().to_vec();
    for (i, b) in merkle_comp.trace_log_degree_bounds().iter().enumerate() {
        sizes[i].extend(b.iter().copied());
    }
    for (i, b) in chan_comp.trace_log_degree_bounds().iter().enumerate() {
        sizes[i].extend(b.iter().copied());
    }
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    if proof.commitments[0] != canonical_tree_root(&sh, &runs, roots) {
        return Ok(false);
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], fs);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], fs);

    mix_public_tree(fs, &sh, &runs, roots);

    let result = verify::<Blake2sM31MerkleChannel>(&components, fs, commitment_scheme, proof);
    Ok(result.is_ok())
}

/// The node's own trace columns — what the NEXT tree level takes as its inner
/// statement.
///
/// A tree is levels of these: a node's trace becomes the statement its parent
/// verifies. Whether that terminates is a question about whether the shape
/// reaches a fixed point, which is measured rather than assumed
/// (`probe_tree_node_self_composition`).
pub fn tree_node_trace_columns(
    statements: &[TreeStatement],
) -> Result<(Vec<Vec<u32>>, u32), String> {
    let sh = node_shape(statements)?;
    if sh.log_size > rv::MAX_LOG_SIZE.min(merkle::MAX_LOG_SIZE).min(channel::MAX_LOG_SIZE) {
        return Err(format!("tree node log_size {} too large", sh.log_size));
    }

    let rv_cols = rv::build_trace_multi_raw(&sh.queries, sh.log_size);
    let (merkle_cols, _roots) =
        merkle::build_trace_multi_raw(&sh.leaves, &sh.sibs, &sh.bits, sh.log_size);
    let (chan_cols, _runs) = channel::build_trace_multi_raw(&sh.transcripts, sh.log_size);

    let mut cols: Vec<Vec<u32>> =
        Vec::with_capacity(rv_cols.len() + merkle_cols.len() + chan_cols.len());
    for c in rv_cols
        .into_iter()
        .chain(merkle_cols.into_iter())
        .chain(chan_cols.into_iter())
    {
        cols.push(c.into_iter().map(|v| v.0).collect());
    }
    Ok((cols, sh.log_size))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursive::channel_t8_air::Step;

    const M31: u64 = M31_P;

    fn rand_m31(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) % M31
    }
    fn rand_qm31(seed: &mut u64) -> u128 {
        (rand_m31(seed) as u128) << 96
            | (rand_m31(seed) as u128) << 64
            | (rand_m31(seed) as u128) << 32
            | rand_m31(seed) as u128
    }

    /// A transcript with enough draws for `1 + num_folds` alphas plus `z_x`,
    /// laid out the way VFRI11 lays its out: z_x first, then the alphas.
    fn transcript(num_folds: usize, salt: u32) -> (Vec<Step>, ChallengeLayout) {
        let n_felts = 1 + 1 + num_folds; // z_x, friAlpha, one per round
        let mut steps = vec![Step::Absorb(salt), Step::Absorb(salt ^ 0x5a5a)];
        for _ in 0..n_felts {
            steps.push(Step::Draw);
            steps.push(Step::Draw);
        }
        // A trailing absorb, so the transcript does not end on a draw — the real
        // one does not either, and the padding path differs.
        steps.push(Step::Absorb(7));
        let layout = ChallengeLayout {
            z_x_at: 0,
            alpha_at: (0..1 + num_folds).map(|i| 2 + 2 * i).collect(),
        };
        (steps, layout)
    }

    /// A query whose challenges ARE the transcript's. Everything else is
    /// arbitrary: the point of the node is the challenge binding, not the values
    /// the fold chain happens to run on.
    fn query_under(
        derived: &DerivedChallenges,
        num_folds: usize,
        seed: &mut u64,
    ) -> (QueryStep, Vec<FoldRound>) {
        let step: QueryStep = (
            rand_qm31(seed),
            rand_qm31(seed),
            rand_m31(seed) as u32,
            derived.z_x,
            rand_qm31(seed),
            rand_qm31(seed),
            derived.alphas[0],
            rand_m31(seed) as u32,
        );
        let rounds: Vec<FoldRound> = (0..num_folds)
            .map(|k| (rand_qm31(seed), derived.alphas[k + 1], rand_m31(seed) as u32))
            .collect();
        (step, rounds)
    }

    #[test]
    fn derived_challenges_are_the_transcript_s_own() {
        let (steps, layout) = transcript(3, 0x11);
        let d = derive_challenges(&steps, &layout).unwrap();

        let mut ch = channel::ChannelT8State::init();
        let drawn = ch.run(&steps);
        assert_eq!(d.drawn, drawn);
        assert_eq!(d.digest, ch.s);
        assert_eq!(d.alphas.len(), 4);
        assert_eq!(d.z_x, felt_from(&drawn, 0));
        // Distinct draws must give distinct challenges, or the layout is aliasing.
        let mut all = vec![d.z_x];
        all.extend(d.alphas.iter().copied());
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j], "challenges {i} and {j} collided");
            }
        }
    }

    #[test]
    fn a_layout_past_the_end_is_named_not_panicked() {
        let (steps, _) = transcript(2, 0x22);
        let bad = ChallengeLayout { z_x_at: 0, alpha_at: vec![2, 4, 999] };
        let err = derive_challenges(&steps, &bad).unwrap_err();
        // A felt at 999 reads draws 999 AND 1000, so 1000 is the index out of
        // range and the one worth naming.
        assert!(err.contains("1000"), "the error should name the index read: {err}");
    }

    /// The node: a fold chain proved under challenges the transcript produced.
    #[test]
    fn an_honest_node_proves_and_verifies() {
        let num_folds = 3;
        let (steps, layout) = transcript(num_folds, 0x33);
        let derived = derive_challenges(&steps, &layout).unwrap();
        let mut s = 0xA66_u64;
        let (step, rounds) = query_under(&derived, num_folds, &mut s);

        let r = match prove_channel_bound_query(&steps, &layout, &step, &rounds) {
            Ok(r) => r,
            Err(e) => panic!("prove failed: {e}"),
        };
        assert_eq!(r.final_fold, rv::recursive_query_final(&step, &rounds));
        assert_eq!(r.challenges.z_x, derived.z_x);
        assert_eq!(r.challenges.alphas, derived.alphas);

        assert!(
            verify_channel_bound_query(
                &r.proof, r.log_size, &steps, &layout, num_folds,
                step.2, r.final_fold, r.challenges.comp_pos, r.challenges.comp_neg,
                &r.challenges.invs,
            ).unwrap(),
            "an honest node must verify");
    }

    /// THE binding. A fold chain run under a challenge the transcript did not
    /// produce must not be provable — otherwise the channel component would be
    /// decoration and the prover could still cherry-pick.
    #[test]
    fn a_chain_under_a_foreign_challenge_cannot_be_proved() {
        let num_folds = 2;
        let (steps, layout) = transcript(num_folds, 0x44);
        let derived = derive_challenges(&steps, &layout).unwrap();
        let mut s = 0xB77_u64;

        // Wrong fold alpha.
        let (step, mut rounds) = query_under(&derived, num_folds, &mut s);
        rounds[0].1 ^= 1;
        let err = match prove_channel_bound_query(&steps, &layout, &step, &rounds) {
            Ok(_) => panic!("a foreign fold challenge must not be provable"),
            Err(e) => e,
        };
        assert!(err.contains("fold challenges"), "unexpected error: {err}");

        // Wrong OODS point.
        let (mut step2, rounds2) = query_under(&derived, num_folds, &mut s);
        step2.3 ^= 1;
        let err = match prove_channel_bound_query(&steps, &layout, &step2, &rounds2) {
            Ok(_) => panic!("a foreign OODS point must not be provable"),
            Err(e) => e,
        };
        assert!(err.contains("z_x"), "unexpected error: {err}");
    }

    /// A proof is bound to ONE transcript: the verifier derives the challenges
    /// from the transcript it is given, so a different one rebuilds a different
    /// pinned tree.
    #[test]
    fn a_proof_does_not_verify_against_another_transcript() {
        let num_folds = 2;
        let (steps, layout) = transcript(num_folds, 0x55);
        let derived = derive_challenges(&steps, &layout).unwrap();
        let mut s = 0xC88_u64;
        let (step, rounds) = query_under(&derived, num_folds, &mut s);
        let r = match prove_channel_bound_query(&steps, &layout, &step, &rounds) {
            Ok(r) => r, Err(e) => panic!("prove failed: {e}"),
        };

        let (other, _) = transcript(num_folds, 0x56); // one absorbed word differs
        assert!(
            !verify_channel_bound_query(
                &r.proof, r.log_size, &other, &layout, num_folds,
                step.2, r.final_fold, r.challenges.comp_pos, r.challenges.comp_neg,
                &r.challenges.invs,
            ).unwrap(),
            "a different transcript must not verify");
    }

    #[test]
    fn input_shapes_are_checked() {
        let num_folds = 2;
        let (steps, layout) = transcript(num_folds, 0x66);
        let derived = derive_challenges(&steps, &layout).unwrap();
        let mut s = 0xD99_u64;
        let (step, rounds) = query_under(&derived, num_folds, &mut s);

        // A layout naming the wrong number of alphas is a mismatch with the chain.
        let short = ChallengeLayout { z_x_at: 0, alpha_at: vec![2] };
        assert!(prove_channel_bound_query(&steps, &short, &step, &rounds).is_err(),
                "a layout naming the wrong alpha count must be refused");

        let r = match prove_channel_bound_query(&steps, &layout, &step, &rounds) {
            Ok(r) => r, Err(e) => panic!("prove failed: {e}"),
        };
        // A non-canonical log_size is refused rather than silently accepted.
        assert!(verify_channel_bound_query(
            &r.proof, r.log_size + 1, &steps, &layout, num_folds,
            step.2, r.final_fold, r.challenges.comp_pos, r.challenges.comp_neg,
            &r.challenges.invs).is_err());
        // As is a twiddle list that does not match the round count.
        assert!(verify_channel_bound_query(
            &r.proof, r.log_size, &steps, &layout, num_folds,
            step.2, r.final_fold, r.challenges.comp_pos, r.challenges.comp_neg,
            &r.challenges.invs[..1]).is_err());
    }

    // ── The aggregation node ─────────────────────────────────────────────────

    fn child(num_folds: usize, salt: u32, seed: &mut u64) -> Child {
        let (steps, layout) = transcript(num_folds, salt);
        let derived = derive_challenges(&steps, &layout).unwrap();
        let (step, rounds) = query_under(&derived, num_folds, seed);
        Child { steps, layout, step, rounds }
    }

    /// The tree's internal node: two children, each bound to its OWN transcript.
    #[test]
    fn a_two_child_node_proves_and_verifies() {
        let num_folds = 2;
        let mut s = 0xE11_u64;
        // Different salts, so genuinely different transcripts — two copies of one
        // child would prove nothing about handling two.
        let children = vec![child(num_folds, 0x71, &mut s), child(num_folds, 0x72, &mut s)];
        assert_ne!(children[0].steps, children[1].steps);

        let r = match prove_aggregation_node(&children) {
            Ok(r) => r,
            Err(e) => panic!("prove failed: {e}"),
        };
        assert_eq!(r.challenges.len(), 2);
        assert_eq!(r.runs.len(), 2);
        // Each child got its own challenges, not a shared set.
        assert_ne!(r.challenges[0].z_x, r.challenges[1].z_x);
        assert_ne!(r.runs[0].digest, r.runs[1].digest);

        assert!(verify_aggregation_node(&r.proof, r.log_size, &children).unwrap(),
                "an honest two-child node must verify");
    }

    /// The binding, at node level: one child running under a foreign challenge
    /// must sink the whole node.
    #[test]
    fn a_node_with_one_bad_child_cannot_be_proved() {
        let num_folds = 2;
        let mut s = 0xF22_u64;
        let mut children = vec![child(num_folds, 0x81, &mut s), child(num_folds, 0x82, &mut s)];
        children[1].rounds[0].1 ^= 1;

        let err = match prove_aggregation_node(&children) {
            Ok(_) => panic!("a child under a foreign challenge must not be provable"),
            Err(e) => e,
        };
        assert!(err.contains("child 1"), "the error should name the child: {err}");
    }

    /// Children must not be swappable: each is bound to its own transcript, so
    /// exchanging them changes what the node claims.
    #[test]
    fn children_cannot_be_swapped() {
        let num_folds = 2;
        let mut s = 0x1A3_u64;
        let children = vec![child(num_folds, 0x91, &mut s), child(num_folds, 0x92, &mut s)];
        let r = match prove_aggregation_node(&children) {
            Ok(r) => r, Err(e) => panic!("prove failed: {e}"),
        };
        let swapped = vec![children[1].clone(), children[0].clone()];
        assert!(!verify_aggregation_node(&r.proof, r.log_size, &swapped).unwrap(),
                "swapped children must not verify");
    }

    #[test]
    fn a_node_rejects_mismatched_child_shapes() {
        let mut s = 0x2B4_u64;
        let a = child(2, 0xA1, &mut s);
        let b = child(3, 0xA2, &mut s); // a different fold count
        let err = match prove_aggregation_node(&[a, b]) {
            Ok(_) => panic!("mismatched fold counts must be refused"),
            Err(e) => e,
        };
        assert!(err.contains("fold rounds"), "unexpected error: {err}");
        assert!(prove_aggregation_node(&[]).is_err(), "an empty node is meaningless");
    }

    /// A node is the same object however many children it has, so the binary
    /// case is not special-cased anywhere.
    #[test]
    fn a_one_child_node_is_the_degenerate_case_of_the_same_thing() {
        let mut s = 0x3C5_u64;
        let children = vec![child(2, 0xB1, &mut s)];
        let r = match prove_aggregation_node(&children) {
            Ok(r) => r, Err(e) => panic!("prove failed: {e}"),
        };
        assert!(verify_aggregation_node(&r.proof, r.log_size, &children).unwrap());
    }

    // ── The complete tree node ───────────────────────────────────────────────

    fn rand_node(seed: &mut u64) -> [u64; 4] {
        [rand_m31(seed), rand_m31(seed), rand_m31(seed), rand_m31(seed)]
    }

    /// One child proof: ONE transcript, `n_queries` queries under it.
    fn statement(
        num_folds: usize,
        n_queries: usize,
        depth: usize,
        comp_depth: usize,
        salt: u32,
        seed: &mut u64,
    ) -> TreeStatement {
        let (steps, layout) = transcript(num_folds, salt);
        let derived = derive_challenges(&steps, &layout).unwrap();
        let mk = |d: usize, seed: &mut u64| -> (Vec<[u64; 4]>, Vec<bool>) {
            (
                (0..d).map(|_| rand_node(seed)).collect(),
                (0..d).map(|_| rand_m31(seed) & 1 == 1).collect(),
            )
        };
        let mut queries = Vec::new();
        let mut paths = Vec::new();
        let mut comp_paths = Vec::new();
        for _ in 0..n_queries {
            // Every query runs under the STATEMENT's challenges — that is what
            // makes one transcript per proof correct rather than per query.
            queries.push(query_under(&derived, num_folds, seed));
            paths.push(mk(depth, seed));
            let (ps, pb) = mk(comp_depth, seed);
            let (ns, nb) = mk(comp_depth, seed);
            comp_paths.push((ps, pb, ns, nb));
        }
        TreeStatement { steps, layout, queries, paths, comp_paths }
    }

    /// The tree's node: two child PROOFS, each with several queries.
    #[test]
    fn a_two_statement_tree_node_proves_and_verifies() {
        let mut s = 0x4D6_u64;
        let statements = vec![
            statement(2, 3, 2, 3, 0xC1, &mut s),
            statement(2, 3, 2, 3, 0xC2, &mut s),
        ];
        let r = match prove_tree_node(&statements) {
            Ok(r) => r,
            Err(e) => panic!("prove failed: {e}"),
        };
        // 6 queries total → 18 paths (final-fold, comp, compNeg).
        assert_eq!(r.challenges.len(), 6);
        assert_eq!(r.roots.len(), 18);
        // ONE channel run per statement, not per query — the whole point of
        // grouping this way.
        assert_eq!(r.runs.len(), 2);
        assert_ne!(r.runs[0].digest, r.runs[1].digest);
        // Queries of one statement share its challenges; the two statements differ.
        assert_eq!(r.challenges[0].z_x, r.challenges[1].z_x);
        assert_ne!(r.challenges[0].z_x, r.challenges[3].z_x);

        assert!(verify_tree_node(&r.proof, r.log_size, &statements, &r.roots).unwrap(),
                "an honest tree node must verify");
    }

    /// One transcript per PROOF, not per query.
    ///
    /// The node's trace does grow with the query count — each query brings three
    /// Merkle paths, and that is inherent. What must not grow with it is the
    /// CHANNEL: `z_x` and the fold challenges are drawn once per proof, so
    /// replaying the transcript per query would prove the same thing over and
    /// over. At the production 84-step transcript and 20 queries that is the
    /// difference between 168 and 1680 channel blocks.
    #[test]
    fn the_channel_runs_once_per_proof_not_once_per_query() {
        let mut s = 0x8AB_u64;
        let many = vec![statement(2, 8, 2, 2, 0xC5, &mut s)];
        let r = match prove_tree_node(&many) {
            Ok(r) => r, Err(e) => panic!("prove failed: {e}"),
        };
        assert_eq!(r.runs.len(), 1, "eight queries, one proof, one channel run");
        assert_eq!(r.challenges.len(), 8);
        // All eight queries ran under the SAME drawn challenges, which is what
        // makes one run correct rather than a shortcut.
        for c in &r.challenges[1..] {
            assert_eq!(c.z_x, r.challenges[0].z_x);
            assert_eq!(c.alphas, r.challenges[0].alphas);
        }
        assert!(verify_tree_node(&r.proof, r.log_size, &many, &r.roots).unwrap());
    }

    /// The channel binding still holds with the membership components present.
    #[test]
    fn a_tree_node_still_refuses_a_foreign_challenge() {
        let mut s = 0x5E7_u64;
        let mut statements = vec![
            statement(2, 2, 2, 3, 0xD1, &mut s),
            statement(2, 2, 2, 3, 0xD2, &mut s),
        ];
        statements[1].queries[1].0 .3 ^= 1; // a z_x the transcript did not produce
        let err = match prove_tree_node(&statements) {
            Ok(_) => panic!("a foreign challenge must not be provable"),
            Err(e) => e,
        };
        assert!(err.contains("statement 1") && err.contains("query 1") && err.contains("z_x"),
                "the error should locate the query: {err}");
    }

    /// Membership is real: a tampered root must not verify.
    #[test]
    fn a_tampered_root_is_rejected() {
        let mut s = 0x6F8_u64;
        let statements = vec![statement(2, 2, 2, 2, 0xE1, &mut s)];
        let r = match prove_tree_node(&statements) {
            Ok(r) => r, Err(e) => panic!("prove failed: {e}"),
        };
        let mut bad = r.roots.clone();
        bad[0][0] = (bad[0][0] + 1) % M31;
        assert!(!verify_tree_node(&r.proof, r.log_size, &statements, &bad).unwrap(),
                "a tampered final-fold root must not verify");
    }

    #[test]
    fn a_tree_node_checks_its_statement_shapes() {
        let mut s = 0x709_u64;
        let a = statement(2, 2, 2, 3, 0xF1, &mut s);
        let b = statement(2, 2, 3, 3, 0xF2, &mut s); // a different path depth
        assert!(prove_tree_node(&[a.clone(), b]).is_err(),
                "mismatched final-fold depths must be refused");

        let mut c = statement(2, 2, 2, 3, 0xF3, &mut s);
        c.comp_paths[0].0.pop(); // a ragged composition path
        assert!(prove_tree_node(&[a.clone(), c]).is_err(),
                "a comp path of the wrong depth must be refused");

        let mut d = statement(2, 2, 2, 3, 0xF4, &mut s);
        d.paths.pop(); // fewer paths than queries
        assert!(prove_tree_node(&[a, d]).is_err(),
                "a statement whose paths do not match its queries must be refused");

        assert!(prove_tree_node(&[]).is_err(), "an empty node is meaningless");
    }
}
