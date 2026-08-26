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
}
