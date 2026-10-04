//! A-4 in circuit: `oldRoot → newRoot` for a batch of nonce updates.
//!
//! # What has to be proved, and what does not
//!
//! The statement is "the stored nonce root moved from `oldRoot` to `newRoot`
//! legally". Writing it out shows that most of it is NOT a circuit's job:
//!
//! | what | where it is checked | why |
//! |---|---|---|
//! | the sibling paths reach their roots | **in circuit** | the siblings are witness — the contract cannot see 2N·D hashes |
//! | `new_nonce > old_nonce` | verifier / contract | the nonces are PUBLIC inputs; comparing two public u64s needs no AIR |
//! | both of a link's paths share one index | verifier / contract | the indices are pinned preprocessed values, i.e. public |
//! | `post_root[i] == pre_root[i+1]` | verifier / contract | the roots are pinned, so the chain is a public-input check |
//! | `leaf == nonce_leaf(nonce)` | verifier / contract | a deterministic public function of a public nonce |
//! | `index == prefix(H(sender))` | **contract only** | H is Keccak; arithmetizing it is limitation 0, not started |
//!
//! So this module adds **no new AIR**. `merkle_path_t8_air` has taken a root
//! PER PATH since R4.11, so 2N paths against N+1 chained roots was already
//! expressible; what was missing was a prove/verify pair that assembles them
//! and a verifier that checks the public-input relations.
//!
//! `docs/TECH_DEBT.md` § A-4 anticipated needing cross-path constraints for the
//! index equality and the strict increase. It does not, and the reason is worth
//! stating: those values are public, not witness. A constraint would be proving
//! something the verifier can simply read. The same move as `composition_t8`
//! binding `leaf4 = qm31_leaf_hash_t8(finalFold)` — a deterministic public
//! function of a pinned value, computed by the verifier rather than constrained.
//!
//! # Where the gas goes
//!
//! Calldata stays O(N): a sender hash, a nonce and an intermediate root per
//! update. Storage becomes O(1): one read of `nonceStateRoot`, one write.
//! Measured today, a sender costs **28,777 gas** of storage against ~512 of
//! calldata, so trading 32 more bytes per update for the `SSTORE` is the whole
//! point. At N = 25 the intermediate roots add ~13k gas against a ~719k saving.
//!
//! # Soundness of the public-input split
//!
//! A prover choosing its own `old_nonce` gains nothing: the old leaf is pinned
//! from that public nonce and must authenticate against `pre_root`, which for
//! the first link IS the contract's stored root. Lying about `old_nonce` means
//! producing a sibling path from a false leaf to the real stored root — a
//! second preimage at the t=8 node bound, ~2^62. Lying about an intermediate
//! root breaks the linkage the verifier checks. Replaying a spent nonce fails
//! the public `new > old`.

use crate::nonce_tree::{nonce_leaf, NonceTransition, MAX_DEPTH};
use crate::recursive::merkle_path_t8_air as merkle;
use crate::vfri2_bridge::p2t8_node_words;

use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, CommitmentSchemeProver};

use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

/// Most updates one proof will carry.
///
/// Not a cryptographic bound — a trace-size and hostile-input one. 2N paths of
/// depth D occupy `2·N·D·22` rows, and the AIR caps `log_size` at 24, so N is
/// bounded anyway; this makes the refusal explicit instead of an allocation
/// failure. (R3.12's lesson: every multi-input entry point gets its caps from
/// the start.)
pub const MAX_UPDATES: usize = 512;

/// The public part of a batch's nonce transition — everything the contract sees.
///
/// Deliberately all-public and all-small: `Vec<u64>` and 4-word roots, no
/// proofs and no sibling paths. The contract can check every relation in here
/// itself; the STARK exists only for the paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceStatement {
    /// The root the contract has stored.
    pub old_root: [u64; 4],
    /// The root the contract will store.
    pub new_root: [u64; 4],
    /// Per update, in the canonical order `nonce_tree::apply_updates` fixes.
    pub updates: Vec<NonceUpdate>,
    /// Tree depth; every path has exactly this many steps.
    pub depth: usize,
}

/// One update as the contract sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceUpdate {
    /// The slot. The CONTRACT checks this is `prefix(H(sender))`; see the
    /// module docs for why that check cannot live in the circuit.
    pub index: u32,
    pub old_nonce: u64,
    pub new_nonce: u64,
    /// The root after this update. The last one must equal `new_root`.
    pub post_root: [u64; 4],
}

impl NonceStatement {
    /// Build the public statement from the off-circuit transitions.
    pub fn from_transitions(
        transitions: &[NonceTransition],
        old_root: &[u8; 32],
        new_root: &[u8; 32],
        depth: usize,
    ) -> Result<Self, String> {
        validate_count(transitions.len())?;
        validate_depth(depth)?;
        for (i, t) in transitions.iter().enumerate() {
            if t.bits.len() != depth || t.sibs.len() != depth {
                return Err(format!(
                    "update {i}: path has {} steps, expected depth {depth}",
                    t.bits.len()
                ));
            }
        }
        Ok(Self {
            old_root: p2t8_node_words(old_root),
            new_root: p2t8_node_words(new_root),
            updates: transitions
                .iter()
                .map(|t| NonceUpdate {
                    index: t.index,
                    old_nonce: t.old_nonce,
                    new_nonce: t.new_nonce,
                    post_root: p2t8_node_words(&t.post_root),
                })
                .collect(),
            depth,
        })
    }

    /// The root each link starts from: `old_root`, then each predecessor's
    /// `post_root`.
    fn pre_roots(&self) -> Vec<[u64; 4]> {
        let mut out = Vec::with_capacity(self.updates.len());
        let mut prev = self.old_root;
        for u in &self.updates {
            out.push(prev);
            prev = u.post_root;
        }
        out
    }

    /// Every relation the verifier can settle without the proof.
    ///
    /// Returns the reason it does not hold, or None. Checked BEFORE the STARK,
    /// so a malformed statement is rejected cheaply and names its own fault
    /// rather than surfacing as "the proof does not verify".
    pub fn check_public(&self) -> Option<String> {
        if let Err(e) = validate_count(self.updates.len()) {
            return Some(e);
        }
        if let Err(e) = validate_depth(self.depth) {
            return Some(e);
        }
        // An empty batch must not move the root. Without this an empty
        // statement would assert any pair of roots with nothing to verify.
        if self.updates.is_empty() {
            return (self.old_root != self.new_root)
                .then(|| "empty batch must leave the root unchanged".to_string());
        }
        let slots = 1u64 << self.depth;
        for (i, u) in self.updates.iter().enumerate() {
            if u64::from(u.index) >= slots {
                return Some(format!(
                    "update {i}: index {} out of range for depth {}",
                    u.index, self.depth
                ));
            }
            // The replay guarantee, as a comparison of two public integers.
            if u.new_nonce <= u.old_nonce {
                return Some(format!(
                    "update {i}: nonce must strictly increase, {} -> {}",
                    u.old_nonce, u.new_nonce
                ));
            }
        }
        // The chain has to END where the contract will write.
        if self.updates[self.updates.len() - 1].post_root != self.new_root {
            return Some("the last update's post_root is not new_root".to_string());
        }
        None
    }

    /// The 2N `(leaf, index, root)` triples the circuit must pin, in path order.
    ///
    /// Path `2i` is link `i`'s OLD leaf against its pre-root; path `2i+1` is its
    /// NEW leaf against its post-root. The leaves are computed HERE, from the
    /// public nonces — a prover never supplies them, which is what makes
    /// `old_nonce` unprofitable to lie about.
    fn pinned_paths(&self) -> (Vec<[u64; 4]>, Vec<u32>, Vec<[u64; 4]>, Vec<usize>) {
        let pre = self.pre_roots();
        let n = self.updates.len();
        let mut leaves = Vec::with_capacity(2 * n);
        let mut indices = Vec::with_capacity(2 * n);
        let mut roots = Vec::with_capacity(2 * n);
        for (i, u) in self.updates.iter().enumerate() {
            leaves.push(p2t8_node_words(&nonce_leaf(u.old_nonce)));
            indices.push(u.index);
            roots.push(pre[i]);

            leaves.push(p2t8_node_words(&nonce_leaf(u.new_nonce)));
            // The SAME index for both paths — § A-4 expected a cross-path
            // constraint for this; pinning both from one public value is
            // stronger and free.
            indices.push(u.index);
            roots.push(u.post_root);
        }
        let depths = vec![self.depth; 2 * n];
        (leaves, indices, roots, depths)
    }
}

fn validate_count(n: usize) -> Result<(), String> {
    if n > MAX_UPDATES {
        return Err(format!("{n} updates exceeds MAX_UPDATES {MAX_UPDATES}"));
    }
    Ok(())
}

fn validate_depth(depth: usize) -> Result<(), String> {
    if depth == 0 || depth > MAX_DEPTH {
        return Err(format!("depth {depth} out of range [1, {MAX_DEPTH}]"));
    }
    if depth > merkle::MAX_DEPTH {
        return Err(format!(
            "depth {depth} exceeds what the path AIR can prove ({})",
            merkle::MAX_DEPTH
        ));
    }
    Ok(())
}

/// Bind the whole public statement into the transcript.
///
/// Every field, in a fixed order, with the update count first so a statement
/// cannot be reinterpreted at a different length — the R4.7 lesson, where
/// `outerBindingRoot` hashed 2 of 8 public fields and left six swappable while
/// still returning ok.
fn mix_statement(channel: &mut Blake2sM31Channel, st: &NonceStatement) {
    let mut words: Vec<u32> = Vec::with_capacity(9 + st.updates.len() * 9);
    words.push(st.updates.len() as u32);
    words.push(st.depth as u32);
    let w = |v: u64| (v % crate::poseidon2::M31_P) as u32;
    words.extend(st.old_root.iter().map(|&v| w(v)));
    words.extend(st.new_root.iter().map(|&v| w(v)));
    for u in &st.updates {
        words.push(u.index);
        // u64 nonces split into two u32 halves: mix_u32s takes words, and a
        // truncated nonce would leave the high half unbound.
        words.push((u.old_nonce & 0xffff_ffff) as u32);
        words.push((u.old_nonce >> 32) as u32);
        words.push((u.new_nonce & 0xffff_ffff) as u32);
        words.push((u.new_nonce >> 32) as u32);
        words.extend(u.post_root.iter().map(|&v| w(v)));
    }
    channel.mix_u32s(&words);
}

/// The trace size a statement needs.
pub fn statement_log_size(st: &NonceStatement) -> Result<u32, String> {
    if let Some(reason) = st.check_public() {
        return Err(reason);
    }
    if st.updates.is_empty() {
        return Err("an empty batch needs no proof".into());
    }
    let (_, _, _, depths) = st.pinned_paths();
    let log_size = merkle::compute_log_size_multi_var(&depths);
    if log_size > merkle::MAX_LOG_SIZE {
        return Err(format!(
            "log_size {log_size} exceeds MAX_LOG_SIZE {} — too many updates for one proof",
            merkle::MAX_LOG_SIZE
        ));
    }
    Ok(log_size)
}

/// Prove that `st`'s transitions are authentic against their chained roots.
///
/// `transitions` supplies the WITNESS (the sibling paths); `st` is the public
/// statement. The two must describe the same batch, which is checked rather
/// than assumed.
pub fn prove_nonce_transitions(
    st: &NonceStatement,
    transitions: &[NonceTransition],
) -> Result<(Vec<u8>, u32), String> {
    if let Some(reason) = st.check_public() {
        return Err(reason);
    }
    if transitions.len() != st.updates.len() {
        return Err(format!(
            "{} transitions for {} updates",
            transitions.len(),
            st.updates.len()
        ));
    }
    let pre = st.pre_roots();
    for (i, (t, u)) in transitions.iter().zip(&st.updates).enumerate() {
        if t.index != u.index || t.old_nonce != u.old_nonce || t.new_nonce != u.new_nonce {
            return Err(format!("transition {i} does not match update {i}"));
        }
        // Catch a mismatched witness HERE, naming the link. The pinned
        // preprocessed root would make it fail verification anyway, but as an
        // opaque "does not verify".
        if p2t8_node_words(&t.pre_root) != pre[i] || p2t8_node_words(&t.post_root) != u.post_root {
            return Err(format!("transition {i}: roots do not match the statement"));
        }
        if t.bits.len() != st.depth || t.sibs.len() != st.depth {
            return Err(format!("transition {i}: path depth is not {}", st.depth));
        }
    }

    let log_size = statement_log_size(st)?;
    let (leaves, indices, roots, depths) = st.pinned_paths();

    // Both of a link's paths use the SAME siblings: they hang off the path, and
    // only the leaf and the nodes above it change. See nonce_tree's
    // `the_sibling_path_is_unchanged_by_an_update`.
    let mut sibs: Vec<Vec<[u64; 4]>> = Vec::with_capacity(2 * transitions.len());
    let mut bits: Vec<Vec<bool>> = Vec::with_capacity(2 * transitions.len());
    for t in transitions {
        let path: Vec<[u64; 4]> = t.sibs.iter().map(p2t8_node_words).collect();
        sibs.push(path.clone());
        bits.push(t.bits.clone());
        sibs.push(path);
        bits.push(t.bits.clone());
    }

    let (main_cols, reached) = merkle::build_trace_multi(&leaves, &sibs, &bits, log_size);
    // The paths must actually land on the roots the statement claims. Checked
    // at PROVING time so an inconsistent witness names itself.
    for (i, (got, want)) in reached.iter().zip(&roots).enumerate() {
        if got != want {
            return Err(format!(
                "path {i} reaches a different root than the statement claims"
            ));
        }
    }
    let preproc = merkle::build_preproc_multi_var(&leaves, &indices, &roots, &depths, log_size);

    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1)
            .circle_domain()
            .half_coset,
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

    mix_statement(channel, st);

    let component = merkle::new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        channel,
        commitment_scheme,
    )
    .map_err(|e| format!("nonce accumulator proving error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("nonce accumulator serialize error: {e:?}"))?;
    Ok((bytes, log_size))
}

/// The statement's main trace columns, for feeding the recursion.
///
/// A direct STARK over these columns costs VFRI11 money on-chain (millions of
/// gas), which would defeat the point. The affordable route is the one the
/// aggregation tree already takes: make this the INNER statement of a recursive
/// proof, so the contract pays one `verifyRecursive` — measured at **2,290,000
/// gas and CONSTANT in batch size**.
///
/// That constant is what removes the ceiling. Against the mapping's measured
/// 28,777 gas per sender it pays for itself above ~80 senders, and unlike the
/// mapping it does not grow, so there is no N at which it stops fitting.
///
/// `vfri2_bridge::build_recursive_bundle` takes COLUMNS rather than a proof, so
/// the wrapping is mechanical — `probe_nonce_outer_shape` measures that the
/// outer trace over a nonce statement has the same shape as over a V23 group,
/// which is what makes the gas figure transferable. Returned as `Vec<Vec<u32>>`
/// to match what that function expects.
pub fn statement_trace_columns(
    st: &NonceStatement,
    transitions: &[NonceTransition],
) -> Result<(Vec<Vec<u32>>, u32), String> {
    if let Some(reason) = st.check_public() {
        return Err(reason);
    }
    if transitions.len() != st.updates.len() {
        return Err("transitions do not match the statement".into());
    }
    let log_size = statement_log_size(st)?;
    let (leaves, _, _, _) = st.pinned_paths();

    let mut sibs: Vec<Vec<[u64; 4]>> = Vec::with_capacity(2 * transitions.len());
    let mut bits: Vec<Vec<bool>> = Vec::with_capacity(2 * transitions.len());
    for t in transitions {
        let path: Vec<[u64; 4]> = t.sibs.iter().map(p2t8_node_words).collect();
        sibs.push(path.clone());
        bits.push(t.bits.clone());
        sibs.push(path);
        bits.push(t.bits.clone());
    }

    let (main_cols, _) = merkle::build_trace_multi(&leaves, &sibs, &bits, log_size);
    let cols: Vec<Vec<u32>> = main_cols
        .iter()
        .map(|c| c.values.iter().map(|v| v.0).collect())
        .collect();
    Ok((cols, log_size))
}

/// Verify a batch's nonce transition against its public statement.
///
/// Two independent gates, and both must hold:
///
/// 1. `st.check_public()` — strict increase, index ranges, the chain ending at
///    `new_root`. No proof involved.
/// 2. the STARK, with the C2 pin over the preprocessed tree, which fixes every
///    path's leaf, index and root to values recomputed HERE from `st`. A forged
///    selector or a swapped root changes that commitment and is rejected.
pub fn verify_nonce_transitions(
    proof_bytes: &[u8],
    log_size: u32,
    st: &NonceStatement,
) -> Result<bool, String> {
    if let Some(reason) = st.check_public() {
        return Err(reason);
    }
    if st.updates.is_empty() {
        return Err("an empty batch has no proof to verify".into());
    }
    let expected_log_size = statement_log_size(st)?;
    if log_size != expected_log_size {
        // A caller-supplied log_size that disagrees with the statement would
        // verify a different-shaped trace against these pins.
        return Ok(false);
    }

    let (leaves, indices, roots, depths) = st.pinned_paths();

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("nonce accumulator deserialize error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let component = merkle::new_component(log_size);
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected >= 2 commitments, got {}",
            proof.commitments.len()
        ));
    }
    if proof.commitments[0]
        != merkle::canonical_preproc_root_multi(&leaves, &indices, &roots, &depths, log_size)
    {
        return Ok(false);
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    mix_statement(verifier_channel, st);

    let result = verify::<Blake2sM31MerkleChannel>(
        &[&component],
        verifier_channel,
        commitment_scheme,
        proof,
    );
    Ok(result.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce_tree::{apply_updates, NonceTree};

    const D: usize = 4;

    fn sender(i: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = i;
        h[1] = i.wrapping_mul(7);
        h
    }

    /// A batch of `n` distinct senders, with the statement and the witness.
    fn batch(n: u8) -> (NonceStatement, Vec<NonceTransition>) {
        let mut tree = NonceTree::new(D).unwrap();
        let updates: Vec<_> = (1..=n).map(|i| (sender(i), u64::from(i))).collect();
        let (old_root, new_root, ts) = apply_updates(&mut tree, &updates).unwrap();
        let st = NonceStatement::from_transitions(&ts, &old_root, &new_root, D).unwrap();
        (st, ts)
    }

    // ── The public gate, which needs no proof ────────────────────────────────

    #[test]
    fn a_valid_statement_passes_the_public_checks() {
        let (st, _) = batch(2);
        assert_eq!(st.check_public(), None);
        assert_eq!(st.updates.len(), 2);
    }

    #[test]
    fn a_non_increasing_nonce_is_refused_without_a_proof() {
        // The replay guarantee, settled by comparing two public integers.
        let (mut st, _) = batch(1);
        st.updates[0].new_nonce = st.updates[0].old_nonce;
        assert!(st.check_public().unwrap().contains("strictly increase"));
    }

    #[test]
    fn a_chain_not_ending_at_new_root_is_refused() {
        let (mut st, _) = batch(2);
        st.new_root = [1, 2, 3, 4];
        assert!(st.check_public().unwrap().contains("not new_root"));
    }

    #[test]
    fn an_empty_batch_must_not_move_the_root() {
        // Otherwise an empty statement would assert any pair of roots with
        // nothing to verify.
        let st = NonceStatement {
            old_root: [1, 1, 1, 1],
            new_root: [2, 2, 2, 2],
            updates: vec![],
            depth: D,
        };
        assert!(st.check_public().unwrap().contains("unchanged"));

        let ok = NonceStatement {
            old_root: [1, 1, 1, 1],
            new_root: [1, 1, 1, 1],
            updates: vec![],
            depth: D,
        };
        assert_eq!(ok.check_public(), None);
        // ...and carries no proof either way.
        assert!(statement_log_size(&ok).is_err());
    }

    #[test]
    fn an_out_of_range_index_is_refused() {
        let (mut st, _) = batch(1);
        st.updates[0].index = 1 << D;
        assert!(st.check_public().unwrap().contains("out of range"));
    }

    #[test]
    fn bad_depths_and_oversized_batches_are_refused() {
        let (mut st, _) = batch(1);
        st.depth = 0;
        assert!(st.check_public().is_some());
        st.depth = MAX_DEPTH + 1;
        assert!(st.check_public().is_some());
        st.depth = D;
        st.updates = vec![st.updates[0].clone(); MAX_UPDATES + 1];
        assert!(st.check_public().unwrap().contains("MAX_UPDATES"));
    }

    #[test]
    fn both_paths_of_a_link_are_pinned_to_the_same_index() {
        // What § A-4 expected a cross-path CONSTRAINT for. Pinning both from
        // one public value is stronger and costs nothing.
        let (st, _) = batch(3);
        let (_, indices, _, _) = st.pinned_paths();
        assert_eq!(indices.len(), 6);
        for (i, u) in st.updates.iter().enumerate() {
            assert_eq!(indices[2 * i], u.index);
            assert_eq!(indices[2 * i + 1], u.index);
        }
    }

    #[test]
    fn the_pinned_roots_follow_the_chain() {
        let (st, _) = batch(3);
        let (_, _, roots, _) = st.pinned_paths();
        // Link 0 starts at old_root; each later link starts where the previous
        // one ended; the last ends at new_root.
        assert_eq!(roots[0], st.old_root);
        for i in 0..st.updates.len() {
            assert_eq!(roots[2 * i + 1], st.updates[i].post_root);
            if i + 1 < st.updates.len() {
                assert_eq!(roots[2 * (i + 1)], st.updates[i].post_root);
            }
        }
        assert_eq!(roots[roots.len() - 1], st.new_root);
    }

    #[test]
    fn the_pinned_leaves_come_from_the_public_nonces() {
        // The prover never supplies a leaf, which is what makes lying about
        // old_nonce unprofitable.
        let (st, _) = batch(2);
        let (leaves, _, _, _) = st.pinned_paths();
        for (i, u) in st.updates.iter().enumerate() {
            assert_eq!(leaves[2 * i], p2t8_node_words(&nonce_leaf(u.old_nonce)));
            assert_eq!(leaves[2 * i + 1], p2t8_node_words(&nonce_leaf(u.new_nonce)));
        }
    }

    // ── The proof ────────────────────────────────────────────────────────────

    #[test]
    #[ignore = "STARK proving; ~seconds"]
    fn a_single_update_proves_and_verifies() {
        let (st, ts) = batch(1);
        let (proof, log_size) = prove_nonce_transitions(&st, &ts).unwrap();
        assert!(verify_nonce_transitions(&proof, log_size, &st).unwrap());
    }

    #[test]
    #[ignore = "STARK proving; ~seconds"]
    fn a_three_update_chain_proves_and_verifies() {
        // Three updates, FOUR roots. The chain is the whole point.
        let (st, ts) = batch(3);
        assert_eq!(st.updates.len(), 3);
        let (proof, log_size) = prove_nonce_transitions(&st, &ts).unwrap();
        assert!(verify_nonce_transitions(&proof, log_size, &st).unwrap());
    }

    #[test]
    #[ignore = "STARK proving; ~seconds"]
    fn a_tampered_root_is_rejected() {
        let (st, ts) = batch(2);
        let (proof, log_size) = prove_nonce_transitions(&st, &ts).unwrap();
        assert!(verify_nonce_transitions(&proof, log_size, &st).unwrap());

        // Claim a different intermediate root: the C2 pin over the
        // preprocessed tree moves, so the proof no longer matches.
        let mut lying = st.clone();
        lying.updates[0].post_root = [7, 7, 7, 7];
        // check_public still passes — the last post_root is untouched — so this
        // is caught by the proof, not by the cheap gate. That is the point.
        assert_eq!(lying.check_public(), None);
        assert!(!verify_nonce_transitions(&proof, log_size, &lying).unwrap());
    }

    #[test]
    #[ignore = "STARK proving; ~seconds"]
    fn a_tampered_nonce_is_rejected_by_the_proof_too() {
        let (st, ts) = batch(2);
        let (proof, log_size) = prove_nonce_transitions(&st, &ts).unwrap();

        // Raise a new_nonce: check_public still passes (it still increases),
        // but the pinned leaf changes, so the proof does not match.
        let mut lying = st.clone();
        lying.updates[0].new_nonce += 1000;
        assert_eq!(lying.check_public(), None);
        assert!(!verify_nonce_transitions(&proof, log_size, &lying).unwrap());
    }

    #[test]
    #[ignore = "STARK proving; ~seconds"]
    fn a_witness_that_does_not_match_the_statement_is_refused_at_proving_time() {
        let (st, mut ts) = batch(2);
        ts[0].new_nonce += 5;
        let err = prove_nonce_transitions(&st, &ts).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    #[ignore = "STARK proving; ~seconds"]
    fn a_mismatched_log_size_is_rejected() {
        let (st, ts) = batch(2);
        let (proof, log_size) = prove_nonce_transitions(&st, &ts).unwrap();
        assert!(!verify_nonce_transitions(&proof, log_size + 1, &st).unwrap());
    }


    #[test]
    #[ignore = "measurement probe; the outer trace over a nonce statement"]
    fn probe_nonce_outer_shape() {
        // The figure that decides whether the contract step is affordable.
        // `verifyRecursive` costs a MEASURED 2,290,000 gas and is constant in
        // batch size, but that was measured on an outer trace of a particular
        // shape. If a nonce statement's outer trace has the same shape, the
        // figure transfers; if not, it has to be re-measured. Measuring beats
        // assuming here — the last time I inferred a total from one component
        // (a4742b5) the submission reverted.
        use crate::recursive::composition_t8::outer_trace_columns_t8;
        use crate::vfri2_bridge::gen_vfri11_recursion_inputs;

        let bound_root: Vec<u8> = (0..32).map(|i| ((11 + 7 * i) % 256) as u8).collect();

        for n in [1u8, 2, 4] {
            let (st, ts) = batch(n);
            let (cols, log_size) = statement_trace_columns(&st, &ts).expect("cols");
            let rec = gen_vfri11_recursion_inputs(&cols, log_size, &bound_root, 1, Some(6))
                .expect("recursion inputs over the nonce statement");
            let (outer_cols, outer_log) =
                outer_trace_columns_t8(&rec.queries, &rec.paths, &rec.comp_paths).expect("outer");
            eprintln!(
                "N={n}: inner {} cols log {log_size} -> outer {} cols log {outer_log}",
                cols.len(),
                outer_cols.len(),
            );
        }
        eprintln!(
            "compare: a V23 group's outer trace is 87 cols at log 14 \
             (verifyRecursive = 2,290,000 gas, constant in batch size)"
        );
    }

    #[test]
    #[ignore = "measurement probe; trace growth per update"]
    fn probe_trace_growth_per_update() {
        // § A-4 pitfall 2 asks for this rather than an estimate: log_size is
        // what sets proving time, and it must be MEASURED against both the
        // update count and the depth.
        println!("updates x depth -> log_size (2N paths of D steps, 22 rows each)");
        for d in [4usize, 8, 16, 24, 28] {
            let mut row = format!("  D={d:2}: ");
            for n in [1usize, 2, 4, 8, 16, 32] {
                let depths = vec![d; 2 * n];
                let ls = merkle::compute_log_size_multi_var(&depths);
                row += &format!("N={n:<3}->{ls:<3} ");
            }
            println!("{row}");
        }
        println!(
            "  AIR cap MAX_LOG_SIZE={}, MAX_DEPTH={}",
            merkle::MAX_LOG_SIZE,
            merkle::MAX_DEPTH
        );
    }
}
