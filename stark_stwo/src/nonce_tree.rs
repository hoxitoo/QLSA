//! The nonce accumulator's state tree (A-4) — replay protection as ONE root.
//!
//! # Why the on-chain mapping has to go
//!
//! `BatchRegistryV7.senderNonces` is a `mapping(bytes32 => uint64)` with an
//! O(n²) duplicate scan over the submitted sender list. Measured
//! (`V7SenderCostProbe.test.js`, marginal `gasUsed` of a sent transaction):
//! **28,777 gas per sender** at n = 10→25, and the marginal cost GROWS with n.
//! Against the 2^24 per-transaction cap that leaves room for about **72
//! senders**, while break-even needs N > 607. It is the one ceiling that no
//! amount of proof optimisation moves, because it is storage, not verification.
//!
//! The state itself cannot be dropped: it is what stops a transaction already
//! finalized in one batch from being replayed in the next. It can only be
//! COMPRESSED — to a single `bytes32` root plus a proof that the transition from
//! the old root to the new one was legal. That makes the on-chain cost one read
//! and one write, independent of N.
//!
//! # The leaf, and why it carries only the nonce
//!
//! ```text
//!     leaf(nonce) = compress_t8( NONCE_DOMAIN, [nonce_lo, nonce_hi, 0, 0] )
//!     index       = the first D bits of H(sender)
//! ```
//!
//! The sender is **not** in the leaf, and that is a deliberate choice with a
//! specific failure mode behind it. The index space is 2^D, so two senders whose
//! hashes agree on the first D bits share a slot. Then:
//!
//! * leaf = `(sender, nonce)` — the second sender can never produce a valid
//!   old-leaf for its own address, because the slot holds someone else's. It is
//!   locked out **permanently**.
//! * leaf = `nonce` alone — the two share one monotonically increasing counter.
//!   Replay is still impossible (any nonce ≤ the stored one is rejected, which
//!   is the whole guarantee), and the affected sender simply submits a higher
//!   nonce.
//!
//! The second degrades; the first breaks. And only the second makes the empty
//! tree's root a CONSTANT: with the sender absent from the leaf, every unused
//! slot holds `leaf(0)`, so "this sender has never been seen" and "this
//! sender's nonce is 0" are the same statement and the circuit needs no separate
//! branch for a first-time sender. That is what `docs/TECH_DEBT.md` § A-4 was
//! reaching for with "all leaves zero"; it works only in this leaf shape.
//!
//! Note the matching convention on-chain: the registries store 0 for an unseen
//! sender and enforce `newNonce > stored`, so 1 is the smallest submittable
//! nonce and `testnet.e2e.build_sender_nonces` maps `tx.nonce → nonce + 1`.
//!
//! # What binds the index to the sender — and where
//!
//! `index == prefix(H(sender))` is **not** checked in-circuit, because H is
//! SHA3/Keccak and arithmetizing Keccak is limitation 0, which is not started.
//! The contract checks it instead: it already receives the sender list, hashing
//! a word costs tens of gas, and it binds the resulting indices into the proof's
//! public inputs. What the proof establishes is the transition at the PINNED
//! indices; what the contract establishes is that those indices are the ones
//! these senders own. Neither alone is enough, and the split needs no new
//! cryptography.
//!
//! What this buys is the storage write, not the calldata: a sender's 32 bytes of
//! calldata cost ~512 gas, against 28,777 for its `SSTORE`.
//!
//! # Depth
//!
//! `MAX_DEPTH` here is bounded by the AIR that has to replicate these paths:
//! `recursive::merkle_path_t8_air::MAX_DEPTH` is 28, and the hard ceiling is 32
//! because `bits_to_index` returns a `u32`. So D ≤ 28 without touching that cap.
//! § A-4 claimed "D = 32 gives 4 billion"; it does not, and 2^28 ≈ 268 million
//! slots is the real figure.
//!
//! # Reuse
//!
//! Nothing new is hashed: `compress_t8` is already arithmetized
//! (`recursive::poseidon2_t8_air::prove_compress`) and paths already by
//! `recursive::merkle_path_t8_air`, whose `build_preproc_multi` takes a root PER
//! PATH — so a before/after pair against two different roots is the existing
//! shape, not an extension of it.

use crate::poseidon2_t8::compress_t8;
use crate::vfri2_bridge::{hash_pair_p2t8, p2t8_node_words, p2t8_pack};

/// Domain tag separating a NONCE leaf from an internal node and from a BATCH
/// leaf.
///
/// `NONCE_DOMAIN[i] = u32_be(SHA-256("QLSA-nonce-leaf-domain" ‖ i_be4)[..4]) mod P`
/// — the same rule as `batch_tree::LEAF_DOMAIN` and the t=8 round constants, and
/// `domain_derivation` now re-derives all three in tests instead of leaving the
/// rule in a comment.
///
/// **Distinct from `LEAF_DOMAIN` on purpose.** Both trees are built from
/// `compress_t8` over 4-word nodes, so a shared tag would make a nonce leaf and
/// a batch leaf interchangeable: a prover could present a batch leaf as a nonce
/// leaf of whatever value its words happen to encode. Forging across the two now
/// needs a preimage hashing to the other tag, ~2^124.
pub const NONCE_DOMAIN: [u64; 4] = [1561581812, 1974539750, 1096381643, 823873995];

/// Largest tree depth this module will build.
///
/// Set by `recursive::merkle_path_t8_air::MAX_DEPTH`, which is what proves these
/// paths; exceeding it would produce a tree no circuit can authenticate.
pub const MAX_DEPTH: usize = 28;

/// Bits per limb. **30, not 31**, and the difference is a correctness bug.
///
/// A 31-bit mask yields the range `[0, 2^31 - 1]`, and `2^31 - 1` IS `M31_P`,
/// which is `≡ 0` in the field. So a 31-bit limb has `P + 1` values for `P`
/// residues: limb `P` and limb `0` are the same field element, two distinct
/// nonces share a leaf, and a spent nonce becomes replayable. 30 bits caps a
/// limb at `2^30 - 1 < P`, so every limb is already reduced and the map is
/// injective.
///
/// Caught by `nonce_words_is_injective_across_the_u64_range`, which checks every
/// limb against `M31_P` rather than assuming a mask is enough. This is the third
/// time this project has hit "a packing that looks injective but is not" — the
/// others were the Poseidon2 sponge padding and the t=16 channel absorbing
/// `[1,2,3]` and `[1,2,3,0]` to one state.
///
/// `batch_tree::words_from_hash` masks to 31 bits in the same shape. There it is
/// NOT exploitable in practice — hitting a word of exactly `P` has probability
/// `2^-31`, and engineering a collision means grinding the other three words to
/// match, far past the `2^62` truncation bound that function already documents —
/// but it is the same latent defect and is recorded in `docs/TECH_DEBT.md`.
const LIMB_BITS: u32 = 30;
const LIMB_MASK: u64 = (1u64 << LIMB_BITS) - 1;

/// A nonce as the four M31 words of a `compress_t8` operand.
///
/// Three 30-bit limbs cover a full `u64` (90 ≥ 64 bits) with the fourth word
/// zero. Little-endian limb order, matching `batch_tree::words_from_hash`.
/// Injective over the whole `u64` range, and every limb is `< M31_P`.
pub fn nonce_words(nonce: u64) -> [u64; 4] {
    [
        nonce & LIMB_MASK,
        (nonce >> LIMB_BITS) & LIMB_MASK,
        (nonce >> (2 * LIMB_BITS)) & LIMB_MASK,
        0,
    ]
}

/// The leaf holding one slot's nonce.
///
/// `leaf(0)` is the empty slot, which is why it is not a special case anywhere.
pub fn nonce_leaf(nonce: u64) -> [u8; 32] {
    p2t8_pack(compress_t8(NONCE_DOMAIN, nonce_words(nonce)))
}

/// The slot index a sender owns: the first `depth` bits of its 32-byte hash.
///
/// LSB-first within the first four bytes, matching `merkle_path_t8_air`'s
/// `bits_to_index` and the `idx & 1` walk in `Poseidon2MerkleVerifierT8._verify`
/// — one bit convention across the Rust tree, the AIR and Solidity.
///
/// The CONTRACT recomputes this from the sender list; the circuit only sees the
/// result. See the module docs for why the hash cannot be checked in-circuit.
pub fn slot_index(sender_hash: &[u8; 32], depth: usize) -> Result<u32, String> {
    if depth == 0 || depth > MAX_DEPTH {
        return Err(format!("depth {depth} out of range [1, {MAX_DEPTH}]"));
    }
    let raw = u32::from_le_bytes([
        sender_hash[0],
        sender_hash[1],
        sender_hash[2],
        sender_hash[3],
    ]);
    // depth <= 28, so the shift is well-defined and never a no-op overflow.
    Ok(raw & ((1u32 << depth) - 1))
}

/// A sparse fixed-depth tree of nonce slots.
///
/// Stored sparsely: only non-empty slots are kept, and every absent slot is
/// `nonce = 0`. A dense 2^28-leaf array would be 8 GiB; the empty subtree roots
/// make the sparse form exact rather than approximate.
#[derive(Clone, Debug)]
pub struct NonceTree {
    depth: usize,
    /// Slot index -> nonce, for non-zero nonces only.
    slots: std::collections::BTreeMap<u32, u64>,
    /// `empty[k]` is the root of a complete empty subtree of height `k`.
    /// `empty[0]` is `nonce_leaf(0)`.
    empty: Vec<[u8; 32]>,
}

impl NonceTree {
    /// An all-empty tree of the given depth.
    pub fn new(depth: usize) -> Result<Self, String> {
        if depth == 0 || depth > MAX_DEPTH {
            return Err(format!("depth {depth} out of range [1, {MAX_DEPTH}]"));
        }
        // Precompute the empty subtree roots bottom-up: this is what lets a
        // 2^depth tree be represented without materialising it.
        let mut empty = Vec::with_capacity(depth + 1);
        empty.push(nonce_leaf(0));
        for k in 0..depth {
            let below = empty[k];
            empty.push(hash_pair_p2t8(&below, &below));
        }
        Ok(Self {
            depth,
            slots: std::collections::BTreeMap::new(),
            empty,
        })
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The nonce stored at `index`; 0 when the slot was never written.
    pub fn get(&self, index: u32) -> u64 {
        self.slots.get(&index).copied().unwrap_or(0)
    }

    /// Set `index` to `nonce`, rejecting anything that is not a strict increase.
    ///
    /// Strict monotonicity is the replay guarantee, enforced here as well as
    /// in-circuit so a caller building an illegal transition finds out at
    /// construction rather than from a proof that will not verify.
    pub fn set(&mut self, index: u32, nonce: u64) -> Result<(), String> {
        if index >= self.slot_count() {
            return Err(format!(
                "index {index} out of range for depth {} ({} slots)",
                self.depth,
                self.slot_count()
            ));
        }
        let current = self.get(index);
        if nonce <= current {
            return Err(format!(
                "nonce must strictly increase: slot {index} holds {current}, got {nonce}"
            ));
        }
        self.slots.insert(index, nonce);
        Ok(())
    }

    /// How many slots this depth admits.
    pub fn slot_count(&self) -> u32 {
        1u32 << self.depth
    }

    /// The node at `(height, index)`, computing empty subtrees from `empty`.
    fn node(&self, height: usize, index: u32) -> [u8; 32] {
        if height == 0 {
            return nonce_leaf(self.get(index));
        }
        // An index range with no occupied slot is an empty subtree — the whole
        // point of the sparse representation.
        let span = 1u64 << height;
        let lo = index as u64 * span;
        let hi = lo + span;
        if !self
            .slots
            .range((lo.min(u32::MAX as u64) as u32)..)
            .next()
            .is_some_and(|(&k, _)| (k as u64) < hi)
        {
            return self.empty[height];
        }
        let left = self.node(height - 1, index * 2);
        let right = self.node(height - 1, index * 2 + 1);
        hash_pair_p2t8(&left, &right)
    }

    /// The state root.
    pub fn root(&self) -> [u8; 32] {
        self.node(self.depth, 0)
    }

    /// The root as four M31 words — the shape the AIR and `InnerPublics` use.
    pub fn root_words(&self) -> [u64; 4] {
        p2t8_node_words(&self.root())
    }

    /// Siblings and direction bits authenticating `index`, LSB-first.
    ///
    /// `bits[k] == true` means the node is the RIGHT child at level `k`, so the
    /// sibling is on the left — the same convention as `batch_tree`,
    /// `merkle_path_t8_air` and `Poseidon2MerkleVerifierT8`.
    pub fn membership_proof(&self, index: u32) -> Result<(Vec<[u8; 32]>, Vec<bool>), String> {
        if index >= self.slot_count() {
            return Err(format!(
                "index {index} out of range for depth {}",
                self.depth
            ));
        }
        let mut sibs = Vec::with_capacity(self.depth);
        let mut bits = Vec::with_capacity(self.depth);
        let mut idx = index;
        for height in 0..self.depth {
            let is_right = idx & 1 == 1;
            let sib_idx = if is_right { idx - 1 } else { idx + 1 };
            sibs.push(self.node(height, sib_idx));
            bits.push(is_right);
            idx /= 2;
        }
        Ok((sibs, bits))
    }
}

/// One slot's nonce advancing from `old` to `new`, as ONE LINK of a chain.
///
/// # Why each transition carries its own pair of roots
///
/// A batch updates several slots, and each update changes the root. So N updates
/// pass through **N + 1 roots**, not two: the contract sees only the first and
/// the last, and the intermediate ones are internal to the proof. Writing this
/// struct with just the batch's `old_root` and `new_root` is wrong, and was
/// wrong here first — `a_transition_verifies_against_both_roots` failed on a
/// two-update batch because the second update's sibling path was captured after
/// the first had already moved the tree.
///
/// Hence `pre_root` / `post_root` per link, and [`verify_chain`] for the
/// property that actually matters: `post_root[i] == pre_root[i+1]`, with
/// `pre_root[0]` the stored root and `post_root[N-1]` the one written back. A
/// per-link check alone would accept a set of individually valid transitions
/// that do not compose.
///
/// Both of a link's inclusion paths are against the SAME index: the old leaf
/// under `pre_root`, the new leaf under `post_root`.
/// `recursive::merkle_path_t8_air` can already prove two paths against two
/// DIFFERENT roots in one component (its `roots` argument is per-path), so this
/// needs no change to that AIR — only the cross-path constraints tying the two
/// indices together and enforcing `new > old`, which belong in a component of
/// their own rather than in the shared path AIR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceTransition {
    pub index: u32,
    pub old_nonce: u64,
    pub new_nonce: u64,
    /// The sibling path — ONE set, shared by both inclusion proofs.
    ///
    /// A path's siblings are the subtrees hanging OFF the path; updating the
    /// leaf at its end rewrites only the nodes ON the path. So the siblings are
    /// identical before and after, and carrying them twice was redundant —
    /// found when `swapped.old_sibs = new_sibs` failed to break anything,
    /// because the two were equal. `the_sibling_path_is_unchanged_by_an_update`
    /// pins it.
    ///
    /// Two path COMPUTATIONS are still required in-circuit (the leaves and the
    /// roots differ), so § A-4 pitfall 1 stands on cost; only the witness
    /// shrinks.
    pub sibs: Vec<[u8; 32]>,
    pub bits: Vec<bool>,
    /// The state root this link starts from.
    pub pre_root: [u8; 32],
    /// The state root this link produces.
    pub post_root: [u8; 32],
}

/// Apply `updates` to `tree`, returning the old root, the new root and one
/// transition per update.
///
/// `updates` is `(sender_hash, new_nonce)`. The order of application is
/// CANONICALISED by sorting on the slot index, then on the new nonce — § A-4
/// pitfall 5: without a fixed order, one set of transactions yields different
/// new roots and the contract cannot know which to expect. Several updates to
/// the same slot (the same sender twice in a batch, or two senders sharing a
/// slot) then apply in increasing-nonce order, which is what the O(n²) on-chain
/// scan enforces today.
pub fn apply_updates(
    tree: &mut NonceTree,
    updates: &[([u8; 32], u64)],
) -> Result<([u8; 32], [u8; 32], Vec<NonceTransition>), String> {
    let old_root = tree.root();

    let mut indexed: Vec<(u32, u64)> = Vec::with_capacity(updates.len());
    for (sender_hash, new_nonce) in updates {
        indexed.push((slot_index(sender_hash, tree.depth())?, *new_nonce));
    }
    indexed.sort_unstable();

    let mut transitions = Vec::with_capacity(indexed.len());
    for (index, new_nonce) in indexed {
        let pre_root = tree.root();
        let old_nonce = tree.get(index);
        let (sibs, bits) = tree.membership_proof(index)?;
        tree.set(index, new_nonce)?;
        debug_assert_eq!(
            tree.membership_proof(index)?,
            (sibs.clone(), bits.clone()),
            "the sibling path moved, which would mean more than the leaf changed"
        );
        transitions.push(NonceTransition {
            index,
            old_nonce,
            new_nonce,
            sibs,
            bits,
            pre_root,
            post_root: tree.root(),
        });
    }

    Ok((old_root, tree.root(), transitions))
}

/// Out-of-circuit reference for what the AIR proves about ONE link.
///
/// Stated separately from the prover so the two can be cross-checked — the same
/// role `batch_tree::verify_batch_membership` plays for membership. Showing that
/// the circuit and the prover agree is not the same as showing either is right.
///
/// A valid link is NOT a valid batch: use [`verify_chain`] for that.
pub fn verify_transition(t: &NonceTransition) -> bool {
    if t.new_nonce <= t.old_nonce {
        return false;
    }
    if t.sibs.len() != t.bits.len() {
        return false;
    }
    crate::batch_tree::verify_batch_membership(
        &t.pre_root,
        &nonce_leaf(t.old_nonce),
        &t.sibs,
        &t.bits,
    ) && crate::batch_tree::verify_batch_membership(
        &t.post_root,
        &nonce_leaf(t.new_nonce),
        &t.sibs,
        &t.bits,
    )
}

/// The statement the contract needs: `old_root` becomes `new_root` legally.
///
/// Every link must verify, AND the links must compose — `post_root[i]` is
/// `pre_root[i+1]`, the chain starts at `old_root` and ends at `new_root`. The
/// linkage is the part a per-link check cannot see: a prover could otherwise
/// present N individually valid transitions taken from unrelated states and
/// claim they move the stored root to one of its choosing.
///
/// An empty batch is the identity: no links, and `old_root == new_root`.
pub fn verify_chain(
    transitions: &[NonceTransition],
    old_root: &[u8; 32],
    new_root: &[u8; 32],
) -> bool {
    if transitions.is_empty() {
        return old_root == new_root;
    }
    if &transitions[0].pre_root != old_root {
        return false;
    }
    if &transitions[transitions.len() - 1].post_root != new_root {
        return false;
    }
    for (i, t) in transitions.iter().enumerate() {
        if !verify_transition(t) {
            return false;
        }
        if i + 1 < transitions.len() && t.post_root != transitions[i + 1].pre_root {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: usize = 8;

    fn sender(i: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = i;
        h[1] = i.wrapping_mul(7);
        h
    }

    // ── The domain tag ────────────────────────────────────────────────────────

    #[test]
    fn nonce_domain_matches_the_documented_rule() {
        // The tag is load-bearing; a literal that is not what its comment says
        // would separate nothing. Until 2026-10-04 nothing checked any of these.
        assert_eq!(
            crate::domain_derivation::derive_domain4("QLSA-nonce-leaf-domain"),
            NONCE_DOMAIN,
        );
    }

    #[test]
    fn the_nonce_tag_differs_from_the_batch_leaf_tag() {
        // Both trees compress 4-word nodes with the same function. Equal tags
        // would make a batch leaf presentable as a nonce leaf.
        assert_ne!(NONCE_DOMAIN, crate::batch_tree::LEAF_DOMAIN);
        assert_ne!(nonce_leaf(0), crate::batch_tree::batch_leaf([0; 4], [0; 4]));
    }

    // ── The leaf ──────────────────────────────────────────────────────────────

    #[test]
    fn nonce_words_is_injective_across_the_u64_range() {
        // Values chosen around every limb boundary (30 and 60 bits) and around
        // M31_P itself, which is where a 31-bit mask used to fold two nonces
        // onto one field element.
        let probes = [
            0u64,
            1,
            2,
            (1u64 << 30) - 1,
            1u64 << 30,
            crate::poseidon2::M31_P - 1,
            crate::poseidon2::M31_P,
            crate::poseidon2::M31_P + 1,
            (1u64 << 60) - 1,
            1u64 << 60,
            u64::MAX,
        ];
        let mut seen = std::collections::HashSet::new();
        for n in probes {
            assert!(seen.insert(nonce_words(n)), "nonce_words collided at {n}");
            // Every limb must be a valid M31 word or compress_t8 is being fed
            // an out-of-range operand.
            for w in nonce_words(n) {
                assert!(w < crate::poseidon2::M31_P, "limb {w} not reduced for {n}");
            }
        }
    }

    #[test]
    fn distinct_nonces_give_distinct_leaves() {
        let leaves: std::collections::HashSet<_> =
            (0u64..64).map(nonce_leaf).collect();
        assert_eq!(leaves.len(), 64);
    }

    // ── Slot indexing ─────────────────────────────────────────────────────────

    #[test]
    fn slot_index_is_bounded_by_depth_and_rejects_bad_depths() {
        for d in 1..=16 {
            let i = slot_index(&sender(200), d).unwrap();
            assert!(i < (1u32 << d), "index {i} exceeds depth {d}");
        }
        assert!(slot_index(&sender(1), 0).is_err());
        assert!(slot_index(&sender(1), MAX_DEPTH + 1).is_err());
    }

    #[test]
    fn max_depth_does_not_exceed_what_the_air_can_prove() {
        // The accumulator's depth is capped by the AIR that authenticates its
        // paths, not by this module's preference. A tree deeper than the AIR
        // allows would be unprovable — the exact mistake § A-4 made by writing
        // "D = 32 gives 4 billion".
        assert!(MAX_DEPTH <= crate::recursive::merkle_path_t8_air::MAX_DEPTH);
    }

    // ── The tree ──────────────────────────────────────────────────────────────

    #[test]
    fn an_empty_tree_has_a_deterministic_root() {
        let a = NonceTree::new(D).unwrap();
        let b = NonceTree::new(D).unwrap();
        assert_eq!(a.root(), b.root());
        // Non-zero: BatchRegistryV7 rejects a zero merkleRoot, and a state root
        // will face the same guard.
        assert_ne!(a.root(), [0u8; 32]);
    }

    #[test]
    fn an_unseen_slot_reads_zero_and_is_a_normal_membership_proof() {
        // THE property that removes the first-time-sender branch from the
        // circuit: "never seen" is just "nonce = 0", proved by an ordinary path.
        let tree = NonceTree::new(D).unwrap();
        let idx = slot_index(&sender(3), D).unwrap();
        assert_eq!(tree.get(idx), 0);
        let (sibs, bits) = tree.membership_proof(idx).unwrap();
        assert!(crate::batch_tree::verify_batch_membership(
            &tree.root(),
            &nonce_leaf(0),
            &sibs,
            &bits
        ));
    }

    #[test]
    fn writing_a_slot_moves_the_root_and_authenticates() {
        let mut tree = NonceTree::new(D).unwrap();
        let before = tree.root();
        let idx = slot_index(&sender(5), D).unwrap();
        tree.set(idx, 7).unwrap();
        assert_ne!(tree.root(), before, "the root must change");
        assert_eq!(tree.get(idx), 7);
        let (sibs, bits) = tree.membership_proof(idx).unwrap();
        assert!(crate::batch_tree::verify_batch_membership(
            &tree.root(),
            &nonce_leaf(7),
            &sibs,
            &bits
        ));
    }

    #[test]
    fn the_sibling_path_is_unchanged_by_an_update() {
        // Why NonceTransition carries ONE sibling set. A path's siblings hang
        // OFF the path; writing the leaf at its end rewrites only nodes ON it.
        // Checked at several depths and on an occupied neighbourhood, so it is
        // not an accident of the empty tree.
        for d in [1usize, 4, 8] {
            let mut tree = NonceTree::new(d).unwrap();
            for i in 0..(1u32 << d).min(6) {
                tree.set(i, u64::from(i) + 1).unwrap();
            }
            let idx = 0u32;
            let (before, bits_before) = tree.membership_proof(idx).unwrap();
            tree.set(idx, 1_000).unwrap();
            let (after, bits_after) = tree.membership_proof(idx).unwrap();
            assert_eq!(before, after, "siblings moved at depth {d}");
            assert_eq!(bits_before, bits_after, "direction bits moved at depth {d}");
        }
    }

    #[test]
    fn a_stale_leaf_does_not_authenticate_against_the_new_root() {
        let mut tree = NonceTree::new(D).unwrap();
        let idx = slot_index(&sender(5), D).unwrap();
        tree.set(idx, 7).unwrap();
        let (sibs, bits) = tree.membership_proof(idx).unwrap();
        assert!(!crate::batch_tree::verify_batch_membership(
            &tree.root(),
            &nonce_leaf(0),
            &sibs,
            &bits
        ));
    }

    #[test]
    fn the_sparse_tree_agrees_with_a_dense_one() {
        // The empty-subtree shortcut is an optimisation; it must be EXACT, not
        // approximate. Checked against a fully materialised tree at a depth
        // small enough to build.
        let d = 4usize;
        let mut sparse = NonceTree::new(d).unwrap();
        let mut dense = vec![0u64; 1 << d];
        for (idx, nonce) in [(0u32, 5u64), (3, 1), (9, 42), (15, 7)] {
            sparse.set(idx, nonce).unwrap();
            dense[idx as usize] = nonce;
        }

        let mut level: Vec<[u8; 32]> = dense.iter().map(|&n| nonce_leaf(n)).collect();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|p| hash_pair_p2t8(&p[0], &p[1]))
                .collect();
        }
        assert_eq!(sparse.root(), level[0]);
    }

    // ── Monotonicity: the replay guarantee ───────────────────────────────────

    #[test]
    fn a_nonce_must_strictly_increase() {
        let mut tree = NonceTree::new(D).unwrap();
        let idx = 1u32;
        tree.set(idx, 5).unwrap();
        assert!(tree.set(idx, 5).is_err(), "equal must be rejected");
        assert!(tree.set(idx, 4).is_err(), "lower must be rejected");
        tree.set(idx, 6).unwrap();
    }

    #[test]
    fn set_rejects_an_out_of_range_index() {
        let mut tree = NonceTree::new(4).unwrap();
        assert!(tree.set(16, 1).is_err());
        assert!(tree.set(15, 1).is_ok());
    }

    // ── Transitions ──────────────────────────────────────────────────────────

    #[test]
    fn a_multi_update_batch_forms_a_verifying_chain() {
        // Three updates pass through FOUR roots. This is the test that caught
        // the single-pair design: with only (old_root, new_root) per link, the
        // second update's path is against an intermediate root and fails.
        let mut tree = NonceTree::new(D).unwrap();
        let (old_root, new_root, ts) =
            apply_updates(&mut tree, &[(sender(1), 1), (sender(2), 1), (sender(3), 4)])
                .unwrap();
        assert_eq!(ts.len(), 3);
        assert_ne!(old_root, new_root);
        for t in &ts {
            assert!(verify_transition(t), "link {} does not verify", t.index);
        }
        assert!(verify_chain(&ts, &old_root, &new_root));
    }

    #[test]
    fn an_empty_batch_is_the_identity() {
        let mut tree = NonceTree::new(D).unwrap();
        let (old_root, new_root, ts) = apply_updates(&mut tree, &[]).unwrap();
        assert!(ts.is_empty());
        assert_eq!(old_root, new_root);
        assert!(verify_chain(&ts, &old_root, &new_root));
    }

    #[test]
    fn a_forged_transition_does_not_verify() {
        let mut tree = NonceTree::new(D).unwrap();
        let (old_root, new_root, ts) =
            apply_updates(&mut tree, &[(sender(1), 3)]).unwrap();
        let t = &ts[0];
        assert!(verify_transition(t));

        // Claiming a different new nonce with the same path fails: the new leaf
        // no longer hashes to post_root.
        let mut lying = t.clone();
        lying.new_nonce = 99;
        assert!(!verify_transition(&lying));

        // A non-increasing nonce is refused outright — the replay guarantee.
        let mut backwards = t.clone();
        backwards.new_nonce = t.old_nonce;
        assert!(!verify_transition(&backwards));

        // A tampered sibling reaches neither root.
        let mut tampered = t.clone();
        tampered.sibs[0] = nonce_leaf(123_456);
        assert!(!verify_transition(&tampered));

        // Flipping a direction bit walks to a different index.
        let mut flipped = t.clone();
        flipped.bits[0] = !flipped.bits[0];
        assert!(!verify_transition(&flipped));

        // A truncated path cannot reach a root of this depth.
        let mut short = t.clone();
        short.sibs.pop();
        assert!(!verify_transition(&short));

        // And the chain rejects a link that does not start where it claims.
        let mut detached = t.clone();
        detached.pre_root = new_root;
        assert!(!verify_chain(&[detached], &old_root, &new_root));
    }

    #[test]
    fn a_broken_chain_is_rejected_though_every_link_verifies() {
        // THE property a per-link check cannot see. Two batches are applied to
        // SEPARATE trees, so each link is internally valid, but link 1 does not
        // start where link 0 ended. Splicing them must not pass for a
        // transition of the stored root.
        let mut a = NonceTree::new(D).unwrap();
        let mut b = NonceTree::new(D).unwrap();
        let (old_root, _, ts_a) = apply_updates(&mut a, &[(sender(1), 1)]).unwrap();
        let (_, new_root_b, ts_b) = apply_updates(&mut b, &[(sender(2), 1)]).unwrap();

        let spliced = vec![ts_a[0].clone(), ts_b[0].clone()];
        for t in &spliced {
            assert!(verify_transition(t), "each link must be valid on its own");
        }
        assert!(
            !verify_chain(&spliced, &old_root, &new_root_b),
            "a spliced chain must be refused"
        );
    }

    #[test]
    fn a_chain_that_does_not_end_at_the_claimed_new_root_is_rejected() {
        let mut tree = NonceTree::new(D).unwrap();
        let (old_root, new_root, ts) =
            apply_updates(&mut tree, &[(sender(1), 1), (sender(2), 2)]).unwrap();
        assert!(verify_chain(&ts, &old_root, &new_root));
        // Dropping the last link leaves a chain ending at an intermediate root;
        // claiming new_root for it must fail.
        assert!(!verify_chain(&ts[..1], &old_root, &new_root));
    }

    #[test]
    fn two_updates_to_one_slot_apply_in_increasing_nonce_order() {
        // The same sender twice in a batch, which the on-chain O(n^2) scan
        // handles today by requiring strict increase among duplicates.
        let mut tree = NonceTree::new(D).unwrap();
        let s = sender(11);
        let (_, _, ts) = apply_updates(&mut tree, &[(s, 2), (s, 5)]).unwrap();
        assert_eq!(ts.len(), 2);
        assert_eq!((ts[0].old_nonce, ts[0].new_nonce), (0, 2));
        assert_eq!((ts[1].old_nonce, ts[1].new_nonce), (2, 5));
        assert_eq!(tree.get(slot_index(&s, D).unwrap()), 5);
    }

    #[test]
    fn out_of_order_duplicates_are_refused_not_silently_reordered() {
        // Sorting is by (index, nonce), so a descending pair for one slot is
        // applied ascending — but a pair that cannot increase at all must fail
        // rather than quietly drop one update.
        let mut tree = NonceTree::new(D).unwrap();
        let s = sender(12);
        tree.set(slot_index(&s, D).unwrap(), 10).unwrap();
        assert!(apply_updates(&mut tree, &[(s, 3)]).is_err());
    }

    #[test]
    fn the_application_order_is_canonical() {
        // § A-4 pitfall 5: one set of updates must give ONE new root, whatever
        // order the caller supplies them in. Otherwise the contract cannot know
        // which root to expect.
        let updates = [(sender(1), 4u64), (sender(2), 9), (sender(3), 2)];
        let mut reversed: Vec<_> = updates.to_vec();
        reversed.reverse();

        let mut a = NonceTree::new(D).unwrap();
        let mut b = NonceTree::new(D).unwrap();
        let (_, root_a, ta) = apply_updates(&mut a, &updates).unwrap();
        let (_, root_b, tb) = apply_updates(&mut b, &reversed).unwrap();

        assert_eq!(root_a, root_b, "the new root depends on input order");
        assert_eq!(ta, tb, "the transitions depend on input order");
    }

    #[test]
    fn new_rejects_a_depth_the_air_cannot_prove() {
        assert!(NonceTree::new(0).is_err());
        assert!(NonceTree::new(MAX_DEPTH + 1).is_err());
        assert!(NonceTree::new(MAX_DEPTH).is_ok());
    }

    #[test]
    fn colliding_senders_share_a_counter_rather_than_losing_access() {
        // Pitfall 6, asserted rather than argued: at a small depth two senders
        // WILL share a slot. Both must remain able to advance it; neither may
        // be locked out. That is the whole reason the leaf excludes the sender.
        let d = 2usize; // 4 slots — a collision is forced
        let mut tree = NonceTree::new(d).unwrap();
        let mut by_slot: std::collections::HashMap<u32, Vec<u8>> = Default::default();
        for i in 0..32u8 {
            by_slot
                .entry(slot_index(&sender(i), d).unwrap())
                .or_default()
                .push(i);
        }
        let (_, sharers) = by_slot
            .iter()
            .find(|(_, v)| v.len() >= 2)
            .expect("depth 2 over 32 senders must collide");
        let (a, b) = (sender(sharers[0]), sender(sharers[1]));
        assert_eq!(
            slot_index(&a, d).unwrap(),
            slot_index(&b, d).unwrap(),
            "test setup: these senders must collide"
        );

        // A advances, then B advances the SAME slot — both succeed.
        let (_, _, ta) = apply_updates(&mut tree, &[(a, 1)]).unwrap();
        assert_eq!(ta[0].new_nonce, 1);
        let (_, _, tb) = apply_updates(&mut tree, &[(b, 2)]).unwrap();
        assert_eq!((tb[0].old_nonce, tb[0].new_nonce), (1, 2));

        // And replay is still impossible: B cannot reuse A's nonce.
        assert!(apply_updates(&mut tree, &[(b, 1)]).is_err());
    }
}
