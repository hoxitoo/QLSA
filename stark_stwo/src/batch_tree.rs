//! The batch Merkle tree, on a hash the recursion can prove.
//!
//! # Why this exists
//!
//! `core/merkle.py` builds the batch tree with **SHA3-512**. That is fine as a
//! commitment — the contracts treat the root as an opaque `bytes32`, mixing it
//! into `keccak256(merkleRoot ‖ traceRoot)` and the commitment, never
//! recomputing it — but it cannot be *proved*: authenticating a SHA3 path
//! in-circuit means arithmetizing Keccak-f[1600], which is A-1 in
//! `docs/TECH_DEBT.md` ("not started, not scheduled").
//!
//! That blocks A-5. The aggregation tree proves N signatures were verified
//! *under* a batch root; it does not prove they are that root's *members*,
//! because no inclusion path is proved. `merkle_path_t8_air` already
//! authenticates Poseidon2-t8 paths — it is what the FRI-layer decommitments
//! use — so a batch tree on the SAME hash makes the membership proof a matter
//! of wiring rather than a new gadget.
//!
//! # The part that is not mechanical: encoding
//!
//! Poseidon2 hashes field elements; a leaf is arbitrary transaction bytes. The
//! bytes → M31 map must be **injective**, or two different transactions share a
//! leaf and the membership proof means nothing.
//!
//! The obvious 4-bytes-to-a-`u32` fails: a `u32` reaches `2^32 - 1 = 2P + 1`,
//! so reduction maps three distinct words onto some residues. Instead this
//! packs **3 bytes** per word (`2^24 < P`, so no reduction happens at all) and
//! appends the byte length. Injective in both directions: equal lengths force a
//! chunk to differ, and unequal lengths differ in the last word.
//!
//! The length word is not decoration. Without it `[1,2,3]` and `[1,2,3,0]` pack
//! to the same chunks — exactly the collision the t=16 channel's padding had
//! (R4.22), where a constant pad let two different absorbed sequences reach one
//! state. A length-carrying tail is the fix in both places.

use crate::vfri2_bridge::{hash_leaf_cols_p2t8, hash_pair_p2t8, p2t8_node_words, p2t8_pack};

/// Bytes per packed word. `2^24 < P = 2^31 - 1`, so a chunk is already reduced
/// and the packing is injective without any modular arithmetic.
const BYTES_PER_WORD: usize = 3;

/// A batch of this many bytes would not fit the length word, and is far past
/// anything a batch could hold.
pub const MAX_LEAF_BYTES: usize = 1 << 30;

/// The largest batch the tree will build. A runaway guard: 2^20 leaves is
/// already three orders of magnitude past the ~150 the on-chain nonce writes
/// admit (A-4).
pub const MAX_LEAVES: usize = 1 << 20;

/// Pack bytes into M31 words, injectively.
///
/// Three bytes per word little-endian, then the byte length as a final word.
/// See the module docs for why the length word is load-bearing.
pub fn bytes_to_m31_words(data: &[u8]) -> Result<Vec<u32>, String> {
    if data.len() >= MAX_LEAF_BYTES {
        return Err(format!(
            "leaf of {} bytes exceeds MAX_LEAF_BYTES {MAX_LEAF_BYTES}", data.len()));
    }
    let mut words = Vec::with_capacity(data.len() / BYTES_PER_WORD + 2);
    for chunk in data.chunks(BYTES_PER_WORD) {
        let mut w = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            w |= (b as u32) << (8 * i);
        }
        words.push(w);
    }
    words.push(data.len() as u32);
    Ok(words)
}

/// Hash one leaf's bytes to a 4-word Poseidon2-t8 node.
pub fn batch_leaf_hash(data: &[u8]) -> Result<[u8; 32], String> {
    Ok(hash_leaf_cols_p2t8(&bytes_to_m31_words(data)?))
}

/// A node as the recursion AIR carries it: four M31 words.
///
/// The tree stores nodes as `[u8; 32]` because that is what the FRI-layer trees
/// and the Solidity verifier use; `merkle_path_t8_air` works in words. Same
/// value, two shapes — this is the seam where they meet, so it is one function
/// rather than an open-coded conversion at each call site.
pub fn node_words(node: &[u8; 32]) -> [u64; 4] {
    p2t8_node_words(node)
}

/// A built batch tree: level 0 is the leaf hashes, the last level is the root.
pub struct BatchTree {
    pub levels: Vec<Vec<[u8; 32]>>,
}

impl BatchTree {
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().expect("a tree has ≥ 1 level")[0]
    }

    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// Path depth — the number of siblings an inclusion proof carries.
    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// The inclusion path for one leaf: siblings bottom-up, and the direction
    /// bits (`true` = this node is the RIGHT child, so the sibling is on the
    /// left), matching `merkle_path_t8_air`'s convention.
    pub fn membership_proof(&self, index: usize) -> Result<(Vec<[u8; 32]>, Vec<bool>), String> {
        if index >= self.leaf_count() {
            return Err(format!(
                "leaf index {index} out of range for {} leaves", self.leaf_count()));
        }
        let mut sibs = Vec::with_capacity(self.depth());
        let mut bits = Vec::with_capacity(self.depth());
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sib = idx ^ 1;
            // A level of odd width duplicates its last node, so the sibling of
            // the final element is itself.
            sibs.push(level[sib.min(level.len() - 1)]);
            bits.push(idx & 1 == 1);
            idx /= 2;
        }
        Ok((sibs, bits))
    }
}

/// Build the batch tree over raw leaf bytes.
pub fn build_batch_tree(leaves: &[Vec<u8>]) -> Result<BatchTree, String> {
    if leaves.is_empty() {
        return Err("a batch tree needs ≥ 1 leaf".into());
    }
    if leaves.len() > MAX_LEAVES {
        return Err(format!("leaf count {} exceeds MAX_LEAVES {MAX_LEAVES}", leaves.len()));
    }

    let mut level: Vec<[u8; 32]> = leaves
        .iter()
        .map(|l| batch_leaf_hash(l))
        .collect::<Result<_, _>>()?;
    let mut levels = vec![level.clone()];

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            // An odd level duplicates its last node rather than padding with a
            // constant: a fixed pad value would be a leaf an adversary could
            // also supply, and then a short batch and a padded one collide.
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            next.push(hash_pair_p2t8(&pair[0], right));
        }
        level = next;
        levels.push(level.clone());
    }

    Ok(BatchTree { levels })
}

/// Recompute a root from an inclusion path — what the AIR proves in-circuit,
/// stated here so the two can be cross-checked.
pub fn verify_batch_membership(
    root: &[u8; 32],
    leaf: &[u8; 32],
    sibs: &[[u8; 32]],
    bits: &[bool],
) -> bool {
    if sibs.len() != bits.len() {
        return false;
    }
    let mut cur = *leaf;
    for (sib, &right) in sibs.iter().zip(bits) {
        cur = if right { hash_pair_p2t8(sib, &cur) } else { hash_pair_p2t8(&cur, sib) };
    }
    cur == *root
}

// ── A-5: the leaf that binds a batch member to the proof of its signature ────

/// Domain tag separating a LEAF from an internal node.
///
/// `LEAF_DOMAIN[i] = u32_be(SHA-256("QLSA-batch-leaf-domain" ‖ i_be4)[..4]) mod P`,
/// the same derivation rule the t=8 round constants use — regenerable, not
/// picked by hand.
///
/// **This is load-bearing, not decoration.** An internal node is
/// `compress_t8(left, right)`; if a leaf were the same function of its operands,
/// a leaf and an internal node would be indistinguishable, which is the classic
/// second-preimage attack on a Merkle tree — an attacker presents an internal
/// node as a leaf and claims membership for something never inserted. Today's
/// `batch_leaf_hash` is separated only by accident (leaf = sponge, node =
/// compression); a compression-based leaf loses that accident and has to say it.
/// Forging a leaf into an internal node now needs a preimage hashing to
/// `LEAF_DOMAIN`, i.e. ~2^124.
pub const LEAF_DOMAIN: [u64; 4] = [1421959497, 1730427068, 1993284430, 1732805141];

/// The first 124 bits of a 32-byte hash, as four M31 words.
///
/// Used for BOTH operands of a leaf — the transaction hash and the Stwo trace
/// root are both 32-byte digests and get the same treatment, so the truncation
/// is written once rather than twice.
///
/// 31 bits per word, so the four words are already reduced and no modular
/// arithmetic runs. **This truncates**: two digests agreeing on
/// the first 124 bits collide, at ~2^62 work. That is exactly the t=8
/// node-collision bound the whole tree already has, so it weakens nothing — but
/// it is a truncation and is recorded as one rather than left to be discovered.
pub fn words_from_hash(digest: &[u8; 32]) -> [u64; 4] {
    let mut bits = 0u128;
    for (i, &b) in digest.iter().take(16).enumerate() {
        bits |= (b as u128) << (8 * i);
    }
    std::array::from_fn(|i| ((bits >> (31 * i)) & 0x7fff_ffff) as u64)
}

/// A batch leaf: the transaction's identity compressed with the trace root of
/// the proof that verifies its signature.
///
/// ```text
///     leaf = compress_t8( LEAF_DOMAIN, compress_t8(tx_id, trace_root) )
/// ```
///
/// # What this proves, and what it does not
///
/// With this leaf shape the circuit can prove two things it could not before:
/// that it verified the statement of THIS trace root, and that a leaf carrying
/// that trace root is a member of the batch root. Until now nothing connected
/// the batch root to any proof at all (`core/batch.py` hashes `tx.tx_hash()`,
/// and the registry never interprets the root — it is a batch id and a
/// cross-binding operand).
///
/// What it does NOT prove is that `tx_id` and `trace_root` belong together: that
/// pairing is asserted by the aggregator. The residual trust is the same one
/// limitation 0 already names — the aggregator pairing a witness with a claimed
/// signature — not a new one. A-5 closes membership *modulo* that, and saying so
/// is the point: "membership proved" without this sentence reads as more than it
/// is.
///
/// Built from `compress_t8` rather than the leaf sponge because `compress_t8` is
/// already arithmetized (`recursive::poseidon2_t8_air::prove_compress`) while a
/// rate-4 sponge AIR does not exist — so membership needs no new gadget.
pub fn batch_leaf(tx_id: [u64; 4], trace_root: [u64; 4]) -> [u8; 32] {
    let inner = crate::poseidon2_t8::compress_t8(tx_id, trace_root);
    p2t8_pack(crate::poseidon2_t8::compress_t8(LEAF_DOMAIN, inner))
}

/// Build a batch tree over `(tx_id, trace_root)` pairs.
pub fn build_batch_tree_bound(pairs: &[([u64; 4], [u64; 4])]) -> Result<BatchTree, String> {
    if pairs.is_empty() {
        return Err("a batch tree needs ≥ 1 leaf".into());
    }
    if pairs.len() > MAX_LEAVES {
        return Err(format!("leaf count {} exceeds MAX_LEAVES {MAX_LEAVES}", pairs.len()));
    }
    let mut level: Vec<[u8; 32]> = pairs.iter().map(|(t, r)| batch_leaf(*t, *r)).collect();
    let mut levels = vec![level.clone()];
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            next.push(hash_pair_p2t8(&pair[0], right));
        }
        level = next;
        levels.push(level.clone());
    }
    Ok(BatchTree { levels })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_packing_is_injective_over_a_trailing_zero() {
        // The collision the length word exists to prevent, and the same one the
        // t=16 channel's constant pad had (R4.22).
        let a = bytes_to_m31_words(&[1, 2, 3]).unwrap();
        let b = bytes_to_m31_words(&[1, 2, 3, 0]).unwrap();
        assert_ne!(a, b, "a trailing zero byte must change the packing");
        assert_ne!(batch_leaf_hash(&[1, 2, 3]).unwrap(), batch_leaf_hash(&[1, 2, 3, 0]).unwrap());
    }

    #[test]
    fn every_packed_word_is_already_a_field_element() {
        // 3 bytes < 2^24 < P, so no reduction runs and none can collide.
        let data: Vec<u8> = (0..=255u8).collect();
        for w in bytes_to_m31_words(&data).unwrap() {
            assert!(w < crate::poseidon2::M31_P as u32, "word {w} is not reduced");
        }
    }

    #[test]
    fn distinct_byte_strings_pack_distinctly() {
        let mut seen = std::collections::HashSet::new();
        // From len 1: at length 0 every seed makes the same empty string, so a
        // "collision" there would be my test data, not the packing.
        for len in 1..40usize {
            for seed in 0..8u8 {
                let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect();
                assert!(seen.insert(bytes_to_m31_words(&data).unwrap()),
                        "collision at len {len} seed {seed}");
            }
        }
    }

    #[test]
    fn an_empty_leaf_is_not_a_zero_leaf() {
        assert_ne!(batch_leaf_hash(&[]).unwrap(), batch_leaf_hash(&[0]).unwrap());
    }

    #[test]
    fn every_leaf_of_a_tree_proves_its_membership() {
        for n in [1usize, 2, 3, 5, 8, 17] {
            let leaves: Vec<Vec<u8>> = (0..n).map(|i| format!("tx-{i}").into_bytes()).collect();
            let tree = build_batch_tree(&leaves).unwrap();
            let root = tree.root();
            for (i, leaf) in leaves.iter().enumerate() {
                let (sibs, bits) = tree.membership_proof(i).unwrap();
                assert!(
                    verify_batch_membership(&root, &batch_leaf_hash(leaf).unwrap(), &sibs, &bits),
                    "leaf {i} of {n} failed to prove membership");
            }
        }
    }

    #[test]
    fn a_leaf_outside_the_batch_does_not_prove_membership() {
        let leaves: Vec<Vec<u8>> = (0..4).map(|i| format!("tx-{i}").into_bytes()).collect();
        let tree = build_batch_tree(&leaves).unwrap();
        let (sibs, bits) = tree.membership_proof(1).unwrap();
        let outsider = batch_leaf_hash(b"tx-not-in-the-batch").unwrap();
        assert!(!verify_batch_membership(&tree.root(), &outsider, &sibs, &bits));
    }

    #[test]
    fn a_tampered_sibling_does_not_prove_membership() {
        let leaves: Vec<Vec<u8>> = (0..4).map(|i| format!("tx-{i}").into_bytes()).collect();
        let tree = build_batch_tree(&leaves).unwrap();
        let (mut sibs, bits) = tree.membership_proof(2).unwrap();
        // Byte 31, not byte 0: a t=8 node is FOUR words in bytes[16..32], and the
        // leading 16 bytes are padding the hash never reads. Flipping byte 0 is
        // not a tamper — the first version of this test did, and failed, which is
        // the test doing its job.
        sibs[0][31] ^= 1;
        assert!(!verify_batch_membership(
            &tree.root(), &batch_leaf_hash(&leaves[2]).unwrap(), &sibs, &bits));
    }

    #[test]
    fn the_direction_bits_are_load_bearing() {
        // Flipping a bit re-associates the path; only a symmetric tree survives.
        let leaves: Vec<Vec<u8>> = (0..4).map(|i| format!("tx-{i}").into_bytes()).collect();
        let tree = build_batch_tree(&leaves).unwrap();
        let (sibs, mut bits) = tree.membership_proof(1).unwrap();
        bits[0] = !bits[0];
        assert!(!verify_batch_membership(
            &tree.root(), &batch_leaf_hash(&leaves[1]).unwrap(), &sibs, &bits));
    }

    #[test]
    fn a_t8_node_lives_in_the_low_16_bytes() {
        // Four M31 words occupy bytes[16..32]; the leading 16 bytes are padding
        // the hash does not read. Recorded because a Merkle check that compares
        // whole 32-byte nodes is comparing 16 bytes of nothing — fine here, since
        // every node this module produces is hash output with a zero prefix, but
        // not something to rely on for an externally supplied node.
        let a = batch_leaf_hash(b"leaf").unwrap();
        let mut b = a;
        b[0] ^= 0xff;
        assert_eq!(hash_pair_p2t8(&a, &a), hash_pair_p2t8(&b, &b),
                   "the high bytes must not affect the hash");
        assert_eq!(&a[..16], &[0u8; 16], "hash output has a zero prefix");
    }

    #[test]
    fn a_different_batch_has_a_different_root() {
        let a: Vec<Vec<u8>> = (0..4).map(|i| format!("tx-{i}").into_bytes()).collect();
        let mut b = a.clone();
        b[3] = b"tx-3-altered".to_vec();
        assert_ne!(build_batch_tree(&a).unwrap().root(), build_batch_tree(&b).unwrap().root());
    }

    #[test]
    fn reordering_a_batch_changes_its_root() {
        let a: Vec<Vec<u8>> = (0..4).map(|i| format!("tx-{i}").into_bytes()).collect();
        let mut b = a.clone();
        b.swap(0, 1);
        assert_ne!(build_batch_tree(&a).unwrap().root(), build_batch_tree(&b).unwrap().root());
    }

    #[test]
    fn the_circuit_accepts_a_path_from_this_tree() {
        // The point of the module. A batch tree whose paths the recursion cannot
        // authenticate would close nothing: the leaf and pair hashes must be the
        // SAME ones `merkle_path_t8_air` arithmetizes, not merely similar.
        use crate::recursive::merkle_path_t8_air::{prove_merkle_path_t8, verify_merkle_path_t8};

        let leaves: Vec<Vec<u8>> = (0..8).map(|i| format!("tx-{i}").into_bytes()).collect();
        let tree = build_batch_tree(&leaves).unwrap();
        let index = 5usize;
        let (sibs, bits) = tree.membership_proof(index).unwrap();

        let leaf_w = node_words(&batch_leaf_hash(&leaves[index]).unwrap());
        let sibs_w: Vec<[u64; 4]> = sibs.iter().map(node_words).collect();

        let (proof, log_size, root_w) = prove_merkle_path_t8(leaf_w, &sibs_w, &bits).unwrap();
        assert_eq!(root_w, node_words(&tree.root()),
                   "the circuit's root must be the tree's root");
        assert!(verify_merkle_path_t8(
            &proof, log_size, sibs.len(), leaf_w, index as u32, root_w).unwrap());
    }

    #[test]
    fn the_circuit_rejects_a_leaf_outside_the_batch() {
        use crate::recursive::merkle_path_t8_air::{prove_merkle_path_t8, verify_merkle_path_t8};

        let leaves: Vec<Vec<u8>> = (0..8).map(|i| format!("tx-{i}").into_bytes()).collect();
        let tree = build_batch_tree(&leaves).unwrap();
        let (sibs, bits) = tree.membership_proof(5).unwrap();
        let sibs_w: Vec<[u64; 4]> = sibs.iter().map(node_words).collect();

        let outsider = node_words(&batch_leaf_hash(b"tx-not-in-the-batch").unwrap());
        let (proof, log_size, root_w) = prove_merkle_path_t8(outsider, &sibs_w, &bits).unwrap();
        // The prover can always prove SOME root for its own leaf; what it cannot
        // do is land on the batch's root.
        assert_ne!(root_w, node_words(&tree.root()));
        assert!(!verify_merkle_path_t8(
            &proof, log_size, sibs.len(), outsider, 5, node_words(&tree.root())).unwrap());
    }

// ── A-5: the bound leaf ─────────────────────────────────────────────────

    fn w(n: u64) -> [u64; 4] { [n, n + 1, n + 2, n + 3] }

    #[test]
    fn a_leaf_is_not_an_internal_node_over_the_same_operands() {
        // The reason LEAF_DOMAIN exists. Without it both would be
        // compress_t8(a, b) and an attacker could present an internal node as a
        // leaf — the classic Merkle second-preimage attack.
        let (a, b) = (w(10), w(100));
        let leaf = batch_leaf(a, b);
        let internal = hash_pair_p2t8(&p2t8_pack(a), &p2t8_pack(b));
        assert_ne!(leaf, internal, "a leaf must not collide with an internal node");
    }

    #[test]
    fn the_trace_root_changes_the_leaf() {
        assert_ne!(batch_leaf(w(1), w(50)), batch_leaf(w(1), w(60)));
    }

    #[test]
    fn the_transaction_changes_the_leaf() {
        assert_ne!(batch_leaf(w(1), w(50)), batch_leaf(w(2), w(50)));
    }

    #[test]
    fn words_from_hash_is_deterministic_and_reduced() {
        let h: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let a = words_from_hash(&h);
        assert_eq!(a, words_from_hash(&h), "must be a function of the hash alone");
        for v in a {
            assert!(v < crate::poseidon2::M31_P, "word {v} is not a field element");
        }
        // It reads the FIRST 16 bytes: touching byte 0 moves it, byte 31 does not.
        let mut h0 = h; h0[0] ^= 1;
        assert_ne!(a, words_from_hash(&h0));
        let mut h31 = h; h31[31] ^= 1;
        assert_eq!(a, words_from_hash(&h31), "documented truncation to 124 bits");
    }

    #[test]
    fn every_bound_leaf_proves_its_membership() {
        for n in [1usize, 2, 3, 5, 8] {
            let pairs: Vec<_> = (0..n).map(|i| (w(i as u64 * 7), w(1000 + i as u64 * 13))).collect();
            let tree = build_batch_tree_bound(&pairs).unwrap();
            let root = tree.root();
            for (i, (tx, tr)) in pairs.iter().enumerate() {
                let (sibs, bits) = tree.membership_proof(i).unwrap();
                assert!(verify_batch_membership(&root, &batch_leaf(*tx, *tr), &sibs, &bits),
                        "leaf {i} of {n}");
            }
        }
    }

    /// **This is what A-5 is about.** Everything else shows that something
    /// hashes; this shows that a signature proved under a DIFFERENT trace root
    /// cannot claim membership in the batch.
    #[test]
    fn a_foreign_trace_root_does_not_reach_the_batch_root() {
        let pairs: Vec<_> = (0..4u64).map(|i| (w(i * 7), w(1000 + i * 13))).collect();
        let tree = build_batch_tree_bound(&pairs).unwrap();
        let (sibs, bits) = tree.membership_proof(2).unwrap();

        // Same transaction, someone else's proof.
        let forged = batch_leaf(pairs[2].0, w(999_000));
        assert!(!verify_batch_membership(&tree.root(), &forged, &sibs, &bits),
                "a leaf carrying a foreign trace root must not verify");

        // And the converse: the right proof filed under the wrong transaction.
        let swapped = batch_leaf(pairs[3].0, pairs[2].1);
        assert!(!verify_batch_membership(&tree.root(), &swapped, &sibs, &bits));
    }

// ── A-5 in-circuit: membership is PROVED, not just computed ─────────────

    /// The leaf's two compressions and its path, each proved by an existing
    /// gadget. No new AIR: `compress_t8` is arithmetized by `poseidon2_t8_air`
    /// and the path by `merkle_path_t8_air`, which is why the leaf is built from
    /// compressions rather than the leaf sponge (no rate-4 sponge AIR exists).
    #[test]
    fn membership_of_a_bound_leaf_is_provable_in_circuit() {
        use crate::recursive::poseidon2_t8_air::{prove_compress, verify_compress};
        use crate::recursive::merkle_path_t8_air::{prove_merkle_path_t8, verify_merkle_path_t8};

        let pairs: Vec<_> = (0..4u64).map(|i| (w(i * 7), w(1000 + i * 13))).collect();
        let tree = build_batch_tree_bound(&pairs).unwrap();
        let root = tree.root();
        let index = 2usize;
        let (tx_id, trace_root) = pairs[index];

        // 1. inner = compress(tx_id, trace_root) — binds the proof to the member.
        let (p1, l1, inner) = prove_compress(tx_id, trace_root).unwrap();
        assert!(verify_compress(&p1, l1, tx_id, trace_root, inner).unwrap());

        // 2. leaf = compress(LEAF_DOMAIN, inner) — separates leaf from node.
        let (p2, l2, leaf_w) = prove_compress(LEAF_DOMAIN, inner).unwrap();
        assert!(verify_compress(&p2, l2, LEAF_DOMAIN, inner, leaf_w).unwrap());
        assert_eq!(leaf_w, node_words(&batch_leaf(tx_id, trace_root)),
                   "the circuit's leaf must be the tree's leaf");

        // 3. the path from that leaf to the batch root.
        let (sibs, bits) = tree.membership_proof(index).unwrap();
        let sibs_w: Vec<[u64; 4]> = sibs.iter().map(node_words).collect();
        let (p3, l3, root_w) = prove_merkle_path_t8(leaf_w, &sibs_w, &bits).unwrap();
        assert_eq!(root_w, node_words(&root), "the circuit must land on the batch root");
        assert!(verify_merkle_path_t8(&p3, l3, sibs.len(), leaf_w, index as u32, root_w).unwrap());
    }

    /// The negative half, and the one that carries the claim: a signature proved
    /// under someone else's trace root cannot reach the batch root, even with a
    /// genuine path and the right transaction.
    #[test]
    fn a_foreign_trace_root_cannot_be_proved_into_the_batch() {
        use crate::recursive::poseidon2_t8_air::prove_compress;
        use crate::recursive::merkle_path_t8_air::{prove_merkle_path_t8, verify_merkle_path_t8};

        let pairs: Vec<_> = (0..4u64).map(|i| (w(i * 7), w(1000 + i * 13))).collect();
        let tree = build_batch_tree_bound(&pairs).unwrap();
        let index = 2usize;
        let (sibs, bits) = tree.membership_proof(index).unwrap();
        let sibs_w: Vec<[u64; 4]> = sibs.iter().map(node_words).collect();

        let (_, _, inner) = prove_compress(pairs[index].0, w(999_000)).unwrap();
        let (_, _, forged_leaf) = prove_compress(LEAF_DOMAIN, inner).unwrap();

        let (p, l, got_root) = prove_merkle_path_t8(forged_leaf, &sibs_w, &bits).unwrap();
        // The prover can always prove SOME root for its own leaf; what it cannot
        // do is land on the batch's.
        assert_ne!(got_root, node_words(&tree.root()));
        assert!(!verify_merkle_path_t8(
            &p, l, sibs.len(), forged_leaf, index as u32, node_words(&tree.root())).unwrap());
    }

    #[test]
    fn input_validation() {
        assert!(build_batch_tree(&[]).is_err());
        assert!(build_batch_tree(&[vec![1]]).unwrap().depth() == 0);
        let tree = build_batch_tree(&[vec![1], vec![2]]).unwrap();
        assert!(tree.membership_proof(2).is_err());
    }
}
