//! Per-query recursive-verifier integration (R3.4).
//!
//! Chains the three recursion sub-proofs that together verify **one FRI query**
//! end-to-end, bound by shared public values (the codebase's sub-proof
//! composition convention — each gadget mixes its public I/O into Fiat-Shamir,
//! and the integration asserts the values line up):
//!
//! ```text
//! ┌─ recursive_verifier ─┐   finalFold    ┌─ leaf hash ─┐  leaf   ┌─ merkle_path ─┐
//! │ OODS± + circle fold  │ ─────────────▶ │ hashLeaf    │ ──────▶ │ leaf@idx +     │
//! │ + K line folds       │  (QM31, bound  │ (t=2 sponge │ (M31,   │ siblings → root│
//! └──────────────────────┘   in channel)  └─────────────┘  bound) └────────────────┘
//!                                                                   = friLayerRoots[K]
//! ```
//!
//! 1. [`recursive_verifier::prove_recursive_query`] proves the per-query OODS +
//!    circle fold + K line folds and binds `finalFold` (QM31) into its transcript.
//! 2. [`qm31_leaf_hash`] hashes `finalFold`'s four QM31 limbs into a single M31
//!    `leaf` via the Poseidon2 t=2 rate-1 sponge — exactly the on-chain
//!    `Poseidon2MerkleVerifier.hashLeaf(qm31Words(·))`.
//! 3. [`merkle_path_air::prove_merkle_path`] proves `leaf @ queryIndex + siblings
//!    → friLayerRoots[K]`.
//!
//! This is the complete per-query FRI verification of VFRI11, assembled from the
//! recursion gadgets.  The remaining R3 work is to aggregate N such queries and
//! replay the Fiat-Shamir transcript ([`channel_air`]) that derives the query
//! indices and folding challenges, yielding the full recursive verifier.
//!
//! [`channel_air`]: super::channel_air
//! [`merkle_path_air::prove_merkle_path`]: super::merkle_path_air::prove_merkle_path
//! [`recursive_verifier::prove_recursive_query`]: super::recursive_verifier::prove_recursive_query

use crate::recursive::channel_air::sponge_absorb;
use crate::recursive::qm31_mul_air::limbs;

/// Hash a QM31 value's four limbs into a single M31 leaf using the Poseidon2
/// t=2 rate-1 sponge — the recursive analogue of the FRI tree's
/// `hash_leaf_qm31_p2` (and on-chain `Poseidon2MerkleVerifier.hashLeaf`).
///
/// `leaf = sponge_absorb([v≫96, v≫64, v≫32, v]).0` (limbs MSB-first, matching
/// `qm31_words` and the gadgets' [`limbs`]).
pub fn qm31_leaf_hash(value: u128) -> u64 {
    let l = limbs(value);
    sponge_absorb(&[l[0], l[1], l[2], l[3]]).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursive::merkle_path_air::{
        bits_to_index, merkle_path_root, prove_merkle_path, verify_merkle_path,
    };
    use crate::recursive::recursive_verifier::{
        prove_recursive_query, recursive_query_final, verify_recursive_query, FoldRound, StepOp,
    };

    const M31_P: u64 = (1u64 << 31) - 1;

    fn rand_m31(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) % M31_P
    }
    fn rand_qm31(seed: &mut u64) -> u128 {
        (rand_m31(seed) as u128) << 96
            | (rand_m31(seed) as u128) << 64
            | (rand_m31(seed) as u128) << 32
            | rand_m31(seed) as u128
    }
    fn sample_step(seed: &mut u64) -> StepOp {
        (
            rand_qm31(seed),
            rand_qm31(seed),
            rand_m31(seed) as u32,
            rand_qm31(seed),
            rand_qm31(seed),
            rand_qm31(seed),
            rand_qm31(seed),
            rand_m31(seed) as u32,
        )
    }
    fn sample_rounds(seed: &mut u64, k: usize) -> Vec<FoldRound> {
        (0..k)
            .map(|_| (rand_qm31(seed), rand_qm31(seed), rand_m31(seed) as u32))
            .collect()
    }

    // qm31_leaf_hash must equal the channel sponge over the four limbs.
    #[test]
    fn test_leaf_hash_matches_sponge() {
        let mut s = 0x1eaf_u64;
        let v = rand_qm31(&mut s);
        let l = limbs(v);
        assert_eq!(qm31_leaf_hash(v), sponge_absorb(&[l[0], l[1], l[2], l[3]]).0);
    }

    // Full per-query verification: recursive_verifier → leaf hash → merkle_path,
    // all three sub-proofs accept and the connecting values line up.
    #[test]
    fn test_end_to_end_one_query() {
        let mut s = 0xc0ffee_u64;

        // ── Step 1: per-query recursive proof (OODS + circle fold + K line folds).
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 4);
        let px = step.2;
        let (rv_bytes, rv_log, final_fold) = prove_recursive_query(&step, &rounds).unwrap();
        assert_eq!(final_fold, recursive_query_final(&step, &rounds));
        assert!(
            verify_recursive_query(&rv_bytes, rv_log, rounds.len(), px, final_fold).unwrap(),
            "recursive per-query proof must verify against its bound final fold",
        );

        // ── Step 2: hash the (bound) final fold into the FRI leaf.
        let leaf = qm31_leaf_hash(final_fold);

        // ── Step 3: Merkle-authenticate the leaf into friLayerRoots[K].
        let depth = 5usize;
        let sibs: Vec<u64> = (0..depth).map(|_| rand_m31(&mut s)).collect();
        let bits: Vec<bool> = (0..depth).map(|_| rand_m31(&mut s) & 1 == 1).collect();
        let index = bits_to_index(&bits);
        let root = merkle_path_root(leaf, &sibs, &bits);

        let (mp_bytes, mp_log, mp_root) = prove_merkle_path(leaf, &sibs, &bits).unwrap();
        assert_eq!(mp_root, root, "merkle path root must match the reference fold");
        assert!(
            verify_merkle_path(&mp_bytes, mp_log, leaf, index, root).unwrap(),
            "merkle path proof must verify the hashed final fold into the layer root",
        );

        // ── Connecting invariant: the Merkle proof's leaf IS the hash of the
        //    recursive proof's bound output. A different final fold ⇒ different
        //    leaf ⇒ a different (failing) Merkle root.
        assert_eq!(leaf, qm31_leaf_hash(final_fold));
        let other_leaf = qm31_leaf_hash(final_fold ^ 1);
        assert_ne!(leaf, other_leaf, "distinct fold values must hash to distinct leaves");
    }

    // A tampered final fold value breaks the chain: the recursive proof no longer
    // verifies against it AND it hashes to a different Merkle leaf.
    #[test]
    fn test_tampered_final_fold_breaks_chain() {
        let mut s = 0xbad_u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 3);
        let px = step.2;
        let (rv_bytes, rv_log, final_fold) = prove_recursive_query(&step, &rounds).unwrap();

        let wrong = final_fold ^ 0x10;
        // The recursive proof rejects the wrong claimed output.
        assert!(!verify_recursive_query(&rv_bytes, rv_log, rounds.len(), px, wrong).unwrap_or(false));
        // And the wrong output hashes to a different leaf, so any Merkle path
        // built for the honest leaf cannot authenticate it.
        assert_ne!(qm31_leaf_hash(final_fold), qm31_leaf_hash(wrong));
    }
}
