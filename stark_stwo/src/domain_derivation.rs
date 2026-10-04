//! The documented rule for deriving this project's frozen M31 constants.
//!
//! Three constant sets are generated from a string tag rather than chosen:
//!
//! ```text
//!     word[i] = u32_be( SHA-256(tag ‖ i_be4)[..4] ) mod M31_P
//! ```
//!
//! * `poseidon2_t8::K_RC`      — tag `"QLSA-Poseidon2-t8"`,       78 words
//! * `batch_tree::LEAF_DOMAIN` — tag `"QLSA-batch-leaf-domain"`,   4 words
//! * `batch_tree::NONCE_DOMAIN` — tag `"QLSA-nonce-leaf-domain"`,  4 words
//!
//! # Why this module exists
//!
//! Until 2026-10-04 the rule lived ONLY in doc comments, and the constants were
//! frozen literals that nothing re-derived — the string
//! `"QLSA-batch-leaf-domain"` appeared exactly once in the whole repository, in
//! the comment describing how its constant had been produced. So "regenerable
//! by the documented rule" was an assertion, not a fact: a typo in a literal, or
//! a comment drifting from the literal it describes, would have been invisible.
//!
//! This project has already been bitten twice by taking a hash construction's
//! property on faith rather than checking it — the Poseidon2 sponge padding
//! collision, and the t=16 channel absorbing `[1,2,3]` and `[1,2,3,0]` to the
//! same state. A domain tag is load-bearing for exactly one reason (it makes a
//! leaf distinguishable from an internal node, defeating the classic Merkle
//! second-preimage attack), and a tag that is not what it claims to be offers no
//! separation at all.
//!
//! # Why it is test-only
//!
//! The shipped library keeps the literals: no hashing at load time, and no
//! SHA-256 in the production dependency graph. `sha2` is a dev-dependency, and
//! it was already in the lockfile transitively (via `starknet-crypto`), so
//! checking the rule adds no supply-chain surface.
//!
//! One implementation of the rule, consumed by every constant's test — the same
//! discipline as the single `vfri11_fri_chain` helper behind the ABI generator
//! and the recursion bridge: two copies of a rule cannot disagree if there is
//! one copy.

use crate::poseidon2::M31_P;
use sha2::{Digest, Sha256};

/// Derive `n` M31 words from `tag` by the documented SHA-256 rule.
pub fn derive_words(tag: &str, n: usize) -> Vec<u32> {
    (0..n)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(tag.as_bytes());
            h.update((i as u32).to_be_bytes());
            let d = h.finalize();
            let raw = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
            // M31_P is u64; the reduced result always fits u32, which is the
            // width K_RC is declared at.
            (u64::from(raw) % M31_P) as u32
        })
        .collect()
}

/// The same, as four `u64` words — the shape the `compress_t8` domain tags use.
pub fn derive_domain4(tag: &str) -> [u64; 4] {
    let w = derive_words(tag, 4);
    std::array::from_fn(|i| w[i] as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rule_is_deterministic_and_reduced() {
        let a = derive_words("QLSA-test-tag", 16);
        let b = derive_words("QLSA-test-tag", 16);
        assert_eq!(a, b, "derivation must be a pure function of the tag");
        assert!(
            a.iter().all(|&w| u64::from(w) < M31_P),
            "every word must be reduced"
        );
    }

    #[test]
    fn different_tags_give_different_words() {
        // The whole point of a domain tag: changing the string changes the
        // constant. If this failed, every tag in the project would separate
        // nothing.
        assert_ne!(
            derive_domain4("QLSA-batch-leaf-domain"),
            derive_domain4("QLSA-nonce-leaf-domain"),
        );
    }

    #[test]
    fn the_index_is_part_of_the_preimage() {
        // word[i] must depend on i, or all four words of a domain tag would be
        // equal and the tag would carry 31 bits instead of 124.
        let w = derive_words("QLSA-batch-leaf-domain", 4);
        assert!(
            w.iter().collect::<std::collections::HashSet<_>>().len() == 4,
            "the four words collided: {w:?}"
        );
    }

    #[test]
    fn poseidon2_t8_round_constants_match_the_documented_rule() {
        // K_RC is a 78-word frozen literal whose doc comment claims this exact
        // derivation. Nothing checked it before.
        let derived = derive_words("QLSA-Poseidon2-t8", 78);
        assert_eq!(
            derived.len(),
            crate::poseidon2_t8::K_RC.len(),
            "length changed: T*R_F + R_P must equal 78"
        );
        assert_eq!(
            derived,
            crate::poseidon2_t8::K_RC.to_vec(),
            "poseidon2_t8::K_RC does not match \
             u32_be(SHA-256(\"QLSA-Poseidon2-t8\" | i_be4)[..4]) mod M31_P"
        );
    }
}
