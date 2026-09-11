// ARCHIVED — NOT COMPILED, NOT IN ANY MODULE TREE.
// The Poseidon2 t=2 and t=2-wide helpers, removed by the Ф1 narrowing together
// with the Solidity backends that used them (Poseidon2M31, Poseidon2Channel,
// Poseidon2MerkleVerifier / ...W). Restored from vfri2_bridge.rs@f2020d9 so the
// code stays visible in the repository rather than only in git history.
//
// Node collision at t=2 is ~2^31, which is why the ladder moved to t=8 (~2^62)
// and t=16 (~2^124). Nothing shipping uses these.

fn p2_absorb(s: &mut [u64; 2], word: u32) {
    // Reduce word to a valid M31 element before adding.
    // A u32 can be >= M31_P (e.g. keccak256 last 4 bytes).  Two subtractions
    // suffice because word < 2^32 = 2*M31_P + 2, so at most two steps needed.
    let mut w = word as u64;
    if w >= crate::poseidon2::M31_P { w -= crate::poseidon2::M31_P; }
    if w >= crate::poseidon2::M31_P { w -= crate::poseidon2::M31_P; }
    s[0] = crate::poseidon2::m31_add(s[0], w);
    crate::poseidon2::permute(s);
}

fn hash_leaf_cols_p2(col_values: &[u32]) -> [u8; 32] {
    let mut s = [0u64; 2];
    for &v in col_values {
        p2_absorb(&mut s, v);
    }
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out
}

fn hash_pair_p2(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let l = u32::from_be_bytes(left[28..32].try_into().unwrap()) as u64;
    let r = u32::from_be_bytes(right[28..32].try_into().unwrap()) as u64;
    let mut s = [l, r];
    crate::poseidon2::permute(&mut s);
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out
}

fn hash_leaf_qm31_p2(value: u128) -> [u8; 32] {
    let words = qm31_words(value);
    let mut s = [0u64; 2];
    for &w in &words {
        p2_absorb(&mut s, w);
    }
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out
}

fn build_tree_p2(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    assert!(leaves.len().is_power_of_two(), "leaves.len() must be power of 2");
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(hash_pair_p2(&chunk[0], &chunk[1]));
        }
        levels.push(next);
    }
    levels
}

struct P2Channel {
    s0: u32,
    s1: u32,
    n_draws: u32,
}

impl P2Channel {
    fn init() -> Self {
        P2Channel { s0: 0, s1: 0, n_draws: 0 }
    }

    fn absorb(&mut self, word: u32) {
        let mut s = [self.s0 as u64, self.s1 as u64];
        p2_absorb(&mut s, word);
        self.s0 = s[0] as u32;
        self.s1 = s[1] as u32;
    }

    fn mix_root(&mut self, root: &[u8; 32]) {
        let m = u32::from_be_bytes(root[28..32].try_into().unwrap());
        self.absorb(m);
        self.n_draws = 0;
    }

    fn mix_u32s(&mut self, words: &[u32]) {
        for &w in words { self.absorb(w); }
        self.n_draws = 0;
    }

    fn draw_pair(&mut self) -> (u32, u32) {
        let w0 = self.s0;
        let w1 = self.s1;
        let mut s = [self.s0 as u64, self.s1 as u64];
        s[0] = crate::poseidon2::m31_add(s[0], self.n_draws as u64);
        crate::poseidon2::permute(&mut s);
        self.s0 = s[0] as u32;
        self.s1 = s[1] as u32;
        self.n_draws += 1;
        (w0, w1)
    }

    fn draw_secure_felt(&mut self) -> u128 {
        let (w0, w1) = self.draw_pair();
        let (w2, w3) = self.draw_pair();
        let c0 = cm31_pack(w0, w1);
        let c1 = cm31_pack(w2, w3);
        qm31_pack_c(c0, c1)
    }

    fn draw_queries(&mut self, log_domain_size: u32, n: usize) -> Vec<usize> {
        let mask = ((1u64 << log_domain_size) - 1) as u32;
        let mut queries = Vec::with_capacity(n);
        while queries.len() < n {
            let (w0, w1) = self.draw_pair();
            queries.push((w0 & mask) as usize);
            if queries.len() < n {
                queries.push((w1 & mask) as usize);
            }
        }
        queries.truncate(n);
        queries
    }
}

fn hash_leaf_cols_p2w(col_values: &[u32]) -> [u8; 32] {
    let mut s = [0u64; 2];
    for &v in col_values {
        p2_absorb(&mut s, v);
    }
    let mut out = [0u8; 32];
    out[24..28].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out[28..32].copy_from_slice(&(s[1] as u32).to_be_bytes());
    out
}

fn hash_pair_p2w(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let l0 = u32::from_be_bytes(left[24..28].try_into().unwrap()) as u64;
    let l1 = u32::from_be_bytes(left[28..32].try_into().unwrap()) as u64;
    let r0 = u32::from_be_bytes(right[24..28].try_into().unwrap()) as u64;
    let r1 = u32::from_be_bytes(right[28..32].try_into().unwrap()) as u64;
    // Duplex compress: state = left, then absorb right one word at a time.
    let mut s = [l0, l1];
    s[0] = crate::poseidon2::m31_add(s[0], r0);
    crate::poseidon2::permute(&mut s);
    s[0] = crate::poseidon2::m31_add(s[0], r1);
    crate::poseidon2::permute(&mut s);
    let mut out = [0u8; 32];
    out[24..28].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out[28..32].copy_from_slice(&(s[1] as u32).to_be_bytes());
    out
}

fn hash_leaf_qm31_p2w(value: u128) -> [u8; 32] {
    let words = qm31_words(value);
    let mut s = [0u64; 2];
    for &w in &words {
        p2_absorb(&mut s, w);
    }
    let mut out = [0u8; 32];
    out[24..28].copy_from_slice(&(s[0] as u32).to_be_bytes());
    out[28..32].copy_from_slice(&(s[1] as u32).to_be_bytes());
    out
}

fn build_tree_p2w(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    assert!(leaves.len().is_power_of_two(), "leaves.len() must be power of 2");
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(hash_pair_p2w(&chunk[0], &chunk[1]));
        }
        levels.push(next);
    }
    levels
}

impl P2Channel {
    /// Absorb a wide Poseidon2 node root (62-bit content) as 2 BE u32 words.
    fn mix_root_w(&mut self, root: &[u8; 32]) {
        self.absorb(u32::from_be_bytes(root[24..28].try_into().unwrap()));
        self.absorb(u32::from_be_bytes(root[28..32].try_into().unwrap()));
        self.n_draws = 0;
    }

    /// Absorb a full 32-byte root (Stwo trace root, batch merkle root) as
    /// 8 big-endian u32 words.  Binds ALL 256 bits into the transcript,
    /// unlike VFRI8's mix_root which only absorbed the low 4 bytes.
    fn mix_root_full(&mut self, root: &[u8; 32]) {
        for i in 0..8 {
            self.absorb(u32::from_be_bytes(root[4 * i..4 * i + 4].try_into().unwrap()));
        }
        self.n_draws = 0;
    }
}


// ARCHIVED — NOT COMPILED, NOT IN ANY MODULE TREE.
// Test modules for retired protocols (VFRI6, VFRI7) and the retired Poseidon2
// t=2 backend, removed by the Ф1 narrowing. Restored from
// vfri2_bridge.rs@f2020d9. They exercise hashes and verifiers nothing ships.

// ── ML-DSA V23 VFRI6 test helpers (need access to private make_v23_inputs) ──
#[cfg(test)]
mod tests_v23_vfri6_inner {
    use super::tests::make_v23_inputs;






    // ── LOG=8 group tests ─────────────────────────────────────────────────────

    pub(super) fn make_log8_hints() -> [[bool; 256]; 6] {
        [[false; 256]; 6]
    }





}

// ── ML-DSA V23 VFRI7 tests ───────────────────────────────────────────────────
#[cfg(test)]
mod tests_v23_vfri7 {
    use super::tests::make_v23_inputs;

    fn make_log8_hints() -> [[bool; 256]; 6] {
        [[false; 256]; 6]
    }

    // ── LOG=10 smoke / determinism ────────────────────────────────────────────





    // ── LOG=8 smoke / determinism ─────────────────────────────────────────────



    // ── Cross-bound hints ─────────────────────────────────────────────────────






}

// ── ML-DSA V23 VFRI8 tests ───────────────────────────────────────────────────
#[cfg(test)]
mod tests_vfri8 {
    use super::*;

    #[test]
    fn test_p2_channel_deterministic() {
        let mut c1 = P2Channel::init();
        let mut c2 = P2Channel::init();
        let root = [0x42u8; 32];
        c1.mix_root(&root);
        c2.mix_root(&root);
        assert_eq!(c1.draw_secure_felt(), c2.draw_secure_felt());
    }

    #[test]
    fn test_p2_channel_differs_from_blake2s() {
        let mut p2 = P2Channel::init();
        let mut b2 = Channel::init();
        let root = [0x42u8; 32];
        p2.mix_root(&root);
        b2.mix_root(&root);
        assert_ne!(p2.draw_secure_felt(), b2.draw_secure_felt(),
            "P2Channel must produce different values than Blake2s channel");
    }

    #[test]
    fn test_hash_pair_p2_deterministic() {
        let left  = [0x11u8; 32];
        let right = [0x22u8; 32];
        let h1 = hash_pair_p2(&left, &right);
        let h2 = hash_pair_p2(&left, &right);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_pair_p2_not_commutative() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let h_ab = hash_pair_p2(&a, &b);
        let h_ba = hash_pair_p2(&b, &a);
        assert_ne!(h_ab, h_ba, "hashPair should not be commutative");
    }

    #[test]
    fn test_hash_leaf_cols_p2_consistency() {
        let cols = vec![1u32, 2, 3, 4];
        let h1 = hash_leaf_cols_p2(&cols);
        let h2 = hash_leaf_cols_p2(&cols);
        assert_eq!(h1, h2);
        // Must differ from Blake2s leaf hash
        let h_b2 = hash_leaf_cols(&cols);
        assert_ne!(h1, h_b2, "P2 leaf hash must differ from Blake2s leaf hash");
    }










    // ── VFRI9 tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_hash_pair_p2w_uses_both_words() {
        // Two nodes that agree in s1 (low word) but differ in s0 (high word)
        // must produce different parent hashes — this is exactly the collision
        // VFRI8's 31-bit nodes could not prevent.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[24..28].copy_from_slice(&1u32.to_be_bytes());
        a[28..32].copy_from_slice(&7u32.to_be_bytes());
        b[24..28].copy_from_slice(&2u32.to_be_bytes());
        b[28..32].copy_from_slice(&7u32.to_be_bytes());
        let sib = [0x05u8; 32];
        assert_ne!(hash_pair_p2w(&a, &sib), hash_pair_p2w(&b, &sib));
        assert_ne!(hash_pair_p2w(&sib, &a), hash_pair_p2w(&sib, &b));
    }

    #[test]
    fn test_hash_leaf_cols_p2w_wide_output() {
        let cols = vec![1u32, 2, 3, 4];
        let h = hash_leaf_cols_p2w(&cols);
        // Narrow VFRI8 leaf and wide VFRI9 leaf must differ in encoding
        let h_narrow = hash_leaf_cols_p2(&cols);
        assert_ne!(h, h_narrow);
        // bytes[0..24] must be zero (62-bit content in low 8 bytes)
        assert_eq!(&h[..24], &[0u8; 24]);
        // Same sponge: wide s0 (bytes 24..28) equals narrow s0 (bytes 28..32)
        assert_eq!(&h[24..28], &h_narrow[28..32],
            "s0 word must match the narrow hash (same sponge)");
    }

    // ── VFRI10 t=4 hash backend cross-check ──────────────────────────────────

    #[test]
    #[ignore = "prints reference vectors for regeneration; values are frozen in test_p2t4_reference_vectors"]
    fn test_p2t4_print_reference_vectors() {
        // Prints the values frozen below + in Poseidon2MerkleVerifierT4.test.js.
        // Run with: cargo test test_p2t4_print_reference_vectors -- --ignored --nocapture
        let leaf = hash_leaf_cols_p2t4(&[1, 2, 3, 4]);
        let l0 = u32::from_be_bytes(leaf[24..28].try_into().unwrap());
        let l1 = u32::from_be_bytes(leaf[28..32].try_into().unwrap());
        eprintln!("hash_leaf_cols_p2t4([1,2,3,4]) = ({l0}, {l1})");

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[24..28].copy_from_slice(&1u32.to_be_bytes());
        a[28..32].copy_from_slice(&2u32.to_be_bytes());
        b[24..28].copy_from_slice(&3u32.to_be_bytes());
        b[28..32].copy_from_slice(&4u32.to_be_bytes());
        let pair = hash_pair_p2t4(&a, &b);
        let p0 = u32::from_be_bytes(pair[24..28].try_into().unwrap());
        let p1 = u32::from_be_bytes(pair[28..32].try_into().unwrap());
        eprintln!("hash_pair_p2t4([1,2],[3,4]) = ({p0}, {p1})");

        let mut ch = P2T4Channel::init();
        ch.mix_root(&[0x11u8; 32]);
        let q = ch.draw_queries(10, 4);
        eprintln!("channel.mix_root(0x11..).draw_queries(10,4) = {q:?}");
        let felt = { let mut c = P2T4Channel::init(); c.mix_u32s(&[1, 2, 3]); c.draw_secure_felt() };
        eprintln!("channel.mix_u32s([1,2,3]).draw_secure_felt() = {felt}");
    }

    #[test]
    fn test_p2t4_reference_vectors() {
        // Frozen — Poseidon2MerkleVerifierT4.test.js asserts the same outputs.
        let leaf = hash_leaf_cols_p2t4(&[1, 2, 3, 4]);
        assert_eq!(u32::from_be_bytes(leaf[24..28].try_into().unwrap()), 188_265_029);
        assert_eq!(u32::from_be_bytes(leaf[28..32].try_into().unwrap()), 348_838_750);

        // hash_pair of nodes (1,2) and (3,4) is exactly compress_t4([1,2],[3,4]).
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[24..28].copy_from_slice(&1u32.to_be_bytes());
        a[28..32].copy_from_slice(&2u32.to_be_bytes());
        b[24..28].copy_from_slice(&3u32.to_be_bytes());
        b[28..32].copy_from_slice(&4u32.to_be_bytes());
        let pair = hash_pair_p2t4(&a, &b);
        assert_eq!(u32::from_be_bytes(pair[24..28].try_into().unwrap()), 1_706_601_437);
        assert_eq!(u32::from_be_bytes(pair[28..32].try_into().unwrap()), 1_471_208_702);
    }

    #[test]
    fn test_p2t4_leaf_is_wide_and_sponge_consistent() {
        let cols = vec![1u32, 2, 3, 4];
        let h = hash_leaf_cols_p2t4(&cols);
        // Content lives in the low 8 bytes; upper 24 bytes are zero.
        assert_eq!(&h[..24], &[0u8; 24]);
        // Leaf == sponge_t4 of the columns (first two words).
        let s = crate::poseidon2_t4::sponge_t4(&[1, 2, 3, 4]);
        assert_eq!(u32::from_be_bytes(h[24..28].try_into().unwrap()), s[0] as u32);
        assert_eq!(u32::from_be_bytes(h[28..32].try_into().unwrap()), s[1] as u32);
        // t=4 leaf differs from the t=2 wide leaf (different permutation).
        assert_ne!(h, hash_leaf_cols_p2w(&cols));
    }

    #[test]
    fn test_p2t4_pair_uses_both_words_and_order_sensitive() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[24..28].copy_from_slice(&1u32.to_be_bytes());
        a[28..32].copy_from_slice(&7u32.to_be_bytes());
        b[24..28].copy_from_slice(&2u32.to_be_bytes());
        b[28..32].copy_from_slice(&7u32.to_be_bytes());
        let sib = [0x05u8; 32];
        // Nodes differing only in the high word must yield different parents.
        assert_ne!(hash_pair_p2t4(&a, &sib), hash_pair_p2t4(&b, &sib));
        // Compression is not commutative.
        assert_ne!(hash_pair_p2t4(&a, &sib), hash_pair_p2t4(&sib, &a));
    }

    #[test]
    fn test_p2t4_tree_roundtrip() {
        // Build a depth-2 tree, walk a Merkle path, confirm it reaches the root.
        let leaves: Vec<[u8; 32]> = (0..4u32)
            .map(|j| hash_leaf_cols_p2t4(&[j, j + 1, j + 2]))
            .collect();
        let levels = build_tree_p2t4(leaves.clone());
        let root = levels.last().unwrap()[0];
        assert_eq!(levels.len(), 3); // 4 → 2 → 1
        // Verify inclusion of leaf index 1 by recomputing up the path.
        let idx = 1usize;
        let mut cur = leaves[idx];
        let sib0 = leaves[0]; // sibling of leaf 1 is leaf 0
        cur = hash_pair_p2t4(&sib0, &cur); // idx odd → sibling on the left
        let sib1 = levels[1][1]; // sibling of node 0 at level 1 is node 1
        cur = hash_pair_p2t4(&cur, &sib1);
        assert_eq!(cur, root);
    }

    #[test]
    fn test_p2t4_channel_deterministic_and_binds() {
        let mut a = P2T4Channel::init();
        let mut b = P2T4Channel::init();
        a.mix_root(&[0x11u8; 32]);
        b.mix_root(&[0x11u8; 32]);
        assert_eq!(a.draw_queries(10, 8), b.draw_queries(10, 8));
        // Different root → different query stream.
        let mut c = P2T4Channel::init();
        c.mix_root(&[0x12u8; 32]);
        let mut d = P2T4Channel::init();
        d.mix_root(&[0x11u8; 32]);
        assert_ne!(c.draw_queries(10, 8), d.draw_queries(10, 8));
        // Queries are within the domain.
        let mut e = P2T4Channel::init();
        e.mix_root(&[0x11u8; 32]);
        for q in e.draw_queries(10, 16) {
            assert!(q < (1 << 10));
        }
    }

    #[test]
    fn test_p2t4_channel_full_root_binds_all_bytes() {
        // mix_root_full must depend on every byte; mix_root (low 4 bytes) must not.
        let mut base = [0u8; 32];
        base[0] = 0xAA; // high byte
        let mut alt = base;
        alt[0] = 0xBB;
        let q_full_base = { let mut c = P2T4Channel::init(); c.mix_root_full(&base); c.draw_queries(8, 4) };
        let q_full_alt = { let mut c = P2T4Channel::init(); c.mix_root_full(&alt); c.draw_queries(8, 4) };
        assert_ne!(q_full_base, q_full_alt, "mix_root_full must bind high bytes");
        // mix_root only looks at bytes[28..32] → high-byte change is invisible.
        let q_lo_base = { let mut c = P2T4Channel::init(); c.mix_root(&base); c.draw_queries(8, 4) };
        let q_lo_alt = { let mut c = P2T4Channel::init(); c.mix_root(&alt); c.draw_queries(8, 4) };
        assert_eq!(q_lo_base, q_lo_alt);
    }

    // ── t=8 hash backend cross-check (Poseidon2T8Backend.test.js) ──────────────

    #[test]
    #[ignore = "prints reference vectors for regeneration; values are frozen in test_p2t8_reference_vectors"]
    fn test_p2t8_print_reference_vectors() {
        // Run with: cargo test test_p2t8_print_reference_vectors -- --ignored --nocapture
        let leaf = hash_leaf_cols_p2t8(&[1, 2, 3, 4]);
        eprintln!("hash_leaf_cols_p2t8([1,2,3,4]) = {:?}", p2t8_node_words(&leaf));

        let a = p2t8_pack([1, 2, 3, 4]);
        let b = p2t8_pack([5, 6, 7, 8]);
        let pair = hash_pair_p2t8(&a, &b);
        eprintln!("hash_pair_p2t8(node[1..4],node[5..8]) = {:?}", p2t8_node_words(&pair));

        let mut ch = P2T8Channel::init();
        ch.mix_root(&[0x11u8; 32]);
        eprintln!("channel.mix_root(0x11..).draw_queries(10,4) = {:?}", ch.draw_queries(10, 4));

        let node = p2t8_pack([1, 2, 3, 4]);
        let mut chw = P2T8Channel::init();
        chw.mix_root_w(&node);
        eprintln!("channel.mix_root_w(node[1..4]).draw_queries(10,4) = {:?}", chw.draw_queries(10, 4));

        let felt = { let mut c = P2T8Channel::init(); c.mix_u32s(&[1, 2, 3]); c.draw_secure_felt() };
        eprintln!("channel.mix_u32s([1,2,3]).draw_secure_felt() = {felt}");
    }

    #[test]
    fn test_p2t8_reference_vectors() {
        // Frozen — Poseidon2T8Backend.test.js asserts the same outputs.
        let leaf = hash_leaf_cols_p2t8(&[1, 2, 3, 4]);
        assert_eq!(p2t8_node_words(&leaf), REF_T8_LEAF);

        // hash_pair of nodes (1,2,3,4) and (5,6,7,8) == compress_t8([1..4],[5..8]).
        let pair = hash_pair_p2t8(&p2t8_pack([1, 2, 3, 4]), &p2t8_pack([5, 6, 7, 8]));
        assert_eq!(p2t8_node_words(&pair), REF_T8_PAIR);
        assert_eq!(
            p2t8_node_words(&pair),
            crate::poseidon2_t8::compress_t8([1, 2, 3, 4], [5, 6, 7, 8])
        );

        let mut ch = P2T8Channel::init();
        ch.mix_root(&[0x11u8; 32]);
        assert_eq!(ch.draw_queries(10, 4), REF_T8_QUERIES.to_vec());

        let mut chw = P2T8Channel::init();
        chw.mix_root_w(&p2t8_pack([1, 2, 3, 4]));
        assert_eq!(chw.draw_queries(10, 4), REF_T8_QUERIES_W.to_vec());

        let felt = { let mut c = P2T8Channel::init(); c.mix_u32s(&[1, 2, 3]); c.draw_secure_felt() };
        assert_eq!(felt, REF_T8_FELT);
    }

    // Frozen t=8 backend reference vectors (from test_p2t8_print_reference_vectors).
    const REF_T8_LEAF: [u64; 4] = [1073120416, 1930841549, 67141568, 840805313];
    const REF_T8_PAIR: [u64; 4] = [890515421, 531626735, 2060583819, 1311645369];
    const REF_T8_QUERIES: [usize; 4] = [436, 378, 839, 927];
    const REF_T8_QUERIES_W: [usize; 4] = [301, 134, 1008, 447];
    const REF_T8_FELT: u128 = 133164500022319262877528816935901679472;

    // ---- t=16 backend (the 128-bit rung) ----------------------------------

    #[test]
    #[ignore = "prints reference vectors for regeneration; values are frozen in test_p2t16_reference_vectors"]
    fn test_p2t16_print_reference_vectors() {
        // Run with: cargo test test_p2t16_print_reference_vectors -- --ignored --nocapture
        let leaf = hash_leaf_cols_p2t16(&[1, 2, 3, 4]);
        eprintln!("hash_leaf_cols_p2t16([1,2,3,4]) = {:?}", p2t16_node_words(&leaf));

        let a = p2t16_pack([1, 2, 3, 4, 5, 6, 7, 8]);
        let b = p2t16_pack([9, 10, 11, 12, 13, 14, 15, 16]);
        eprintln!(
            "hash_pair_p2t16(node[1..8],node[9..16]) = {:?}",
            p2t16_node_words(&hash_pair_p2t16(&a, &b))
        );

        let mut ch = P2T16Channel::init();
        ch.mix_root(&[0x11u8; 32]);
        eprintln!("channel.mix_root(0x11..).draw_queries(10,4) = {:?}", ch.draw_queries(10, 4));

        let mut chw = P2T16Channel::init();
        chw.mix_root_w(&a);
        eprintln!("channel.mix_root_w(node[1..8]).draw_queries(10,4) = {:?}", chw.draw_queries(10, 4));

        let felt = { let mut c = P2T16Channel::init(); c.mix_u32s(&[1, 2, 3]); c.draw_secure_felt() };
        eprintln!("channel.mix_u32s([1,2,3]).draw_secure_felt() = {felt}");
    }

    #[test]
    fn test_p2t16_reference_vectors() {
        // Frozen — Poseidon2T16Backend.test.js asserts the same outputs.
        let leaf = hash_leaf_cols_p2t16(&[1, 2, 3, 4]);
        assert_eq!(p2t16_node_words(&leaf), REF_T16_LEAF);

        let pair = hash_pair_p2t16(
            &p2t16_pack([1, 2, 3, 4, 5, 6, 7, 8]),
            &p2t16_pack([9, 10, 11, 12, 13, 14, 15, 16]),
        );
        assert_eq!(p2t16_node_words(&pair), REF_T16_PAIR);
        // hash_pair of those two nodes IS compress_t16 of their words — the
        // packing must not perturb the value.
        assert_eq!(
            p2t16_node_words(&pair),
            crate::poseidon2_t16::compress_t16([1, 2, 3, 4, 5, 6, 7, 8], [9, 10, 11, 12, 13, 14, 15, 16])
        );

        let mut ch = P2T16Channel::init();
        ch.mix_root(&[0x11u8; 32]);
        assert_eq!(ch.draw_queries(10, 4), REF_T16_QUERIES.to_vec());

        let mut chw = P2T16Channel::init();
        chw.mix_root_w(&p2t16_pack([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(chw.draw_queries(10, 4), REF_T16_QUERIES_W.to_vec());

        let felt = { let mut c = P2T16Channel::init(); c.mix_u32s(&[1, 2, 3]); c.draw_secure_felt() };
        assert_eq!(felt, REF_T16_FELT);
    }

    // Frozen t=16 backend reference vectors (from test_p2t16_print_reference_vectors).
    // Regenerated 2026-08-28: the sponge pad now carries the block LENGTH rather
    // than a constant. Four words at rate 8 is a PARTIAL block, so this vector
    // moved; the pair/channel vectors below did not, because compression is a
    // bare permutation and the t=16 channel has its own (already length-carrying)
    // pad. That asymmetry is the check that the fix touched only padded blocks.
    const REF_T16_LEAF: [u64; 8] = [
        1933241813, 1010030854, 312951712, 1497891741, 1179285824, 51901796, 1581778953, 222789585,
    ];
    // Note this equals permute_t16([1..16])[0..8] — compress of nodes (1..8) and
    // (9..16) is the permutation of their concatenation, so this vector also
    // pins that p2t16_pack/node_words do not perturb the value.
    const REF_T16_PAIR: [u64; 8] = [
        1896676506, 1113082531, 1826142252, 1263581674, 694653155, 1856461508, 173489390, 625083048,
    ];
    const REF_T16_QUERIES: [usize; 4] = [821, 259, 182, 183];
    const REF_T16_QUERIES_W: [usize; 4] = [362, 455, 247, 671];
    const REF_T16_FELT: u128 = 1407887379921827972915931489114976420;

    #[test]
    fn test_p2t16_node_fills_the_whole_word() {
        // t=2/t=4 use bytes[24..32], t=8 bytes[16..32]; t=16's eight words are
        // exactly 32 bytes, so there is no zero padding left to distinguish.
        // That is the point: 248 bits of node content, ~2^124 collision cost.
        let h = hash_leaf_cols_p2t16(&[1, 2, 3, 4]);
        assert_ne!(&h[..16], &[0u8; 16], "a t=16 node must use the full 32 bytes");
        let s = crate::poseidon2_t16::sponge_t16(&[1, 2, 3, 4]);
        assert_eq!(p2t16_node_words(&h), [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
        // Wider state and a different permutation ⇒ a different leaf than t=8.
        assert_ne!(h, hash_leaf_cols_p2t8(&[1, 2, 3, 4]));
    }

    #[test]
    fn test_p2t16_pack_roundtrips() {
        let w = [1u64, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(p2t16_node_words(&p2t16_pack(w)), w);
        // Every word position is distinguishable — a packing that dropped or
        // aliased a word would still roundtrip the identity above.
        for k in 0..8 {
            let mut v = w;
            v[k] += 1;
            assert_ne!(p2t16_pack(v), p2t16_pack(w));
        }
    }

    #[test]
    fn test_p2t16_pair_order_sensitive_and_diffuses() {
        let a = p2t16_pack([1, 2, 3, 7, 0, 0, 0, 0]);
        let b = p2t16_pack([2, 2, 3, 7, 0, 0, 0, 0]);
        let sib = p2t16_pack([5, 5, 5, 5, 5, 5, 5, 5]);
        assert_ne!(hash_pair_p2t16(&a, &sib), hash_pair_p2t16(&b, &sib));
        assert_ne!(hash_pair_p2t16(&a, &sib), hash_pair_p2t16(&sib, &a));
    }

    #[test]
    fn test_p2t16_tree_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0..4u32)
            .map(|j| hash_leaf_cols_p2t16(&[j, j + 1, j + 2]))
            .collect();
        let levels = build_tree_p2t16(leaves.clone());
        let root = levels.last().unwrap()[0];
        assert_eq!(levels.len(), 3); // 4 → 2 → 1
        let mut cur = leaves[1];
        cur = hash_pair_p2t16(&leaves[0], &cur); // idx 1 odd → sibling on the left
        cur = hash_pair_p2t16(&cur, &levels[1][1]);
        assert_eq!(cur, root);
    }

    #[test]
    fn test_p2t16_channel_deterministic_and_binds() {
        let mut a = P2T16Channel::init();
        let mut b = P2T16Channel::init();
        a.mix_root(&[0x11u8; 32]);
        b.mix_root(&[0x11u8; 32]);
        assert_eq!(a.draw_queries(10, 8), b.draw_queries(10, 8));

        let mut c = P2T16Channel::init();
        c.mix_root(&[0x12u8; 32]);
        let mut d = P2T16Channel::init();
        d.mix_root(&[0x11u8; 32]);
        assert_ne!(c.draw_queries(10, 8), d.draw_queries(10, 8));

        let mut e = P2T16Channel::init();
        e.mix_root(&[0x11u8; 32]);
        for q in e.draw_queries(10, 16) {
            assert!(q < (1 << 10));
        }
    }

    #[test]
    fn test_p2t16_channel_differs_from_t8() {
        // A VFRI12 must NOT accept VFRI11 hints: same transcript shape, but the
        // permutation differs, so the derived query indices must differ too.
        let mut t16 = P2T16Channel::init();
        t16.mix_root_full(&[0x11u8; 32]);
        let mut t8 = P2T8Channel::init();
        t8.mix_root_full(&[0x11u8; 32]);
        assert_ne!(t16.draw_queries(10, 8), t8.draw_queries(10, 8));
    }

    #[test]
    fn test_p2t16_absorb_is_rate_8_with_padding_separation() {
        // Rate 8: a full block is one permutation. The padding flag in capacity
        // cell 15 is what keeps a short block from colliding with the same words
        // zero-extended to the rate — without it, absorbing [1,2,3] and
        // [1,2,3,0,0,0,0,0] would reach an identical state.
        let short = { let mut c = P2T16Channel::init(); c.mix_u32s(&[1, 2, 3]); c.draw_queries(10, 4) };
        let padded = {
            let mut c = P2T16Channel::init();
            c.mix_u32s(&[1, 2, 3, 0, 0, 0, 0, 0]);
            c.draw_queries(10, 4)
        };
        assert_ne!(short, padded, "padding flag must separate a short block");

        // The pad encodes the block LENGTH, so trailing zeros are not free:
        // [1,2,3] and [1,2,3,0] pad to the same eight cells and would collide
        // under a constant flag.
        let three = { let mut c = P2T16Channel::init(); c.mix_u32s(&[1, 2, 3]); c.draw_queries(10, 4) };
        let four = { let mut c = P2T16Channel::init(); c.mix_u32s(&[1, 2, 3, 0]); c.draw_queries(10, 4) };
        assert_ne!(three, four, "padding must encode the block length");

        // Absorbing an empty slice is a no-op, as in the rate-1 channels.
        let empty = { let mut c = P2T16Channel::init(); c.mix_u32s(&[]); c.draw_queries(10, 4) };
        let untouched = { let mut c = P2T16Channel::init(); c.draw_queries(10, 4) };
        assert_eq!(empty, untouched);

        // Nine words span two blocks; the ninth must still matter.
        let a = { let mut c = P2T16Channel::init(); c.mix_u32s(&[1, 2, 3, 4, 5, 6, 7, 8, 9]); c.draw_queries(10, 4) };
        let b = { let mut c = P2T16Channel::init(); c.mix_u32s(&[1, 2, 3, 4, 5, 6, 7, 8, 10]); c.draw_queries(10, 4) };
        assert_ne!(a, b);

        // Splitting a call ON a block boundary is indistinguishable — mix_u32s
        // only resets an already-zero nDraws, so [1..8] then [9] absorbs exactly
        // as [1..9] does. That holds at every width (the rate-1 channels have the
        // same property for any split) and no caller depends on separating
        // adjacent mixes; the transcript's structure is fixed.
        let aligned = {
            let mut c = P2T16Channel::init();
            c.mix_u32s(&[1, 2, 3, 4, 5, 6, 7, 8]);
            c.mix_u32s(&[9]);
            c.draw_queries(10, 4)
        };
        assert_eq!(a, aligned);

        // Splitting OFF a block boundary is not, because the first half then
        // pads. This is what makes the block structure observable at all.
        let unaligned = {
            let mut c = P2T16Channel::init();
            c.mix_u32s(&[1, 2, 3, 4]);
            c.mix_u32s(&[5, 6, 7, 8, 9]);
            c.draw_queries(10, 4)
        };
        assert_ne!(a, unaligned);
    }

    #[test]
    fn test_p2t16_mix_root_is_one_block() {
        // A 32-byte root is exactly the rate, so mix_root_full must equal a
        // single 8-word mix_u32s — no padding flag, one permutation.
        let root = [0x5au8; 32];
        let via_root = { let mut c = P2T16Channel::init(); c.mix_root_full(&root); c.draw_queries(10, 4) };
        let words: Vec<u32> = (0..8)
            .map(|i| u32::from_be_bytes(root[4 * i..4 * i + 4].try_into().unwrap()))
            .collect();
        let via_words = { let mut c = P2T16Channel::init(); c.mix_u32s(&words); c.draw_queries(10, 4) };
        assert_eq!(via_root, via_words);
    }

    #[test]
    fn test_p2t16_absorb_handles_unreduced_words() {
        // A u32 can reach 2P+1, so `absorb` needs TWO conditional subtractions.
        // Absorbing v and v+P must land in the same state; one subtraction would
        // leave them apart for v+P ≥ 2P.
        let p = crate::poseidon2::M31_P as u32;
        for v in [0u32, 1, 7, p - 1] {
            let mut a = P2T16Channel::init();
            a.mix_u32s(&[v]);
            let mut b = P2T16Channel::init();
            b.mix_u32s(&[v.wrapping_add(p)]);
            assert_eq!(a.draw_queries(10, 4), b.draw_queries(10, 4), "v = {v}");
        }
    }

    #[test]
    fn test_p2t8_leaf_is_wide_and_differs_from_t4() {
        let cols = vec![1u32, 2, 3, 4];
        let h = hash_leaf_cols_p2t8(&cols);
        // Content lives in bytes[16..32]; upper 16 bytes are zero.
        assert_eq!(&h[..16], &[0u8; 16]);
        // Leaf == sponge_t8 of the columns (first four words).
        let s = crate::poseidon2_t8::sponge_t8(&[1, 2, 3, 4]);
        assert_eq!(p2t8_node_words(&h), [s[0], s[1], s[2], s[3]]);
        // t=8 leaf differs from the t=4 leaf (wider state, different permutation).
        assert_ne!(h, hash_leaf_cols_p2t4(&cols));
    }

    #[test]
    fn test_p2t8_pair_order_sensitive_and_diffuses() {
        let a = p2t8_pack([1, 2, 3, 7]);
        let b = p2t8_pack([2, 2, 3, 7]);
        let sib = p2t8_pack([5, 5, 5, 5]);
        // Nodes differing only in the first word must yield different parents.
        assert_ne!(hash_pair_p2t8(&a, &sib), hash_pair_p2t8(&b, &sib));
        // Compression is not commutative.
        assert_ne!(hash_pair_p2t8(&a, &sib), hash_pair_p2t8(&sib, &a));
    }

    #[test]
    fn test_p2t8_tree_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0..4u32)
            .map(|j| hash_leaf_cols_p2t8(&[j, j + 1, j + 2]))
            .collect();
        let levels = build_tree_p2t8(leaves.clone());
        let root = levels.last().unwrap()[0];
        assert_eq!(levels.len(), 3); // 4 → 2 → 1
        let mut cur = leaves[1];
        cur = hash_pair_p2t8(&leaves[0], &cur); // idx 1 odd → sibling on the left
        cur = hash_pair_p2t8(&cur, &levels[1][1]);
        assert_eq!(cur, root);
    }

    #[test]
    fn test_p2t8_channel_deterministic_and_binds() {
        let mut a = P2T8Channel::init();
        let mut b = P2T8Channel::init();
        a.mix_root(&[0x11u8; 32]);
        b.mix_root(&[0x11u8; 32]);
        assert_eq!(a.draw_queries(10, 8), b.draw_queries(10, 8));
        let mut c = P2T8Channel::init();
        c.mix_root(&[0x12u8; 32]);
        let mut d = P2T8Channel::init();
        d.mix_root(&[0x11u8; 32]);
        assert_ne!(c.draw_queries(10, 8), d.draw_queries(10, 8));
        let mut e = P2T8Channel::init();
        e.mix_root(&[0x11u8; 32]);
        for q in e.draw_queries(10, 16) {
            assert!(q < (1 << 10));
        }
    }

    #[test]
    fn test_p2t8_channel_full_root_binds_all_bytes() {
        let mut base = [0u8; 32];
        base[0] = 0xAA;
        let mut alt = base;
        alt[0] = 0xBB;
        let q_full_base = { let mut c = P2T8Channel::init(); c.mix_root_full(&base); c.draw_queries(8, 4) };
        let q_full_alt = { let mut c = P2T8Channel::init(); c.mix_root_full(&alt); c.draw_queries(8, 4) };
        assert_ne!(q_full_base, q_full_alt, "mix_root_full must bind high bytes");
        let q_lo_base = { let mut c = P2T8Channel::init(); c.mix_root(&base); c.draw_queries(8, 4) };
        let q_lo_alt = { let mut c = P2T8Channel::init(); c.mix_root(&alt); c.draw_queries(8, 4) };
        assert_eq!(q_lo_base, q_lo_alt);
    }




    #[test]
    fn test_vfri11_smoke_small() {
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..16).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0xceu8; 32];
        let result = gen_vfri11_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2));
        assert!(result.is_ok(), "VFRI11 smoke test failed: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
        // VFRI11 version marker = 5.
        assert_eq!(u64::from_le_bytes(proof[0..8].try_into().unwrap()), 5u64);
    }


    #[test]
    fn test_vfri11_deterministic() {
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..16).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0x22u8; 32];
        let r1 = gen_vfri11_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        let r2 = gen_vfri11_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_vfri12_smoke_small() {
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..16).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0xceu8; 32];
        let result = gen_vfri12_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2));
        assert!(result.is_ok(), "VFRI12 smoke test failed: {:?}", result.err());
        let (proof, commitment, hints) = result.unwrap();
        assert!(proof.len() >= 700);
        assert_eq!(commitment.len(), 32);
        assert!(!hints.is_empty());
        // VFRI12 version marker = 6.
        assert_eq!(u64::from_le_bytes(proof[0..8].try_into().unwrap()), 6u64);
    }

    #[test]
    fn test_vfri12_differs_from_vfri11() {
        // Same inputs, t=16 vs t=8 hash backend → different trace root / hints.
        // This is what makes VFRI11 hints unusable against VFRI12: the derived
        // query indices differ, so the Merkle paths do not land.
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..16).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0xceu8; 32];
        let (p11, _, h11) = gen_vfri11_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        let (p12, _, h12) = gen_vfri12_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        assert_ne!(&p11[8..40], &p12[8..40], "t=16 trace root must differ from t=8");
        assert_ne!(h11, h12, "VFRI12 hints must differ from VFRI11 (wider nodes)");
        assert_eq!(u64::from_le_bytes(p12[0..8].try_into().unwrap()), 6u64);
    }

    #[test]
    fn test_vfri12_deterministic() {
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..16).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0x22u8; 32];
        let r1 = gen_vfri12_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        let r2 = gen_vfri12_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_vfri12_hint_size_matches_vfri11() {
        // The ABI is byte-COMPATIBLE across the width change — only node contents
        // widen, and a node is a bytes32 either way. Equal encoded length is the
        // cheap check that no layout drifted; the differing CONTENT is asserted
        // by test_vfri12_differs_from_vfri11.
        let cols: Vec<Vec<u32>> = (0..4).map(|j| (0..16).map(|i| (i*4 + j) as u32).collect()).collect();
        let batch_root = [0x31u8; 32];
        let (_, _, h11) = gen_vfri11_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        let (_, _, h12) = gen_vfri12_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        assert_eq!(h11.len(), h12.len());
    }

    // R4.1: the recursion bridge extracts per-query inputs from the REAL VFRI11
    // FRI chain, and the t=8 recursive composition proves + verifies the inner
    // proof's decommitments against the GENUINE committed last-layer root.
    #[test]
    fn test_vfri11_recursion_inputs_end_to_end() {
        use crate::recursive::composition_t8::{
            prove_queries_membership_t8, verify_queries_membership_t8,
        };
        let n = 16usize;
        let cols: Vec<Vec<u32>> = (0..6)
            .map(|j| (0..n).map(|i| ((i * 7 + j * 13 + 1) as u32) % 2_147_483_647).collect())
            .collect();
        let batch_root = [0x22u8; 32];

        let inputs = gen_vfri11_recursion_inputs(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        assert_eq!(inputs.queries.len(), 2);
        assert_eq!(inputs.paths.len(), 2);
        // Last layer at depth 4 with 2 folds: 16/4 = 4 leaves → path depth 2.
        assert_eq!(inputs.paths[0].0.len(), 2);

        // Shared-chain consistency: the ABI generator embeds the SAME trace root.
        let (proof_bytes, _, _) =
            gen_vfri11_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2)).unwrap();
        assert_eq!(&proof_bytes[8..40], &inputs.trace_root, "bridge and ABI generator must share the chain");

        // The recursion proves the REAL decommitments in ONE STARK…
        let r =
            prove_queries_membership_t8(&inputs.queries, &inputs.paths, &inputs.comp_paths).unwrap();
        assert_eq!(r.finals, inputs.finals, "recursion finals must equal the real fold-chain outputs");

        // The comp paths are DEEPER than the fold paths on real data — compRoot
        // spans the whole trace domain, the last FRI layer does not. This is the
        // shape that made the uniform-depth attempt fail before R4.11.
        let n = inputs.queries.len();
        assert!(
            r.comp_depth > r.depth,
            "real data must exercise mixed depths (comp {} vs fold {})",
            r.comp_depth, r.depth,
        );

        // Every final-fold path lands on the GENUINE committed last-layer root…
        for root in &r.roots[..n] {
            assert_eq!(*root, inputs.last_layer_root, "path must authenticate into friLayerRoots[K]");
        }
        // …and every composition path lands on the GENUINE committed compRoot.
        // THIS is the binding: compValue is pinned in-circuit (R4.10) and that
        // pinned value is now proven to be a member of the inner proof's committed
        // composition tree, so `fₚ` can no longer be chosen freely.
        for root in &r.roots[n..] {
            assert_eq!(*root, inputs.comp_root, "comp path must authenticate into compRoot");
        }
        let pxs: Vec<u32> = inputs.queries.iter().map(|(s, _)| s.2).collect();
        assert!(
            verify_queries_membership_t8(
                &r.proof, r.log_size, r.num_folds, r.depth, r.comp_depth, &r.challenges,
                &pxs, &r.finals, &r.indices, &r.roots,
            )
            .unwrap(),
            "the recursive proof over REAL VFRI11 data must verify",
        );
        // A tampered claimed root (≠ the committed one) must not verify.
        let mut bad = r.roots.clone();
        bad[0][0] ^= 1;
        assert!(
            !verify_queries_membership_t8(
                &r.proof, r.log_size, r.num_folds, r.depth, r.comp_depth, &r.challenges,
                &pxs, &r.finals, &r.indices, &bad,
            )
            .unwrap_or(false),
            "a root ≠ the committed FRI-layer root must not verify",
        );
    }

    // R4.2: replaying the channel from PUBLIC roots + OODS combos alone (no
    // trace/witness) reproduces exactly the challenges + query indices the real
    // VFRI11 chain drew — the on-chain channel-replay spec for
    // QLSAVerifierRecursive.sol. A tampered root must change the drawn challenges.
    #[test]
    fn test_vfri11_channel_replay_matches_chain() {
        let n = 16usize;
        let cols: Vec<Vec<u32>> = (0..5)
            .map(|j| (0..n).map(|i| ((i * 9 + j * 31 + 3) as u32) % 2_147_483_647).collect())
            .collect();
        let batch_root = [0x5Cu8; 32];
        let ch = vfri11_fri_chain(&cols, 4, &batch_root, 3, Some(2)).unwrap();

        let inp = Vfri11ChannelInputs {
            trace_root: ch.trace_root,
            oods_combo_pos: ch.oods_combo_pos,
            oods_combo_neg: ch.oods_combo_neg,
            comp_root: ch.comp_root,
            fri_layer_roots: ch.layer_roots.clone(),
            batch_root,
            tree_depth: 4,
            n_queries: 3,
        };
        let replay = vfri11_replay_channel(&inp).unwrap();

        // Byte-identical to the real chain's Fiat-Shamir draws.
        assert_eq!(replay.z_x, ch.z_x, "z_x");
        assert_eq!(replay.comp_alpha, ch.comp_alpha, "comp_alpha");
        assert_eq!(replay.fri_alpha, ch.fri_alpha, "fri_alpha");
        assert_eq!(replay.fri_alphas, ch.fri_alphas, "per-fold fri_alphas");
        assert_eq!(replay.query_indices, ch.derived_indices, "query indices");

        // Public-input soundness: a tampered committed root changes the challenges
        // (so an adversary can't cherry-pick queries by swapping a root on-chain).
        // trace_root is absorbed via mix_root_full (all 32 bytes), so any bit flip
        // reshuffles the whole downstream transcript incl. the query indices.
        let mut bad = inp.clone();
        bad.trace_root[0] ^= 1;
        let replay_bad = vfri11_replay_channel(&bad).unwrap();
        assert_ne!(replay_bad.query_indices, replay.query_indices, "tampered trace_root must move the queries");
        assert_ne!(replay_bad.z_x, replay.z_x, "tampered trace_root must change z_x");
    }

    /// Writes the channel-replay fixture consumed by the Solidity cross-check
    /// (RecursiveChannelReplay.test.js). Inputs = public roots + OODS combos;
    /// expected = the challenges/indices vfri11_replay_channel draws. Run with:
    /// cargo test write_vfri11_channel_replay_fixture -- --ignored --nocapture
    #[test]
    #[ignore = "regenerates contracts/test/fixtures/vfri11_channel_replay.json"]
    fn write_vfri11_channel_replay_fixture() {
        let n = 16usize;
        let cols: Vec<Vec<u32>> = (0..5)
            .map(|j| (0..n).map(|i| ((i * 9 + j * 31 + 3) as u32) % 2_147_483_647).collect())
            .collect();
        let batch_root = [0x5Cu8; 32];
        let (tree_depth, n_queries, num_folds) = (4u32, 3usize, 2usize);
        let ch = vfri11_fri_chain(&cols, tree_depth, &batch_root, n_queries, Some(num_folds)).unwrap();
        let inp = Vfri11ChannelInputs {
            trace_root: ch.trace_root,
            oods_combo_pos: ch.oods_combo_pos,
            oods_combo_neg: ch.oods_combo_neg,
            comp_root: ch.comp_root,
            fri_layer_roots: ch.layer_roots.clone(),
            batch_root,
            tree_depth,
            n_queries,
        };
        let out = vfri11_replay_channel(&inp).unwrap();

        let hx = |b: &[u8; 32]| format!("0x{}", hex::encode(b));
        let roots_json: Vec<String> = inp.fri_layer_roots.iter().map(|r| hx(r)).collect();
        // uint128 challenges + query indices are emitted as QUOTED strings so
        // JSON.parse keeps them exact (bare numbers > 2^53 lose precision as JS floats).
        let alphas_json: Vec<String> = out.fri_alphas.iter().map(|a| format!("\"{a}\"")).collect();
        let idx_json: Vec<String> = out.query_indices.iter().map(|i| format!("\"{i}\"")).collect();
        let json = format!(
            concat!(
                "{{\n",
                "  \"traceRoot\": \"{}\",\n",
                "  \"oodsComboPos\": \"{}\",\n",
                "  \"oodsComboNeg\": \"{}\",\n",
                "  \"compRoot\": \"{}\",\n",
                "  \"friLayerRoots\": [{}],\n",
                "  \"batchRoot\": \"{}\",\n",
                "  \"treeDepth\": {},\n",
                "  \"nQueries\": {},\n",
                "  \"expected\": {{\n",
                "    \"zX\": \"{}\",\n",
                "    \"compAlpha\": \"{}\",\n",
                "    \"friAlpha\": \"{}\",\n",
                "    \"friAlphas\": [{}],\n",
                "    \"queryIndices\": [{}]\n",
                "  }}\n}}\n"
            ),
            hx(&inp.trace_root),
            inp.oods_combo_pos,
            inp.oods_combo_neg,
            hx(&inp.comp_root),
            roots_json.iter().map(|r| format!("\"{r}\"")).collect::<Vec<_>>().join(", "),
            hx(&inp.batch_root),
            inp.tree_depth,
            inp.n_queries,
            out.z_x,
            out.comp_alpha,
            out.fri_alpha,
            alphas_json.join(", "),
            idx_json.join(", "),
        );
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../contracts/test/fixtures/vfri11_channel_replay.json");
        std::fs::write(path, json).expect("write fixture");
        println!("wrote {path}");
    }

    // R4.3 tie-together: the query indices the on-chain channel replay derives are
    // EXACTLY the positions the recursion proof commits to (each query's px =
    // coset_at(idx).x). This is the composition invariant QLSAVerifierRecursive.sol
    // relies on: replay → indices, then verify the recursion bound to those px —
    // a prover can't prove membership at cherry-picked positions.
    #[test]
    fn test_channel_indices_match_recursion_query_points() {
        let n = 16usize;
        let cols: Vec<Vec<u32>> = (0..5)
            .map(|j| (0..n).map(|i| ((i * 9 + j * 31 + 3) as u32) % 2_147_483_647).collect())
            .collect();
        let batch_root = [0x5Cu8; 32];
        let (tree_depth, n_queries, num_folds) = (4u32, 3usize, 2usize);

        let ch = vfri11_fri_chain(&cols, tree_depth, &batch_root, n_queries, Some(num_folds)).unwrap();
        let inp = Vfri11ChannelInputs {
            trace_root: ch.trace_root,
            oods_combo_pos: ch.oods_combo_pos,
            oods_combo_neg: ch.oods_combo_neg,
            comp_root: ch.comp_root,
            fri_layer_roots: ch.layer_roots.clone(),
            batch_root,
            tree_depth,
            n_queries,
        };
        let replay = vfri11_replay_channel(&inp).unwrap();
        let rec = gen_vfri11_recursion_inputs(&cols, tree_depth, &batch_root, n_queries, Some(num_folds)).unwrap();

        assert_eq!(replay.query_indices.len(), rec.queries.len());
        for q in 0..replay.query_indices.len() {
            let idx = replay.query_indices[q];
            let px_from_index = coset_at(tree_depth, idx as u64).0;
            // queries[q].step.2 is the px the recursion proof pins for this query.
            assert_eq!(
                px_from_index, rec.queries[q].0 .2,
                "channel-derived index {idx} must equal the recursion query point px at slot {q}",
            );
            // And the replay's FRI challenges are the ones the recursion consumes:
            // query q's circle-fold alpha (step.6) == the single fri_alpha; the
            // per-fold alphas (rounds[k].1) == replay.fri_alphas[k].
            assert_eq!(rec.queries[q].0 .6, replay.fri_alpha, "circle-fold alpha");
            for (k, round) in rec.queries[q].1.iter().enumerate() {
                assert_eq!(round.1, replay.fri_alphas[k], "fold-round {k} alpha");
            }
        }
    }

    // R4.4: the OUTER recursive trace exports as plain columns and feeds the
    // EXISTING VFRI11 hint generator — the path to on-chain verification of the
    // recursion by the deployed VFRI11 machinery at small constant gas. The outer
    // proof is cross-bound to the INNER proof's public roots via batch_root =
    // keccak(inner trace_root ‖ inner last-layer root) (BatchRegistryV4 pattern).
    #[test]
    fn test_recursive_outer_trace_vfri11_hints() {
        use crate::recursive::composition_t8::outer_trace_columns_t8;

        let n = 16usize;
        let cols: Vec<Vec<u32>> = (0..5)
            .map(|j| (0..n).map(|i| ((i * 9 + j * 31 + 3) as u32) % 2_147_483_647).collect())
            .collect();
        let inner_batch_root = [0x5Cu8; 32];
        let rec = gen_vfri11_recursion_inputs(&cols, 4, &inner_batch_root, 2, Some(2)).unwrap();

        // Outer trace: 87 columns at the composition's shared log_size.
        let (outer_cols, outer_log) = outer_trace_columns_t8(&rec.queries, &rec.paths, &rec.comp_paths).unwrap();
        assert_eq!(outer_cols.len(), 87, "rv 42 + merkle_t8 45 main columns");
        assert!(outer_cols.iter().all(|c| c.len() == 1usize << outer_log));

        // Cross-bind the outer proof to the inner proof's public roots.
        let ch_full = vfri11_fri_chain(&cols, 4, &inner_batch_root, 2, Some(2)).unwrap();
        let outer_batch_root: [u8; 32] = outer_binding_root(&Vfri11ChannelInputs {
            trace_root: ch_full.trace_root,
            oods_combo_pos: ch_full.oods_combo_pos,
            oods_combo_neg: ch_full.oods_combo_neg,
            comp_root: ch_full.comp_root,
            fri_layer_roots: ch_full.layer_roots.clone(),
            batch_root: inner_batch_root,
            tree_depth: 4,
            n_queries: 2,
        });

        // The outer trace feeds the EXISTING VFRI11 hint generator unchanged.
        let (proof1, commit1, hints1) = gen_vfri11_hints_from_cols_nfolds(
            &outer_cols, outer_log, &outer_batch_root, 2, Some(3),
        )
        .unwrap();
        assert_eq!(proof1[0..8], 5u64.to_le_bytes(), "VFRI11 version marker");
        assert!(!hints1.is_empty());

        // Deterministic…
        let (proof2, commit2, hints2) = gen_vfri11_hints_from_cols_nfolds(
            &outer_cols, outer_log, &outer_batch_root, 2, Some(3),
        )
        .unwrap();
        assert_eq!((&proof1, &commit1, &hints1), (&proof2, &commit2, &hints2));

        // …and genuinely bound: a different inner binding root changes the outer
        // hints (query indices shift), so outer proofs can't be replayed across
        // different inner proofs.
        let mut other_root = outer_batch_root;
        other_root[0] ^= 1;
        let (_, _, hints3) =
            gen_vfri11_hints_from_cols_nfolds(&outer_cols, outer_log, &other_root, 2, Some(3))
                .unwrap();
        assert_ne!(hints1, hints3, "outer hints must be bound to the inner roots");
    }

    /// Writes the full R4.5 recursive-verifier E2E fixture consumed by
    /// QLSAVerifierRecursive.test.js: the inner proof's public roots, the outer
    /// (recursive-trace) VFRI11 proof/commitment/hints cross-bound to them, and
    /// the expected replayed challenges. Run with:
    /// cargo test write_recursive_e2e_fixture -- --ignored --nocapture
    #[test]
    #[ignore = "regenerates contracts/test/fixtures/recursive_e2e.json"]
    fn write_recursive_e2e_fixture() {
        use crate::recursive::composition_t8::outer_trace_columns_t8;

        // ── Inner VFRI11 statement (same params as the channel-replay fixture).
        let n = 16usize;
        let cols: Vec<Vec<u32>> = (0..5)
            .map(|j| (0..n).map(|i| ((i * 9 + j * 31 + 3) as u32) % 2_147_483_647).collect())
            .collect();
        let inner_batch_root = [0x5Cu8; 32];
        // Inner config chosen so the OUTER trace stays inside the deployed
        // VFRI11's validated gas profile: num_folds=3 leaves a 2-element last
        // layer → membership path depth 1 → outer merkle block = 22 rows, so the
        // outer trace fits log_size 5 (vs 7 for the earlier depth-2 paths).
        let (tree_depth, n_queries, num_folds) = (4u32, 1usize, 3usize);
        let ch = vfri11_fri_chain(&cols, tree_depth, &inner_batch_root, n_queries, Some(num_folds)).unwrap();
        let rec = gen_vfri11_recursion_inputs(&cols, tree_depth, &inner_batch_root, n_queries, Some(num_folds)).unwrap();

        // ── Outer recursive trace → VFRI11 hints, cross-bound to the inner publics.
        let (outer_cols, outer_log) = outer_trace_columns_t8(&rec.queries, &rec.paths, &rec.comp_paths).unwrap();
        let chan_inputs = Vfri11ChannelInputs {
            trace_root: ch.trace_root,
            oods_combo_pos: ch.oods_combo_pos,
            oods_combo_neg: ch.oods_combo_neg,
            comp_root: ch.comp_root,
            fri_layer_roots: ch.layer_roots.clone(),
            batch_root: inner_batch_root,
            tree_depth,
            n_queries,
        };
        // R4.7: bind EVERY public inner field, not just trace+last-layer roots.
        let outer_bound: [u8; 32] = outer_binding_root(&chan_inputs);
        // Outer FRI params sized to the deployed VFRI11's gas envelope: cost
        // scales ~ n_queries·(3+2·folds)·tree_depth; the generic on-chain E2E
        // (depth 4, 2 queries, 2 folds ≈ 13.1M gas) is 56 such units, this is 35.
        let outer_folds = 2usize;
        let (outer_proof, outer_commit_hex, outer_hints) =
            gen_vfri11_hints_from_cols_nfolds(&outer_cols, outer_log, &outer_bound, 1, Some(outer_folds))
                .unwrap();

        // ── Expected replayed challenges (the contract returns these).
        let replay = vfri11_replay_channel(&chan_inputs).unwrap();

        let hx = |b: &[u8]| format!("0x{}", hex::encode(b));
        let roots_json: Vec<String> =
            ch.layer_roots.iter().map(|r| format!("\"{}\"", hx(r))).collect();
        let idx_json: Vec<String> =
            replay.query_indices.iter().map(|i| format!("\"{i}\"")).collect();
        // The final FRI layer's evaluations — the on-chain bounded-degree check
        // rebuilds their tree and compares it with friLayerRoots[K] (R4.13).
        let last_evals_json: Vec<String> = ch.layer_values[ch.num_folds]
            .iter()
            .map(|v| format!("\"{v}\""))
            .collect();
        let json = format!(
            concat!(
                "{{\n",
                "  \"inner\": {{\n",
                "    \"traceRoot\": \"{}\",\n",
                "    \"oodsComboPos\": \"{}\",\n",
                "    \"oodsComboNeg\": \"{}\",\n",
                "    \"compRoot\": \"{}\",\n",
                "    \"friLayerRoots\": [{}],\n",
                "    \"batchRoot\": \"{}\",\n",
                "    \"treeDepth\": {},\n",
                "    \"nQueries\": {},\n",
                "    \"lastLayerEvals\": [{}]\n",
                "  }},\n",
                "  \"outer\": {{\n",
                "    \"bindingRoot\": \"{}\",\n",
                "    \"proof\": \"{}\",\n",
                "    \"commitment\": \"0x{}\",\n",
                "    \"hints\": \"{}\"\n",
                "  }},\n",
                "  \"expected\": {{\n",
                "    \"zX\": \"{}\",\n",
                "    \"compAlpha\": \"{}\",\n",
                "    \"friAlpha\": \"{}\",\n",
                "    \"friAlphas\": [{}],\n",
                "    \"queryIndices\": [{}]\n",
                "  }}\n}}\n"
            ),
            hx(&ch.trace_root),
            ch.oods_combo_pos,
            ch.oods_combo_neg,
            hx(&ch.comp_root),
            roots_json.join(", "),
            hx(&inner_batch_root),
            tree_depth,
            n_queries,
            last_evals_json.join(", "),
            hx(&outer_bound),
            hx(&outer_proof),
            outer_commit_hex,
            hx(&outer_hints),
            replay.z_x,
            replay.comp_alpha,
            replay.fri_alpha,
            replay
                .fri_alphas
                .iter()
                .map(|a| format!("\"{a}\""))
                .collect::<Vec<_>>()
                .join(", "),
            idx_json.join(", "),
        );
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../contracts/test/fixtures/recursive_e2e.json");
        std::fs::write(path, json).expect("write fixture");
        println!("wrote {path} (outer_log={outer_log}, outer_folds={outer_folds})");
    }

    // The bridge must work at the odd-orientation edge too: many queries so some
    // fold rounds hit the high half (cur_idx ≥ layer_sz → negated twiddle inverse).
    #[test]
    fn test_vfri11_recursion_inputs_orientation_coverage() {
        use crate::recursive::composition_t8::prove_queries_membership_t8;
        let n = 32usize;
        let cols: Vec<Vec<u32>> = (0..3)
            .map(|j| (0..n).map(|i| ((i * 11 + j * 17 + 5) as u32) % 2_147_483_647).collect())
            .collect();
        let batch_root = [0x9Au8; 32];
        // depth 5, 3 folds, 6 queries → high odds of both fold orientations.
        let inputs = gen_vfri11_recursion_inputs(&cols, 5, &batch_root, 6, Some(3)).unwrap();
        // The hard invariant inside the bridge already rejects any orientation
        // error; proving must then succeed over the real data.
        let r = prove_queries_membership_t8(&inputs.queries, &inputs.paths, &inputs.comp_paths).unwrap();
        assert_eq!(r.finals, inputs.finals);
        // Roots are laid out as N final-fold, then 2N composition paths.
        let n = inputs.queries.len();
        for root in &r.roots[..n] {
            assert_eq!(*root, inputs.last_layer_root);
        }
        for root in &r.roots[n..] {
            assert_eq!(*root, inputs.comp_root);
        }
    }

    /// The v8 core: cross-bound recursive bundles from REAL V23 data.
    ///
    /// Validates the wiring at q=2 (fast); the production-shaped fixture is
    /// emitted by `write_v23_recursive_bundles_fixture` below.
    ///
    ///   cargo test test_v23_recursive_bundles -- --ignored --nocapture
    #[test]
    #[ignore]
    fn test_v23_recursive_bundles() {
        use sha3::{Digest as Sha3Digest, Keccak256};

        let (z, c, t1, a_hat) = super::tests::make_v23_inputs(777);
        let hints = [[false; 256]; 6];
        let batch_root = [0x66u8; 32];

        let (b10, b8) =
            gen_mldsa_v23_recursive_bundles(&z, &c, &t1, &a_hat, &hints, &batch_root, 2, Some(6))
                .unwrap();

        // Groups and depths are the real V23 shape.
        assert_eq!(b10.tree_depth, 10);
        assert_eq!(b8.tree_depth, 8);
        assert_eq!(b10.fri_layer_roots.len(), 7, "num_folds=6 -> 7 roots");
        // Last layer sizes: 2^(10-6)=16 and 2^(8-6)=4.
        assert_eq!(b10.last_layer_evals.len(), 16);
        assert_eq!(b8.last_layer_evals.len(), 4);

        // Cross-binding holds in BOTH directions and the roots differ.
        let keccak2 = |a: &[u8], b: &[u8; 32]| -> [u8; 32] {
            let mut h = Keccak256::new();
            h.update(a);
            h.update(b);
            h.finalize().into()
        };
        assert_eq!(b10.bound_root, keccak2(&batch_root, &b8.trace_root));
        assert_eq!(b8.bound_root, keccak2(&batch_root, &b10.trace_root));
        assert_ne!(b10.bound_root, b8.bound_root);

        // Each bundle's channel replay must succeed from its OWN publics alone —
        // this is exactly what QLSAVerifierRecursive.replayChallenges recomputes.
        for b in [&b10, &b8] {
            let ch = vfri11_replay_channel(&Vfri11ChannelInputs {
                trace_root: b.trace_root,
                oods_combo_pos: b.oods_combo_pos,
                oods_combo_neg: b.oods_combo_neg,
                comp_root: b.comp_root,
                fri_layer_roots: b.fri_layer_roots.clone(),
                batch_root: b.bound_root,
                tree_depth: b.tree_depth,
                n_queries: b.n_queries,
            })
            .unwrap();
            assert_eq!(ch.query_indices.len(), b.n_queries);
            assert!(!b.outer_proof.is_empty() && !b.outer_hints.is_empty());
        }
    }

    /// Emits the REAL-V23 recursive-bundle fixture for BatchRegistryV7's on-chain
    /// E2E, at the PRODUCTION n_queries = 20 (130-bit). Slow (~10+ min).
    ///
    ///   cargo test write_v23_recursive_bundles_fixture -- --ignored --nocapture
    #[test]
    #[ignore]
    fn write_v23_recursive_bundles_fixture() {
        let (z, c, t1, a_hat) = super::tests::make_v23_inputs(16600);
        let hints = [[false; 256]; 6];
        let batch_root = [0xB2u8; 32];
        let n_queries = 20usize;

        let (b10, b8) = gen_mldsa_v23_recursive_bundles(
            &z, &c, &t1, &a_hat, &hints, &batch_root, n_queries, Some(6),
        )
        .unwrap();

        let hx = |b: &[u8]| format!("0x{}", hex::encode(b));
        let bundle_json = |b: &RecursiveBundleData| -> String {
            let roots: Vec<String> =
                b.fri_layer_roots.iter().map(|r| format!("\"{}\"", hx(r))).collect();
            let evals: Vec<String> =
                b.last_layer_evals.iter().map(|v| format!("\"{v}\"")).collect();
            format!(
                concat!(
                    "{{\n",
                    "      \"inner\": {{\n",
                    "        \"traceRoot\": \"{}\",\n",
                    "        \"oodsComboPos\": \"{}\",\n",
                    "        \"oodsComboNeg\": \"{}\",\n",
                    "        \"compRoot\": \"{}\",\n",
                    "        \"friLayerRoots\": [{}],\n",
                    "        \"batchRoot\": \"{}\",\n",
                    "        \"treeDepth\": {},\n",
                    "        \"nQueries\": {}\n",
                    "      }},\n",
                    "      \"outerProof\": \"{}\",\n",
                    "      \"outerCommitment\": \"0x{}\",\n",
                    "      \"outerHints\": \"{}\",\n",
                    "      \"lastLayerEvals\": [{}]\n",
                    "    }}"
                ),
                hx(&b.trace_root),
                b.oods_combo_pos,
                b.oods_combo_neg,
                hx(&b.comp_root),
                roots.join(", "),
                hx(&b.bound_root),
                b.tree_depth,
                b.n_queries,
                hx(&b.outer_proof),
                b.outer_commitment,
                hx(&b.outer_hints),
                evals.join(", "),
            )
        };
        let json = format!(
            "{{\n  \"merkleRoot\": \"{}\",\n  \"bundle10\": {},\n  \"bundle8\": {}\n}}\n",
            hx(&batch_root),
            bundle_json(&b10),
            bundle_json(&b8),
        );
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../contracts/test/fixtures/v23_recursive_bundles_e2e.json"
        );
        std::fs::write(path, json).unwrap();
        println!("wrote {path}");
    }

    /// The recursion over REAL V23 data at PRODUCTION security (n_queries = 20).
    ///
    /// Everything measured so far used synthetic inner statements. Those give the
    /// right OUTER cost — the outer trace depends only on
    /// (n_queries, num_folds, tree_depth) — but they do not prove the extraction
    /// works on the actual 1298-column V23 LOG=10 group. This does.
    ///
    /// Slow (a 20-query V23 chain), hence #[ignore]:
    ///   cargo test test_v23_recursion_inputs_production -- --ignored --nocapture
    #[test]
    #[ignore]
    fn test_v23_recursion_inputs_production() {
        use crate::recursive::composition_t8::{
            outer_trace_columns_t8, prove_queries_membership_t8, verify_queries_membership_t8,
        };

        let (z, c, t1, a_hat) = super::tests::make_v23_inputs(4242);
        let batch_root = [0x31u8; 32];
        let n_queries = 20usize;
        let num_folds = 6usize;

        // Same columns the ABI hint generator uses (shared builder, so no drift).
        let rec = gen_mldsa_v23_recursion_inputs_log10(
            &z, &c, &t1, &a_hat, &batch_root, n_queries, Some(num_folds),
        )
        .unwrap();
        assert_eq!(rec.queries.len(), n_queries);
        assert_eq!(rec.paths.len(), n_queries);
        assert_eq!(rec.comp_paths.len(), n_queries);

        // The bridge and the ABI generator must share the chain: same trace root.
        let (proof_bytes, _, _) = gen_mldsa_v23_vfri11_hints(
            &z, &c, &t1, &a_hat, &batch_root, n_queries, Some(num_folds),
        )
        .unwrap();
        assert_eq!(
            &proof_bytes[8..40],
            &rec.trace_root,
            "recursion bridge and ABI generator must share the V23 chain",
        );

        // Comp paths span the whole trace domain; fold paths are shallower.
        assert!(
            rec.comp_paths[0].0.len() > rec.paths[0].0.len(),
            "real V23 data must exercise MIXED path depths (comp {} vs fold {})",
            rec.comp_paths[0].0.len(),
            rec.paths[0].0.len(),
        );

        let (outer_cols, outer_log) =
            outer_trace_columns_t8(&rec.queries, &rec.paths, &rec.comp_paths).unwrap();
        println!(
            "V23 LOG=10 @ q={n_queries}: outer_log={outer_log} outer_cols={}",
            outer_cols.len()
        );

        // Prove + verify the recursion over the REAL V23 decommitments.
        let r =
            prove_queries_membership_t8(&rec.queries, &rec.paths, &rec.comp_paths).unwrap();
        assert_eq!(r.finals, rec.finals, "finals must equal the real fold-chain outputs");
        for root in &r.roots[..n_queries] {
            assert_eq!(*root, rec.last_layer_root, "fold path must land on friLayerRoots[K]");
        }
        for root in &r.roots[n_queries..] {
            assert_eq!(*root, rec.comp_root, "comp path must land on the committed compRoot");
        }
        let pxs: Vec<u32> = rec.queries.iter().map(|(s, _)| s.2).collect();
        assert!(
            verify_queries_membership_t8(
                &r.proof, r.log_size, r.num_folds, r.depth, r.comp_depth, &r.challenges,
                &pxs, &r.finals, &r.indices, &r.roots,
            )
            .unwrap(),
            "the recursion over REAL V23 data at production security must verify",
        );
    }

    /// Scaling study: DIRECT VFRI11 verification vs the RECURSION, as a function of
    /// the inner query count, at production depth/folds.
    ///
    /// R4.15 measured a single point (n_queries = 1) and found the recursion 2.7x
    /// more expensive. The open question is where the two curves cross: direct
    /// verification should scale linearly in n_queries, while the outer trace grows
    /// only logarithmically. Both costs are essentially independent of the inner
    /// column count — VFRI6+ moved the O(n_cols) composition work off-chain — so
    /// synthetic statements at the real depth/folds give the real answer.
    ///
    /// Run with: cargo test write_recursion_scaling_fixture -- --ignored --nocapture
    #[test]
    #[ignore]
    fn write_recursion_scaling_fixture() {
        use crate::recursive::composition_t8::outer_trace_columns_t8;

        let tree_depth = 10u32;
        let num_folds = 6usize;
        let batch_root = [0x77u8; 32];
        let n = 1usize << tree_depth;
        let cols: Vec<Vec<u32>> = (0..5)
            .map(|j| (0..n).map(|i| ((i * 9 + j * 31 + 3) as u32) % 2_147_483_647).collect())
            .collect();
        let hx = |b: &[u8]| format!("0x{}", hex::encode(b));

        let mut entries: Vec<String> = Vec::new();
        // q=20 is the production security point: log_blowup(6)*20 + pow_bits(10)
        // = 130 bits. The whole production plan rests on what happens there, and
        // extrapolation has been wrong every time this series (see
        // docs/conclusions.md §1.4), so it is measured rather than projected.
        for &q in &[1usize, 2, 4, 8, 16, 20] {
            // ── DIRECT: what BatchRegistryV5 verifies today, per group.
            let (d_proof, d_commit, d_hints) =
                gen_vfri11_hints_from_cols_nfolds(&cols, tree_depth, &batch_root, q, Some(num_folds))
                    .unwrap();

            // ── RECURSIVE: the same statement proved by the recursion.
            let ch = vfri11_fri_chain(&cols, tree_depth, &batch_root, q, Some(num_folds)).unwrap();
            let rec =
                gen_vfri11_recursion_inputs(&cols, tree_depth, &batch_root, q, Some(num_folds)).unwrap();
            let (outer_cols, outer_log) =
                outer_trace_columns_t8(&rec.queries, &rec.paths, &rec.comp_paths).unwrap();
            let chan_inputs = Vfri11ChannelInputs {
                trace_root: ch.trace_root,
                oods_combo_pos: ch.oods_combo_pos,
                oods_combo_neg: ch.oods_combo_neg,
                comp_root: ch.comp_root,
                fri_layer_roots: ch.layer_roots.clone(),
                batch_root,
                tree_depth,
                n_queries: q,
            };
            let outer_bound: [u8; 32] = outer_binding_root(&chan_inputs);
            // Scale the OUTER fold count with the outer trace. The on-chain
            // last-layer check rebuilds a tree of 2^(outer_log − outer_folds)
            // leaves, so a fixed fold count makes that term grow linearly with the
            // outer trace and dominate everything else. Targeting a 32-leaf last
            // layer keeps it constant instead.
            let outer_folds = (outer_log as usize).saturating_sub(5).max(1);
            let (o_proof, o_commit, o_hints) = gen_vfri11_hints_from_cols_nfolds(
                &outer_cols, outer_log, &outer_bound, 1, Some(outer_folds),
            )
            .unwrap();

            let roots_json: Vec<String> =
                ch.layer_roots.iter().map(|r| format!("\"{}\"", hx(r))).collect();
            let evals_json: Vec<String> =
                ch.layer_values[ch.num_folds].iter().map(|v| format!("\"{v}\"")).collect();

            entries.push(format!(
                concat!(
                    "{{\n",
                    "    \"nQueries\": {},\n",
                    "    \"outerLog\": {},\n",
                    "    \"direct\": {{\n",
                    "      \"proof\": \"{}\",\n",
                    "      \"commitment\": \"0x{}\",\n",
                    "      \"batchRoot\": \"{}\",\n",
                    "      \"hints\": \"{}\"\n",
                    "    }},\n",
                    "    \"recursive\": {{\n",
                    "      \"inner\": {{\n",
                    "        \"traceRoot\": \"{}\",\n",
                    "        \"oodsComboPos\": \"{}\",\n",
                    "        \"oodsComboNeg\": \"{}\",\n",
                    "        \"compRoot\": \"{}\",\n",
                    "        \"friLayerRoots\": [{}],\n",
                    "        \"batchRoot\": \"{}\",\n",
                    "        \"treeDepth\": {},\n",
                    "        \"nQueries\": {}\n",
                    "      }},\n",
                    "      \"outerProof\": \"{}\",\n",
                    "      \"outerCommitment\": \"0x{}\",\n",
                    "      \"outerHints\": \"{}\",\n",
                    "      \"lastLayerEvals\": [{}]\n",
                    "    }}\n",
                    "  }}"
                ),
                q, outer_log,
                hx(&d_proof), d_commit, hx(&batch_root), hx(&d_hints),
                hx(&ch.trace_root), ch.oods_combo_pos, ch.oods_combo_neg, hx(&ch.comp_root),
                roots_json.join(", "), hx(&batch_root), tree_depth, q,
                hx(&o_proof), o_commit, hx(&o_hints), evals_json.join(", "),
            ));
            println!(
                "q={q}: outer_log={outer_log} outer_folds={outer_folds} direct_hints={}B outer_hints={}B",
                d_hints.len(), o_hints.len(),
            );
        }

        let json = format!("{{\n  \"points\": [{}]\n}}\n", entries.join(", "));
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../contracts/test/fixtures/recursion_scaling.json"
        );
        std::fs::write(path, json).unwrap();
        println!("wrote {path}");
    }

    /// Sizing probe: how big is the OUTER recursive trace at production inner
    /// parameters?  The outer trace depends on (n_queries, num_folds, tree_depth)
    /// only — NOT on the inner column count — so a synthetic inner statement at
    /// the real config gives the real answer, and V23's 1298/2206 columns are
    /// irrelevant here.
    ///
    /// Run with: cargo test probe_outer_trace_sizes -- --ignored --nocapture
    #[test]
    #[ignore]
    fn probe_outer_trace_sizes() {
        use crate::recursive::composition_t8::outer_trace_columns_t8;
        for &(tree_depth, num_folds, n_queries) in &[
            (4u32, 3usize, 1usize),   // current toy fixture
            (8, 6, 1),                // V23 LOG=8 group, 1 query
            (10, 6, 1),               // V23 LOG=10 group, 1 query
            (10, 6, 2),
            (10, 6, 4),
        ] {
            let n = 1usize << tree_depth;
            let cols: Vec<Vec<u32>> = (0..5)
                .map(|j| (0..n).map(|i| ((i * 9 + j * 31 + 3) as u32) % 2_147_483_647).collect())
                .collect();
            let br = [0x5Cu8; 32];
            match gen_vfri11_recursion_inputs(&cols, tree_depth, &br, n_queries, Some(num_folds)) {
                Ok(rec) => match outer_trace_columns_t8(&rec.queries, &rec.paths, &rec.comp_paths) {
                    Ok((outer_cols, outer_log)) => println!(
                        "depth={tree_depth} folds={num_folds} queries={n_queries} -> outer_log={outer_log} rows={} cols={}",
                        1usize << outer_log,
                        outer_cols.len(),
                    ),
                    Err(e) => println!("depth={tree_depth} folds={num_folds} queries={n_queries} -> outer trace ERR {e}"),
                },
                Err(e) => println!("depth={tree_depth} folds={num_folds} queries={n_queries} -> inputs ERR {e}"),
            }
        }
    }

    /// Writes the CROSS-BOUND PAIR fixture consumed by BatchRegistryV7E2E.test.js.
    ///
    /// A V23 batch is two trace groups, so BatchRegistryV7 takes two recursive
    /// bundles and requires each to have been produced against the OTHER group's
    /// trace root — the same cross-proof binding BatchRegistryV5 enforces:
    ///
    ///     bundleA.inner.batchRoot == keccak(merkleRoot ‖ traceRootB)
    ///     bundleB.inner.batchRoot == keccak(merkleRoot ‖ traceRootA)
    ///
    /// Generated in two passes, which is sound only because the trace root is
    /// committed BEFORE `batchRoot` enters the channel (it is mixed just before
    /// drawQueries). The generator asserts that invariant instead of assuming it.
    ///
    /// Run with: cargo test write_recursive_pair_fixture -- --ignored --nocapture
    #[test]
    #[ignore]
    fn write_recursive_pair_fixture() {
        emit_recursive_pair_fixture("recursive_pair_e2e.json", (4, 3), (4, 3));
    }

    /// Same as above at PRODUCTION inner parameters: the V23 LOG=10 group is
    /// tree_depth 10 and the LOG=8 group is tree_depth 8, both with num_folds=6.
    /// The recursion's outer trace depends on (n_queries, num_folds, tree_depth)
    /// only — not on the inner column count — so a synthetic inner statement at the
    /// real config yields the real outer proof size, and V23's 1298/2206 columns
    /// do not enter into it.
    ///
    /// Run with: cargo test write_recursive_pair_prod_fixture -- --ignored --nocapture
    #[test]
    #[ignore]
    fn write_recursive_pair_prod_fixture() {
        emit_recursive_pair_fixture("recursive_pair_prod_e2e.json", (10, 6), (8, 6));
    }

    /// Shared generator for a cross-bound pair fixture.
    fn emit_recursive_pair_fixture(
        file_name: &str,
        (depth_a, folds_a): (u32, usize),
        (depth_b, folds_b): (u32, usize),
    ) {
        use crate::recursive::composition_t8::outer_trace_columns_t8;
        use sha3::{Digest as Sha3Digest, Keccak256};

        let merkle_root = [0xA7u8; 32];
        let n_queries = 1usize;
        let mk_cols = |depth: u32, seed: usize, ncols: usize| -> Vec<Vec<u32>> {
            let n = 1usize << depth;
            (0..ncols)
                .map(|j| {
                    (0..n)
                        .map(|i| ((i * 9 + j * 31 + seed) as u32) % 2_147_483_647)
                        .collect()
                })
                .collect()
        };
        // Two DISTINCT statements standing in for the LOG=10 / LOG=8 groups.
        let cols_a = mk_cols(depth_a, 3, 5);
        let cols_b = mk_cols(depth_b, 11, 4);

        let chain_a = |br: &[u8; 32]| {
            vfri11_fri_chain(&cols_a, depth_a, br, n_queries, Some(folds_a)).unwrap()
        };
        let chain_b = |br: &[u8; 32]| {
            vfri11_fri_chain(&cols_b, depth_b, br, n_queries, Some(folds_b)).unwrap()
        };
        let keccak2 = |a: &[u8; 32], b: &[u8; 32]| -> [u8; 32] {
            let mut h = Keccak256::new();
            h.update(a);
            h.update(b);
            h.finalize().into()
        };

        // Pass 1: provisional roots, only to learn each group's trace root.
        let t_a = chain_a(&merkle_root).trace_root;
        let t_b = chain_b(&merkle_root).trace_root;

        // Pass 2: each group bound to the OTHER's trace root.
        let bound_a = keccak2(&merkle_root, &t_b);
        let bound_b = keccak2(&merkle_root, &t_a);
        let ch_a = chain_a(&bound_a);
        let ch_b = chain_b(&bound_b);
        assert_eq!(ch_a.trace_root, t_a, "trace root must not depend on batchRoot");
        assert_eq!(ch_b.trace_root, t_b, "trace root must not depend on batchRoot");

        let hx = |b: &[u8]| format!("0x{}", hex::encode(b));

        // Build one bundle's JSON from its chain + the batch root it was bound to.
        let bundle_json = |cols: &Vec<Vec<u32>>, ch: &Vfri11Chain, br: &[u8; 32],
                           tree_depth: u32, num_folds: usize| -> String {
            let rec =
                gen_vfri11_recursion_inputs(cols, tree_depth, br, n_queries, Some(num_folds)).unwrap();
            let (outer_cols, outer_log) =
                outer_trace_columns_t8(&rec.queries, &rec.paths, &rec.comp_paths).unwrap();
            let chan_inputs = Vfri11ChannelInputs {
                trace_root: ch.trace_root,
                oods_combo_pos: ch.oods_combo_pos,
                oods_combo_neg: ch.oods_combo_neg,
                comp_root: ch.comp_root,
                fri_layer_roots: ch.layer_roots.clone(),
                batch_root: *br,
                tree_depth,
                n_queries,
            };
            let outer_bound: [u8; 32] = outer_binding_root(&chan_inputs);
            // Scale the OUTER fold count with the outer trace: the on-chain
            // last-layer check rebuilds 2^(outer_log − outer_folds) leaves, so a
            // FIXED fold count makes that term grow linearly with the outer trace
            // and dominate the whole verification (measured in R4.16 — it was what
            // made R4.15 read "recursion is 2.7x more expensive"). Targeting a
            // 32-leaf last layer keeps it constant.
            let outer_folds = (outer_log as usize).saturating_sub(5).max(1);
            let (outer_proof, outer_commit_hex, outer_hints) = gen_vfri11_hints_from_cols_nfolds(
                &outer_cols, outer_log, &outer_bound, 1, Some(outer_folds),
            )
            .unwrap();
            let roots_json: Vec<String> =
                ch.layer_roots.iter().map(|r| format!("\"{}\"", hx(r))).collect();
            let evals_json: Vec<String> =
                ch.layer_values[ch.num_folds].iter().map(|v| format!("\"{v}\"")).collect();
            format!(
                concat!(
                    "{{\n",
                    "      \"inner\": {{\n",
                    "        \"traceRoot\": \"{}\",\n",
                    "        \"oodsComboPos\": \"{}\",\n",
                    "        \"oodsComboNeg\": \"{}\",\n",
                    "        \"compRoot\": \"{}\",\n",
                    "        \"friLayerRoots\": [{}],\n",
                    "        \"batchRoot\": \"{}\",\n",
                    "        \"treeDepth\": {},\n",
                    "        \"nQueries\": {}\n",
                    "      }},\n",
                    "      \"outerProof\": \"{}\",\n",
                    "      \"outerCommitment\": \"0x{}\",\n",
                    "      \"outerHints\": \"{}\",\n",
                    "      \"lastLayerEvals\": [{}]\n",
                    "    }}"
                ),
                hx(&ch.trace_root),
                ch.oods_combo_pos,
                ch.oods_combo_neg,
                hx(&ch.comp_root),
                roots_json.join(", "),
                hx(br),
                tree_depth,
                n_queries,
                hx(&outer_proof),
                outer_commit_hex,
                hx(&outer_hints),
                evals_json.join(", "),
            )
        };

        let json = format!(
            "{{\n  \"merkleRoot\": \"{}\",\n  \"bundle10\": {},\n  \"bundle8\": {}\n}}\n",
            hx(&merkle_root),
            bundle_json(&cols_a, &ch_a, &bound_a, depth_a, folds_a),
            bundle_json(&cols_b, &ch_b, &bound_b, depth_b, folds_b),
        );

        let path = format!(
            "{}/../contracts/test/fixtures/{}",
            env!("CARGO_MANIFEST_DIR"),
            file_name
        );
        std::fs::write(&path, json).unwrap();
        println!("wrote {path}");
    }

    /// Writes the VFRI11 E2E fixture consumed by QLSAVerifierVFRI11E2E.test.js.
    /// Run with: cargo test write_vfri11_e2e_fixture -- --ignored --nocapture
    #[test]
    #[ignore = "regenerates contracts/test/fixtures/vfri11_e2e.json"]
    fn write_vfri11_e2e_fixture() {
        let n = 16usize;
        let cols: Vec<Vec<u32>> = (0..6)
            .map(|j| (0..n).map(|i| ((i * 7 + j * 13 + 1) as u32) % 2_147_483_647).collect())
            .collect();
        let mut batch_root = [0u8; 32];
        for (i, b) in batch_root.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(9).wrapping_add(3); }

        let (proof, commitment_hex, hints) =
            gen_vfri11_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2))
                .expect("VFRI11 fixture generation failed");

        let json = format!(
            "{{\n  \"proof\": \"0x{}\",\n  \"commitment\": \"0x{}\",\n  \"merkleRoot\": \"0x{}\",\n  \"queryHints\": \"0x{}\",\n  \"n_queries\": 2,\n  \"num_folds\": 2,\n  \"tree_depth\": 4\n}}\n",
            hex::encode(&proof),
            commitment_hex,
            hex::encode(batch_root),
            hex::encode(&hints),
        );
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../contracts/test/fixtures/vfri11_e2e.json");
        std::fs::write(path, json).expect("failed to write fixture");
        eprintln!("wrote {path}");
    }

    /// Measures the OUTER recursion proof under both hash widths.
    ///
    /// The recursion's on-chain cost is dominated by verifying the OUTER proof,
    /// whose trace is the recursive circuit — ~87 columns at outer_log≈14,
    /// regardless of how large the inner statement was. Whether the recursion
    /// can be moved to t=16 (and so reach 128-bit NODE binding at the same time
    /// as its 130-bit FRI soundness) turns on what that one verify costs.
    ///
    /// This emits the SAME outer trace, at production n_queries=20, proved twice
    /// — once with the t=8 pipeline, once with t=16 — so the JS side can measure
    /// both against the deployed verifiers and the difference is only the width.
    /// Run with: cargo test write_outer_width_probe -- --ignored --nocapture
    /// The step list must reproduce the REAL VFRI11 transcript, challenge for
    /// challenge.
    ///
    /// This is the gate on wiring `channel_t8_air` into the composition. The
    /// gadget proves a transcript expressed as steps; if those steps are not the
    /// transcript the chain actually runs, the recursion would prove the wrong
    /// Fiat-Shamir and every challenge under it would be free to choose. Nothing
    /// downstream can catch that, so it is checked here against the imperative
    /// replay that the on-chain contract mirrors.
    #[test]
    fn transcript_steps_reproduce_the_real_vfri11_challenges() {
        use crate::recursive::channel_t8_air::ChannelT8State;

        // A production-shaped statement: depth 10, 6 folds, 20 queries.
        let mut fri_layer_roots = Vec::new();
        for k in 0..7u8 {
            let mut r = [0u8; 32];
            for (i, b) in r.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(13).wrapping_add(k * 7 + 1);
            }
            fri_layer_roots.push(r);
        }
        let inp = Vfri11ChannelInputs {
            trace_root: [0x3au8; 32],
            oods_combo_pos: 0x0123_4567_89ab_cdef_0011_2233_4455_6677u128,
            oods_combo_neg: 0x7766_5544_3322_1100_fedc_ba98_7654_3210u128,
            comp_root: [0x5cu8; 32],
            fri_layer_roots,
            batch_root: [0xa7u8; 32],
            tree_depth: 10,
            n_queries: 20,
        };

        let want = vfri11_replay_channel(&inp).expect("imperative replay");
        let steps = vfri11_transcript_steps(&inp).expect("transcript as steps");

        let mut ch = ChannelT8State::init();
        let drawn = ch.run(&steps);

        // Rebuild each challenge from the pairs, in the order the transcript
        // draws them. A QM31 felt is two pairs; a query index is one word of a
        // pair, two indices per pair.
        let felt = |d: &[(u32, u32)], i: usize| {
            qm31_pack_c(cm31_pack(d[i].0, d[i].1), cm31_pack(d[i + 1].0, d[i + 1].1))
        };
        assert_eq!(felt(&drawn, 0), want.z_x, "z_x");
        assert_eq!(felt(&drawn, 2), want.comp_alpha, "comp_alpha");
        assert_eq!(felt(&drawn, 4), want.fri_alpha, "fri_alpha");
        let num_folds = inp.fri_layer_roots.len() - 1;
        for k in 0..num_folds {
            assert_eq!(felt(&drawn, 6 + 2 * k), want.fri_alphas[k], "fri_alphas[{k}]");
        }

        let mask = (1u32 << inp.tree_depth) - 1;
        let q_start = 6 + 2 * num_folds;
        let mut got_q = Vec::with_capacity(inp.n_queries);
        for pair in &drawn[q_start..] {
            got_q.push((pair.0 & mask) as usize);
            if got_q.len() < inp.n_queries {
                got_q.push((pair.1 & mask) as usize);
            }
        }
        got_q.truncate(inp.n_queries);
        assert_eq!(got_q, want.query_indices, "query indices");

        // And the step count is what the trace has to hold.
        assert_eq!(steps.len(), 84, "production transcript length");
        assert_eq!(
            crate::recursive::channel_t8_air::compute_log_size(steps.len()),
            11,
            "a whole production transcript fits a log-11 trace");
    }

    /// PROVE a whole production VFRI11 transcript and verify it.
    ///
    /// The milestone this run establishes: the replay that costs 1,052,669 gas
    /// on-chain can instead be proved — which is what lets an intermediate tree
    /// level derive its children's challenges rather than have them handed down
    /// as public inputs, and so what lets N grow past a single level's fan-in.
    #[test]
    fn a_whole_production_transcript_proves_and_verifies() {
        use crate::recursive::channel_t8_air::{
            prove_channel_t8, verify_channel_t8, ChannelT8State,
        };

        let mut fri_layer_roots = Vec::new();
        for k in 0..7u8 {
            let mut r = [0u8; 32];
            for (i, b) in r.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(13).wrapping_add(k * 7 + 1);
            }
            fri_layer_roots.push(r);
        }
        let inp = Vfri11ChannelInputs {
            trace_root: [0x3au8; 32],
            oods_combo_pos: 0x0123_4567_89ab_cdef_0011_2233_4455_6677u128,
            oods_combo_neg: 0x7766_5544_3322_1100_fedc_ba98_7654_3210u128,
            comp_root: [0x5cu8; 32],
            fri_layer_roots,
            batch_root: [0xa7u8; 32],
            tree_depth: 10,
            n_queries: 20,
        };
        let steps = vfri11_transcript_steps(&inp).unwrap();

        let (proof, log_size, digest, drawn) =
            prove_channel_t8(&steps).expect("prove the production transcript");
        assert!(verify_channel_t8(&proof, log_size, &steps, &drawn, digest).unwrap(),
                "a real VFRI11 transcript must verify");

        // The proved challenges are the ones the imperative replay produces —
        // not merely internally consistent.
        let mut reference = ChannelT8State::init();
        assert_eq!(drawn, reference.run(&steps));
        assert_eq!(digest, reference.s);

        // Tampering with any absorbed root must break it: this is what binds the
        // proof to ONE inner statement.
        let mut other = inp.clone();
        other.trace_root[0] ^= 1;
        let other_steps = vfri11_transcript_steps(&other).unwrap();
        assert!(!verify_channel_t8(&proof, log_size, &other_steps, &drawn, digest).unwrap(),
                "a changed trace root must not verify against the same proof");
    }

    /// The tree's level step, on REAL data: a V23 group becomes a statement, and
    /// its challenges line up with its transcript without adjustment.
    ///
    /// That alignment is the invariant the whole tree rests on. The extraction
    /// (`gen_vfri11_recursion_inputs`) and the transcript
    /// (`vfri11_transcript_steps`) are two readings of one chain run; if they
    /// ever drifted, every node above would simply fail to prove, with nothing
    /// pointing at the cause.
    #[test]
    fn a_real_v23_group_becomes_a_tree_statement() {
        use crate::recursive::composition_channel_t8 as node;

        let (z, c, t1, a_hat) = super::tests::make_v23_inputs(16600);
        let merkle_root: Vec<u8> = (0..32).map(|i| ((11 + 7 * i) % 256) as u8).collect();
        let (cols, tree_depth) =
            v23_vfri11_cols_log10(&z, &c, &t1, &a_hat, &merkle_root, 4).expect("V23 columns");

        let st = match tree_statement_from_columns(&cols, tree_depth, &merkle_root, 4, Some(6)) {
            Ok(s) => s,
            Err(e) => panic!("level step failed: {e}"),
        };
        assert_eq!(st.queries.len(), 4);
        assert_eq!(st.paths.len(), 4);
        assert_eq!(st.comp_paths.len(), 4);

        // A node over it must build — which exercises the same binding check a
        // second time, through the node rather than the level step.
        let sized = node::tree_node_log_size(std::slice::from_ref(&st));
        assert!(sized.is_ok(), "the statement must form a valid node: {sized:?}");
    }

    /// Two levels: a node's own columns become the next level's statement.
    ///
    /// This is the tree, twice. If it holds here it holds at any depth, because
    /// the shape was measured to be a fixed point.
    #[test]
    fn a_node_s_columns_become_the_next_level_s_statement() {
        use crate::recursive::composition_channel_t8 as node;

        let (z, c, t1, a_hat) = super::tests::make_v23_inputs(16600);
        let merkle_root: Vec<u8> = (0..32).map(|i| ((11 + 7 * i) % 256) as u8).collect();
        let (cols0, depth0) =
            v23_vfri11_cols_log10(&z, &c, &t1, &a_hat, &merkle_root, 2).expect("V23 columns");

        let st0 = tree_statement_from_columns(&cols0, depth0, &merkle_root, 2, Some(6))
            .expect("level-0 statement");
        let (cols1, depth1) = node::tree_node_trace_columns(std::slice::from_ref(&st0))
            .expect("level-1 node columns");
        eprintln!("level-1 node: {} cols, log {}", cols1.len(), depth1);

        // And those columns are themselves a statement for the level above.
        let st1 = match tree_statement_from_columns(&cols1, depth1, &merkle_root, 2, Some(6)) {
            Ok(s) => s,
            Err(e) => panic!("level-1 -> level-2 step failed: {e}"),
        };
        assert_eq!(st1.queries.len(), 2);
        assert!(node::tree_node_log_size(std::slice::from_ref(&st1)).is_ok());
    }

    /// A whole tree over four real V23 statements, proved end to end.
    ///
    /// Four leaves at fan-in 2 is two levels: two nodes, then the root. That is
    /// the smallest tree that exercises everything a deeper one does — a level
    /// consuming the level below's columns — since the shape was measured to be
    /// a fixed point, so depth adds no new behaviour.
    #[test]
    fn a_tree_over_four_real_statements_proves() {
        use crate::recursive::composition_channel_t8 as node;

        let merkle_root: Vec<u8> = (0..32).map(|i| ((11 + 7 * i) % 256) as u8).collect();
        let mut leaves = Vec::new();
        for seed in [16600u64, 16601, 16602, 16603] {
            let (z, c, t1, a_hat) = super::tests::make_v23_inputs(seed);
            leaves.push(
                v23_vfri11_cols_log10(&z, &c, &t1, &a_hat, &merkle_root, 1)
                    .expect("V23 columns"),
            );
        }

        let tree = match prove_aggregation_tree(&leaves, &merkle_root, 1, Some(6), 2) {
            Ok(t) => t,
            Err(e) => panic!("tree proving failed: {e}"),
        };

        // Four leaves, fan-in 2 → level 0 has two nodes, level 1 has the root.
        assert_eq!(tree.depth(), 2, "four leaves at fan-in 2 is two levels");
        assert_eq!(tree.levels[0].nodes.len(), 2);
        assert_eq!(tree.levels[1].nodes.len(), 1);
        assert_eq!(tree.node_count(), 3);

        // The root is one proof, whatever the leaf count — the property the whole
        // tree exists for.
        let root = tree.root();
        assert!(!root.proof.is_empty());
        eprintln!(
            "tree: {} leaves, {} levels, {} nodes, root log {}",
            leaves.len(), tree.depth(), tree.node_count(), root.log_size);

        // And the root verifies against the statements it was built from.
        let (cols, depth) = &tree.levels[0].columns[0];
        let a = tree_statement_from_columns(cols, *depth, &merkle_root, 1, Some(6)).unwrap();
        let (cols, depth) = &tree.levels[0].columns[1];
        let b = tree_statement_from_columns(cols, *depth, &merkle_root, 1, Some(6)).unwrap();
        assert!(
            node::verify_tree_node(&root.proof, root.log_size, &[a, b], &root.roots).unwrap(),
            "the root must verify against its two children");
    }

    /// A ragged tree needs no padding: a node is the same object at any fan-in.
    #[test]
    fn a_tree_over_three_statements_is_not_padded() {
        let merkle_root: Vec<u8> = (0..32).map(|i| ((11 + 7 * i) % 256) as u8).collect();
        let mut leaves = Vec::new();
        for seed in [16700u64, 16701, 16702] {
            let (z, c, t1, a_hat) = super::tests::make_v23_inputs(seed);
            leaves.push(
                v23_vfri11_cols_log10(&z, &c, &t1, &a_hat, &merkle_root, 1).expect("cols"),
            );
        }
        let tree = match prove_aggregation_tree(&leaves, &merkle_root, 1, Some(6), 2) {
            Ok(t) => t, Err(e) => panic!("tree proving failed: {e}"),
        };
        // Three leaves at fan-in 2: a full pair and a lone one, then the root.
        assert_eq!(tree.levels[0].nodes.len(), 2);
        assert_eq!(tree.depth(), 2);
        assert_eq!(tree.root().challenges.len(), 2, "the root has two children");
    }

    #[test]
    fn a_tree_checks_its_inputs() {
        let root = vec![0u8; 32];
        assert!(prove_aggregation_tree(&[], &root, 1, Some(6), 2).is_err(), "no leaves");
        let (z, c, t1, a_hat) = super::tests::make_v23_inputs(16600);
        let one = vec![v23_vfri11_cols_log10(&z, &c, &t1, &a_hat, &root, 1).unwrap()];
        assert!(prove_aggregation_tree(&one, &root, 1, Some(6), 1).is_err(), "fan_in 1 never ends");
    }

    /// Does the TREE NODE's shape reach a fixed point, as the 2-component one did?
    ///
    /// `probe_recursion_self_composition` measured the 87-column shape converging
    /// at log 14. A tree node is three components — 120 columns — because the
    /// channel rides along, so its trace is bigger, so the next level's Merkle
    /// paths are deeper, so ITS trace is bigger. Whether that settles or runs
    /// away is the question a tree builder is built on, and it is not answerable
    /// by looking at the 2-component number.
    ///
    /// Run with: cargo test probe_tree_node_self_composition -- --ignored --nocapture
    #[test]
    #[ignore = "measurement probe; prints tree-node sizes across levels"]
    fn probe_tree_node_self_composition() {
        use crate::recursive::composition_channel_t8 as node;

        let (z, c, t1, a_hat) = super::tests::make_v23_inputs(16600);
        let merkle_root: Vec<u8> = (0..32).map(|i| ((11 + 7 * i) % 256) as u8).collect();

        // Level 0: a real V23 group at production security.
        let rec0 = gen_mldsa_v23_recursion_inputs_log10(
            &z, &c, &t1, &a_hat, &merkle_root, 20, Some(6),
        ).expect("level-0 recursion inputs");

        let num_folds = rec0.queries[0].1.len();
        let inp0 = Vfri11ChannelInputs {
            trace_root: rec0.trace_root,
            oods_combo_pos: 1,
            oods_combo_neg: 2,
            comp_root: [0x5cu8; 32],
            fri_layer_roots: (0..=num_folds as u8)
                .map(|k| { let mut r = [0u8; 32]; r[0] = k + 1; r })
                .collect(),
            batch_root: [0xa7u8; 32],
            tree_depth: 10,
            n_queries: 20,
        };
        let steps = vfri11_transcript_steps(&inp0).expect("transcript");
        // The VFRI11 layout: z_x first, then friAlpha, then one alpha per fold.
        let layout = node::ChallengeLayout {
            z_x_at: 0,
            alpha_at: (0..1 + num_folds).map(|i| 4 + 2 * i).collect(),
        };

        // The statement's queries must run under the transcript's challenges, so
        // rebuild them from the derived values rather than reusing rec0's.
        let derived = match node::derive_challenges(&steps, &layout) {
            Ok(d) => d,
            Err(e) => { eprintln!("challenge derivation failed: {e}"); return; }
        };
        let queries: Vec<_> = rec0.queries.iter().map(|(st, rounds)| {
            let mut st2 = *st;
            st2.3 = derived.z_x;
            st2.6 = derived.alphas[0];
            let rounds2: Vec<_> = rounds.iter().enumerate()
                .map(|(k, &(sib, _, inv))| (sib, derived.alphas[k + 1], inv))
                .collect();
            (st2, rounds2)
        }).collect();

        let statement = node::TreeStatement {
            steps,
            layout,
            queries,
            paths: rec0.paths.clone(),
            comp_paths: rec0.comp_paths.clone(),
        };

        match node::tree_node_trace_columns(std::slice::from_ref(&statement)) {
            Ok((cols, log)) => eprintln!(
                "tree node over ONE real V23 statement (20 queries): {} cols, log {}",
                cols.len(), log),
            Err(e) => eprintln!("one-statement node failed: {e}"),
        }
        match node::tree_node_trace_columns(&[statement.clone(), statement.clone()]) {
            Ok((cols, log)) => eprintln!(
                "tree node over TWO such statements:               {} cols, log {}",
                cols.len(), log),
            Err(e) => eprintln!("two-statement node failed: {e}"),
        }

        // THE question a tree builder rests on. A node's trace is its parent's
        // inner statement, so a deeper trace means deeper Merkle paths at the
        // next level, which means a deeper trace again. Iterate the map and see
        // whether it settles — the 2-component shape did, at log 14, but that
        // number says nothing about this one.
        eprintln!();
        eprintln!("depth d of a child's trace  ->  log_size of the node above it");
        let mut d = 14u32;
        for step in 0..8 {
            let sized = node::tree_node_log_size(&[
                shape_at_depth(&statement, d),
                shape_at_depth(&statement, d),
            ]);
            match sized {
                Ok(next) => {
                    eprintln!("  d = {d:2}  ->  log {next}");
                    if next == d {
                        eprintln!("FIXED POINT at log {d} (reached after {step} steps)");
                        return;
                    }
                    d = next;
                }
                Err(e) => { eprintln!("  d = {d}: {e}"); return; }
            }
        }
        eprintln!("NO FIXED POINT within 8 iterations — the tree would have a depth ceiling");
    }

    /// The same statement with its paths lengthened to `d`, standing in for a
    /// child whose own trace is log-`d`. Only the LENGTHS matter for sizing.
    fn shape_at_depth(
        st: &crate::recursive::composition_channel_t8::TreeStatement,
        d: u32,
    ) -> crate::recursive::composition_channel_t8::TreeStatement {
        let grow = |v: &(Vec<[u64; 4]>, Vec<bool>)| -> (Vec<[u64; 4]>, Vec<bool>) {
            let mut s = v.0.clone();
            let mut b = v.1.clone();
            s.resize(d as usize, [0u64; 4]);
            b.resize(d as usize, false);
            (s, b)
        };
        let mut out = st.clone();
        out.paths = st.paths.iter().map(grow).collect();
        out.comp_paths = st.comp_paths.iter().map(|(ps, pb, ns, nb)| {
            let (ps, pb) = grow(&(ps.clone(), pb.clone()));
            let (ns, nb) = grow(&(ns.clone(), nb.clone()));
            (ps, pb, ns, nb)
        }).collect();
        out
    }

    /// How long does one aggregation node take, and what does that make N?
    ///
    /// On-chain cost is constant in N (the recursion is a fixed point), so N is
    /// chosen by PROVING time and latency, not by gas. A binary tree over N
    /// signatures has N leaves and N−1 internal nodes; the leaves are V23 proofs
    /// and the internal nodes are 87-column log-14 composition proofs. This
    /// measures the internal node, which is the part that repeats N−1 times.
    ///
    /// Run with: cargo test probe_aggregation_node_cost -- --ignored --nocapture
    #[test]
    #[ignore = "measurement probe; times one aggregation node"]
    fn probe_aggregation_node_cost() {
        use crate::recursive::composition_t8::{
            outer_trace_columns_t8, prove_queries_membership_t8,
        };
        use std::time::Instant;

        let (z, c, t1, a_hat) = super::tests::make_v23_inputs(16600);
        let merkle_root: Vec<u8> = (0..32).map(|i| ((11 + 7 * i) % 256) as u8).collect();

        let t0 = Instant::now();
        let rec = gen_mldsa_v23_recursion_inputs_log10(
            &z, &c, &t1, &a_hat, &merkle_root, 20, Some(6),
        ).expect("leaf recursion inputs");
        let leaf_inputs_s = t0.elapsed().as_secs_f64();

        let (cols, log) = outer_trace_columns_t8(&rec.queries, &rec.paths, &rec.comp_paths)
            .expect("outer trace");

        let t1_ = Instant::now();
        let _ = prove_queries_membership_t8(&rec.queries, &rec.paths, &rec.comp_paths)
            .expect("aggregation node proof");
        let node_s = t1_.elapsed().as_secs_f64();

        eprintln!("leaf: recursion inputs from a real V23 group  = {leaf_inputs_s:.2} s");
        eprintln!("node: {} cols, log {}, prove                 = {node_s:.2} s", cols.len(), log);
        eprintln!();
        eprintln!("A binary tree over N signatures: N leaves, N-1 internal nodes,");
        eprintln!("log2(N) levels, each level internally parallel.");
        for n in [64usize, 256, 512, 1024, 3000] {
            let depth = (n as f64).log2().ceil();
            // Wall clock on one core; a level is embarrassingly parallel, so with
            // W workers divide each level's work by W.
            let serial = n as f64 * leaf_inputs_s + (n - 1) as f64 * node_s;
            eprintln!(
                "  N={n:5}: depth {depth:.0}, serial {:.0} s, per-signature on-chain {:.0} gas",
                serial, 13_168_471.0 / n as f64);
        }
    }

    /// Can ONE recursive proof attest TWO independent inner statements?
    ///
    /// This is the 2-to-1 aggregation node a tree is built from (A-2 in
    /// docs/TECH_DEBT.md). The claim being tested is that the existing
    /// multi-path machinery already supports it: `prove_queries_membership_t8`
    /// takes a LIST of per-query inputs, and `verify_queries_membership_t8`
    /// takes a per-path `roots` array rather than one global root — so queries
    /// belonging to DIFFERENT inner proofs, landing on DIFFERENT FRI-layer
    /// roots, are already expressible.
    ///
    /// If this holds, aggregating N signatures needs no new gadget: concatenate
    /// per-proof inputs at each level, and iterate the self-composition the
    /// previous probe measured as size-stable.
    ///
    /// Run with: cargo test probe_two_inner_proofs_in_one -- --ignored --nocapture
    #[test]
    #[ignore = "measurement probe; proves two inner statements in one proof"]
    fn probe_two_inner_proofs_in_one() {
        use crate::recursive::composition_t8::{
            outer_trace_columns_t8, prove_queries_membership_t8,
        };

        let merkle_root: Vec<u8> = (0..32).map(|i| ((11 + 7 * i) % 256) as u8).collect();

        // Two DIFFERENT signatures — distinct seeds, so distinct traces, distinct
        // FRI-layer roots. Aggregating two copies of one statement would prove
        // nothing about aggregation.
        let mut recs = Vec::new();
        for seed in [16600u64, 16601] {
            let (z, c, t1, a_hat) = super::tests::make_v23_inputs(seed);
            recs.push(
                gen_mldsa_v23_recursion_inputs_log10(
                    &z, &c, &t1, &a_hat, &merkle_root, 4, Some(6))
                    .expect("recursion inputs"),
            );
        }
        assert_ne!(recs[0].last_layer_root, recs[1].last_layer_root,
                   "the two statements must be genuinely different");

        for (i, r) in recs.iter().enumerate() {
            eprintln!("inner {i}: {} queries, last-layer root {:?}",
                      r.queries.len(), r.last_layer_root);
        }

        // Concatenate. Each query keeps its OWN path and its own root.
        let mut queries = Vec::new();
        let mut paths = Vec::new();
        let mut comp_paths = Vec::new();
        for r in &recs {
            queries.extend(r.queries.iter().cloned());
            paths.extend(r.paths.iter().cloned());
            comp_paths.extend(r.comp_paths.iter().cloned());
        }
        eprintln!("aggregated: {} queries from {} independent inner proofs",
                  queries.len(), recs.len());

        let (cols, log) = outer_trace_columns_t8(&queries, &paths, &comp_paths)
            .expect("aggregated outer trace");
        eprintln!("aggregated outer trace: {} cols, log {}", cols.len(), log);

        let proved = prove_queries_membership_t8(&queries, &paths, &comp_paths)
            .expect("aggregated composition proof");
        eprintln!("aggregated composition proof built, log_size {}", proved.log_size);
        eprintln!("VERDICT: two independent inner statements prove in ONE recursive proof.");
    }

    /// Does the recursion compose with ITSELF, and does the trace converge?
    ///
    /// This decides whether aggregating N signatures is reachable by iterating
    /// what already exists (A-2 in docs/TECH_DEBT.md). A tree of 2-to-1
    /// aggregation nodes only works if a recursion level can take the PREVIOUS
    /// level's outer proof as its inner statement, and if the outer trace does
    /// not grow from level to level — a trace that grows has a ceiling, and the
    /// tree stops at whatever depth exceeds it.
    ///
    /// `gen_vfri11_recursion_inputs` is generic over columns, so feeding it the
    /// outer trace's own columns is exactly a second level. What it costs is a
    /// question about the SHAPE at each level, which is what this measures:
    /// level 0 verifies a V23 group at 20 queries; level 1 verifies level 0's
    /// outer proof, whose own query count is the parameter that drives level 1's
    /// size.
    ///
    /// Run with: cargo test probe_recursion_self_composition -- --ignored --nocapture
    #[test]
    #[ignore = "measurement probe; prints trace sizes across recursion levels"]
    fn probe_recursion_self_composition() {
        use crate::recursive::composition_t8::outer_trace_columns_t8;

        let (z, c, t1, a_hat) = super::tests::make_v23_inputs(16600);
        let merkle_root: Vec<u8> = (0..32).map(|i| ((11 + 7 * i) % 256) as u8).collect();

        // Level 0 — the shipped v8 shape: a real V23 group at production security.
        let rec0 = gen_mldsa_v23_recursion_inputs_log10(
            &z, &c, &t1, &a_hat, &merkle_root, 20, Some(6),
        ).expect("level-0 recursion inputs");
        let (cols0, log0) = outer_trace_columns_t8(&rec0.queries, &rec0.paths, &rec0.comp_paths)
            .expect("level-0 outer trace");
        eprintln!("level 0: inner = V23 LOG=10 @ 20 queries");
        eprintln!("         outer trace = {} cols, log {}", cols0.len(), log0);

        // Level 1 — the SAME machinery, with level 0's outer trace as the inner
        // statement. The driver is level 0's outer query count: more queries
        // there means more per-query work to verify here.
        let folds0 = (log0 as usize).saturating_sub(5).max(1);
        let bound = [0x5cu8; 32];
        for q0 in [1usize, 2, 4, 8, 16, 20] {
            let rec1 = match gen_vfri11_recursion_inputs(&cols0, log0, &bound, q0, Some(folds0)) {
                Ok(r) => r,
                Err(e) => { eprintln!("level 1 @ q0={q0}: extraction failed: {e}"); continue; }
            };
            match outer_trace_columns_t8(&rec1.queries, &rec1.paths, &rec1.comp_paths) {
                Ok((cols1, log1)) => eprintln!(
                    "level 1 @ level-0 outer q={q0}: outer trace = {} cols, log {}  \
                     ({}x rows vs level 0)",
                    cols1.len(), log1,
                    (1u64 << log1) as f64 / (1u64 << log0) as f64),
                Err(e) => eprintln!("level 1 @ q0={q0}: outer trace failed: {e}"),
            }
        }

        // Building the trace is necessary but not sufficient: a level-1 proof
        // must actually VERIFY, or self-composition is only structural.
        let rec1 = gen_vfri11_recursion_inputs(&cols0, log0, &bound, 20, Some(folds0))
            .expect("level-1 recursion inputs at production security");
        let proved = crate::recursive::composition_t8::prove_queries_membership_t8(
            &rec1.queries, &rec1.paths, &rec1.comp_paths,
        ).expect("level-1 composition proof");
        eprintln!(
            "level 1 @ q0=20: composition proof built, log_size {}",
            proved.log_size);
        eprintln!("VERDICT: the recursion composes with itself and the trace does not grow.");
    }

    #[test]
    #[ignore = "regenerates contracts/test/fixtures/outer_width_probe.json"]
    fn write_outer_width_probe() {
        use crate::recursive::composition_t8::outer_trace_columns_t8;

        let (z, c, t1, a_hat) = super::tests::make_v23_inputs(16600);
        let merkle_root: Vec<u8> = (0..32).map(|i| ((11 + 7 * i) % 256) as u8).collect();

        // Production security: 20 FRI queries on the INNER statement.
        let rec = gen_mldsa_v23_recursion_inputs_log10(
            &z, &c, &t1, &a_hat, &merkle_root, 20, Some(6),
        ).expect("recursion inputs");
        let (outer_cols, outer_log) =
            outer_trace_columns_t8(&rec.queries, &rec.paths, &rec.comp_paths)
                .expect("outer trace");

        // Same rule build_recursive_bundle uses (R4.16): a 32-leaf outer last
        // layer, so the on-chain rebuild stays constant as the outer trace grows.
        let outer_folds = (outer_log as usize).saturating_sub(5).max(1);
        let bound = [0x5cu8; 32];

        let (p11, c11, h11) =
            gen_vfri11_hints_from_cols_nfolds(&outer_cols, outer_log, &bound, 1, Some(outer_folds))
                .expect("outer VFRI11");
        let (p12, c12, h12) =
            gen_vfri12_hints_from_cols_nfolds(&outer_cols, outer_log, &bound, 1, Some(outer_folds))
                .expect("outer VFRI12");

        let json = format!(
            "{{\n  \"note\": \"outer recursion trace, inner n_queries=20\",\n  \"n_cols\": {},\n  \"outer_log\": {},\n  \"outer_folds\": {},\n  \"boundRoot\": \"0x{}\",\n  \"vfri11\": {{\n    \"proof\": \"0x{}\",\n    \"commitment\": \"0x{}\",\n    \"queryHints\": \"0x{}\"\n  }},\n  \"vfri12\": {{\n    \"proof\": \"0x{}\",\n    \"commitment\": \"0x{}\",\n    \"queryHints\": \"0x{}\"\n  }}\n}}\n",
            outer_cols.len(), outer_log, outer_folds,
            hex::encode(bound),
            hex::encode(&p11), c11, hex::encode(&h11),
            hex::encode(&p12), c12, hex::encode(&h12),
        );
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../contracts/test/fixtures/outer_width_probe.json"
        );
        std::fs::write(path, json).expect("failed to write fixture");
        eprintln!("wrote {path}");
        eprintln!("  outer: {} cols, log={outer_log}, folds={outer_folds}", outer_cols.len());
        eprintln!("  hints: vfri11={}B vfri12={}B", h11.len(), h12.len());
    }

    /// Writes the FULL-V23 cross-bound VFRI12 fixture — the measurement that
    /// decides whether 128-bit node binding is directly deployable on-chain, or
    /// only reachable through recursion.
    ///
    /// Same seed / n_queries / num_folds as full_v23_vfri11_cross_bound_e2e.json
    /// so the two are directly comparable: identical trace, identical FRI shape,
    /// only the hash width differs.
    /// Run with: cargo test write_v23_vfri12_fixture -- --ignored --nocapture
    #[test]
    #[ignore = "regenerates contracts/test/fixtures/full_v23_vfri12_cross_bound_e2e.json"]
    fn write_v23_vfri12_fixture() {
        let (z, c, t1, a_hat) = super::tests::make_v23_inputs(16600);
        let hints = [[false; 256]; 6];
        let merkle_root: Vec<u8> = (0..32).map(|i| ((11 + 7 * i) % 256) as u8).collect();

        let (p10, c10, h10, p8, c8, h8) = gen_mldsa_v23_vfri12_cross_bound_hints(
            &z, &c, &t1, &a_hat, &hints, &merkle_root, 1, Some(6),
        ).expect("VFRI12 V23 cross-bound generation failed");

        let json = format!(
            "{{\n  \"merkleRoot\": \"0x{}\",\n  \"log10_proof\": \"0x{}\",\n  \"log10_commitment\": \"0x{}\",\n  \"log10_queryHints\": \"0x{}\",\n  \"log8_proof\": \"0x{}\",\n  \"log8_commitment\": \"0x{}\",\n  \"log8_queryHints\": \"0x{}\",\n  \"n_queries\": 1,\n  \"num_folds\": 6\n}}\n",
            hex::encode(&merkle_root),
            hex::encode(&p10), c10, hex::encode(&h10),
            hex::encode(&p8),  c8,  hex::encode(&h8),
        );
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../contracts/test/fixtures/full_v23_vfri12_cross_bound_e2e.json"
        );
        std::fs::write(path, json).expect("failed to write fixture");
        eprintln!("wrote {path}");
        eprintln!("  log10 hints={}B  log8 hints={}B", h10.len(), h8.len());
    }

    /// Writes the VFRI12 E2E fixture consumed by QLSAVerifierVFRI12E2E.test.js.
    /// Same shape as the VFRI11 fixture — the ABI is unchanged, only the width.
    /// Run with: cargo test write_vfri12_e2e_fixture -- --ignored --nocapture
    #[test]
    #[ignore = "regenerates contracts/test/fixtures/vfri12_e2e.json"]
    fn write_vfri12_e2e_fixture() {
        let n = 16usize;
        let cols: Vec<Vec<u32>> = (0..6)
            .map(|j| (0..n).map(|i| ((i * 7 + j * 13 + 1) as u32) % 2_147_483_647).collect())
            .collect();
        let mut batch_root = [0u8; 32];
        for (i, b) in batch_root.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(9).wrapping_add(3); }

        let (proof, commitment_hex, hints) =
            gen_vfri12_hints_from_cols_nfolds(&cols, 4, &batch_root, 2, Some(2))
                .expect("VFRI12 fixture generation failed");

        let json = format!(
            "{{\n  \"proof\": \"0x{}\",\n  \"commitment\": \"0x{}\",\n  \"merkleRoot\": \"0x{}\",\n  \"queryHints\": \"0x{}\",\n  \"n_queries\": 2,\n  \"num_folds\": 2,\n  \"tree_depth\": 4\n}}\n",
            hex::encode(&proof),
            commitment_hex,
            hex::encode(batch_root),
            hex::encode(&hints),
        );
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../contracts/test/fixtures/vfri12_e2e.json");
        std::fs::write(path, json).expect("failed to write fixture");
        eprintln!("wrote {path}");
    }








}


// Test fixtures orphaned when their only callers were retired.

    fn make_vfri5_polys(n_polys: usize, seed: usize) -> Vec<[i64; 256]> {
        (0..n_polys).map(|k| {
            let mut p = [0i64; 256];
            for (i, x) in p.iter_mut().enumerate() {
                *x = ((seed + k * 257 + i + 1) % 500) as i64;
            }
            p
        }).collect()
    }

    pub(super) fn make_log8_hints() -> [[bool; 256]; 6] {
        [[false; 256]; 6]
    }
