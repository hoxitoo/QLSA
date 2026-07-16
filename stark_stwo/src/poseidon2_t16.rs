/// Poseidon2 permutation over M31 with state width t = 16 — the FINAL rung of
/// the 128-bit binding ladder.
///
/// Width 16 lets a 2-to-1 compression carry **8-word (248-bit) children**,
/// raising node collision cost to ~2^124 ≈ 128-bit — the target soundness level
/// (and the width of Stwo's native Poseidon2-16):
///
///   t=2 (31-bit nodes, 2^15.5) → t=4 (2-word nodes, 2^31)
///   → t=8 (4-word nodes, 2^62) → t=16 (THIS: 8-word nodes, ~2^124 ≈ 128-bit)
///
/// Its value is as the **inner hash AIR of the recursive proof** (path decision
/// 2026-06-17): a standalone t=16 on-chain verifier would cost ~400M+ gas, but
/// inside the recursion the on-chain cost is constant regardless of width.
///
/// Parameters (research instance — same derivation convention as the t=4/t=8
/// instances; not a standardised parameter set):
///   - state width      t = 16
///   - S-Box            x^5 (gcd(5, p−1) = 1 over M31)
///   - external rounds  R_F = 8 (4 initial + 4 final), S-box on all 16 cells
///   - internal rounds  R_P = 14, S-box on cell 0 only (Poseidon2 Table 1 for
///     31-bit fields, t=16, α=5)
///   - external matrix  M_E = circ(2·M4, M4, M4, M4) over 4-cell blocks
///     (Poseidon2 §5.1 block construction for t = 4·t': apply M4 to each block,
///     then add the sum of all blocks to every block).
///     M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]].
///   - internal matrix  M_I = J + diag(1,2,…,16) over M31 (J = all-ones 16×16;
///     invertibility asserted in tests)
///   - round constants  RC[i] = u32_be(SHA-256("QLSA-Poseidon2-t16" ‖ i_be4)[..4])
///     mod M31_P, for i in 0..142 (external rounds consume RC[0..128] — 16 per
///     round; internal rounds consume RC[128..142] — 1 per round).  Frozen as
///     literals below; regenerable by the documented rule.
///
/// Layout follows the Poseidon2 specification:
///   state ← M_E·state
///   4 × (AddRC → SBox(all 16) → M_E)
///   14 × (AddRC[0] → SBox(cell 0) → M_I)
///   4 × (AddRC → SBox(all 16) → M_E)

use crate::poseidon2::{m31_add, sbox, M31_P};
use crate::poseidon2_t8::m4;

pub const T: usize = 16;
pub const R_F: usize = 8; // external (full) rounds, split 4 + 4
pub const R_P: usize = 14; // internal (partial) rounds

/// Round constants RC[i] = u32_be(SHA-256("QLSA-Poseidon2-t16" ‖ i_be4)[..4]) mod
/// M31_P, for i in 0..(T·R_F + R_P) = 0..142.  All are already < M31_P.
/// External round r uses K_RC[T·r .. T·r+T); internal round j uses K_RC[T·R_F + j].
pub const K_RC: [u32; 142] = [
    365599062, 1474211102, 866857359, 1423631047, 1080988498, 133537033,
    584306829, 983816483, 53274617, 2099993270, 418238203, 1016757858,
    533087121, 2018829672, 1860145444, 621119419, 1687563266, 1247989187,
    1034463516, 771059345, 1188773184, 1786717504, 1847351358, 1045643482,
    84722888, 1442236670, 1666688001, 1388157994, 1820176570, 906346470,
    596545147, 1521621262, 1342830669, 968102142, 472008583, 293487879,
    1464743836, 965541824, 703259861, 1074971177, 917288885, 1389101982,
    2076140359, 1456667583, 532329430, 1278318691, 19391291, 1805123501,
    1132599018, 645006741, 414583027, 1941539328, 1369383844, 1750671612,
    226015350, 1399468129, 2028042418, 1575978581, 625970722, 502417283,
    2044239643, 1237037626, 732696444, 719958381, 1855405411, 462239201,
    1417199097, 1351623844, 1214852644, 1566313405, 823484549, 2038808093,
    59462027, 432410698, 874996701, 585332624, 1347599388, 78793182,
    582527429, 655061291, 1038936950, 1444363910, 1185681344, 1635162776,
    329635127, 287626090, 199315315, 1669214696, 405993748, 320581075,
    928589308, 1765854973, 486377493, 910646161, 1585806573, 453018086,
    1478416193, 1829395642, 598689827, 935118246, 1336932458, 2147459779,
    1014410290, 259794828, 2129660335, 718753456, 2050072474, 254931253,
    1080146963, 540554929, 506016650, 156055845, 995169882, 969325822,
    232662561, 741460961, 1179400441, 1084927451, 319071821, 409684197,
    1232688177, 561313406, 1656574415, 11718892, 216659011, 952908412,
    1380765329, 1521369242, 907051838, 1803830187, 47658112, 824628367,
    713854912, 1489720594, 1695950527, 898987930, 1276627535, 990382248,
    258309882, 108327904, 771518169, 645853941,
];

/// External linear layer: state ← M_E·state with M_E = circ(2·M4, M4, M4, M4).
/// Apply M4 to each 4-cell block (→ v0..v3), then out_block_i = v_i + Σ_j v_j.
#[inline]
pub fn mat_external(s: &mut [u64; 16]) {
    let mut v: [[u64; 4]; 4] = [
        [s[0], s[1], s[2], s[3]],
        [s[4], s[5], s[6], s[7]],
        [s[8], s[9], s[10], s[11]],
        [s[12], s[13], s[14], s[15]],
    ];
    for b in v.iter_mut() {
        m4(b);
    }
    for k in 0..4 {
        let sigma = m31_add(m31_add(v[0][k], v[1][k]), m31_add(v[2][k], v[3][k]));
        for b in 0..4 {
            s[4 * b + k] = m31_add(v[b][k], sigma);
        }
    }
}

/// Internal linear layer: state ← (J + diag(1,…,16))·state, i.e.
/// out_i = (Σ_j s_j) + μ_i·s_i with μ = (1,2,…,16).
#[inline]
pub fn mat_internal(s: &mut [u64; 16]) {
    let mut sum = 0u64;
    for &v in s.iter() {
        sum = m31_add(sum, v);
    }
    for i in 0..16 {
        let si = s[i];
        let mut acc = sum;
        for _ in 0..=i {
            acc = m31_add(acc, si);
        }
        s[i] = acc;
    }
}

/// Full Poseidon2 t=16 permutation.
pub fn permute_t16(s: &mut [u64; 16]) {
    mat_external(s);
    for r in 0..R_F / 2 {
        for i in 0..T {
            s[i] = m31_add(s[i], K_RC[T * r + i] as u64);
        }
        for i in 0..T {
            s[i] = sbox(s[i]);
        }
        mat_external(s);
    }
    for j in 0..R_P {
        s[0] = m31_add(s[0], K_RC[T * R_F + j] as u64);
        s[0] = sbox(s[0]);
        mat_internal(s);
    }
    for r in R_F / 2..R_F {
        for i in 0..T {
            s[i] = m31_add(s[i], K_RC[T * r + i] as u64);
        }
        for i in 0..T {
            s[i] = sbox(s[i]);
        }
        mat_external(s);
    }
}

// ── Sponge / compression helpers ─────────────────────────────────────────────

/// Rate-8 capacity-8 sponge: absorb 8 M31 words per block into cells 0–7,
/// permute after each block.  An odd-length tail sets a domain-separation flag
/// in capacity cell 15 on the final block.  Returns the full 16-word state;
/// callers take cells 0–7 as the 8-word (248-bit) node.
pub fn sponge_t16(values: &[u64]) -> [u64; 16] {
    let mut state = [0u64; 16];
    let mut chunks = values.chunks_exact(8);
    for c in &mut chunks {
        for k in 0..8 {
            state[k] = m31_add(state[k], c[k] % M31_P);
        }
        permute_t16(&mut state);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        for (k, &v) in rem.iter().enumerate() {
            state[k] = m31_add(state[k], v % M31_P);
        }
        state[15] = m31_add(state[15], 1);
        permute_t16(&mut state);
    }
    state
}

/// Two-to-one compression for 248-bit Merkle nodes: each node is 8 M31 words.
/// state = (l0..l7, r0..r7) → permute → output (s0..s7).
pub fn compress_t16(left: [u64; 8], right: [u64; 8]) -> [u64; 8] {
    let mut state = [
        left[0], left[1], left[2], left[3], left[4], left[5], left[6], left[7],
        right[0], right[1], right[2], right[3], right[4], right[5], right[6], right[7],
    ];
    permute_t16(&mut state);
    [
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    ]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::{m31_mul, m31_sub};

    // The internal matrix J + diag(1..16) must be invertible over M31
    // (det ≠ 0). Check via Gaussian elimination on the 16×16 matrix.
    #[test]
    fn test_internal_matrix_invertible() {
        let n = 16usize;
        // Build M_I: m[i][j] = 1 + (i==j)·(i+1)  → J + diag(1..16).
        let mut m: Vec<Vec<u64>> = (0..n)
            .map(|i| (0..n).map(|j| if i == j { 1 + (i as u64 + 1) } else { 1 }).collect())
            .collect();
        let mut det = 1u64;
        for col in 0..n {
            // find pivot
            let piv = (col..n).find(|&r| m[r][col] != 0).expect("singular");
            if piv != col {
                m.swap(piv, col);
                det = m31_sub(0, det); // sign flip
            }
            let inv = mod_inv(m[col][col]);
            det = m31_mul(det, m[col][col]);
            for r in (col + 1)..n {
                let f = m31_mul(m[r][col], inv);
                for c in col..n {
                    let sub = m31_mul(f, m[col][c]);
                    m[r][c] = m31_sub(m[r][c], sub);
                }
            }
        }
        assert_ne!(det, 0, "M_I = J + diag(1..16) must be invertible over M31");
    }

    // ── 16×16 naive reference matrices + helpers (mirror poseidon2_t8.rs) ────────

    fn det16(mat: [[u64; 16]; 16]) -> u64 {
        let mut m = mat;
        let mut det = 1u64;
        for col in 0..16 {
            let mut piv = col;
            while piv < 16 && m[piv][col] % M31_P == 0 {
                piv += 1;
            }
            if piv == 16 {
                return 0;
            }
            if piv != col {
                m.swap(piv, col);
                det = m31_sub(0, det);
            }
            det = m31_mul(det, m[col][col]);
            let inv_p = mod_inv(m[col][col]);
            for row in (col + 1)..16 {
                let factor = m31_mul(m[row][col], inv_p);
                for k in col..16 {
                    let sub = m31_mul(factor, m[col][k]);
                    m[row][k] = m31_sub(m[row][k], sub);
                }
            }
        }
        det
    }

    // Naive M_E = circ(2·M4, M4, M4, M4): block (a,b) is 2·M4 on the diagonal
    // (a==b), M4 off-diagonal — the circulant with first block-row [2·M4,M4,M4,M4].
    fn external_matrix16() -> [[u64; 16]; 16] {
        const M4: [[u64; 4]; 4] = [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]];
        let mut m = [[0u64; 16]; 16];
        for a in 0..4 {
            for b in 0..4 {
                let scale = if a == b { 2 } else { 1 };
                for i in 0..4 {
                    for j in 0..4 {
                        m[4 * a + i][4 * b + j] = m31_mul(scale, M4[i][j]);
                    }
                }
            }
        }
        m
    }

    fn internal_matrix16() -> [[u64; 16]; 16] {
        let mut m = [[1u64; 16]; 16];
        for i in 0..16 {
            m[i][i] = (1 + (i as u64 + 1)) % M31_P; // J diagonal (1) + μ_i (i+1)
        }
        m
    }

    fn matvec16(m: &[[u64; 16]; 16], v: &[u64; 16]) -> [u64; 16] {
        let mut out = [0u64; 16];
        for i in 0..16 {
            let mut acc = 0u64;
            for j in 0..16 {
                acc = m31_add(acc, m31_mul(m[i][j], v[j] % M31_P));
            }
            out[i] = acc;
        }
        out
    }

    #[test]
    fn test_external_matrix_invertible() {
        assert_ne!(det16(external_matrix16()), 0, "M_E must be invertible over M31");
    }

    #[test]
    fn test_mat_external_matches_naive() {
        let me = external_matrix16();
        let inputs: [[u64; 16]; 3] = [
            std::array::from_fn(|i| (i as u64) + 1),
            {
                let mut a = [0u64; 16];
                a[9] = 1;
                a
            },
            std::array::from_fn(|i| ((i as u64 + 1) * 123_456_789) % M31_P),
        ];
        for inp in inputs {
            let mut fast = inp;
            mat_external(&mut fast);
            assert_eq!(fast, matvec16(&me, &inp), "fast M_E diverges for {inp:?}");
        }
    }

    #[test]
    fn test_mat_internal_matches_naive() {
        let mi = internal_matrix16();
        let inputs: [[u64; 16]; 3] = [
            std::array::from_fn(|i| (i as u64) + 1),
            {
                let mut a = [0u64; 16];
                a[3] = 1;
                a
            },
            std::array::from_fn(|i| (M31_P - 1 - i as u64) % M31_P),
        ];
        for inp in inputs {
            let mut fast = inp;
            mat_internal(&mut fast);
            assert_eq!(fast, matvec16(&mi, &inp), "fast M_I diverges for {inp:?}");
        }
    }

    #[test]
    fn test_rc_count_and_range() {
        assert_eq!(K_RC.len(), T * R_F + R_P);
        assert_eq!(K_RC.len(), 142);
        for &c in K_RC.iter() {
            assert!((c as u64) < M31_P);
        }
    }

    fn mod_inv(a: u64) -> u64 {
        // Fermat: a^(p-2) mod p
        let mut base = a % M31_P;
        let mut exp = M31_P - 2;
        let mut acc = 1u64;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = m31_mul(acc, base);
            }
            base = m31_mul(base, base);
            exp >>= 1;
        }
        acc
    }

    // Frozen reference vectors — regression anchors for the permutation.
    // Generated once from this implementation (derivation rule documented in
    // the module header); any change to constants/matrices/rounds breaks these.
    #[test]
    fn test_reference_vectors() {
        let mut z = [0u64; 16];
        permute_t16(&mut z);
        let mut seq = [0u64; 16];
        for (i, v) in seq.iter_mut().enumerate() {
            *v = (i + 1) as u64;
        }
        permute_t16(&mut seq);

        // Determinism + non-triviality.
        assert_ne!(z, [0u64; 16], "permute(0) must not be the identity");
        assert_ne!(z, seq);
        let mut z2 = [0u64; 16];
        permute_t16(&mut z2);
        assert_eq!(z, z2, "permutation must be deterministic");

        // Frozen values (first 4 cells of each) — regression anchors.
        assert_eq!(
            [z[0], z[1], z[2], z[3]],
            [816977494, 440045756, 1261832507, 1370560761],
            "permute_t16([0;16])[0..4] regression anchor",
        );
        assert_eq!(
            [seq[0], seq[1], seq[2], seq[3]],
            [1896676506, 1113082531, 1826142252, 1263581674],
            "permute_t16([1..16])[0..4] regression anchor",
        );
    }

    #[test]
    fn test_compress_matches_permute() {
        let l = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let r = [9u64, 10, 11, 12, 13, 14, 15, 16];
        let mut st = [0u64; 16];
        st[..8].copy_from_slice(&l);
        st[8..].copy_from_slice(&r);
        permute_t16(&mut st);
        assert_eq!(compress_t16(l, r), st[..8], "compress = permute[0..8]");
    }

    #[test]
    fn test_sponge_full_block_vs_padded() {
        // 8 words = exactly one rate block (no padding flag);
        // 7 words = padded block (capacity flag set) → must differ.
        let full: Vec<u64> = (1..=8).collect();
        let short: Vec<u64> = (1..=7).collect();
        let s_full = sponge_t16(&full);
        let mut short_padded = short.clone();
        short_padded.push(0); // zero-extend WITHOUT the flag
        let s_short = sponge_t16(&short);
        let s_zero_ext = sponge_t16(&short_padded);
        assert_ne!(s_full, s_short);
        assert_ne!(
            s_short, s_zero_ext,
            "domain-separation flag must distinguish a padded block from a zero-extended one",
        );
    }

    #[test]
    fn test_sponge_multi_block() {
        // 16 words = two rate blocks; must differ from the first block alone.
        let two: Vec<u64> = (1..=16).collect();
        let one: Vec<u64> = (1..=8).collect();
        assert_ne!(sponge_t16(&two), sponge_t16(&one));
    }

    #[test]
    fn test_external_matrix_all_blocks_mixed() {
        // A single non-zero cell must propagate to ALL 16 cells after M_E
        // (the block-sum term touches every block).
        let mut s = [0u64; 16];
        s[5] = 1;
        mat_external(&mut s);
        // v-block containing cell 5 is non-trivial; sum propagates everywhere:
        // every OUTPUT block gets sigma added, and M4 mixes within blocks.
        let nonzero = s.iter().filter(|&&v| v != 0).count();
        assert!(nonzero >= 12, "external layer must diffuse across blocks, got {nonzero} non-zero");
    }
}
