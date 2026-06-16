/// Poseidon2 permutation over M31 with state width t = 8 (MVP-6, 128-bit ladder).
///
/// Motivation: VFRI10's t=4 backend still emits 2-word (62-bit) Merkle nodes —
/// node collision ~2^31 (documented limitation #6).  Width 8 lets a 2-to-1
/// compression carry 4-word (124-bit) children, raising node collision cost to
/// ~2^62.  It is the next rung on the ladder to genuine 128-bit binding:
///
///   t=2 (62-bit state) → t=4 (124-bit state, 2-word nodes, 2^31 node collision)
///   → t=8 (THIS: 4-word nodes, 2^62 node collision)
///   → t=16 (8-word nodes, ~2^124 ≈ 128-bit — matches Stwo's native Poseidon2-16)
///
/// Parameters (research instance — same derivation convention as the t=2/t=4
/// instances; not a standardised parameter set):
///   - state width      t = 8
///   - S-Box            x^5 (gcd(5, p−1) = 1 over M31)
///   - external rounds  R_F = 8 (4 initial + 4 final), S-box on all 8 cells
///   - internal rounds  R_P = 14, S-box on cell 0 only
///   - external matrix  M_E = [[2·M4, M4], [M4, 2·M4]] (Poseidon2 §5.1 block
///     construction for t = 4·t': apply M4 to each 4-cell block, then add the
///     block-sum to every block).  M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]].
///   - internal matrix  M_I = J + diag(1,2,…,8) over M31 (J = all-ones 8×8;
///     diagonal entries (2,3,…,9); invertibility asserted in tests)
///   - round constants  RC[i] = u32_be(SHA-256("QLSA-Poseidon2-t8" ‖ i_be4)[..4])
///     mod M31_P, for i in 0..78 (external rounds consume RC[0..64] — 8 per
///     round; internal rounds consume RC[64..78] — 1 per round).  Frozen as
///     literals below; regenerable by the documented rule.
///
/// Layout follows the Poseidon2 specification:
///   state ← M_E·state
///   4 × (AddRC → SBox(all 8) → M_E)
///   14 × (AddRC[0] → SBox(cell 0) → M_I)
///   4 × (AddRC → SBox(all 8) → M_E)

use crate::poseidon2::{m31_add, sbox, M31_P};

pub const T: usize = 8;
pub const R_F: usize = 8; // external (full) rounds, split 4 + 4
pub const R_P: usize = 14; // internal (partial) rounds

/// Round constants RC[i] = u32_be(SHA-256("QLSA-Poseidon2-t8" ‖ i_be4)[..4]) mod
/// M31_P, for i in 0..(T·R_F + R_P) = 0..78.  All are already < M31_P.
/// External round r uses K_RC[T·r .. T·r+T); internal round j uses K_RC[T·R_F + j].
pub const K_RC: [u32; 78] = [
    2012176458, 1849299961, 1732939933, 390435213, 1583598125, 1521506328,
    1850315157, 593064883, 442979704, 49299287, 668322884, 1478447923,
    2117627097, 894462472, 335092600, 304090409, 1725083656, 1823780446,
    1589693490, 336928399, 1533176076, 1472808391, 1197491867, 1980232791,
    1332985942, 553469441, 542603061, 145062400, 1801771230, 501797052,
    191408558, 124556117, 767378382, 870276988, 2046892345, 12605708,
    1937961243, 903615558, 781360720, 458985484, 768021800, 1017409239,
    1219264179, 1642454766, 518313705, 101708341, 1618375810, 1323121046,
    1721228118, 339098950, 1976827842, 1756100371, 1309626382, 451150501,
    491114795, 994585973, 1034786474, 575533575, 1809299734, 1497205669,
    961538106, 1152123009, 606500650, 2046687220, 672534258, 1626884035,
    1258567472, 1521030780, 609641534, 426249300, 1360556010, 668676905,
    453695314, 178868843, 1293599881, 595916213, 1841032014, 29885509,
];

/// The 4×4 M4 block multiply (Poseidon2 §5.1 fast path, 8 additions).
#[inline]
fn m4(s: &mut [u64; 4]) {
    let t0 = m31_add(s[0], s[1]);
    let t1 = m31_add(s[2], s[3]);
    let t2 = m31_add(m31_add(s[1], s[1]), t1);
    let t3 = m31_add(m31_add(s[3], s[3]), t0);
    let t4 = m31_add(m31_add(m31_add(t1, t1), m31_add(t1, t1)), t3);
    let t5 = m31_add(m31_add(m31_add(t0, t0), m31_add(t0, t0)), t2);
    s[0] = m31_add(t3, t5);
    s[1] = t5;
    s[2] = m31_add(t2, t4);
    s[3] = t4;
}

/// External linear layer: state ← M_E·state with M_E = [[2·M4, M4], [M4, 2·M4]].
/// Apply M4 to each 4-cell block (→ v0, v1), then out_block_i = v_i + (v0 + v1).
#[inline]
pub fn mat_external(s: &mut [u64; 8]) {
    let mut v0 = [s[0], s[1], s[2], s[3]];
    let mut v1 = [s[4], s[5], s[6], s[7]];
    m4(&mut v0);
    m4(&mut v1);
    for k in 0..4 {
        let sigma = m31_add(v0[k], v1[k]);
        s[k] = m31_add(v0[k], sigma); // 2·v0 + v1
        s[4 + k] = m31_add(v1[k], sigma); // v0 + 2·v1
    }
}

/// Internal linear layer: state ← (J + diag(1,…,8))·state, i.e.
/// out_i = (Σ_j s_j) + μ_i·s_i with μ = (1,2,…,8).
#[inline]
pub fn mat_internal(s: &mut [u64; 8]) {
    let mut sum = 0u64;
    for &v in s.iter() {
        sum = m31_add(sum, v);
    }
    for i in 0..8 {
        // out_i = sum + (i+1)·s_i; sum already contains one copy of s_i, so add
        // s_i an additional (i+1) times relative to nothing — i.e. (i+1) copies.
        let si = s[i];
        let mut acc = sum;
        for _ in 0..=i {
            acc = m31_add(acc, si);
        }
        s[i] = acc;
    }
}

/// Full Poseidon2 t=8 permutation.
pub fn permute_t8(s: &mut [u64; 8]) {
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

/// Rate-4 capacity-4 sponge: absorb 4 M31 words per block into cells 0–3,
/// permute after each block.  An odd-length tail sets a domain-separation flag
/// in capacity cell 7 on the final block (outside the rate, so no data words can
/// imitate the padded block).  Returns the full 8-word state; callers take cells
/// 0–3 as the 4-word (124-bit) node.
pub fn sponge_t8(values: &[u64]) -> [u64; 8] {
    let mut state = [0u64; 8];
    let mut chunks = values.chunks_exact(4);
    for c in &mut chunks {
        for k in 0..4 {
            state[k] = m31_add(state[k], c[k] % M31_P);
        }
        permute_t8(&mut state);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        for (k, &v) in rem.iter().enumerate() {
            state[k] = m31_add(state[k], v % M31_P);
        }
        state[7] = m31_add(state[7], 1);
        permute_t8(&mut state);
    }
    state
}

/// Two-to-one compression for 124-bit Merkle nodes: each node is 4 M31 words.
/// state = (l0..l3, r0..r3) → permute → output (s0..s3).
pub fn compress_t8(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
    let mut state = [
        left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3],
    ];
    permute_t8(&mut state);
    [state[0], state[1], state[2], state[3]]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::{m31_mul, m31_sub};

    /// Naive 8×8 multiply over M31 (test reference).
    fn matvec(m: &[[u64; 8]; 8], x: &[u64; 8]) -> [u64; 8] {
        let mut out = [0u64; 8];
        for i in 0..8 {
            for j in 0..8 {
                out[i] = m31_add(out[i], m31_mul(m[i][j], x[j]));
            }
        }
        out
    }

    /// Determinant mod M31 via fraction-free Bareiss elimination (test-only).
    fn det8(mat: [[u64; 8]; 8]) -> u64 {
        // Work in the prime field: use modular inverse for pivoting.
        fn inv(a: u64) -> u64 {
            // Fermat: a^(p-2) mod p
            let mut r = 1u64;
            let mut b = a % M31_P;
            let mut e = (M31_P as u64) - 2;
            while e > 0 {
                if e & 1 == 1 {
                    r = m31_mul(r, b);
                }
                b = m31_mul(b, b);
                e >>= 1;
            }
            r
        }
        let mut m = mat;
        let mut det = 1u64;
        for col in 0..8 {
            // find pivot
            let mut piv = col;
            while piv < 8 && m[piv][col] % M31_P == 0 {
                piv += 1;
            }
            if piv == 8 {
                return 0;
            }
            if piv != col {
                m.swap(piv, col);
                det = m31_sub(0, det); // sign flip
            }
            det = m31_mul(det, m[col][col]);
            let inv_p = inv(m[col][col]);
            for row in (col + 1)..8 {
                let factor = m31_mul(m[row][col], inv_p);
                for k in col..8 {
                    let sub = m31_mul(factor, m[col][k]);
                    m[row][k] = m31_sub(m[row][k], sub);
                }
            }
        }
        det
    }

    fn external_matrix() -> [[u64; 8]; 8] {
        const M4: [[u64; 4]; 4] = [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]];
        let mut m = [[0u64; 8]; 8];
        for i in 0..4 {
            for j in 0..4 {
                // [[2·M4, M4], [M4, 2·M4]]
                m[i][j] = m31_mul(2, M4[i][j]);
                m[i][4 + j] = M4[i][j];
                m[4 + i][j] = M4[i][j];
                m[4 + i][4 + j] = m31_mul(2, M4[i][j]);
            }
        }
        m
    }

    fn internal_matrix() -> [[u64; 8]; 8] {
        let mut m = [[1u64; 8]; 8];
        for i in 0..8 {
            m[i][i] = m31_add(1, (i as u64) + 1); // J diagonal (1) + μ_i (i+1)
        }
        m
    }

    #[test]
    fn test_external_matrix_invertible() {
        assert_ne!(det8(external_matrix()), 0, "M_E must be invertible over M31");
    }

    #[test]
    fn test_internal_matrix_invertible() {
        assert_ne!(det8(internal_matrix()), 0, "M_I must be invertible over M31");
    }

    #[test]
    fn test_mat_external_matches_naive() {
        let me = external_matrix();
        let inputs: [[u64; 8]; 3] = [
            [1, 2, 3, 4, 5, 6, 7, 8],
            [0, 0, 0, 0, 0, 0, 0, 1],
            [M31_P - 1, 7, 123_456_789, 42, 1, 2, 3, 4],
        ];
        for inp in inputs {
            let mut fast = inp;
            mat_external(&mut fast);
            assert_eq!(fast, matvec(&me, &inp), "fast M_E diverges for {inp:?}");
        }
    }

    #[test]
    fn test_mat_internal_matches_naive() {
        let mi = internal_matrix();
        let inputs: [[u64; 8]; 3] = [
            [1, 2, 3, 4, 5, 6, 7, 8],
            [0, 1, 0, 0, 0, 0, 0, 0],
            [M31_P - 1, M31_P - 2, 5, 6, 7, 8, 9, 10],
        ];
        for inp in inputs {
            let mut fast = inp;
            mat_internal(&mut fast);
            assert_eq!(fast, matvec(&mi, &inp), "fast M_I diverges for {inp:?}");
        }
    }

    #[test]
    fn test_rc_count_and_range() {
        assert_eq!(K_RC.len(), T * R_F + R_P);
        assert_eq!(K_RC.len(), 78);
        for &c in K_RC.iter() {
            assert!((c as u64) < M31_P);
        }
    }

    #[test]
    fn test_permute_deterministic_and_in_field() {
        let mut a = [42u64, 7, 99, 3, 11, 22, 33, 44];
        let mut b = a;
        permute_t8(&mut a);
        permute_t8(&mut b);
        assert_eq!(a, b);
        assert!(a.iter().all(|&v| v < M31_P));
    }

    #[test]
    fn test_permute_zero_nontrivial() {
        let mut s = [0u64; 8];
        permute_t8(&mut s);
        assert!(s.iter().any(|&v| v != 0));
    }

    #[test]
    fn test_permute_full_diffusion() {
        // Flipping one input cell must change every output cell.
        let mut a = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let mut b = [1u64, 2, 3, 4, 5, 6, 7, 9];
        permute_t8(&mut a);
        permute_t8(&mut b);
        for i in 0..8 {
            assert_ne!(a[i], b[i], "cell {i} unchanged after single-cell input flip");
        }
    }

    #[test]
    fn test_sponge_deterministic_and_in_field() {
        let s1 = sponge_t8(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let s2 = sponge_t8(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(s1, s2);
        assert!(s1.iter().all(|&v| v < M31_P));
    }

    #[test]
    fn test_sponge_padding_distinguishes_lengths() {
        let a = sponge_t8(&[1, 2, 3]);
        let b = sponge_t8(&[1, 2, 3, 1]);
        let c = sponge_t8(&[1, 2, 3, 0]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_compress_order_sensitive() {
        let l = [11u64, 22, 33, 44];
        let r = [55u64, 66, 77, 88];
        assert_ne!(compress_t8(l, r), compress_t8(r, l));
    }

    /// Reference vectors locking the permutation across implementations
    /// (Solidity Poseidon2M31T8 must reproduce these exact outputs).
    #[test]
    fn test_reference_vectors() {
        let mut z = [0u64; 8];
        permute_t8(&mut z);
        assert_eq!(z, REF_PERMUTE_ZERO);

        let mut seq = [1u64, 2, 3, 4, 5, 6, 7, 8];
        permute_t8(&mut seq);
        assert_eq!(seq, REF_PERMUTE_SEQ);

        assert_eq!(sponge_t8(&[1, 2, 3, 4, 5, 6, 7, 8]), REF_SPONGE);
        assert_eq!(compress_t8([1, 2, 3, 4], [5, 6, 7, 8]), REF_COMPRESS);
    }

    // Frozen reference vectors (from print_reference_vectors).
    const REF_PERMUTE_ZERO: [u64; 8] =
        [216312942, 155820902, 926495998, 1144704772, 1934653642, 1380128781, 12500119, 1030062085];
    const REF_PERMUTE_SEQ: [u64; 8] =
        [890515421, 531626735, 2060583819, 1311645369, 1183191699, 1798384804, 1654039744, 1303745775];
    const REF_SPONGE: [u64; 8] =
        [1440998077, 1368105497, 587877558, 669993876, 613862076, 1115134094, 498218752, 624943054];
    const REF_COMPRESS: [u64; 4] = [890515421, 531626735, 2060583819, 1311645369];

    #[test]
    #[ignore = "prints reference vectors to freeze in the consts above and the Solidity mirror"]
    fn print_reference_vectors() {
        let mut z = [0u64; 8];
        permute_t8(&mut z);
        println!("permute([0;8])     = {z:?}");
        let mut seq = [1u64, 2, 3, 4, 5, 6, 7, 8];
        permute_t8(&mut seq);
        println!("permute([1..8])    = {seq:?}");
        println!("sponge([1..8])     = {:?}", sponge_t8(&[1, 2, 3, 4, 5, 6, 7, 8]));
        println!("compress([1..4],[5..8]) = {:?}", compress_t8([1, 2, 3, 4], [5, 6, 7, 8]));
    }
}
