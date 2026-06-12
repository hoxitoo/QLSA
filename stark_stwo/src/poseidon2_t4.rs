/// Poseidon2 permutation over M31 with state width t = 4 (MVP-6).
///
/// Motivation: the t=2 instance (poseidon2.rs) caps the sponge capacity and
/// Merkle node content at 62 bits — collision/transcript attacks at ~2^31
/// (documented limitation #6).  Width 4 doubles the state: a capacity-2
/// sponge and 124-bit wide nodes raise node collision cost to ~2^62.
///
/// Parameters (research instance — same derivation convention as the t=2
/// instance; not a standardised parameter set):
///   - state width      t = 4
///   - S-Box            x^5 (gcd(5, p−1) = 1 over M31)
///   - external rounds  R_F = 8 (4 initial + 4 final), S-box on all 4 cells
///   - internal rounds  R_P = 21, S-box on cell 0 only
///     (R_P taken from the Poseidon2 paper's t=4 64-bit instance — strictly
///      more partial rounds than the 31-bit algebraic bound requires)
///   - external matrix  M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]
///     (the M_4 block from the Poseidon2 paper §5.1, applied to the state
///      before round 1 and after every external round)
///   - internal matrix  M_I = J + diag(1,2,3,4) over M31
///     (J = all-ones; diagonal entries (2,3,4,5); invertibility asserted in
///      tests: det(M_I) ≠ 0 mod P)
///   - round constants  SHA-256 K[0..53] reduced mod M31_P
///     (external rounds consume K[0..32] — 4 per round; internal rounds
///      consume K[32..53] — 1 per round)
///
/// The permutation layout follows the Poseidon2 specification:
///   state ← M_E·state
///   4 × (AddRC → SBox(all) → M_E)
///   21 × (AddRC[0] → SBox(cell 0) → M_I)
///   4 × (AddRC → SBox(all) → M_E)

use crate::poseidon2::{m31_add, m31_mul, sbox, M31_P};

pub const T: usize = 4;
pub const R_F: usize = 8; // external (full) rounds, split 4 + 4
pub const R_P: usize = 21; // internal (partial) rounds

/// Reduce a raw u32 constant into [0, M31_P).  u32::MAX = 2·P + 1, so two
/// conditional subtractions suffice.
const fn rc(x: u32) -> u32 {
    let p = M31_P as u32;
    let mut v = x;
    if v >= p {
        v -= p;
    }
    if v >= p {
        v -= p;
    }
    v
}

/// SHA-256 round constants K[0..53] reduced mod M31_P.
/// External round r uses K_RC[4r .. 4r+4); internal round j uses K_RC[32 + j].
pub const K_RC: [u32; 53] = [
    rc(0x428a2f98),
    rc(0x71374491),
    rc(0xb5c0fbcf),
    rc(0xe9b5dba5),
    rc(0x3956c25b),
    rc(0x59f111f1),
    rc(0x923f82a4),
    rc(0xab1c5ed5),
    rc(0xd807aa98),
    rc(0x12835b01),
    rc(0x243185be),
    rc(0x550c7dc3),
    rc(0x72be5d74),
    rc(0x80deb1fe),
    rc(0x9bdc06a7),
    rc(0xc19bf174),
    rc(0xe49b69c1),
    rc(0xefbe4786),
    rc(0x0fc19dc6),
    rc(0x240ca1cc),
    rc(0x2de92c6f),
    rc(0x4a7484aa),
    rc(0x5cb0a9dc),
    rc(0x76f988da),
    rc(0x983e5152),
    rc(0xa831c66d),
    rc(0xb00327c8),
    rc(0xbf597fc7),
    rc(0xc6e00bf3),
    rc(0xd5a79147),
    rc(0x06ca6351),
    rc(0x14292967),
    rc(0x27b70a85),
    rc(0x2e1b2138),
    rc(0x4d2c6dfc),
    rc(0x53380d13),
    rc(0x650a7354),
    rc(0x766a0abb),
    rc(0x81c2c92e),
    rc(0x92722c85),
    rc(0xa2bfe8a1),
    rc(0xa81a664b),
    rc(0xc24b8b70),
    rc(0xc76c51a3),
    rc(0xd192e819),
    rc(0xd6990624),
    rc(0xf40e3585),
    rc(0x106aa070),
    rc(0x19a4c116),
    rc(0x1e376c08),
    rc(0x2748774c),
    rc(0x34b0bcb5),
    rc(0x391c0cb3),
];

/// External linear layer: state ← M4 · state where
/// M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]].
#[inline]
pub fn mat_external(s: &mut [u64; 4]) {
    // The Poseidon2 M4 multiply in 8 additions (paper §5.1 fast path):
    //   t0 = s0 + s1;  t1 = s2 + s3
    //   t2 = 2·s1 + t1;  t3 = 2·s3 + t0
    //   t4 = 4·t1 + t3;  t5 = 4·t0 + t2
    //   out = (t3 + t5, t5, t2 + t4, t4)
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

/// Internal linear layer: state ← (J + diag(1,2,3,4)) · state, i.e.
/// out_i = (Σ_j s_j) + μ_i · s_i with μ = (1, 2, 3, 4).
#[inline]
pub fn mat_internal(s: &mut [u64; 4]) {
    let sum = m31_add(m31_add(s[0], s[1]), m31_add(s[2], s[3]));
    s[0] = m31_add(sum, s[0]);
    s[1] = m31_add(sum, m31_add(s[1], s[1]));
    s[2] = m31_add(sum, m31_add(m31_add(s[2], s[2]), s[2]));
    s[3] = m31_add(sum, m31_add(m31_add(s[3], s[3]), m31_add(s[3], s[3])));
}

/// Full Poseidon2 t=4 permutation.
pub fn permute_t4(s: &mut [u64; 4]) {
    mat_external(s);
    for r in 0..R_F / 2 {
        for i in 0..T {
            s[i] = m31_add(s[i], K_RC[4 * r + i] as u64);
        }
        for i in 0..T {
            s[i] = sbox(s[i]);
        }
        mat_external(s);
    }
    for j in 0..R_P {
        s[0] = m31_add(s[0], K_RC[32 + j] as u64);
        s[0] = sbox(s[0]);
        mat_internal(s);
    }
    for r in R_F / 2..R_F {
        for i in 0..T {
            s[i] = m31_add(s[i], K_RC[4 * r + i] as u64);
        }
        for i in 0..T {
            s[i] = sbox(s[i]);
        }
        mat_external(s);
    }
}

// ── Sponge / compression helpers ─────────────────────────────────────────────

/// Rate-2 capacity-2 sponge: absorb pairs of M31 words into cells 0–1,
/// permute after each pair.  An odd-length input sets a domain-separation
/// flag in capacity cell 3 on the final block — the flag lives outside the
/// rate, so no choice of data words can imitate the padded final block
/// (adding 1 to a rate cell would collide with a legitimate trailing 1).
/// Returns the full 4-word state.
pub fn sponge_t4(values: &[u64]) -> [u64; 4] {
    let mut state = [0u64; 4];
    let mut chunks = values.chunks_exact(2);
    for pair in &mut chunks {
        state[0] = m31_add(state[0], pair[0] % M31_P);
        state[1] = m31_add(state[1], pair[1] % M31_P);
        permute_t4(&mut state);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        state[0] = m31_add(state[0], rem[0] % M31_P);
        state[3] = m31_add(state[3], 1);
        permute_t4(&mut state);
    }
    state
}

/// Two-to-one compression for 124-bit Merkle nodes: each node is 2 M31 words.
/// state = (l0, l1, r0, r1) → permute → output (s0, s1).
pub fn compress_t4(left: [u64; 2], right: [u64; 2]) -> [u64; 2] {
    let mut state = [left[0], left[1], right[0], right[1]];
    permute_t4(&mut state);
    [state[0], state[1]]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::m31_sub;

    /// 4×4 determinant mod M31 by cofactor expansion (test-only).
    fn det4(m: [[u64; 4]; 4]) -> u64 {
        fn det3(m: [[u64; 3]; 3]) -> u64 {
            let a = m31_mul(m[0][0], m31_sub(m31_mul(m[1][1], m[2][2]), m31_mul(m[1][2], m[2][1])));
            let b = m31_mul(m[0][1], m31_sub(m31_mul(m[1][0], m[2][2]), m31_mul(m[1][2], m[2][0])));
            let c = m31_mul(m[0][2], m31_sub(m31_mul(m[1][0], m[2][1]), m31_mul(m[1][1], m[2][0])));
            m31_add(m31_sub(a, b), c)
        }
        let minor = |skip: usize| -> [[u64; 3]; 3] {
            let mut out = [[0u64; 3]; 3];
            for (ri, row) in m.iter().skip(1).enumerate() {
                let mut ci = 0;
                for (j, &v) in row.iter().enumerate() {
                    if j != skip {
                        out[ri][ci] = v;
                        ci += 1;
                    }
                }
            }
            out
        };
        let mut acc = 0u64;
        for j in 0..4 {
            let term = m31_mul(m[0][j], det3(minor(j)));
            acc = if j % 2 == 0 { m31_add(acc, term) } else { m31_sub(acc, term) };
        }
        acc
    }

    const M4: [[u64; 4]; 4] = [
        [5, 7, 1, 3],
        [4, 6, 1, 1],
        [1, 3, 5, 7],
        [1, 1, 4, 6],
    ];
    const MI: [[u64; 4]; 4] = [
        [2, 1, 1, 1],
        [1, 3, 1, 1],
        [1, 1, 4, 1],
        [1, 1, 1, 5],
    ];

    #[test]
    fn test_external_matrix_invertible() {
        assert_ne!(det4(M4), 0, "external matrix M4 must be invertible over M31");
    }

    #[test]
    fn test_internal_matrix_invertible() {
        assert_ne!(det4(MI), 0, "internal matrix M_I must be invertible over M31");
    }

    #[test]
    fn test_mat_external_matches_naive() {
        let inputs = [[1u64, 2, 3, 4], [0, 0, 0, 1], [M31_P - 1, 7, 123_456_789, 42]];
        for inp in inputs {
            let mut fast = inp;
            mat_external(&mut fast);
            let mut naive = [0u64; 4];
            for i in 0..4 {
                for j in 0..4 {
                    naive[i] = m31_add(naive[i], m31_mul(M4[i][j], inp[j]));
                }
            }
            assert_eq!(fast, naive, "fast M4 path diverges from naive multiply for {inp:?}");
        }
    }

    #[test]
    fn test_mat_internal_matches_naive() {
        let inputs = [[1u64, 2, 3, 4], [0, 1, 0, 0], [M31_P - 1, M31_P - 2, 5, 6]];
        for inp in inputs {
            let mut fast = inp;
            mat_internal(&mut fast);
            let mut naive = [0u64; 4];
            for i in 0..4 {
                for j in 0..4 {
                    naive[i] = m31_add(naive[i], m31_mul(MI[i][j], inp[j]));
                }
            }
            assert_eq!(fast, naive, "fast M_I path diverges from naive multiply for {inp:?}");
        }
    }

    #[test]
    fn test_rc_count_and_range() {
        assert_eq!(K_RC.len(), 4 * R_F + R_P);
        for &c in K_RC.iter() {
            assert!((c as u64) < M31_P);
        }
    }

    #[test]
    fn test_permute_deterministic() {
        let mut a = [42u64, 7, 99, 3];
        let mut b = a;
        permute_t4(&mut a);
        permute_t4(&mut b);
        assert_eq!(a, b);
        assert!(a.iter().all(|&v| v < M31_P));
    }

    #[test]
    fn test_permute_zero_nontrivial() {
        let mut s = [0u64; 4];
        permute_t4(&mut s);
        assert!(s.iter().any(|&v| v != 0));
    }

    #[test]
    fn test_permute_single_bit_diffusion() {
        // Flipping one input cell must change every output cell.
        let mut a = [1u64, 2, 3, 4];
        let mut b = [1u64, 2, 3, 5];
        permute_t4(&mut a);
        permute_t4(&mut b);
        for i in 0..4 {
            assert_ne!(a[i], b[i], "cell {i} unchanged after single-cell input flip");
        }
    }

    #[test]
    fn test_sponge_deterministic_and_in_field() {
        let s1 = sponge_t4(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let s2 = sponge_t4(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(s1, s2);
        assert!(s1.iter().all(|&v| v < M31_P));
    }

    #[test]
    fn test_sponge_padding_distinguishes_lengths() {
        // [1,2,3] (padded) must differ from [1,2,3,1] (the same words absorbed
        // without padding) and from [1,2,3,0].
        let a = sponge_t4(&[1, 2, 3]);
        let b = sponge_t4(&[1, 2, 3, 1]);
        let c = sponge_t4(&[1, 2, 3, 0]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_compress_order_sensitive() {
        let l = [11u64, 22];
        let r = [33u64, 44];
        assert_ne!(compress_t4(l, r), compress_t4(r, l));
    }

    /// Reference vectors locking the permutation across implementations
    /// (Solidity Poseidon2M31T4 must reproduce these exact outputs).
    #[test]
    fn test_reference_vectors() {
        let mut z = [0u64; 4];
        permute_t4(&mut z);
        assert_eq!(z, [201_095_161, 440_871_427, 944_955_487, 992_273_343]);

        let mut seq = [1u64, 2, 3, 4];
        permute_t4(&mut seq);
        assert_eq!(seq, [1_706_601_437, 1_471_208_702, 244_698_605, 2_091_016_348]);

        let sp = sponge_t4(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(sp, [1_315_656_215, 594_434_174, 137_860_571, 1_608_246_984]);

        let cp = compress_t4([1, 2], [3, 4]);
        assert_eq!(cp, [1_706_601_437, 1_471_208_702]);
    }
}
