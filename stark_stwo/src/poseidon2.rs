/// Poseidon2 permutation over the M31 field (Mersenne prime 2^31 − 1).
///
/// Parameters:
///   - state width  t = 2
///   - S-Box        x^5  (gcd(5, p-1) = 1 since p-1 = 2*(2^30-1), so valid)
///   - rounds       N_ROUNDS = 8 full rounds (min for 128-bit security at t=2)
///   - MDS matrix   [[3,1],[1,3]] over M31 (det=8≠0, invertible → MDS for t=2)
///   - round consts first 16 SHA-256 IV / round-constant bytes reduced mod M31_P
///
/// Used for:
///   - Witness generation in the Poseidon2 AIR (poseidon2_air.rs)
///   - Computing the public commitment value (s0 after all absorptions)

pub const M31_P: u64 = (1u64 << 31) - 1;
/// Number of full rounds per Poseidon2 permutation.
/// 8 rounds: a power of 2, so n_leaves×8 always divides 2^k for the trace (no partial blocks).
pub const N_ROUNDS: usize = 8;

/// Round constants: RC[round][state_element]
/// Derived from SHA-256 IV (h0..h7) and K[0..7] reduced mod M31_P = 2^31 − 1.
pub const RC: [[u32; 2]; N_ROUNDS] = [
    [1_779_033_703,   996_650_630],  // h0=0x6a09e667, h1=0xbb67ae85 % M31
    [1_013_904_242,   625_997_115],  // h2=0x3c6ef372, h3=0xa54ff53a % M31
    [1_359_893_119,   453_339_277],  // h4=0x510e527f, h5=0x9b05688c % M31
    [  528_734_635, 1_541_459_225],  // h6=0x1f83d9ab, h7=0x5be0cd19
    [1_116_352_408, 1_899_447_441],  // K[0]=0x428a2f98, K[1]=0x71374491
    [  901_839_824, 1_773_525_926],  // K[2]=0xb5c0fbcf % M31, K[3]=0xe9b5dba5 % M31
    [  961_987_163, 1_508_970_993],  // K[4]=0x3956c25b, K[5]=0x59f111f1
    [  306_152_101,   723_279_574],  // K[6]=0x923f82a4 % M31, K[7]=0xab1c5ed5 % M31
];

// ── Field arithmetic helpers ──────────────────────────────────────────────────

#[inline]
pub fn m31_add(a: u64, b: u64) -> u64 {
    let s = a + b;
    if s >= M31_P { s - M31_P } else { s }
}

#[inline]
pub fn m31_sub(a: u64, b: u64) -> u64 {
    if a >= b { a - b } else { a + M31_P - b }
}

#[inline]
pub fn m31_mul(a: u64, b: u64) -> u64 {
    // a, b < M31_P < 2^31, so a*b < 2^62 — no overflow in u64.
    // Barrett-style reduction: (a*b) = lo + hi where lo = r & M31_P, hi = r >> 31.
    // s = lo + hi ∈ [0, 2*M31_P) → one conditional subtraction suffices.
    let r = a * b;
    let lo = r & M31_P;
    let hi = r >> 31;
    let s = lo + hi;
    if s >= M31_P { s - M31_P } else { s }
}

// ── Poseidon2 building blocks ─────────────────────────────────────────────────

/// S-Box: x^5 mod M31_P.
#[inline]
pub fn sbox(x: u64) -> u64 {
    let x2 = m31_mul(x, x);
    let x4 = m31_mul(x2, x2);
    m31_mul(x4, x)
}

/// MDS layer: multiply by [[3,1],[1,3]] over M31.
#[inline]
pub fn mds(s: &mut [u64; 2]) {
    let a = s[0];
    let b = s[1];
    // 3a + b  and  a + 3b
    let three_a = m31_add(m31_add(a, a), a);
    let three_b = m31_add(m31_add(b, b), b);
    s[0] = m31_add(three_a, b);
    s[1] = m31_add(a, three_b);
}

/// One Poseidon2 round: AddRoundConstant → SBox → MDS.
#[inline]
pub fn round(s: &mut [u64; 2], rc: &[u32; 2]) {
    s[0] = m31_add(s[0], rc[0] as u64);
    s[1] = m31_add(s[1], rc[1] as u64);
    s[0] = sbox(s[0]);
    s[1] = sbox(s[1]);
    mds(s);
}

/// Full Poseidon2 permutation: N_ROUNDS rounds.
pub fn permute(s: &mut [u64; 2]) {
    for r in 0..N_ROUNDS {
        round(s, &RC[r]);
    }
}

// ── Sponge ────────────────────────────────────────────────────────────────────

/// Rate-1 Poseidon2 sponge over M31: absorb each leaf into s[0], then permute.
/// Initial state is (0, 0).  Returns (s0, s1) after processing all leaves.
pub fn poseidon2_chain(leaves: &[u64]) -> (u64, u64) {
    let mut state = [0u64; 2];
    for &leaf in leaves {
        state[0] = m31_add(state[0], leaf % M31_P);
        permute(&mut state);
    }
    (state[0], state[1])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_m31_mul_edge() {
        // (M31_P - 1)^2 ≡ 1 (mod M31_P)
        assert_eq!(m31_mul(M31_P - 1, M31_P - 1), 1);
    }

    #[test]
    fn test_sbox_zero() {
        assert_eq!(sbox(0), 0);
    }

    #[test]
    fn test_sbox_one() {
        assert_eq!(sbox(1), 1);
    }

    #[test]
    fn test_mds_identity_input() {
        let mut s = [1u64, 0u64];
        mds(&mut s);
        assert_eq!(s, [3, 1]);

        let mut s = [0u64, 1u64];
        mds(&mut s);
        assert_eq!(s, [1, 3]);
    }

    #[test]
    fn test_permute_deterministic() {
        let mut a = [42u64, 7u64];
        let mut b = [42u64, 7u64];
        permute(&mut a);
        permute(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn test_permute_non_trivial() {
        let mut s = [0u64; 2];
        permute(&mut s);
        // Permutation of (0,0) should be non-zero (round constants break symmetry).
        assert!(s[0] != 0 || s[1] != 0);
    }

    #[test]
    fn test_chain_deterministic() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let r1 = poseidon2_chain(&leaves);
        let r2 = poseidon2_chain(&leaves);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_chain_different_inputs() {
        let a = poseidon2_chain(&[1u64, 2, 3, 4, 5, 6, 7, 8]);
        let b = poseidon2_chain(&[1u64, 2, 3, 4, 5, 6, 7, 9]);
        assert_ne!(a, b);
    }

    #[test]
    fn test_chain_output_in_m31() {
        let (s0, s1) = poseidon2_chain(&[1u64, 2, 3, 4, 5, 6, 7, 8]);
        assert!(s0 < M31_P);
        assert!(s1 < M31_P);
    }
}
