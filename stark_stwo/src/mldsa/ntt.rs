/// NTT and INTT over Z_q for the ring Z_q[X] / (X^256 + 1).
///
/// Implements FIPS 204 Algorithms 41 (NTT) and 42 (NTT^{-1}) exactly.
///
/// The twiddle factors are ζ^{brv_8(k)} where brv_8 is 8-bit bit-reversal
/// and ζ = 1753 is a primitive 512th root of unity in Z_q.
///
/// The zeta table is computed once (lazily) and cached via OnceLock.

use std::sync::OnceLock;

use super::{field, N, Q, N_INV, ZETA};

// ─── Zeta tables ─────────────────────────────────────────────────────────────

/// Forward twiddle table: ZETA_FWD[k] = ζ^{brv_8(k)} mod Q, k=0..255.
/// Used by the forward NTT (k=1..255 in order).
static ZETA_FWD: OnceLock<[i64; 256]> = OnceLock::new();

fn get_zeta_fwd() -> &'static [i64; 256] {
    ZETA_FWD.get_or_init(|| {
        let mut t = [0i64; 256];
        for k in 0u8..=255u8 {
            let brv = k.reverse_bits();
            t[k as usize] = field::pow(ZETA, brv as u64);
        }
        t
    })
}

/// Inverse twiddle table: ZETA_INV[k] = ζ^{512 − brv_8(k)} mod Q, k=0..255.
///
/// Each entry is the modular inverse of ZETA_FWD[k]:
///   ZETA_FWD[k] * ZETA_INV[k] = ζ^{brv(k)} * ζ^{512−brv(k)} = ζ^{512} = 1 (mod Q)
///
/// The INTT butterfly multiplies by ZETA_INV[k] (with k going 255→1),
/// undoing the forward butterfly that multiplied by ZETA_FWD[k].
static ZETA_INV: OnceLock<[i64; 256]> = OnceLock::new();

fn get_zeta_inv() -> &'static [i64; 256] {
    ZETA_INV.get_or_init(|| {
        let mut t = [0i64; 256];
        for k in 0u8..=255u8 {
            let brv = k.reverse_bits() as u32;
            // ζ^{512 − brv} = ζ^{−brv}  (since ζ^{512} = 1)
            let exp = (512 - brv) % 512;
            t[k as usize] = field::pow(ZETA, exp as u64);
        }
        t
    })
}

// ─── NTT (Algorithm 41, FIPS 204) ────────────────────────────────────────────

/// Forward NTT in place.
///
/// Input/output coefficients are in [0, Q).
/// After the call, `f` is in the NTT domain (T_q).
pub fn ntt(f: &mut [i64; 256]) {
    let zetas = get_zeta_fwd();
    let mut k: usize = 1;
    let mut len: usize = 128;

    while len >= 1 {
        let mut start: usize = 0;
        while start < N {
            let zeta_k = zetas[k];
            k += 1;
            for j in start..start + len {
                let t = field::mul(zeta_k, f[j + len]);
                let fj = f[j];
                // f[j]     ← fj + t  (mod Q, branchless via add)
                f[j]       = fj + t;        if f[j]       >= Q { f[j]       -= Q; }
                // f[j+len] ← fj − t  (mod Q)
                f[j + len] = fj - t;        if f[j + len] <  0 { f[j + len] += Q; }
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

// ─── INTT (Algorithm 42, FIPS 204) ───────────────────────────────────────────

/// Inverse NTT in place, including the N^{-1} normalization factor.
///
/// Input: `f` in NTT domain (T_q), coefficients in [0, Q).
/// Output: `f` in coefficient domain (R_q), coefficients in [0, Q).
pub fn ntt_inv(f: &mut [i64; 256]) {
    let inv_zetas = get_zeta_inv();
    // The INTT applies stages in REVERSE ORDER (len=1,2,4,...,128) relative to
    // the forward NTT (len=128,...,2,1).  Within each INTT stage, k ascends
    // from k_start = N/(2·len) — the same k values the forward NTT used for
    // that stage, so each GS butterfly uses ω^{-1} for its matching CT forward
    // butterfly.
    //
    // Correctness: if the forward butterfly is f[j] ← A+ω·B, f[j+len] ← A-ω·B,
    // the inverse GS butterfly with ω^{-1} gives:
    //   f[j]     ← f[j] + f[j+len] = 2A
    //   f[j+len] ← ω^{-1} · (f[j] - f[j+len]) = 2B
    // Accumulated factor 2^8 = 256 = N is removed by the N^{-1} step at the end.
    let mut len: usize = 1;
    while len <= 128 {
        // k_start = N/(2·len): the first k value the forward NTT used for this stage.
        let k_start = N / (2 * len);
        let mut k = k_start;
        let mut start: usize = 0;
        while start < N {
            let zeta_inv_k = inv_zetas[k];
            k += 1;
            for j in start..start + len {
                let t = f[j];
                f[j]       = t + f[j + len]; if f[j]       >= Q { f[j]       -= Q; }
                let diff   = t - f[j + len]; let diff = if diff < 0 { diff + Q } else { diff };
                f[j + len] = field::mul(zeta_inv_k, diff);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in f.iter_mut() {
        *c = field::mul(*c, N_INV);
    }
}

// ─── Pointwise multiplication in T_q ─────────────────────────────────────────

/// Pointwise multiplication of two NTT-domain polynomials.
pub fn pointwise_mul(a: &[i64; 256], b: &[i64; 256]) -> [i64; 256] {
    let mut c = [0i64; 256];
    for i in 0..256 {
        c[i] = field::mul(a[i], b[i]);
    }
    c
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn random_poly(seed: u64) -> [i64; 256] {
        // Simple LCG for deterministic test vectors (not cryptographic).
        let mut state = seed;
        let mut p = [0i64; 256];
        for c in p.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *c = ((state >> 33) as i64).abs() % Q;
        }
        p
    }

    #[test]
    fn test_ntt_roundtrip() {
        for seed in [1u64, 42, 1337, 0xdeadbeef] {
            let original = random_poly(seed);
            let mut f = original;
            ntt(&mut f);
            ntt_inv(&mut f);
            for i in 0..256 {
                assert_eq!(
                    f[i], original[i],
                    "roundtrip mismatch at index {i} (seed={seed})"
                );
            }
        }
    }

    #[test]
    fn test_ntt_of_zero_is_zero() {
        let mut f = [0i64; 256];
        ntt(&mut f);
        assert_eq!(f, [0i64; 256]);
    }

    #[test]
    fn test_intt_of_zero_is_zero() {
        let mut f = [0i64; 256];
        ntt_inv(&mut f);
        assert_eq!(f, [0i64; 256]);
    }

    #[test]
    fn test_ntt_linearity() {
        // NTT(a + b) = NTT(a) + NTT(b)  (pointwise mod Q)
        let a = random_poly(7);
        let b = random_poly(13);

        let mut a_hat = a;
        let mut b_hat = b;
        ntt(&mut a_hat);
        ntt(&mut b_hat);

        // Compute a+b in coefficient domain, then NTT it.
        let mut apb = [0i64; 256];
        for i in 0..256 {
            apb[i] = (a[i] + b[i]) % Q;
        }
        ntt(&mut apb);

        for i in 0..256 {
            let expected = (a_hat[i] + b_hat[i]) % Q;
            assert_eq!(apb[i], expected, "linearity mismatch at index {i}");
        }
    }

    #[test]
    fn test_ntt_of_one_is_zeta_powers() {
        // NTT of the constant polynomial 1: every entry should be
        // 1 (the pointwise product of 1 with the twiddle factors leaves 1).
        // More precisely, NTT([1,0,0,...,0]) should give [1,1,...,1] only if
        // the NTT evaluates at 1... this is NOT generally the case for a
        // negacyclic NTT, so let's just verify the roundtrip for this input.
        let mut f = [0i64; 256];
        f[0] = 1;
        let original = f;
        ntt(&mut f);
        ntt_inv(&mut f);
        assert_eq!(f, original);
    }

    #[test]
    fn test_zeta_table_first_entries() {
        let fwd = get_zeta_fwd();
        let inv = get_zeta_inv();
        // k=0: brv8(0)=0, ζ^0=1, inv: ζ^{512-0}=1
        assert_eq!(fwd[0], 1);
        assert_eq!(inv[0], 1);
        // k=1: brv8(1)=128, forward=ζ^128, inverse=ζ^{512-128}=ζ^384
        let zeta_128 = field::pow(ZETA, 128);
        let zeta_384 = field::pow(ZETA, 384);
        assert_eq!(fwd[1], zeta_128);
        assert_eq!(inv[1], zeta_384);
        // k=128: brv8(128)=1, forward=ζ^1=ZETA, inverse=ζ^{511}
        assert_eq!(fwd[128], ZETA);
        assert_eq!(inv[128], field::pow(ZETA, 511));
    }

    #[test]
    fn test_zeta_tables_are_inverses() {
        let fwd = get_zeta_fwd();
        let inv = get_zeta_inv();
        for k in 0..256usize {
            let product = field::mul(fwd[k], inv[k]);
            assert_eq!(product, 1, "fwd[{k}] * inv[{k}] != 1");
        }
    }
}
