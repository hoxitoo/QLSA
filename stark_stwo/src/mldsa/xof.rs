/// XOF (eXtendable Output Function) operations for ML-DSA-65.
///
/// Wraps SHA3 (SHAKE-128 / SHAKE-256) for:
///   ExpandA        — sample matrix A from seed ρ (SHAKE-128, Algorithm 26)
///   SampleInBall   — sample challenge c from c̃  (SHAKE-256, Algorithm 1)
///   H              — SHAKE-256 hash (tr, μ computation)

use sha3::{Shake128, Shake256, digest::{ExtendableOutput, XofReader, Update}};

use super::{Q, N};
use super::poly::{Poly, NTTPoly};
use super::polyvec::{NTTPolyVec, NTTMatrix};
use super::params::{K, L, TAU};

// ─── ExpandA (FIPS 204 Algorithm 26) ─────────────────────────────────────────

/// Expand the public matrix A from seed ρ.
///
/// A[i][j] = RejNTTPoly(ρ ∥ j ∥ i) for i∈[0,k), j∈[0,l).
/// The result is already in NTT domain (each polynomial is uniform mod q).
pub fn expand_a(rho: &[u8; 32]) -> NTTMatrix {
    let rows: Vec<NTTPolyVec> = (0..K).map(|i| {
        let cols: Vec<NTTPoly> = (0..L).map(|j| {
            let seed = [rho.as_slice(), &[j as u8], &[i as u8]].concat();
            let coeffs = rej_ntt_poly(&seed);
            NTTPoly { coeffs }
        }).collect();
        NTTPolyVec(cols)
    }).collect();
    NTTMatrix { rows }
}

/// Rejection-sample a uniformly random NTT polynomial from SHAKE-128(seed).
///
/// FIPS 204 Algorithm 24 (RejNTTPoly): read 3 bytes at a time, form
///   z = b₀ + 256·b₁ + 65536·(b₂ & 0x7F)
/// and accept if z < q.
fn rej_ntt_poly(seed: &[u8]) -> [i64; N] {
    let mut hasher = Shake128::default();
    hasher.update(seed);
    let mut xof = hasher.finalize_xof();

    let mut coeffs = [0i64; N];
    let mut j = 0usize;
    let mut buf = [0u8; 3];
    while j < N {
        xof.read(&mut buf);
        let z = (buf[0] as i64) | ((buf[1] as i64) << 8) | (((buf[2] & 0x7F) as i64) << 16);
        if z < Q {
            coeffs[j] = z;
            j += 1;
        }
    }
    coeffs
}

// ─── SampleInBall (FIPS 204 Algorithm 1) ─────────────────────────────────────

/// Sample the challenge polynomial c from c̃.
///
/// Output: polynomial c ∈ {−1, 0, 1}^N with exactly τ non-zero coefficients.
pub fn sample_in_ball(c_tilde: &[u8]) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(c_tilde);
    let mut xof = hasher.finalize_xof();

    // Read 8 bytes for the signs bitmask.
    let mut sign_bytes = [0u8; 8];
    xof.read(&mut sign_bytes);
    let mut signs: u64 = u64::from_le_bytes(sign_bytes);

    let mut c = [0i64; N];
    // Place TAU ±1s via rejection sampling, scanning i = N-τ .. N-1.
    for i in (N - TAU)..N {
        // Sample j ∈ [0, i] with rejection.
        let j = loop {
            let mut b = [0u8; 1];
            xof.read(&mut b);
            let b = b[0] as usize;
            if b <= i { break b; }
        };
        c[i] = c[j];
        c[j] = 1 - 2 * (signs & 1) as i64;
        signs >>= 1;
    }
    // Reduce to [0, Q): coefficients are −1, 0, 1 — reduce −1 to Q−1.
    for x in c.iter_mut() {
        if *x < 0 { *x += Q; }
    }
    Poly::from_coeffs(c)
}

// ─── SHAKE-256 hash helpers ──────────────────────────────────────────────────

/// Compute tr = SHAKE-256(pk, 512 bits) = 64 bytes.
pub fn hash_pk(pk: &[u8]) -> [u8; 64] {
    shake256(pk, 64).try_into().unwrap()
}

/// Compute μ = SHAKE-256(tr ∥ msg, 512 bits) = 64 bytes.
pub fn hash_mu(tr: &[u8; 64], msg: &[u8]) -> [u8; 64] {
    let mut input = tr.to_vec();
    input.extend_from_slice(msg);
    shake256(&input, 64).try_into().unwrap()
}

/// Compute c̃' = SHAKE-256(μ ∥ w₁Enc, λ/4 bytes).
pub fn hash_commit(mu: &[u8; 64], w1_enc: &[u8], out_len: usize) -> Vec<u8> {
    let mut input = mu.to_vec();
    input.extend_from_slice(w1_enc);
    shake256(&input, out_len)
}

fn shake256(input: &[u8], out_bytes: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut xof = hasher.finalize_xof();
    let mut out = vec![0u8; out_bytes];
    xof.read(&mut out);
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_a_dimensions() {
        let rho = [0u8; 32];
        let a = expand_a(&rho);
        assert_eq!(a.rows.len(), K);
        for row in &a.rows {
            assert_eq!(row.len(), L);
        }
    }

    #[test]
    fn test_expand_a_coefficients_in_range() {
        let rho = [42u8; 32];
        let a = expand_a(&rho);
        for row in &a.rows {
            for p in &row.0 {
                for &c in &p.coeffs {
                    assert!(c >= 0 && c < Q, "coeff {c} out of [0, Q)");
                }
            }
        }
    }

    #[test]
    fn test_expand_a_deterministic() {
        let rho = [1u8; 32];
        let a1 = expand_a(&rho);
        let a2 = expand_a(&rho);
        for (r1, r2) in a1.rows.iter().zip(&a2.rows) {
            for (p1, p2) in r1.0.iter().zip(&r2.0) {
                assert_eq!(p1.coeffs, p2.coeffs);
            }
        }
    }

    #[test]
    fn test_expand_a_different_rho_different_matrix() {
        let a1 = expand_a(&[0u8; 32]);
        let a2 = expand_a(&[1u8; 32]);
        // At least one coefficient should differ
        let any_diff = a1.rows.iter().zip(&a2.rows).any(|(r1, r2)| {
            r1.0.iter().zip(&r2.0).any(|(p1, p2)| p1.coeffs != p2.coeffs)
        });
        assert!(any_diff);
    }

    #[test]
    fn test_sample_in_ball_exactly_tau_nonzero() {
        for seed in [&[0u8; 48][..], &[1u8; 48], &[42u8; 48]] {
            let c = sample_in_ball(seed);
            let nonzero: usize = c.coeffs.iter().filter(|&&x| x != 0).count();
            assert_eq!(nonzero, TAU, "SampleInBall: expected {TAU} non-zero, got {nonzero}");
        }
    }

    #[test]
    fn test_sample_in_ball_values_are_plus_minus_one() {
        let c = sample_in_ball(&[7u8; 48]);
        for &x in &c.coeffs {
            assert!(x == 0 || x == 1 || x == Q - 1,
                "coefficient {x} is not 0, 1, or Q-1");
        }
    }

    #[test]
    fn test_sample_in_ball_deterministic() {
        let c1 = sample_in_ball(&[5u8; 48]);
        let c2 = sample_in_ball(&[5u8; 48]);
        assert_eq!(c1.coeffs, c2.coeffs);
    }

    #[test]
    fn test_hash_pk_length() {
        let pk = vec![0u8; 100];
        let tr = hash_pk(&pk);
        assert_eq!(tr.len(), 64);
    }

    #[test]
    fn test_hash_mu_deterministic() {
        let tr = [3u8; 64];
        let msg = b"test message";
        let mu1 = hash_mu(&tr, msg);
        let mu2 = hash_mu(&tr, msg);
        assert_eq!(mu1, mu2);
    }

    #[test]
    fn test_hash_commit_length() {
        use super::super::params::LAMBDA_BYTES;
        let mu = [0u8; 64];
        let w1 = vec![0u8; 768]; // K * 128
        let out = hash_commit(&mu, &w1, LAMBDA_BYTES);
        assert_eq!(out.len(), LAMBDA_BYTES);
    }
}
