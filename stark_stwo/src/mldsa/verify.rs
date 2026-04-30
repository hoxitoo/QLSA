/// ML-DSA-65 signature verification (FIPS 204 Algorithm 3).
///
/// `ml_dsa_verify(pk, msg, sig) → bool`
///
/// This is a pure-Rust reference implementation intended as the witness
/// for the STARK AIR circuit (MVP-3). It does NOT use liboqs.

use super::params::{BETA, GAMMA1, LAMBDA_BYTES, PK_BYTES, SIG_BYTES};
use super::encoding::{pk_decode, sig_decode, w1_encode};
use super::polyvec::PolyVec;
use super::xof::{expand_a, sample_in_ball, hash_pk, hash_mu, hash_commit};

/// Verify an ML-DSA-65 signature.
///
/// Returns `true` iff the signature is valid for `msg` under `pk`.
pub fn ml_dsa_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    // ── Step 1: Basic length checks ──────────────────────────────────────────
    if pk.len() != PK_BYTES || sig.len() != SIG_BYTES {
        return false;
    }

    // ── Step 2: Decode public key and signature ───────────────────────────────
    let (rho, t1) = match pk_decode(pk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let (c_tilde, z, hints) = match sig_decode(sig) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // ── Step 3: ‖z‖∞ < γ₁ − β (FIPS 204 step 4) ─────────────────────────────
    // z coefficients from bit_unpack are in (−γ₁, γ₁]; centered norm is max |c|.
    let z_norm = z.0.iter()
        .flat_map(|p| p.coeffs.iter())
        .map(|&c| {
            // coefficients in (−γ₁, γ₁] stored as positive via Q complement for −1
            // but bit_unpack returns them signed directly (not reduced mod Q)
            c.abs()
        })
        .max()
        .unwrap_or(0);
    if z_norm >= GAMMA1 - BETA {
        return false;
    }

    // ── Step 4: Recompute w₁' ────────────────────────────────────────────────
    // A_hat = ExpandA(ρ) (in NTT domain)
    let a_hat = expand_a(&rho);

    // c = SampleInBall(c̃); ĉ = NTT(c)
    let c = sample_in_ball(&c_tilde);
    let c_hat = c.ntt();

    // NTT(z): z coefficients must be reduced to [0, Q) first
    let z_reduced = PolyVec(z.0.iter().map(|p| {
        use super::{N, field};
        let mut coeffs = [0i64; N];
        for (i, &x) in p.coeffs.iter().enumerate() {
            coeffs[i] = field::reduce(x);
        }
        super::poly::Poly::from_coeffs(coeffs)
    }).collect());
    let z_hat = z_reduced.ntt();

    // NTT(t₁·2^d): scale t₁ by 2^d then NTT
    let t1_scaled = t1.scale_power2(super::params::D);
    let t1_scaled_hat = t1_scaled.ntt();

    // A·NTT(z) − ĉ⊙NTT(t₁·2^d) = approximation of A·y in the verification eq
    let az_hat = a_hat.mul_vec(&z_hat);
    let ct1_hat = t1_scaled_hat.scale_poly(&c_hat);
    let w_hat = az_hat.sub(&ct1_hat);

    // w = INTT(...)
    let w = w_hat.intt();

    // ── Step 5: UseHint(h, w) → w₁' ─────────────────────────────────────────
    let w1_prime = w.use_hint(&hints);

    // ── Step 6: Recompute μ and c̃' ───────────────────────────────────────────
    let tr = hash_pk(pk);
    // FIPS 204 §3.3 external API: M' = 0x00 ∥ IntToBytes(|ctx|,1) ∥ ctx ∥ M
    // With empty context: M' = [0x00, 0x00] ∥ msg.
    let mut m_prime = vec![0u8, 0u8];
    m_prime.extend_from_slice(msg);
    let mu = hash_mu(&tr, &m_prime);
    let w1_enc = w1_encode(&w1_prime);
    let c_tilde_prime = hash_commit(&mu, &w1_enc, LAMBDA_BYTES);

    // ── Step 7: Compare c̃ = c̃' ──────────────────────────────────────────────
    c_tilde == c_tilde_prime
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_wrong_pk_length() {
        assert!(!ml_dsa_verify(&[0u8; 10], b"msg", &[0u8; SIG_BYTES]));
    }

    #[test]
    fn test_verify_wrong_sig_length() {
        assert!(!ml_dsa_verify(&[0u8; PK_BYTES], b"msg", &[0u8; 10]));
    }

    #[test]
    fn test_verify_all_zeros_is_invalid() {
        // Zero pk/sig will fail the norm check or hash mismatch.
        let pk = vec![0u8; PK_BYTES];
        let sig = vec![0u8; SIG_BYTES];
        assert!(!ml_dsa_verify(&pk, b"hello", &sig));
    }

    #[test]
    fn test_verify_random_sig_is_invalid() {
        // Random bytes should virtually never form a valid signature.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        42u64.hash(&mut h);
        let seed = h.finish();

        // Build deterministic fake pk/sig from seed
        let mut state = seed;
        let lcg = |s: &mut u64| -> u8 {
            *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (*s >> 33) as u8
        };
        let pk: Vec<u8> = (0..PK_BYTES).map(|_| lcg(&mut state)).collect();
        let sig: Vec<u8> = (0..SIG_BYTES).map(|_| lcg(&mut state)).collect();

        // Almost certainly invalid; the only way this could accidentally pass
        // is a hash collision probability of ~2^{-192}.
        assert!(!ml_dsa_verify(&pk, b"test", &sig));
    }
}
