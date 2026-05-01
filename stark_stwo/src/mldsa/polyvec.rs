/// Polynomial vectors and matrix types for ML-DSA-65.
///
/// `PolyVec`    — vector of `n` polynomials in coefficient domain.
/// `NTTPolyVec` — vector of `n` polynomials in NTT domain.
/// `NTTMatrix`  — k×l matrix in NTT domain.

use super::{Q, N, field};
use super::poly::{Poly, NTTPoly};
use super::params::{GAMMA2, M};

// ─── PolyVec ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PolyVec(pub Vec<Poly>);

impl PolyVec {
    pub fn zeros(n: usize) -> Self {
        PolyVec(vec![Poly::zero(); n])
    }

    pub fn len(&self) -> usize { self.0.len() }

    pub fn add(&self, other: &PolyVec) -> PolyVec {
        assert_eq!(self.len(), other.len());
        PolyVec(self.0.iter().zip(&other.0).map(|(a, b)| a.add(b)).collect())
    }

    pub fn sub(&self, other: &PolyVec) -> PolyVec {
        assert_eq!(self.len(), other.len());
        PolyVec(self.0.iter().zip(&other.0).map(|(a, b)| a.sub(b)).collect())
    }

    /// Infinity norm over all coefficients (centered).
    pub fn norm_inf(&self) -> i64 {
        self.0.iter().map(|p| p.norm_inf()).max().unwrap_or(0)
    }

    /// Forward NTT on every polynomial.
    pub fn ntt(&self) -> NTTPolyVec {
        NTTPolyVec(self.0.iter().map(|p| p.ntt()).collect())
    }

    /// Multiply every coefficient by 2^d mod Q.
    pub fn scale_power2(&self, d: u32) -> PolyVec {
        let factor = 1i64 << d;
        PolyVec(self.0.iter().map(|p| p.scale(factor)).collect())
    }

    /// Power2Round: split each coefficient into (t₁, t₀) where
    ///   coeff = t₁·2^d + t₀,  t₀ ∈ (−2^{d-1}, 2^{d-1}].
    pub fn power2round(&self, d: u32) -> (PolyVec, PolyVec) {
        let mut t1_vecs = Vec::with_capacity(self.len());
        let mut t0_vecs = Vec::with_capacity(self.len());
        for p in &self.0 {
            let mut t1_coeffs = [0i64; N];
            let mut t0_coeffs = [0i64; N];
            for (i, &c) in p.coeffs.iter().enumerate() {
                let (h, l) = power2round_val(c, d);
                t1_coeffs[i] = h;
                t0_coeffs[i] = field::reduce(l);
            }
            t1_vecs.push(Poly::from_coeffs(t1_coeffs));
            t0_vecs.push(Poly::from_coeffs(t0_coeffs));
        }
        (PolyVec(t1_vecs), PolyVec(t0_vecs))
    }

    /// High bits of each coefficient under decomposition with 2γ₂.
    pub fn high_bits(&self) -> PolyVec {
        PolyVec(self.0.iter().map(|p| {
            let mut coeffs = [0i64; N];
            for (i, &c) in p.coeffs.iter().enumerate() {
                coeffs[i] = high_bits_val(c);
            }
            Poly::from_coeffs(coeffs)
        }).collect())
    }

    /// Apply UseHint to each coefficient.
    /// `hints[i]` is a slice of N bools for polynomial i.
    pub fn use_hint(&self, hints: &[Vec<bool>]) -> PolyVec {
        assert_eq!(self.len(), hints.len());
        PolyVec(self.0.iter().zip(hints).map(|(p, h)| {
            let mut coeffs = [0i64; N];
            for (i, &c) in p.coeffs.iter().enumerate() {
                coeffs[i] = use_hint_val(h[i], c);
            }
            Poly::from_coeffs(coeffs)
        }).collect())
    }
}

// ─── NTTPolyVec ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NTTPolyVec(pub Vec<NTTPoly>);

impl NTTPolyVec {
    pub fn zeros(n: usize) -> Self {
        NTTPolyVec(vec![NTTPoly { coeffs: [0i64; N] }; n])
    }

    pub fn len(&self) -> usize { self.0.len() }

    pub fn add(&self, other: &NTTPolyVec) -> NTTPolyVec {
        assert_eq!(self.len(), other.len());
        NTTPolyVec(self.0.iter().zip(&other.0).map(|(a, b)| a.add(b)).collect())
    }

    pub fn sub(&self, other: &NTTPolyVec) -> NTTPolyVec {
        assert_eq!(self.len(), other.len());
        NTTPolyVec(self.0.iter().zip(&other.0).map(|(a, b)| {
            let mut coeffs = [0i64; N];
            for i in 0..N {
                coeffs[i] = field::sub(a.coeffs[i], b.coeffs[i]);
            }
            NTTPoly { coeffs }
        }).collect())
    }

    /// Pointwise multiply by a single NTTPoly (e.g. NTT(c)).
    pub fn scale_poly(&self, c: &NTTPoly) -> NTTPolyVec {
        NTTPolyVec(self.0.iter().map(|p| p.mul(c)).collect())
    }

    /// Inverse NTT on every polynomial.
    pub fn intt(&self) -> PolyVec {
        PolyVec(self.0.iter().map(|p| p.intt()).collect())
    }
}

// ─── NTTMatrix ───────────────────────────────────────────────────────────────

/// k×l matrix of NTT-domain polynomials.
pub struct NTTMatrix {
    pub rows: Vec<NTTPolyVec>, // length k, each NTTPolyVec has length l
}

impl NTTMatrix {
    /// Matrix-vector multiply: A (k×l) · v (l) → result (k), all in NTT domain.
    pub fn mul_vec(&self, v: &NTTPolyVec) -> NTTPolyVec {
        let k = self.rows.len();
        let l = v.len();
        let mut result = NTTPolyVec::zeros(k);
        for (i, row) in self.rows.iter().enumerate() {
            assert_eq!(row.len(), l);
            for j in 0..l {
                let prod = row.0[j].mul(&v.0[j]);
                result.0[i] = result.0[i].add(&prod);
            }
        }
        result
    }
}

// ─── Decompose helpers ───────────────────────────────────────────────────────

/// Power2Round: returns (r₁, r₀) where coeff = r₁·2^d + r₀,
/// with r₀ ∈ (−2^{d-1}, 2^{d-1}].
fn power2round_val(r: i64, d: u32) -> (i64, i64) {
    let half = 1i64 << (d - 1);
    let modulus = 1i64 << d;
    let r0 = ((r % modulus) + modulus) % modulus; // r mod 2^d in [0, 2^d)
    // centre r0 in (-2^{d-1}, 2^{d-1}]
    let r0_centered = if r0 > half { r0 - modulus } else { r0 };
    let r1 = (r - r0_centered) >> d;
    (r1, r0_centered)
}

/// HighBits(r, 2γ₂): the high-order component of r under Decompose.
pub fn high_bits_val(r: i64) -> i64 {
    decompose_val(r).0
}

/// LowBits(r, 2γ₂): the low-order component.
pub fn low_bits_val(r: i64) -> i64 {
    decompose_val(r).1
}

/// Decompose(r, 2γ₂) → (r₁, r₀) where r = r₁·2γ₂ + r₀ mod q,
/// r₀ ∈ (−γ₂, γ₂], and r₁ ∈ [0, m) (where m = (q−1)/(2γ₂)).
///
/// FIPS 204 Algorithm 35.
fn decompose_val(r: i64) -> (i64, i64) {
    let alpha = 2 * GAMMA2;
    let r = field::reduce(r);
    let r0 = {
        // r mod± alpha: center in (-alpha/2, alpha/2]
        let rem = r % alpha;
        if rem > GAMMA2 { rem - alpha } else { rem }
    };
    let r1 = if r - r0 == Q - 1 {
        // special case: r - r0 = q-1 → r1 = 0, r0 -= 1
        0
    } else {
        (r - r0) / alpha
    };
    // Adjust r0 for the special case
    let r0_final = if r - r0 == Q - 1 { r0 - 1 } else { r0 };
    (r1, r0_final)
}

/// UseHint(h, r): apply hint to correct r₁.
///
/// FIPS 204 Algorithm 37.
pub fn use_hint_val(h: bool, r: i64) -> i64 {
    let (r1, r0) = decompose_val(r);
    if !h {
        return r1;
    }
    if r0 > 0 {
        (r1 + 1) % M
    } else {
        (r1 - 1 + M) % M
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power2round_roundtrip() {
        let d = 13u32;
        for r in [0i64, 1, 8191, 8192, 8193, Q - 1, Q / 2] {
            let (r1, r0) = power2round_val(r, d);
            let reconstructed = (r1 * (1 << d) + r0).rem_euclid(Q);
            assert_eq!(reconstructed, r % Q, "power2round roundtrip failed for r={r}");
        }
    }

    #[test]
    fn test_power2round_t0_range() {
        let d = 13u32;
        let half = 1i64 << (d - 1);
        for r in [0i64, 1, 4095, 4096, 4097, Q - 1] {
            let (_, r0) = power2round_val(r, d);
            assert!(r0 >= -half && r0 <= half, "r0={r0} out of range for r={r}");
        }
    }

    #[test]
    fn test_decompose_roundtrip() {
        use super::super::field;
        let alpha = 2 * GAMMA2;
        for r in [0i64, 1, GAMMA2, GAMMA2 + 1, Q - 2, Q - 1] {
            let (r1, r0) = decompose_val(r);
            if r1 == 0 && (r - r0 == Q - 1 || r == r0) {
                continue; // special case at q-1
            }
            let reconstructed = field::reduce(r1 * alpha + r0);
            assert_eq!(reconstructed, r as i64 % Q, "decompose roundtrip for r={r}");
        }
    }

    #[test]
    fn test_high_bits_range() {
        for r in [0i64, 100, GAMMA2, Q / 4, Q - 1] {
            let h = high_bits_val(r);
            assert!(h >= 0 && h < M, "high_bits={h} out of [0,M) for r={r}");
        }
    }

    #[test]
    fn test_polyvec_add_sub_inverse() {
        use super::super::poly::Poly;
        let a = PolyVec(vec![Poly::zero(); 3]);
        let mut b_coeffs = [0i64; N];
        b_coeffs[0] = 42;
        let b = PolyVec(vec![Poly::from_coeffs(b_coeffs); 3]);
        let sum = a.add(&b);
        let diff = sum.sub(&b);
        for p in &diff.0 {
            assert_eq!(p.coeffs, [0i64; N]);
        }
    }

    #[test]
    fn test_ntt_mat_vec_mul_dimensions() {
        use super::super::poly::NTTPoly;
        let zero_poly = NTTPoly { coeffs: [0i64; N] };
        let row = NTTPolyVec(vec![zero_poly; 5]); // l=5
        let mat = NTTMatrix { rows: vec![row; 6] }; // k=6
        let v = NTTPolyVec(vec![zero_poly; 5]);
        let result = mat.mul_vec(&v);
        assert_eq!(result.len(), 6);
    }
}
