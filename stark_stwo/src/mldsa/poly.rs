/// Polynomial types for Z_q[X] / (X^256 + 1).
///
/// Two representations are used:
///   `Poly`    — coefficient domain, as used in ML-DSA public/private keys.
///   `NTTPoly` — NTT domain (T_q), as used for efficient multiplication.
///
/// Multiplication via NTT: poly_mul(a, b) = INTT(NTT(a) ⊙ NTT(b)).

use super::{N, field};
use super::ntt::{ntt, ntt_inv, pointwise_mul};

// ─── Poly ────────────────────────────────────────────────────────────────────

/// Polynomial in R_q = Z_q[X] / (X^256 + 1).
/// Coefficients are in [0, Q).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [i64; N],
}

impl Poly {
    pub fn zero() -> Self {
        Poly { coeffs: [0i64; N] }
    }

    pub fn from_coeffs(coeffs: [i64; N]) -> Self {
        Poly { coeffs }
    }

    /// Reduce all coefficients to [0, Q).
    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = field::reduce(*c);
        }
    }

    /// Addition in R_q: coefficient-wise mod Q.
    pub fn add(&self, other: &Poly) -> Poly {
        let mut coeffs = [0i64; N];
        for i in 0..N {
            coeffs[i] = field::add(self.coeffs[i], other.coeffs[i]);
        }
        Poly { coeffs }
    }

    /// Subtraction in R_q: coefficient-wise mod Q.
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut coeffs = [0i64; N];
        for i in 0..N {
            coeffs[i] = field::sub(self.coeffs[i], other.coeffs[i]);
        }
        Poly { coeffs }
    }

    /// Scalar multiplication: multiply every coefficient by `s`.
    pub fn scale(&self, s: i64) -> Poly {
        let s = field::reduce(s);
        let mut coeffs = [0i64; N];
        for i in 0..N {
            coeffs[i] = field::mul(self.coeffs[i], s);
        }
        Poly { coeffs }
    }

    /// Infinity norm: max |coeff_centered| where centered means in (−Q/2, Q/2].
    pub fn norm_inf(&self) -> i64 {
        self.coeffs
            .iter()
            .map(|&c| field::reduce_centered(c).abs())
            .max()
            .unwrap_or(0)
    }

    /// Forward NTT — returns the NTT-domain representation.
    pub fn ntt(&self) -> NTTPoly {
        let mut coeffs = self.coeffs;
        ntt(&mut coeffs);
        NTTPoly { coeffs }
    }

    /// Schoolbook multiplication in R_q (for testing — O(n²)).
    pub fn mul_naive(&self, other: &Poly) -> Poly {
        let a = &self.coeffs;
        let b = &other.coeffs;
        let mut tmp = [0i64; 2 * N];
        for i in 0..N {
            for j in 0..N {
                tmp[i + j] += a[i] * b[j];
            }
        }
        // Reduce modulo X^256 + 1: tmp[256+i] wraps with sign flip.
        let mut coeffs = [0i64; N];
        for i in 0..N {
            coeffs[i] = field::reduce(tmp[i] - tmp[i + N]);
        }
        Poly { coeffs }
    }
}

// ─── NTTPoly ─────────────────────────────────────────────────────────────────

/// Polynomial in the NTT domain T_q.
/// Each entry is an independent element of Z_q.
#[derive(Clone, Copy, Debug)]
pub struct NTTPoly {
    pub coeffs: [i64; N],
}

impl NTTPoly {
    /// Pointwise multiplication (corresponds to polynomial multiplication in R_q).
    pub fn mul(&self, other: &NTTPoly) -> NTTPoly {
        NTTPoly {
            coeffs: pointwise_mul(&self.coeffs, &other.coeffs),
        }
    }

    /// Pointwise addition.
    pub fn add(&self, other: &NTTPoly) -> NTTPoly {
        let mut coeffs = [0i64; N];
        for i in 0..N {
            coeffs[i] = field::add(self.coeffs[i], other.coeffs[i]);
        }
        NTTPoly { coeffs }
    }

    /// Inverse NTT — returns the coefficient-domain representation.
    pub fn intt(&self) -> Poly {
        let mut coeffs = self.coeffs;
        ntt_inv(&mut coeffs);
        Poly { coeffs }
    }
}

// ─── Public helpers ───────────────────────────────────────────────────────────

/// Multiply two polynomials in R_q via NTT.
///
/// Complexity: O(n log n) vs O(n²) for schoolbook.
pub fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    a.ntt().mul(&b.ntt()).intt()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::Q;

    fn rng(seed: u64) -> impl FnMut() -> i64 {
        let mut state = seed;
        move || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((state >> 33) as i64).abs() % Q
        }
    }

    fn random_poly(seed: u64) -> Poly {
        let mut gen = rng(seed);
        let mut coeffs = [0i64; N];
        for c in coeffs.iter_mut() { *c = gen(); }
        Poly { coeffs }
    }

    #[test]
    fn test_poly_mul_matches_naive() {
        // NTT-based multiplication must agree with schoolbook for small inputs.
        for seed in [1u64, 7, 31, 100, 999] {
            let a = random_poly(seed);
            let b = random_poly(seed + 1);
            let fast = poly_mul(&a, &b);
            let naive = a.mul_naive(&b);
            assert_eq!(
                fast.coeffs, naive.coeffs,
                "NTT mul != naive for seed={seed}"
            );
        }
    }

    #[test]
    fn test_poly_mul_commutativity() {
        let a = random_poly(42);
        let b = random_poly(43);
        assert_eq!(poly_mul(&a, &b), poly_mul(&b, &a));
    }

    #[test]
    fn test_poly_mul_with_zero() {
        let a = random_poly(5);
        let zero = Poly::zero();
        assert_eq!(poly_mul(&a, &zero), zero);
    }

    #[test]
    fn test_poly_mul_with_one() {
        // Polynomial "1" is [1, 0, 0, ..., 0]
        let a = random_poly(6);
        let mut one_coeffs = [0i64; N];
        one_coeffs[0] = 1;
        let one = Poly::from_coeffs(one_coeffs);
        assert_eq!(poly_mul(&a, &one), a);
    }

    #[test]
    fn test_poly_add_commutativity() {
        let a = random_poly(10);
        let b = random_poly(11);
        assert_eq!(a.add(&b), b.add(&a));
    }

    #[test]
    fn test_poly_mul_associativity() {
        let a = random_poly(20);
        let b = random_poly(21);
        let c = random_poly(22);
        let ab_c = poly_mul(&poly_mul(&a, &b), &c);
        let a_bc = poly_mul(&a, &poly_mul(&b, &c));
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn test_poly_mul_distributivity() {
        // a * (b + c) == a*b + a*c
        let a = random_poly(30);
        let b = random_poly(31);
        let c = random_poly(32);
        let lhs = poly_mul(&a, &b.add(&c));
        let rhs = poly_mul(&a, &b).add(&poly_mul(&a, &c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_scale() {
        let a = random_poly(99);
        // scale(2) == a + a
        let doubled = a.scale(2);
        let sum = a.add(&a);
        assert_eq!(doubled, sum);
    }

    #[test]
    fn test_norm_inf_zero() {
        assert_eq!(Poly::zero().norm_inf(), 0);
    }

    #[test]
    fn test_norm_inf_constant() {
        let mut coeffs = [0i64; N];
        coeffs[0] = 100;
        let p = Poly::from_coeffs(coeffs);
        assert_eq!(p.norm_inf(), 100);
    }

    #[test]
    fn test_x_squared_plus_one_in_ring() {
        // X^256 ≡ −1 (mod X^256+1), so X^256 + 1 ≡ 0.
        // As coefficient vectors: let a = X^128.
        // a * a = X^256 ≡ -1 ≡ Q-1 at index 0.
        let mut x128 = [0i64; N];
        x128[128] = 1;
        let a = Poly::from_coeffs(x128);
        let a2 = poly_mul(&a, &a);
        // a² = X^256 ≡ −1 in R_q, i.e., coefficient 0 = Q-1, rest = 0
        let mut expected = [0i64; N];
        expected[0] = Q - 1;
        assert_eq!(a2.coeffs, expected, "X^256 ≢ −1 in the ring");
    }
}
