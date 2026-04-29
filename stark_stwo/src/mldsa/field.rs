/// Z_q field arithmetic for q = 8 380 417.
///
/// All public functions expect inputs in [0, Q) and return values in [0, Q).
/// Internal intermediates may temporarily exceed this range; each function
/// restores the invariant before returning.

use super::Q;

/// Reduce `a` (possibly negative or > Q) to [0, Q).
#[inline]
pub fn reduce(a: i64) -> i64 {
    let r = a % Q;
    if r < 0 { r + Q } else { r }
}

/// Reduce to the centered representation (−Q/2, Q/2].
#[inline]
pub fn reduce_centered(a: i64) -> i64 {
    let r = reduce(a);
    if r > Q / 2 { r - Q } else { r }
}

#[inline]
pub fn add(a: i64, b: i64) -> i64 {
    debug_assert!(a >= 0 && a < Q, "add: a={a} out of range");
    debug_assert!(b >= 0 && b < Q, "add: b={b} out of range");
    let r = a + b;
    if r >= Q { r - Q } else { r }
}

#[inline]
pub fn sub(a: i64, b: i64) -> i64 {
    debug_assert!(a >= 0 && a < Q, "sub: a={a} out of range");
    debug_assert!(b >= 0 && b < Q, "sub: b={b} out of range");
    let r = a - b;
    if r < 0 { r + Q } else { r }
}

#[inline]
pub fn mul(a: i64, b: i64) -> i64 {
    debug_assert!(a >= 0 && a < Q, "mul: a={a} out of range");
    debug_assert!(b >= 0 && b < Q, "mul: b={b} out of range");
    (a * b) % Q
}

/// Square-and-multiply exponentiation: base^exp mod Q.
pub fn pow(mut base: i64, mut exp: u64) -> i64 {
    let mut result = 1i64;
    base = reduce(base);
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % Q;
        }
        base = (base * base) % Q;
        exp >>= 1;
    }
    result
}

/// Modular inverse via Fermat's little theorem: a^{Q−2} mod Q.
/// Panics if a ≡ 0 (mod Q).
pub fn inv(a: i64) -> i64 {
    let a = reduce(a);
    assert!(a != 0, "inv(0) is undefined");
    pow(a, (Q - 2) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reduce_positive() {
        assert_eq!(reduce(0), 0);
        assert_eq!(reduce(Q - 1), Q - 1);
        assert_eq!(reduce(Q), 0);
        assert_eq!(reduce(Q + 1), 1);
        assert_eq!(reduce(2 * Q + 3), 3);
    }

    #[test]
    fn test_reduce_negative() {
        assert_eq!(reduce(-1), Q - 1);
        assert_eq!(reduce(-Q), 0);
        assert_eq!(reduce(-(Q + 1)), Q - 1);
    }

    #[test]
    fn test_add_wraps() {
        assert_eq!(add(Q - 1, 1), 0);
        assert_eq!(add(Q - 1, 0), Q - 1);
        assert_eq!(add(0, 0), 0);
    }

    #[test]
    fn test_sub_wraps() {
        assert_eq!(sub(0, 1), Q - 1);
        assert_eq!(sub(5, 3), 2);
        assert_eq!(sub(Q - 1, Q - 1), 0);
    }

    #[test]
    fn test_mul_basic() {
        assert_eq!(mul(0, 12345), 0);
        assert_eq!(mul(1, 12345), 12345);
        assert_eq!(mul(2, (Q + 1) / 2), 1); // 2 * ((Q+1)/2) ≡ 1 (mod Q) only if Q is odd — it is
        // 2 * 4190209 = 8380418 = Q + 1 ≡ 1 (mod Q) ✓
        assert_eq!(mul(2, 4190209), 1);
    }

    #[test]
    fn test_pow() {
        assert_eq!(pow(1, 1000), 1);
        assert_eq!(pow(0, 5), 0);
        assert_eq!(pow(2, 10), 1024);
        // Fermat: a^(Q-1) ≡ 1 (mod Q)
        assert_eq!(pow(1753, (Q - 1) as u64), 1);
    }

    #[test]
    fn test_zeta_is_512th_root() {
        use super::super::ZETA;
        // ζ^512 ≡ 1 (mod Q)
        assert_eq!(pow(ZETA, 512), 1);
        // ζ^256 ≡ Q−1 ≡ −1 (mod Q) — makes Z_q[X]/(X^256+1) the right ring
        assert_eq!(pow(ZETA, 256), Q - 1);
    }

    #[test]
    fn test_n_inv() {
        use super::super::N_INV;
        // 256 * N_INV ≡ 1 (mod Q)
        assert_eq!(mul(256, N_INV), 1);
    }

    #[test]
    fn test_inv() {
        for a in [1i64, 2, 100, 1753, Q - 1] {
            assert_eq!(mul(a, inv(a)), 1, "inv failed for a={a}");
        }
    }
}
