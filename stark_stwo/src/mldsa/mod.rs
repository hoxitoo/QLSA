/// ML-DSA (FIPS 204) mathematical primitives.
///
/// This module implements the arithmetic foundation required for ML-DSA
/// signature verification inside a STARK circuit (MVP-3 target).
///
/// Components:
///   field  — Z_q arithmetic (q = 8 380 417)
///   ntt    — NTT / INTT per FIPS 204 Algorithms 41 & 42
///   poly   — Poly and NTTPoly types; polynomial multiplication via NTT
///
/// All values are in the range [0, Q) unless otherwise noted.
pub mod field;
pub mod ntt;
pub mod poly;

/// ML-DSA modulus: q = 2^23 − 2^13 + 1 (prime)
pub const Q: i64 = 8_380_417;

/// Ring dimension: polynomials live in Z_q[X] / (X^256 + 1)
pub const N: usize = 256;

/// Primitive 512th root of unity in Z_q.
/// ζ^512 ≡ 1 (mod Q) and ζ^256 ≡ −1 (mod Q).
/// Source: FIPS 204 §4.1.
pub const ZETA: i64 = 1753;

/// N^{-1} mod Q: 256^{-1} mod 8 380 417 = 8 347 681.
/// Derived via extended Euclidean: 8 380 417 = 32 736 × 256 + 1.
pub const N_INV: i64 = 8_347_681;
