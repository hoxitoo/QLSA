/// ML-DSA (FIPS 204) mathematical primitives and verification.
///
/// Components:
///   params   — ML-DSA-65 parameter constants (k, l, η, γ₁, γ₂, …)
///   field    — Z_q arithmetic (q = 8 380 417)
///   ntt      — NTT / INTT per FIPS 204 Algorithms 41 & 42
///   poly     — Poly and NTTPoly types; polynomial multiplication via NTT
///   polyvec  — PolyVec / NTTPolyVec / NTTMatrix; Decompose / UseHint helpers
///   encoding — bit-packing: pkDecode, sigDecode, w1Encode (Algorithms 16–22)
///   xof      — SHAKE-128/256: ExpandA, SampleInBall, hash helpers
///   verify   — ML-DSA.Verify (FIPS 204 Algorithm 3)
pub mod params;
pub mod field;
pub mod ntt;
pub mod poly;
pub mod polyvec;
pub mod encoding;
pub mod xof;
pub mod verify;

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
