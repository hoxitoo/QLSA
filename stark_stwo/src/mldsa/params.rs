/// ML-DSA-65 parameter set (FIPS 204, Table 1).

/// Rows in matrix A (output vector length).
pub const K: usize = 6;
/// Columns in matrix A (input vector length).
pub const L: usize = 5;
/// Secret key norm bound η.
pub const ETA: i64 = 4;
/// Number of ±1 coefficients in the challenge polynomial.
pub const TAU: usize = 49;
/// Norm bound for z: β = τ·η.
pub const BETA: i64 = 196;
/// Masking range: γ₁ = 2^19.
pub const GAMMA1: i64 = 1 << 19;
/// Decomposition rounding modulus: γ₂ = (q−1)/32.
pub const GAMMA2: i64 = (crate::mldsa::Q - 1) / 32; // 261 888
/// Low-order rounding bits dropped from t.
pub const D: u32 = 13;
/// Security parameter in bits (determines challenge seed length).
pub const LAMBDA: usize = 192;
/// Byte length of the challenge seed c̃ = λ/4.
pub const LAMBDA_BYTES: usize = LAMBDA / 4; // 48
/// Maximum number of hint ones across all k polynomials.
pub const OMEGA: usize = 55;

/// High-order ring modulus m = (q−1)/(2·γ₂) = 16.
pub const M: i64 = (crate::mldsa::Q - 1) / (2 * GAMMA2); // 16

/// Bits needed to encode one t₁ coefficient (2^d = 8192, q/2^d < 2^10).
pub const T1_BITS: u32 = 10;
/// Bits needed to encode one z coefficient (2·γ₁ = 2^20).
pub const Z_BITS: u32 = 20;
/// Bits needed to encode one w₁ coefficient (m=16, fits in 4 bits).
pub const W1_BITS: u32 = 4;

/// Public key byte length: ρ (32) + k·t₁_poly (k·320).
pub const PK_BYTES: usize = 32 + K * (crate::mldsa::N * T1_BITS as usize / 8); // 1952
/// Signature byte length: c̃ + z + hints.
pub const SIG_BYTES: usize = LAMBDA_BYTES
    + L * (crate::mldsa::N * Z_BITS as usize / 8)
    + OMEGA
    + K; // 48 + 3200 + 55 + 6 = 3309
