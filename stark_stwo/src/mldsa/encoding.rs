/// Bit-packing and polynomial encoding for ML-DSA-65.
///
/// Implements FIPS 204 Algorithms 16–22 (SimpleBitPack, BitPack, pkDecode,
/// sigDecode, HintBitUnpack, w1Encode).

use super::N;
use super::poly::Poly;
use super::polyvec::PolyVec;
use super::params::{K, L, T1_BITS, Z_BITS, W1_BITS, GAMMA1, LAMBDA_BYTES, OMEGA, PK_BYTES, SIG_BYTES};

// ─── Low-level bit packing ───────────────────────────────────────────────────

/// Pack `values` at `bits` bits per element (little-endian bit order).
fn pack_bits(values: &[i64], bits: u32) -> Vec<u8> {
    let total_bits = values.len() * bits as usize;
    let mut out = vec![0u8; (total_bits + 7) / 8];
    let mut pos = 0usize;
    for &v in values {
        for b in 0..bits {
            if (v >> b) & 1 == 1 {
                out[pos / 8] |= 1u8 << (pos % 8);
            }
            pos += 1;
        }
    }
    out
}

/// Unpack `count` values at `bits` bits each from `bytes`.
fn unpack_bits(bytes: &[u8], bits: u32, count: usize) -> Vec<i64> {
    let mut out = vec![0i64; count];
    let mut pos = 0usize;
    for v in out.iter_mut() {
        let mut val = 0i64;
        for b in 0..bits {
            if pos / 8 < bytes.len() && (bytes[pos / 8] >> (pos % 8)) & 1 == 1 {
                val |= 1i64 << b;
            }
            pos += 1;
        }
        *v = val;
    }
    out
}

// ─── FIPS 204 Algorithm 16: SimpleBitPack ────────────────────────────────────

/// Pack polynomial `w` with coefficients in [0, 2^bits) at `bits` bits each.
pub fn simple_bit_pack(w: &[i64; N], bits: u32) -> Vec<u8> {
    pack_bits(w, bits)
}

/// Unpack polynomial from bytes assuming coefficients in [0, 2^bits).
pub fn simple_bit_unpack(v: &[u8], bits: u32) -> [i64; N] {
    let vals = unpack_bits(v, bits, N);
    let mut out = [0i64; N];
    out.copy_from_slice(&vals);
    out
}

// ─── FIPS 204 Algorithm 18: BitPack / BitUnpack ───────────────────────────────

/// Pack polynomial `w` with coefficients in [−a, b] where a+b+1 = 2^bits.
/// Maps coeff → b − coeff ∈ [0, a+b], then packs at `bits` bits.
pub fn bit_pack(w: &[i64; N], upper: i64, bits: u32) -> Vec<u8> {
    let mapped: Vec<i64> = w.iter().map(|&c| upper - c).collect();
    pack_bits(&mapped, bits)
}

/// Unpack polynomial packed by `bit_pack(w, upper, bits)`.
/// Returns coefficients in [upper − 2^bits + 1, upper].
pub fn bit_unpack(v: &[u8], upper: i64, bits: u32) -> [i64; N] {
    let vals = unpack_bits(v, bits, N);
    let mut out = [0i64; N];
    for (i, &x) in vals.iter().enumerate() {
        out[i] = upper - x;
    }
    out
}

// ─── FIPS 204 Algorithm 17: pkDecode ─────────────────────────────────────────

/// Decode public key bytes into (ρ, t₁).
///
/// `pk` must be exactly `PK_BYTES` bytes.
pub fn pk_decode(pk: &[u8]) -> Result<([u8; 32], PolyVec), String> {
    if pk.len() != PK_BYTES {
        return Err(format!("pk_decode: expected {PK_BYTES} bytes, got {}", pk.len()));
    }
    let rho: [u8; 32] = pk[..32].try_into().unwrap();
    let t1_stride = N * T1_BITS as usize / 8; // 320 bytes per poly
    let mut t1_polys = Vec::with_capacity(K);
    for i in 0..K {
        let chunk = &pk[32 + i * t1_stride .. 32 + (i + 1) * t1_stride];
        let coeffs = simple_bit_unpack(chunk, T1_BITS);
        t1_polys.push(Poly::from_coeffs(coeffs));
    }
    Ok((rho, PolyVec(t1_polys)))
}

// ─── FIPS 204 Algorithm 19: sigDecode ────────────────────────────────────────

/// Decode signature bytes into (c̃, z, hints).
///
/// `sig` must be exactly `SIG_BYTES` bytes.
/// Returns `Err` if the hint encoding is malformed.
pub fn sig_decode(sig: &[u8]) -> Result<(Vec<u8>, PolyVec, Vec<Vec<bool>>), String> {
    if sig.len() != SIG_BYTES {
        return Err(format!("sig_decode: expected {SIG_BYTES} bytes, got {}", sig.len()));
    }

    let c_tilde = sig[..LAMBDA_BYTES].to_vec();

    let z_stride = N * Z_BITS as usize / 8; // 640 bytes per poly
    let mut z_polys = Vec::with_capacity(L);
    for j in 0..L {
        let off = LAMBDA_BYTES + j * z_stride;
        let chunk = &sig[off .. off + z_stride];
        let coeffs = bit_unpack(chunk, GAMMA1, Z_BITS);
        z_polys.push(Poly::from_coeffs(coeffs));
    }

    let hint_off = LAMBDA_BYTES + L * z_stride;
    let hints = hint_bit_unpack(&sig[hint_off .. hint_off + OMEGA + K])?;

    Ok((c_tilde, PolyVec(z_polys), hints))
}

// ─── FIPS 204 Algorithm 22: HintBitUnpack ────────────────────────────────────

/// Decode the packed hint bytes into k vectors of N bools.
///
/// Returns `Err` if the encoding is malformed (out-of-range indices,
/// non-strictly-increasing, or nonzero padding).
fn hint_bit_unpack(y: &[u8]) -> Result<Vec<Vec<bool>>, String> {
    // y has ω + k bytes: first ω bytes are indices, next k bytes are offsets.
    if y.len() != OMEGA + K {
        return Err(format!("hint_bit_unpack: expected {} bytes, got {}", OMEGA + K, y.len()));
    }
    let mut h = vec![vec![false; N]; K];
    let mut k = 0usize; // running index into the index bytes
    for i in 0..K {
        let ki = y[OMEGA + i] as usize;
        if ki < k || ki > OMEGA {
            return Err(format!("hint_bit_unpack: offset[{i}]={ki} out of [k={k}, ω={OMEGA}]"));
        }
        // Each successive index must be strictly increasing.
        let mut prev = 0u8;
        for idx_pos in k..ki {
            let idx = y[idx_pos];
            if idx_pos > k && idx <= prev {
                return Err(format!("hint_bit_unpack: indices not strictly increasing at pos {idx_pos}"));
            }
            prev = idx;
            h[i][idx as usize] = true;
        }
        k = ki;
    }
    // Remaining padding bytes must be zero.
    for j in k..OMEGA {
        if y[j] != 0 {
            return Err(format!("hint_bit_unpack: non-zero padding byte at pos {j}"));
        }
    }
    Ok(h)
}

// ─── FIPS 204 Algorithm 20: w₁Encode ─────────────────────────────────────────

/// Encode a length-k PolyVec w₁ (coefficients in [0, m)) into bytes.
/// For ML-DSA-65: 4 bits per coefficient → 128 bytes per polynomial.
pub fn w1_encode(w1: &PolyVec) -> Vec<u8> {
    let mut out = Vec::with_capacity(w1.len() * N * W1_BITS as usize / 8);
    for p in &w1.0 {
        out.extend_from_slice(&simple_bit_pack(&p.coeffs, W1_BITS));
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn filled_poly(val: i64) -> [i64; N] {
        [val; N]
    }

    #[test]
    fn test_simple_bit_pack_unpack_roundtrip_t1() {
        let orig: [i64; N] = std::array::from_fn(|i| (i as i64 % (1 << T1_BITS)));
        let packed = simple_bit_pack(&orig, T1_BITS);
        assert_eq!(packed.len(), N * T1_BITS as usize / 8);
        let unpacked = simple_bit_unpack(&packed, T1_BITS);
        assert_eq!(unpacked, orig);
    }

    #[test]
    fn test_bit_pack_unpack_roundtrip_z() {
        let _orig: [i64; N] = std::array::from_fn(|i| {
            let c = (i as i64 * 1000) % GAMMA1;
            GAMMA1 - 1 - c // in [0, GAMMA1-1], then mapped to signed by bit_unpack
        });
        // Actually store signed values directly:
        let signed: [i64; N] = std::array::from_fn(|i| {
            let c = (i as i64 * 997) % GAMMA1;
            if i % 2 == 0 { c } else { -c }
        });
        let packed = bit_pack(&signed, GAMMA1, Z_BITS);
        assert_eq!(packed.len(), N * Z_BITS as usize / 8);
        let unpacked = bit_unpack(&packed, GAMMA1, Z_BITS);
        assert_eq!(unpacked, signed);
    }

    #[test]
    fn test_bit_pack_zero_roundtrip() {
        let zero = [0i64; N];
        let packed = bit_pack(&zero, GAMMA1, Z_BITS);
        let unpacked = bit_unpack(&packed, GAMMA1, Z_BITS);
        assert_eq!(unpacked, zero);
    }

    #[test]
    fn test_pk_decode_wrong_length() {
        assert!(pk_decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_pk_decode_all_zeros() {
        let pk = vec![0u8; PK_BYTES];
        let (rho, t1) = pk_decode(&pk).unwrap();
        assert_eq!(rho, [0u8; 32]);
        assert_eq!(t1.len(), K);
        for p in &t1.0 {
            assert_eq!(p.coeffs, [0i64; N]);
        }
    }

    #[test]
    fn test_sig_decode_wrong_length() {
        assert!(sig_decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_hint_bit_unpack_all_zeros() {
        let y = vec![0u8; OMEGA + K];
        let h = hint_bit_unpack(&y).unwrap();
        assert_eq!(h.len(), K);
        for poly_h in &h {
            assert_eq!(poly_h.len(), N);
            assert!(poly_h.iter().all(|&b| !b));
        }
    }

    #[test]
    fn test_hint_bit_unpack_malformed_nonzero_padding() {
        let mut y = vec![0u8; OMEGA + K];
        y[0] = 5; // hint index in padding, but offset[0]=0 so it's padding
        // y[OMEGA+0] = 0 means no hints for poly 0, but y[0] != 0 → error
        assert!(hint_bit_unpack(&y).is_err());
    }

    #[test]
    fn test_hint_bit_unpack_valid_single_hint() {
        let mut y = vec![0u8; OMEGA + K];
        // One hint for poly 0 at index 7
        y[0] = 7;            // index byte
        y[OMEGA] = 1;        // offset for poly 0: 1 hint
        // Offsets for poly 1..K-1 all = 1 (no new hints)
        for i in 1..K {
            y[OMEGA + i] = 1;
        }
        let h = hint_bit_unpack(&y).unwrap();
        assert!(h[0][7]);
        assert!(!h[0][8]);
    }

    #[test]
    fn test_w1_encode_length() {
        use super::super::poly::Poly;
        let w1 = PolyVec(vec![Poly::zero(); K]);
        let enc = w1_encode(&w1);
        assert_eq!(enc.len(), K * N * W1_BITS as usize / 8); // 6 * 128 = 768
    }
}
