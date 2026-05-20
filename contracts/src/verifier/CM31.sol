// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./M31.sol";

/// @title CM31 — Complex extension of M31: GF(2^31-1)[i] / (i² + 1)
///
/// Elements a + b·i where i² = -1 (i.e. i² ≡ P-1 mod P).
/// Matches Stwo's CM31 type (stwo/src/core/fields/cm31.rs).
///
/// Encoding: a single uint64, bits 63:32 = a (real), bits 31:0 = b (imag).
/// Both a and b must be fully reduced M31 values (< P = 2^31-1).
library CM31 {

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 internal constant P = M31.P;  // 2^31 - 1

    // The imaginary unit i as a CM31 element: 0 + 1·i → pack(0, 1)
    uint64  internal constant IMAG_UNIT = 1;  // pack(0, 1)

    // ── Packing ───────────────────────────────────────────────────────────────

    /// @notice Pack (a, b) → uint64. Both must be < P.
    function pack(uint256 a, uint256 b) internal pure returns (uint64) {
        return uint64((a << 32) | b);
    }

    /// @notice Real part of a CM31 element.
    function re(uint64 e) internal pure returns (uint256) {
        return uint256(e >> 32);
    }

    /// @notice Imaginary part of a CM31 element.
    function im(uint64 e) internal pure returns (uint256) {
        return uint256(e & 0xFFFFFFFF);
    }

    /// @notice Construct CM31 from a single M31 value: a + 0·i.
    function fromM31(uint256 a) internal pure returns (uint64) {
        return pack(a, 0);
    }

    // ── Arithmetic ────────────────────────────────────────────────────────────

    /// @notice (a+bi) + (c+di) = (a+c) + (b+d)i
    function add(uint64 x, uint64 y) internal pure returns (uint64) {
        return pack(M31.add(re(x), re(y)), M31.add(im(x), im(y)));
    }

    /// @notice (a+bi) - (c+di) = (a-c) + (b-d)i
    function sub(uint64 x, uint64 y) internal pure returns (uint64) {
        return pack(M31.sub(re(x), re(y)), M31.sub(im(x), im(y)));
    }

    /// @notice (a+bi)(c+di) = (ac-bd) + (ad+bc)i  (since i² = -1)
    function mul(uint64 x, uint64 y) internal pure returns (uint64) {
        uint256 a = re(x); uint256 b = im(x);
        uint256 c = re(y); uint256 d = im(y);
        uint256 r = M31.sub(M31.mul(a, c), M31.mul(b, d));
        uint256 i_ = M31.add(M31.mul(a, d), M31.mul(b, c));
        return pack(r, i_);
    }

    /// @notice -(a+bi) = (-a) + (-b)i
    function neg(uint64 x) internal pure returns (uint64) {
        return pack(M31.neg(re(x)), M31.neg(im(x)));
    }

    /// @notice Scale by an M31 scalar: s·(a+bi) = (s·a) + (s·b)i
    function scale(uint64 x, uint256 s) internal pure returns (uint64) {
        return pack(M31.mul(re(x), s), M31.mul(im(x), s));
    }

    /// @notice Complex conjugate: conj(a+bi) = a - bi
    function conj(uint64 x) internal pure returns (uint64) {
        return pack(re(x), M31.neg(im(x)));
    }

    /// @notice Multiplicative inverse: 1/(a+bi) = (a-bi)/(a²+b²)
    /// @dev Reverts if x == 0.
    function inv(uint64 x) internal pure returns (uint64) {
        uint256 a = re(x); uint256 b = im(x);
        // norm = a² + b²
        uint256 norm = M31.add(M31.mul(a, a), M31.mul(b, b));
        uint256 normInv = M31.inv(norm);  // reverts if norm == 0 (i.e. x == 0)
        // (a + bi)^-1 = a/norm - b/norm * i
        return pack(M31.mul(a, normInv), M31.mul(M31.neg(b), normInv));
    }

    // ── Validation ────────────────────────────────────────────────────────────

    /// @notice True iff both components are valid reduced M31 values.
    function isValid(uint64 x) internal pure returns (bool) {
        return M31.isValid(re(x)) && M31.isValid(im(x));
    }

    // ── Encoding ─────────────────────────────────────────────────────────────

    /// @notice Decode 8 little-endian bytes (as output by Stwo) into a CM31 element.
    /// Stwo serialises CM31 as two consecutive little-endian uint32 words: [real, imag].
    function fromBytes8LE(bytes memory data, uint256 offset) internal pure returns (uint64) {
        require(offset + 8 <= data.length, "CM31: out of bounds");
        uint256 a = _readLE32(data, offset);       // real part
        uint256 b = _readLE32(data, offset + 4);   // imag part
        require(a < M31.P && b < M31.P, "CM31: value out of M31 range");
        return pack(a, b);
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    function _readLE32(bytes memory data, uint256 off) private pure returns (uint256 w) {
        unchecked {
            w  = uint256(uint8(data[off]));
            w |= uint256(uint8(data[off + 1])) << 8;
            w |= uint256(uint8(data[off + 2])) << 16;
            w |= uint256(uint8(data[off + 3])) << 24;
        }
    }
}
