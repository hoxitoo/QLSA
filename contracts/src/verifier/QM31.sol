// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./M31.sol";
import "./CM31.sol";

/// @title QM31 — Quartic extension of M31: CM31[u] / (u² - R) where R = 2 + i
///
/// Elements are pairs (c0, c1) of CM31 representing c0 + c1·u where u² = R.
/// R = CM31(2, 1) = 2 + i.  This matches Stwo's QM31 definition:
///     const R: CM31 = CM31::from_u32_unchecked(2, 1);
///
/// Encoding: uint128, bits 127:64 = c0 (CM31), bits 63:0 = c1 (CM31).
/// Each CM31 is encoded as uint64: bits 63:32 = real, bits 31:0 = imag.
library QM31 {

    // ── Constants ─────────────────────────────────────────────────────────────

    // R = 2 + i as a CM31 element: pack(2, 1)
    uint64 internal constant R = uint64((2 << 32) | 1);

    // ── Packing ───────────────────────────────────────────────────────────────

    /// @notice Pack (a, b) → uint128 where a = c0 component, b = c1 component.
    function pack(uint64 a, uint64 b) internal pure returns (uint128) {
        return uint128((uint128(a) << 64) | uint128(b));
    }

    /// @notice First CM31 component c0 (coefficients of 1).
    function c0(uint128 q) internal pure returns (uint64) {
        return uint64(q >> 64);
    }

    /// @notice Second CM31 component c1 (coefficients of u).
    function c1(uint128 q) internal pure returns (uint64) {
        return uint64(q & 0xFFFFFFFFFFFFFFFF);
    }

    /// @notice Embed a CM31 element as QM31: e + 0·u.
    function fromCM31(uint64 e) internal pure returns (uint128) {
        return pack(e, 0);
    }

    /// @notice Embed an M31 element as QM31: a + 0·i + 0·u + 0·(i·u).
    function fromM31(uint256 a) internal pure returns (uint128) {
        return fromCM31(CM31.fromM31(a));
    }

    // ── Arithmetic ────────────────────────────────────────────────────────────

    /// @notice (c0+c1·u) + (d0+d1·u) = (c0+d0) + (c1+d1)·u
    function add(uint128 x, uint128 y) internal pure returns (uint128) {
        return pack(CM31.add(c0(x), c0(y)), CM31.add(c1(x), c1(y)));
    }

    /// @notice (c0+c1·u) - (d0+d1·u) = (c0-d0) + (c1-d1)·u
    function sub(uint128 x, uint128 y) internal pure returns (uint128) {
        return pack(CM31.sub(c0(x), c0(y)), CM31.sub(c1(x), c1(y)));
    }

    /// @notice (c0+c1·u)(d0+d1·u) = (c0·d0 + R·c1·d1) + (c0·d1 + c1·d0)·u
    ///         where u² = R = 2 + i.
    function mul(uint128 x, uint128 y) internal pure returns (uint128) {
        uint64 a = c0(x); uint64 b = c1(x);
        uint64 c = c0(y); uint64 d = c1(y);
        // r0 = a*c + R*b*d
        uint64 r0 = CM31.add(CM31.mul(a, c), CM31.mul(R, CM31.mul(b, d)));
        // r1 = a*d + b*c
        uint64 r1 = CM31.add(CM31.mul(a, d), CM31.mul(b, c));
        return pack(r0, r1);
    }

    /// @notice -(c0+c1·u) = (-c0) + (-c1)·u
    function neg(uint128 x) internal pure returns (uint128) {
        return pack(CM31.neg(c0(x)), CM31.neg(c1(x)));
    }

    /// @notice Scale by an M31 scalar.
    function scaleM31(uint128 x, uint256 s) internal pure returns (uint128) {
        return pack(CM31.scale(c0(x), s), CM31.scale(c1(x), s));
    }

    /// @notice Scale by a CM31 element.
    function scaleCM31(uint128 x, uint64 s) internal pure returns (uint128) {
        return pack(CM31.mul(c0(x), s), CM31.mul(c1(x), s));
    }

    /// @notice Multiplicative inverse of q.
    /// @dev Uses the formula: q^-1 = conj(q) / (q * conj(q)) where conj is
    ///      the QM31 conjugate (c0 - c1·u) and the product lands in CM31.
    ///      Actually: 1/(c0+c1·u) — computed via norm in CM31[u]/(u²-R).
    ///      norm(c0+c1·u) = c0² - R·c1² ∈ CM31  (since (c0+c1·u)(c0-c1·u) = c0²-R·c1²)
    function inv(uint128 x) internal pure returns (uint128) {
        uint64 a = c0(x); uint64 b = c1(x);
        // norm = a² - R·b²  (in CM31)
        uint64 norm = CM31.sub(CM31.mul(a, a), CM31.mul(R, CM31.mul(b, b)));
        uint64 normInv = CM31.inv(norm);
        // x^-1 = (a - b·u) / norm = a*norm_inv + (-b*norm_inv)*u
        return pack(CM31.mul(a, normInv), CM31.mul(CM31.neg(b), normInv));
    }

    // ── FRI folding ───────────────────────────────────────────────────────────

    /// @notice FRI linear combination fold step (real-valued evaluations).
    ///
    /// Given evaluations f_plus = f(P) and f_minus = f(-P) at a circle point
    /// and its antipode, fold to a single QM31 value using challenge alpha:
    ///
    ///   fold = (f_plus + f_minus)/2 + alpha * (f_plus - f_minus)/2
    ///
    /// The division by 2 is exact in M31 (multiply by inv(2)).
    ///
    /// @param fPlus   f(P)  — M31 evaluation (as uint256 < P)
    /// @param fMinus  f(-P) — M31 evaluation (as uint256 < P)
    /// @param alpha   FRI challenge in QM31
    function friLinearFold(
        uint256 fPlus,
        uint256 fMinus,
        uint128 alpha
    ) internal pure returns (uint128) {
        uint256 inv2 = M31.inv(2);
        uint256 sumHalf  = M31.mul(M31.add(fPlus, fMinus), inv2);  // (f+ + f-)/2
        uint256 diffHalf = M31.mul(M31.sub(fPlus, fMinus), inv2);  // (f+ - f-)/2
        // fold = sumHalf + alpha * diffHalf
        uint128 alphaDiff = scaleM31(alpha, diffHalf);
        return add(fromM31(sumHalf), alphaDiff);
    }

    // ── Validation ────────────────────────────────────────────────────────────

    /// @notice True iff both CM31 components are valid.
    function isValid(uint128 x) internal pure returns (bool) {
        return CM31.isValid(c0(x)) && CM31.isValid(c1(x));
    }

    // ── Encoding ─────────────────────────────────────────────────────────────

    /// @notice Decode 16 little-endian bytes (Stwo serialisation) into a QM31 element.
    /// Stwo serialises QM31 as: [c0.real LE32, c0.imag LE32, c1.real LE32, c1.imag LE32].
    function fromBytes16LE(bytes memory data, uint256 offset) internal pure returns (uint128) {
        require(offset + 16 <= data.length, "QM31: out of bounds");
        uint64 _c0 = CM31.fromBytes8LE(data, offset);
        uint64 _c1 = CM31.fromBytes8LE(data, offset + 8);
        return pack(_c0, _c1);
    }
}
