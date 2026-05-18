// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./M31.sol";
import "./QM31.sol";

/// @title CirclePoint — Circle group arithmetic over M31 for Stwo Circle STARK
///
/// The circle group over M31 is the algebraic group of points (x, y) ∈ M31²
/// satisfying x² + y² = 1 (mod P).  It is isomorphic to ℤ/(2^31).
///
/// Group law (complex multiplication on the unit circle):
///   (x1, y1) + (x2, y2) = (x1·x2 − y1·y2,  x1·y2 + x2·y1)
///
/// Generator:
///   G = (2, 1268011823)  — order 2^31 (matches Stwo M31_CIRCLE_GEN).
///
/// CanonicCoset of log-size n:
///   Coset::odds(n) = G_{2n} + ⟨G_n⟩
///   initial_index = 2^(30−n),  step_size = 2^(31−n)
///   at(i) = G^(initial_index + i·step_size)
///
/// FRI fold formulas (matching Stwo fri.rs exactly):
///   Circle fold (circle → line):  f_new = (f+ + f−) + α·(f+ − f−)·y⁻¹
///   Line   fold (line  → point):  f_new = (f+ + f−) + α·(f+ − f−)·x⁻¹
///
/// Operands f+, f− and α are QM31 (uint128). The twiddle y⁻¹ / x⁻¹ is M31.
library CirclePoint {

    uint256 internal constant P = M31.P; // 2^31 − 1
    uint256 internal constant LOG_ORDER = 31;

    // Generator G = M31_CIRCLE_GEN in Stwo's circle.rs
    uint256 internal constant GEN_X = 2;
    uint256 internal constant GEN_Y = 1268011823;

    // ── On-circle validation ──────────────────────────────────────────────────

    /// @notice True iff (x, y) lies on the circle: x² + y² ≡ 1 (mod P).
    function isOnCircle(uint256 x, uint256 y) internal pure returns (bool) {
        return M31.add(M31.mul(x, x), M31.mul(y, y)) == 1;
    }

    // ── Group operations ──────────────────────────────────────────────────────

    /// @notice Add two circle points: (x1,y1) + (x2,y2) = (x1x2−y1y2, x1y2+x2y1).
    function pointAdd(
        uint256 x1, uint256 y1,
        uint256 x2, uint256 y2
    ) internal pure returns (uint256 x, uint256 y) {
        x = M31.sub(M31.mul(x1, x2), M31.mul(y1, y2));
        y = M31.add(M31.mul(x1, y2), M31.mul(x2, y1));
    }

    /// @notice Double a circle point: (x,y) → (2x²−1, 2xy).
    function pointDouble(uint256 x, uint256 y) internal pure returns (uint256 rx, uint256 ry) {
        uint256 x2 = M31.mul(x, x);
        rx = M31.sub(M31.add(x2, x2), 1);
        ry = M31.add(M31.mul(x, y), M31.mul(x, y));
    }

    /// @notice Scalar multiplication: scalar · G using double-and-add.
    /// @param scalar  Value in [0, 2^31). Operates mod 2^31.
    function genMul(uint256 scalar) internal pure returns (uint256 rx, uint256 ry) {
        // Identity element is (1, 0).
        rx = 1; ry = 0;
        uint256 cx = GEN_X; uint256 cy = GEN_Y;
        uint256 s = scalar & ((1 << LOG_ORDER) - 1); // reduce mod 2^31
        while (s > 0) {
            if (s & 1 == 1) (rx, ry) = pointAdd(rx, ry, cx, cy);
            (cx, cy) = pointDouble(cx, cy);
            s >>= 1;
        }
    }

    // ── CanonicCoset ──────────────────────────────────────────────────────────

    /// @notice Compute the circle domain point for query index `idx`
    ///         in a CanonicCoset of log-size `logN`.
    ///
    /// CanonicCoset::new(logN).at(idx) in Stwo:
    ///   initial_index = 2^(30 − logN)
    ///   step_size     = 2^(31 − logN)
    ///   index_at(idx) = (initial_index + idx · step_size) mod 2^31
    ///   at(idx)       = G^index_at(idx)
    ///
    /// @param logN  Log2 of coset size; must be in [1, 30].
    /// @param idx   Query index in [0, 2^logN).
    function cosetAt(uint256 logN, uint256 idx) internal pure returns (uint256 x, uint256 y) {
        require(logN >= 1 && logN <= 30, "CirclePoint: logN out of range");
        require(idx < (1 << logN), "CirclePoint: idx out of coset range");
        uint256 mod = 1 << LOG_ORDER; // 2^31 — circle group order
        uint256 initialIndex = (1 << (30 - logN)) % mod;
        uint256 stepSize     = (1 << (31 - logN)) % mod;
        uint256 pointIndex   = (initialIndex + (idx * stepSize) % mod) % mod;
        (x, y) = genMul(pointIndex);
    }

    // ── FRI fold formulas ─────────────────────────────────────────────────────

    /// @notice Circle → line fold (first FRI fold layer in Stwo).
    ///
    /// Matching Stwo fold_circle_into_line:
    ///   f_new = (f+ + f−) + α·(f+ − f−)·y⁻¹
    ///
    /// @param fPlus   f evaluated at circle point p (QM31, uint128).
    /// @param fMinus  f evaluated at conjugate point −p = (x, −y) (QM31, uint128).
    /// @param alpha   FRI folding challenge (QM31, uint128).
    /// @param yInv    Multiplicative inverse of the y-coordinate: M31.inv(p.y).
    function circleFold(
        uint128 fPlus,
        uint128 fMinus,
        uint128 alpha,
        uint256 yInv
    ) internal pure returns (uint128) {
        uint128 sum  = QM31.add(fPlus, fMinus);
        uint128 diff = QM31.sub(fPlus, fMinus);
        // diff · yInv: scale each CM31 component by yInv (M31 scalar)
        uint128 diffScaled = QM31.scaleM31(diff, yInv);
        return QM31.add(sum, QM31.mul(alpha, diffScaled));
    }

    /// @notice Line → point fold (inner FRI layers in Stwo).
    ///
    /// Matching Stwo fold_line:
    ///   f_new = (f+ + f−) + α·(f+ − f−)·x⁻¹
    ///
    /// @param fPlus   f evaluated at line point x (QM31, uint128).
    /// @param fMinus  f evaluated at −x (QM31, uint128).
    /// @param alpha   FRI folding challenge (QM31, uint128).
    /// @param xInv    Multiplicative inverse of the x-coordinate: M31.inv(x).
    function lineFold(
        uint128 fPlus,
        uint128 fMinus,
        uint128 alpha,
        uint256 xInv
    ) internal pure returns (uint128) {
        uint128 sum  = QM31.add(fPlus, fMinus);
        uint128 diff = QM31.sub(fPlus, fMinus);
        uint128 diffScaled = QM31.scaleM31(diff, xInv);
        return QM31.add(sum, QM31.mul(alpha, diffScaled));
    }
}
