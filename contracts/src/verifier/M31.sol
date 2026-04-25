// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title M31 — Arithmetic over the Mersenne prime field M31 = GF(2^31 − 1)
///
/// All inputs must be reduced (< P) unless stated otherwise.
/// Stwo (Circle STARK) uses M31 as its base field.
library M31 {
    /// @notice The Mersenne prime p = 2^31 − 1 = 2_147_483_647.
    uint256 internal constant P = 2_147_483_647;

    // ── Field operations ──────────────────────────────────────────────────────

    function add(uint256 a, uint256 b) internal pure returns (uint256 r) {
        unchecked { r = a + b; }
        if (r >= P) unchecked { r -= P; }
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a - b : a + P - b;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, P);
    }

    /// @notice Modular exponentiation (base^exp mod P).
    function pow(uint256 base, uint256 exp) internal pure returns (uint256 result) {
        result = 1;
        base = base % P;
        while (exp > 0) {
            if (exp & 1 == 1) result = mulmod(result, base, P);
            base = mulmod(base, base, P);
            exp >>= 1;
        }
    }

    /// @notice Multiplicative inverse via Fermat's little theorem: a^(P−2) mod P.
    /// Reverts if a == 0.
    function inv(uint256 a) internal pure returns (uint256) {
        require(a != 0, "M31: zero has no inverse");
        return pow(a, P - 2);
    }

    /// @notice Additive inverse: −a mod P.
    function neg(uint256 a) internal pure returns (uint256) {
        return a == 0 ? 0 : P - a;
    }

    // ── Validation ────────────────────────────────────────────────────────────

    /// @notice Returns true iff a is a valid, fully reduced M31 element (< P).
    function isValid(uint256 a) internal pure returns (bool) {
        return a < P;
    }

    // ── Encoding ─────────────────────────────────────────────────────────────

    /// @notice Decode a little-endian bytes4 (as produced by Rust's `to_le_bytes()`)
    ///         into a uint256 M31 element.
    ///
    /// Stwo serialises M31 values as little-endian uint32. When those bytes arrive
    /// in Solidity (e.g. as the first 4 bytes of a bytes8 commitment), they are
    /// stored in big-endian memory order. This function reverses them to recover
    /// the original integer.
    function fromBytes4LE(bytes4 b) internal pure returns (uint256) {
        uint32 be = uint32(b);
        uint32 le = ((be & 0xFF) << 24)
                  | ((be & 0xFF00) << 8)
                  | ((be >> 8) & 0xFF00)
                  | ((be >> 24) & 0xFF);
        return uint256(le);
    }

    /// @notice Encode a uint256 M31 element as little-endian bytes4.
    function toBytes4LE(uint256 a) internal pure returns (bytes4) {
        require(a < P, "M31: value out of range");
        uint32 v = uint32(a);
        uint32 le = ((v & 0xFF) << 24)
                  | ((v & 0xFF00) << 8)
                  | ((v >> 8) & 0xFF00)
                  | ((v >> 24) & 0xFF);
        return bytes4(le);
    }
}
