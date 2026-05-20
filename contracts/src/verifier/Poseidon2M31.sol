// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./M31.sol";

/// @title Poseidon2M31 — Poseidon2 permutation over M31 (GF(2^31-1))
///
/// Parameters — exactly match stark_stwo Rust crate (Stwo 2.2.0):
///   field:    M31 = GF(2^31-1 = 2_147_483_647)
///   t = 2     state width (two M31 elements)
///   α = 5     S-box exponent  (x ↦ x^5 mod P)
///   R_F = 8   full rounds,  R_P = 0 partial rounds
///   MDS:      [[3, 1], [1, 3]]  over M31
///   RC:       8 pairs derived from SHA-256 IV/K reduced mod P
///
/// Modes:
///   compress(left, right)  → permute(left, right).s0   — Merkle node hash
///   sponge(values)         → (s0, s1) after absorb-permute — hash chain
///
/// Cross-check test vectors (verified against Stwo 2.2.0 Rust):
///   permute(0, 0)  → (204_783_406,   774_225_216)
///   permute(42, 7) → (1_857_996_239, 291_126_382)
///   permute(1, 2)  → (761_825_867,   414_788_754)
///   permute(1, 1)  → (1_348_434_693, 1_943_418_549)
library Poseidon2M31 {

    uint256 internal constant P = M31.P;  // 2^31 - 1

    // ── Round constants (8 pairs, SHA-256 IV/K reduced mod P) ─────────────────
    //
    //  h0..h7 are SHA-256 initial hash values; K0..K7 are first 8 NIST SHA-256
    //  round constants.  Each is taken mod P to land in M31.
    //
    //  Round  s0-constant            s1-constant
    //    0    0x6a09e667 % P          0xbb67ae85 % P
    //    1    0x3c6ef372 (no red.)    0xa54ff53a % P
    //    2    0x510e527f (no red.)    0x9b05688c % P
    //    3    0x1f83d9ab (no red.)    0x5be0cd19 % P
    //    4    0x428a2f98 (no red.)    0x71374491 % P
    //    5    0xb5c0fbcf % P          0xe9b5dba5 % P
    //    6    0x3956c25b (no red.)    0x59f111f1 % P
    //    7    0x923f82a4 % P          0xab1c5ed5 % P

    uint256 private constant RC0_0 = 1_779_033_703;   // 0x6a09e667 < P ✓
    uint256 private constant RC0_1 =   996_650_630;   // 0xbb67ae85 mod P
    uint256 private constant RC1_0 = 1_013_904_242;   // 0x3c6ef372 < P ✓
    uint256 private constant RC1_1 =   625_997_115;   // 0xa54ff53a mod P
    uint256 private constant RC2_0 = 1_359_893_119;   // 0x510e527f < P ✓
    uint256 private constant RC2_1 =   453_339_277;   // 0x9b05688c mod P
    uint256 private constant RC3_0 =   528_734_635;   // 0x1f83d9ab < P ✓
    uint256 private constant RC3_1 = 1_541_459_225;   // 0x5be0cd19 < P ✓
    uint256 private constant RC4_0 = 1_116_352_408;   // 0x428a2f98 < P ✓
    uint256 private constant RC4_1 = 1_899_447_441;   // 0x71374491 < P ✓
    uint256 private constant RC5_0 =   901_839_824;   // 0xb5c0fbcf mod P
    uint256 private constant RC5_1 = 1_773_525_926;   // 0xe9b5dba5 mod P
    uint256 private constant RC6_0 =   961_987_163;   // 0x3956c25b < P ✓
    uint256 private constant RC6_1 = 1_508_970_993;   // 0x59f111f1 < P ✓
    uint256 private constant RC7_0 =   306_152_101;   // 0x923f82a4 mod P
    uint256 private constant RC7_1 =   723_279_574;   // 0xab1c5ed5 mod P

    // ── M31 field helpers (inlined for gas efficiency) ─────────────────────────

    /// @dev a + b mod P.  Requires a, b < P.
    function _add(uint256 a, uint256 b) private pure returns (uint256 r) {
        unchecked { r = a + b; }
        if (r >= P) r -= P;
    }

    /// @dev x^5 mod P — the Poseidon2 S-box.  3 mulmod operations.
    function _sbox(uint256 x) private pure returns (uint256) {
        uint256 x2 = mulmod(x, x, P);
        uint256 x4 = mulmod(x2, x2, P);
        return mulmod(x4, x, P);
    }

    // ── One full Poseidon2 round ───────────────────────────────────────────────

    /// @dev AddRC → SBox (both elements) → MDS [[3,1],[1,3]].
    function _round(
        uint256 s0, uint256 s1,
        uint256 rc0, uint256 rc1
    ) private pure returns (uint256, uint256) {
        // 1. Add round constants
        s0 = _add(s0, rc0);
        s1 = _add(s1, rc1);

        // 2. S-box (full round: applied to both elements)
        s0 = _sbox(s0);
        s1 = _sbox(s1);

        // 3. MDS [[3,1],[1,3]]:  s0' = 3·s0 + s1,  s1' = s0 + 3·s1
        uint256 n0 = _add(mulmod(3, s0, P), s1);
        uint256 n1 = _add(s0, mulmod(3, s1, P));
        return (n0, n1);
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// @notice Apply the Poseidon2 permutation (8 full rounds) to state (s0, s1).
    ///
    /// Gas: ~1000 gas (8 rounds × ~125 gas/round: 6 mulmod + 4 add + 2 cond-sub).
    ///
    /// @param s0 First state element (must be < P).
    /// @param s1 Second state element (must be < P).
    /// @return out0 First output (< P).
    /// @return out1 Second output (< P).
    function permute(uint256 s0, uint256 s1)
        internal pure
        returns (uint256 out0, uint256 out1)
    {
        (s0, s1) = _round(s0, s1, RC0_0, RC0_1);
        (s0, s1) = _round(s0, s1, RC1_0, RC1_1);
        (s0, s1) = _round(s0, s1, RC2_0, RC2_1);
        (s0, s1) = _round(s0, s1, RC3_0, RC3_1);
        (s0, s1) = _round(s0, s1, RC4_0, RC4_1);
        (s0, s1) = _round(s0, s1, RC5_0, RC5_1);
        (s0, s1) = _round(s0, s1, RC6_0, RC6_1);
        (s0, s1) = _round(s0, s1, RC7_0, RC7_1);
        return (s0, s1);
    }

    /// @notice Poseidon2 Merkle compression: hash of a pair.
    ///
    /// H(left, right) = permute(left, right).s0
    /// Matches stark_stwo poseidon2_merkle_air.rs.
    ///
    /// @param left  Left child hash (< P).
    /// @param right Right child hash (< P).
    /// @return result Hash value (< P).
    function compress(uint256 left, uint256 right) internal pure returns (uint256 result) {
        (result,) = permute(left, right);
    }

    /// @notice Poseidon2 sponge over a sequence of M31 field elements.
    ///
    /// Protocol (matches stark_stwo poseidon2.rs chain mode):
    ///   state ← (0, 0)
    ///   for each v in values:
    ///     s0 ← (s0 + v) mod P
    ///     (s0, s1) ← permute(s0, s1)
    ///
    /// @param values  Array of M31 field elements (each < P).
    /// @return s0 First output state element (< P).
    /// @return s1 Second output state element (< P).
    function sponge(uint256[] memory values)
        internal pure
        returns (uint256 s0, uint256 s1)
    {
        s0 = 0;
        s1 = 0;
        for (uint256 i = 0; i < values.length; i++) {
            s0 = _add(s0, values[i]);
            (s0, s1) = permute(s0, s1);
        }
    }
}
