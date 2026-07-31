// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./M31.sol";

/// @title Poseidon2M31T16 — Poseidon2 permutation over M31 with state width t = 16
///
/// Parameters — exactly match stark_stwo/src/poseidon2_t16.rs:
///   field:  M31 = GF(2^31-1)
///   t = 16  state width          α = 5    S-box (x ↦ x^5)
///   R_F = 8 external rounds      R_P = 14 internal rounds
///   M_E:    circ(2·M4, M4, M4, M4) — apply M4 per 4-cell block, then add the
///           per-column sum of the four blocks back into every block
///   M_I:    J + diag(1,…,16)
///   RC:     K_RC[0..142]; external round r uses K_RC[16r..16r+16),
///           internal round j uses K_RC[128 + j]
///
/// Why t=16: it carries 8-word (248-bit) Merkle nodes, so node collision cost is
/// ~2^124 ≈ 128-bit — the last rung of the ladder (t=2/t=4 → 2^31, t=8 → 2^62).
/// This is Stwo's native Poseidon2-16 width.
///
/// IMPLEMENTATION NOTE — where this sits between the two t=8 shapes.
/// Poseidon2M31T8 keeps its whole state in stack locals across fully-unrolled
/// rounds; that is what made it ~3.5x cheaper than the naive form. At t=16 the
/// same shape builds an expression tree large enough to exhaust the solc-js WASM
/// compiler (std::bad_alloc), so it cannot be built at all. This file takes the
/// middle path: the state lives in a `uint256[16] memory`, but every round is a
/// straight-line function reached through CONSTANT indices, and the round
/// constants are packed eight-to-a-word as code immediates. That removes the two
/// costs the naive loop form actually pays — a per-access bounds check on every
/// dynamic index, and a 128-element array literal rebuilt on every call — while
/// cutting the expression tree at each round's memory write-back, so the compiler
/// never sees the tree that broke it. Measured: the naive loop form costs 199,608
/// gas per permutation, this one 64,812 — 3.08x less, and only 1.79x a t=8
/// permutation while carrying TWICE the node width. Per bit of node capacity t=16
/// is therefore cheaper than t=8, which is why a t=16 on-chain verifier is worth
/// building rather than a rung to be skipped.
///
/// Lazy reduction still applies: the linear layers add without `mod P`, which is
/// exact because add/mul mod P are ring homomorphisms and every S-box passes
/// through `mulmod(…, P)`. Reduction is owed only on the way out.
/// Magnitude bound: M_E's largest row-coefficient sum is 5·16 = 80 and every
/// external round S-boxes first, so M_E sees inputs < 2^32 and emits < 2^39; an
/// internal round emits ≤ 32·B, so 14 of them stay under 32^14·2^39 = 2^109,
/// after which the next S-box collapses back under P. Peak ≈ 2^109 ≪ 2^256.
///
/// Cross-check vectors (frozen in poseidon2_t16.rs::test_reference_vectors):
///   permute([0;16])[0..4]  → [816977494, 440045756, 1261832507, 1370560761]
///   permute([1..16])[0..4] → [1896676506, 1113082531, 1826142252, 1263581674]
library Poseidon2M31T16 {

    uint256 internal constant P = M31.P; // 2^31 - 1
    uint256 internal constant T = 16;
    uint256 internal constant R_F = 8;
    uint256 internal constant R_P = 14;

    uint256 private constant MASK32 = 0xffffffff;

    // Round constants as code immediates: each KE*A/KE*B packs eight uint32
    // constants, cell i at bit offset 224 - 32*(i mod 8). Generated from the same
    // K_RC table as poseidon2_t16.rs; the frozen reference vectors pin them.
    uint256 private constant KE0A = 0x15ca995657dead1e33ab318f54dae2c7406e935207f59d0922d3d08d3aa3d923;
    uint256 private constant KE0B = 0x032ce7f97d2b5ab618edcefb3c9a7e621fc643917854e5686edf9124250587bb;
    uint256 private constant KE1A = 0x64962c024a62cdc33da8a91c2df56e9146db3d406a7f25406e1c583e3e5340da;
    uint256 private constant KE1B = 0x050cc4c855f6c8fe6357a40152bd9c2a6c7db0ba3605bfe6238e8e7b5ab2190e;
    uint256 private constant KE2A = 0x5009f84d39b410fe1c224787117e4507574e379c398cffc029eae4d54012c229;
    uint256 private constant KE2B = 0x36acb7b552cc039e7bbf634756d2fbbf1fbab3d64c3198630127e33b6b97ffad;
    uint256 private constant KE3A = 0x438216ea2672059518b608f373b98a00519f23a4685920fc0d78b876536a3061;
    uint256 private constant KE3B = 0x78e178b25def8655254f8e221df2478379d89f1b49bbb23a2bac0f7c2ae9b16d;
    uint256 private constant KE4A = 0x6e973d631b8d35e15478bdf9509024a448692e245d5c0bbd311560857985be1d;
    uint256 private constant KE4B = 0x038b518b19c6104a342763dd22e377905052bc1c04b249de22b8a9c5270b712b;
    uint256 private constant KE5A = 0x3deceb7656173e8646ac0fc061769a9813a5d5371124d36a0be14f73637e31e8;
    uint256 private constant KE5B = 0x1832f914131badd3375925fc6940cefd1cfd881536475b915e857ced1b0081e6;
    uint256 private constant KE6A = 0x581ed7416d0a5cba23af482337bcc5a64faff86a7fffa2c33c76ac320f7c278c;
    uint256 private constant KE6B = 0x7ef009af2ad74eb07a319f9a0f31f1354061bc13203836b11e29338a094d3925;
    uint256 private constant KE7A = 0x3b51165a39c6bcfe0dde26212c31cbe1464c38f940aaaddb1304a64d186b48e5;
    uint256 private constant KE7B = 0x497954312174f67e62bd51cf00b2d0ec0ce9f44338cc3a7c524cce915aae409a;

    uint256 private constant KI0 = 907051838;
    uint256 private constant KI1 = 1803830187;
    uint256 private constant KI2 = 47658112;
    uint256 private constant KI3 = 824628367;
    uint256 private constant KI4 = 713854912;
    uint256 private constant KI5 = 1489720594;
    uint256 private constant KI6 = 1695950527;
    uint256 private constant KI7 = 898987930;
    uint256 private constant KI8 = 1276627535;
    uint256 private constant KI9 = 990382248;
    uint256 private constant KI10 = 258309882;
    uint256 private constant KI11 = 108327904;
    uint256 private constant KI12 = 771518169;
    uint256 private constant KI13 = 645853941;

    /// @dev x^5 mod P — the Poseidon2 S-box. 3 mulmods; accepts unreduced x.
    function _sbox(uint256 x) private pure returns (uint256) {
        uint256 x2 = mulmod(x, x, P);
        uint256 x4 = mulmod(x2, x2, P);
        return mulmod(x4, x, P);
    }

    /// @dev M4 on one 4-cell block (Poseidon2 §5.1), on the stack, unreduced.
    function _m4(uint256 a, uint256 b, uint256 c, uint256 d)
        private pure
        returns (uint256, uint256, uint256, uint256)
    {
        unchecked {
            uint256 t0 = a + b;
            uint256 t1 = c + d;
            uint256 t2 = b + b + t1;
            uint256 t3 = d + d + t0;
            uint256 t4 = (t1 << 2) + t3;
            uint256 t5 = (t0 << 2) + t2;
            return (t3 + t5, t5, t2 + t4, t4);
        }
    }

    /// @dev External linear layer: M4 per block, then add the per-column sum of
    ///      the four blocks back into every block.
    function _matE(uint256[16] memory s) private pure {
        unchecked {
            (s[0], s[1], s[2], s[3])     = _m4(s[0], s[1], s[2], s[3]);
            (s[4], s[5], s[6], s[7])     = _m4(s[4], s[5], s[6], s[7]);
            (s[8], s[9], s[10], s[11])   = _m4(s[8], s[9], s[10], s[11]);
            (s[12], s[13], s[14], s[15]) = _m4(s[12], s[13], s[14], s[15]);

            uint256 g0 = s[0] + s[4] + s[8] + s[12];
            uint256 g1 = s[1] + s[5] + s[9] + s[13];
            uint256 g2 = s[2] + s[6] + s[10] + s[14];
            uint256 g3 = s[3] + s[7] + s[11] + s[15];

            s[0] += g0;  s[1] += g1;  s[2] += g2;  s[3] += g3;
            s[4] += g0;  s[5] += g1;  s[6] += g2;  s[7] += g3;
            s[8] += g0;  s[9] += g1;  s[10] += g2; s[11] += g3;
            s[12] += g0; s[13] += g1; s[14] += g2; s[15] += g3;
        }
    }

    /// @dev Internal linear layer: out_i = (Σ_j s_j) + μ_i·s_i, μ = (1,…,16).
    function _matI(uint256[16] memory s) private pure {
        unchecked {
            uint256 sum = s[0] + s[1] + s[2] + s[3] + s[4] + s[5] + s[6] + s[7] + s[8] + s[9] + s[10] + s[11] + s[12] + s[13] + s[14] + s[15];
            s[0] = sum + mulmod(1, s[0], P);
            s[1] = sum + mulmod(2, s[1], P);
            s[2] = sum + mulmod(3, s[2], P);
            s[3] = sum + mulmod(4, s[3], P);
            s[4] = sum + mulmod(5, s[4], P);
            s[5] = sum + mulmod(6, s[5], P);
            s[6] = sum + mulmod(7, s[6], P);
            s[7] = sum + mulmod(8, s[7], P);
            s[8] = sum + mulmod(9, s[8], P);
            s[9] = sum + mulmod(10, s[9], P);
            s[10] = sum + mulmod(11, s[10], P);
            s[11] = sum + mulmod(12, s[11], P);
            s[12] = sum + mulmod(13, s[12], P);
            s[13] = sum + mulmod(14, s[13], P);
            s[14] = sum + mulmod(15, s[14], P);
            s[15] = sum + mulmod(16, s[15], P);
        }
    }

    /// @dev One external round: add this round's 16 constants, S-box, then M_E.
    function _extRound(uint256[16] memory s, uint256 ca, uint256 cb) private pure {
        unchecked {
            s[0] = _sbox(s[0] + (ca >> 224));
            s[1] = _sbox(s[1] + ((ca >> 192) & MASK32));
            s[2] = _sbox(s[2] + ((ca >> 160) & MASK32));
            s[3] = _sbox(s[3] + ((ca >> 128) & MASK32));
            s[4] = _sbox(s[4] + ((ca >> 96) & MASK32));
            s[5] = _sbox(s[5] + ((ca >> 64) & MASK32));
            s[6] = _sbox(s[6] + ((ca >> 32) & MASK32));
            s[7] = _sbox(s[7] + ((ca >> 0) & MASK32));
            s[8] = _sbox(s[8] + (cb >> 224));
            s[9] = _sbox(s[9] + ((cb >> 192) & MASK32));
            s[10] = _sbox(s[10] + ((cb >> 160) & MASK32));
            s[11] = _sbox(s[11] + ((cb >> 128) & MASK32));
            s[12] = _sbox(s[12] + ((cb >> 96) & MASK32));
            s[13] = _sbox(s[13] + ((cb >> 64) & MASK32));
            s[14] = _sbox(s[14] + ((cb >> 32) & MASK32));
            s[15] = _sbox(s[15] + ((cb >> 0) & MASK32));
        }
        _matE(s);
    }

    /// @notice Apply the Poseidon2 t=16 permutation in place.
    /// @dev Inputs may exceed P (reduced through the first S-box layer); every
    ///      returned cell is < P.
    function permute(uint256[16] memory s) internal pure returns (uint256[16] memory) {
        unchecked {
            _matE(s);

            _extRound(s, KE0A, KE0B);
            _extRound(s, KE1A, KE1B);
            _extRound(s, KE2A, KE2B);
            _extRound(s, KE3A, KE3B);

            s[0] = _sbox(s[0] + KI0);
            _matI(s);
            s[0] = _sbox(s[0] + KI1);
            _matI(s);
            s[0] = _sbox(s[0] + KI2);
            _matI(s);
            s[0] = _sbox(s[0] + KI3);
            _matI(s);
            s[0] = _sbox(s[0] + KI4);
            _matI(s);
            s[0] = _sbox(s[0] + KI5);
            _matI(s);
            s[0] = _sbox(s[0] + KI6);
            _matI(s);
            s[0] = _sbox(s[0] + KI7);
            _matI(s);
            s[0] = _sbox(s[0] + KI8);
            _matI(s);
            s[0] = _sbox(s[0] + KI9);
            _matI(s);
            s[0] = _sbox(s[0] + KI10);
            _matI(s);
            s[0] = _sbox(s[0] + KI11);
            _matI(s);
            s[0] = _sbox(s[0] + KI12);
            _matI(s);
            s[0] = _sbox(s[0] + KI13);
            _matI(s);

            _extRound(s, KE4A, KE4B);
            _extRound(s, KE5A, KE5B);
            _extRound(s, KE6A, KE6B);
            _extRound(s, KE7A, KE7B);

            // The only place reduction is owed: on the way out.
            s[0] %= P;
            s[1] %= P;
            s[2] %= P;
            s[3] %= P;
            s[4] %= P;
            s[5] %= P;
            s[6] %= P;
            s[7] %= P;
            s[8] %= P;
            s[9] %= P;
            s[10] %= P;
            s[11] %= P;
            s[12] %= P;
            s[13] %= P;
            s[14] %= P;
            s[15] %= P;
            return s;
        }
    }

    /// @notice Rate-8 capacity-8 sponge over M31 words; returns the 8-word node.
    /// @dev Absorbs eight values per block into cells 0–7 and permutes after each.
    ///      A trailing partial block additionally bumps capacity cell 15 as a
    ///      domain-separation flag, so `[a,b]` and `[a,b,0,…]` cannot collide.
    ///      An EMPTY input permutes zero times and returns the zero node — the
    ///      same convention as `sponge_t16` in poseidon2_t16.rs.
    function sponge8(uint256[] memory values)
        internal pure
        returns (uint256[8] memory node)
    {
        unchecked {
            uint256[16] memory s;
            uint256 n = values.length;
            uint256 full = (n / 8) * 8;

            for (uint256 i = 0; i < full; i += 8) {
                for (uint256 k = 0; k < 8; k++) {
                    s[k] = _addM31(s[k], values[i + k] % P);
                }
                permute(s);
            }
            if (full < n) {
                for (uint256 k = 0; full + k < n; k++) {
                    s[k] = _addM31(s[k], values[full + k] % P);
                }
                s[15] = _addM31(s[15], 1);
                permute(s);
            }

            for (uint256 k = 0; k < 8; k++) {
                node[k] = s[k];
            }
        }
    }

    /// @dev a + b mod P for a, b < P.
    function _addM31(uint256 a, uint256 b) private pure returns (uint256 r) {
        unchecked {
            r = a + b;
            if (r >= P) r -= P;
        }
    }

    /// @notice Two-to-one compression for 248-bit wide Merkle nodes.
    /// @dev Node = 8 M31 words. state = (left‖right) → permute → cells 0..7.
    ///      Matches `compress_t16` in poseidon2_t16.rs.
    function compress8(uint256[8] memory left, uint256[8] memory right)
        internal pure
        returns (uint256[8] memory out)
    {
        uint256[16] memory s;
        for (uint256 i = 0; i < 8; i++) {
            s[i] = left[i];
            s[8 + i] = right[i];
        }
        s = permute(s);
        for (uint256 i = 0; i < 8; i++) {
            out[i] = s[i];
        }
    }
}
