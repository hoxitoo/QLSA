// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./M31.sol";

/// @title Poseidon2M31T8 — Poseidon2 permutation over M31 with state width t = 8
///
/// Parameters — exactly match stark_stwo/src/poseidon2_t8.rs (research instance,
/// same constant-derivation convention as the t=2/t=4 libraries):
///   field:     M31 = GF(2^31-1 = 2_147_483_647)
///   t = 8      state width (eight M31 elements)
///   α = 5      S-box exponent (x ↦ x^5 mod P)
///   R_F = 8    external (full) rounds, split 4 + 4
///   R_P = 14   internal (partial) rounds, S-box on cell 0 only
///   M_E:       [[2·M4, M4], [M4, 2·M4]] (Poseidon2 §5.1 block matrix; apply M4
///              to each 4-cell block, then add the block-sum to every block).
///              M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]
///   M_I:       J + diag(1,…,8)  (all-ones plus diagonal; invertible over M31)
///   RC:        RC[i] = u32_be(SHA-256("QLSA-Poseidon2-t8" ‖ i_be4)[..4]) mod P,
///              i in 0..78 (external rounds use RC[0..64] — 8 per round;
///              internal rounds use RC[64..78])
///
/// Permutation layout (Poseidon2 spec):
///   state ← M_E·state
///   4 × (AddRC → SBox(all 8) → M_E)        external rounds 0..3, RC[0..32)
///   14 × (AddRC[0] → SBox(cell 0) → M_I)   internal rounds,      RC[64..78)
///   4 × (AddRC → SBox(all 8) → M_E)        external rounds 4..7, RC[32..64)
///
/// Motivation: VFRI10's t=4 backend emits 2-word (62-bit) Merkle nodes —
/// node collision ~2^31.  Width 8 lets a 2-to-1 compression carry 4-word
/// (124-bit) children, raising node collision cost to ~2^62.  This is the next
/// rung on the ladder to 128-bit binding (t=16 → 8-word nodes → ~2^124).
///
/// Cross-check vectors (frozen in stark_stwo poseidon2_t8.rs test_reference_vectors):
///   permute([0;8])             → [216312942,155820902,926495998,1144704772,
///                                 1934653642,1380128781,12500119,1030062085]
///   permute([1..8])            → [890515421,531626735,2060583819,1311645369,
///                                 1183191699,1798384804,1654039744,1303745775]
///   sponge([1..8]) node[0..4]  → [1440998077,1368105497,587877558,669993876]
///   compress([1..4],[5..8])    → [890515421,531626735,2060583819,1311645369]
library Poseidon2M31T8 {

    uint256 internal constant P = M31.P; // 2^31 - 1

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

    /// @dev M4 block multiply (Poseidon2 §5.1 fast path, 8 additions).
    function _m4(uint256 a0, uint256 a1, uint256 a2, uint256 a3)
        private pure
        returns (uint256, uint256, uint256, uint256)
    {
        uint256 t0 = _add(a0, a1);
        uint256 t1 = _add(a2, a3);
        uint256 t2 = _add(_add(a1, a1), t1);
        uint256 t3 = _add(_add(a3, a3), t0);
        uint256 t4 = _add(_add(_add(t1, t1), _add(t1, t1)), t3);
        uint256 t5 = _add(_add(_add(t0, t0), _add(t0, t0)), t2);
        return (_add(t3, t5), t5, _add(t2, t4), t4);
    }

    /// @dev External linear layer: M_E = [[2·M4, M4], [M4, 2·M4]].
    ///      out_block_i = M4·block_i + (M4·block_0 + M4·block_1).
    function _matE(uint256[8] memory s) private pure {
        (uint256 a0, uint256 a1, uint256 a2, uint256 a3) = _m4(s[0], s[1], s[2], s[3]);
        (uint256 b0, uint256 b1, uint256 b2, uint256 b3) = _m4(s[4], s[5], s[6], s[7]);
        uint256 g0 = _add(a0, b0);
        uint256 g1 = _add(a1, b1);
        uint256 g2 = _add(a2, b2);
        uint256 g3 = _add(a3, b3);
        s[0] = _add(a0, g0);
        s[1] = _add(a1, g1);
        s[2] = _add(a2, g2);
        s[3] = _add(a3, g3);
        s[4] = _add(b0, g0);
        s[5] = _add(b1, g1);
        s[6] = _add(b2, g2);
        s[7] = _add(b3, g3);
    }

    /// @dev Internal linear layer: out_i = (Σ_j s_j) + μ_i·s_i with μ = (1,…,8).
    ///      μ_i·s_i computed as a single mulmod (== (i+1) repeated adds in the
    ///      Rust reference, identical result mod P).
    function _matI(uint256[8] memory s) private pure {
        uint256 sum = 0;
        for (uint256 i = 0; i < 8; i++) {
            sum = _add(sum, s[i]);
        }
        for (uint256 i = 0; i < 8; i++) {
            s[i] = _add(sum, mulmod(i + 1, s[i], P));
        }
    }

    /// @dev One external round: AddRC → SBox(all 8) → M_E.
    function _ext(
        uint256[8] memory s,
        uint256 c0, uint256 c1, uint256 c2, uint256 c3,
        uint256 c4, uint256 c5, uint256 c6, uint256 c7
    ) private pure {
        s[0] = _sbox(_add(s[0], c0));
        s[1] = _sbox(_add(s[1], c1));
        s[2] = _sbox(_add(s[2], c2));
        s[3] = _sbox(_add(s[3], c3));
        s[4] = _sbox(_add(s[4], c4));
        s[5] = _sbox(_add(s[5], c5));
        s[6] = _sbox(_add(s[6], c6));
        s[7] = _sbox(_add(s[7], c7));
        _matE(s);
    }

    /// @dev One internal round: AddRC to cell 0 → SBox(cell 0) → M_I.
    function _int(uint256[8] memory s, uint256 c0) private pure {
        s[0] = _sbox(_add(s[0], c0));
        _matI(s);
    }

    /// @notice Apply the Poseidon2 t=8 permutation in place to an 8-cell state.
    /// @dev All inputs must be < P; outputs are < P.
    function permute(uint256[8] memory s) internal pure returns (uint256[8] memory) {
        _matE(s);

        // External rounds 0..3 — RC[0..32).
        _ext(s, 2012176458, 1849299961, 1732939933, 390435213, 1583598125, 1521506328, 1850315157, 593064883);
        _ext(s, 442979704, 49299287, 668322884, 1478447923, 2117627097, 894462472, 335092600, 304090409);
        _ext(s, 1725083656, 1823780446, 1589693490, 336928399, 1533176076, 1472808391, 1197491867, 1980232791);
        _ext(s, 1332985942, 553469441, 542603061, 145062400, 1801771230, 501797052, 191408558, 124556117);

        // Internal rounds 0..13 — RC[64..78).
        _int(s, 672534258);
        _int(s, 1626884035);
        _int(s, 1258567472);
        _int(s, 1521030780);
        _int(s, 609641534);
        _int(s, 426249300);
        _int(s, 1360556010);
        _int(s, 668676905);
        _int(s, 453695314);
        _int(s, 178868843);
        _int(s, 1293599881);
        _int(s, 595916213);
        _int(s, 1841032014);
        _int(s, 29885509);

        // External rounds 4..7 — RC[32..64).
        _ext(s, 767378382, 870276988, 2046892345, 12605708, 1937961243, 903615558, 781360720, 458985484);
        _ext(s, 768021800, 1017409239, 1219264179, 1642454766, 518313705, 101708341, 1618375810, 1323121046);
        _ext(s, 1721228118, 339098950, 1976827842, 1756100371, 1309626382, 451150501, 491114795, 994585973);
        _ext(s, 1034786474, 575533575, 1809299734, 1497205669, 961538106, 1152123009, 606500650, 2046687220);

        return s;
    }

    /// @notice Two-to-one compression for 124-bit wide Merkle nodes.
    /// @dev Node = 4 M31 words.  state = (l0..l3, r0..r3) → permute → (s0..s3).
    ///      Matches compress_t8 in poseidon2_t8.rs.
    function compress(uint256[4] memory left, uint256[4] memory right)
        internal pure
        returns (uint256[4] memory out)
    {
        uint256[8] memory s;
        s[0] = left[0]; s[1] = left[1]; s[2] = left[2]; s[3] = left[3];
        s[4] = right[0]; s[5] = right[1]; s[6] = right[2]; s[7] = right[3];
        s = permute(s);
        out[0] = s[0]; out[1] = s[1]; out[2] = s[2]; out[3] = s[3];
    }

    /// @notice Rate-4 capacity-4 sponge over a sequence of M31 field elements.
    ///
    /// Protocol (matches sponge_t8 in poseidon2_t8.rs):
    ///   state ← (0,…,0)
    ///   for each 4-word block (v0..v3): s0..s3 += v0..v3; permute
    ///   odd trailing 1..3 words:        s0.. += v..;  s7 += 1;  permute
    /// The odd-length flag lives in capacity cell 7 — outside the rate — so no
    /// choice of data words can imitate a padded final block.
    ///
    /// @param values Array of M31 field elements (each < P).
    /// @return out   The 4-word (124-bit) node: state cells 0..3 after absorption.
    function sponge(uint256[] memory values) internal pure returns (uint256[4] memory out) {
        uint256[8] memory s;
        uint256 n = values.length;
        uint256 i = 0;
        for (; i + 4 <= n; i += 4) {
            s[0] = _add(s[0], values[i]);
            s[1] = _add(s[1], values[i + 1]);
            s[2] = _add(s[2], values[i + 2]);
            s[3] = _add(s[3], values[i + 3]);
            s = permute(s);
        }
        if (i < n) {
            uint256 k = 0;
            for (; i < n; i++) {
                s[k] = _add(s[k], values[i]);
                k++;
            }
            s[7] = _add(s[7], 1);
            s = permute(s);
        }
        out[0] = s[0]; out[1] = s[1]; out[2] = s[2]; out[3] = s[3];
    }
}
