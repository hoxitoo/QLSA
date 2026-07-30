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

    // ── Lazy reduction ────────────────────────────────────────────────────────
    //
    // The linear layers below add WITHOUT reducing mod P.  This is exact, not an
    // approximation: addition and multiplication mod P are ring homomorphisms, so
    // an unreduced accumulator ≡ the reduced one (mod P), and every S-box goes
    // through `mulmod(…, P)`, which reduces its output regardless of how large
    // its inputs were.  Reduction therefore only has to happen where a value
    // LEAVES the permutation (see the `% P` on permute8's return).
    //
    // Magnitude bound (why uint256 never overflows).  M_E's largest row-coefficient
    // sum is 48 (2·M4 ‖ M4, M4's max row sum being 16), and every external round
    // S-boxes before its linear layer, so M_E only ever sees inputs < 2^32 and
    // emits < 48·2^32 < 2^38.  An internal round emits sum + μ_i·s_i < 8·B + P, so
    // 14 of them starting from B < 2^38 stay under 8^14·2^38 < 2^80.  The following
    // external round S-boxes first, collapsing back under P.  Peak ≈ 2^80 ≪ 2^256.

    /// @dev x^5 mod P — the Poseidon2 S-box.  3 mulmods; accepts unreduced x.
    function _sbox(uint256 x) private pure returns (uint256) {
        uint256 x2 = mulmod(x, x, P);
        uint256 x4 = mulmod(x2, x2, P);
        return mulmod(x4, x, P);
    }

    /// @dev M4 block multiply (Poseidon2 §5.1 fast path), unreduced.
    function _m4(uint256 a0, uint256 a1, uint256 a2, uint256 a3)
        private pure
        returns (uint256, uint256, uint256, uint256)
    {
        unchecked {
            uint256 t0 = a0 + a1;
            uint256 t1 = a2 + a3;
            uint256 t2 = a1 + a1 + t1;
            uint256 t3 = a3 + a3 + t0;
            uint256 t4 = (t1 << 2) + t3;
            uint256 t5 = (t0 << 2) + t2;
            return (t3 + t5, t5, t2 + t4, t4);
        }
    }

    /// @dev External linear layer: M_E = [[2·M4, M4], [M4, 2·M4]], unreduced.
    ///      out_block_i = M4·block_i + (M4·block_0 + M4·block_1).
    function _matE(
        uint256 s0, uint256 s1, uint256 s2, uint256 s3,
        uint256 s4, uint256 s5, uint256 s6, uint256 s7
    )
        private pure
        returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256)
    {
        unchecked {
            (uint256 a0, uint256 a1, uint256 a2, uint256 a3) = _m4(s0, s1, s2, s3);
            (uint256 b0, uint256 b1, uint256 b2, uint256 b3) = _m4(s4, s5, s6, s7);
            uint256 g0 = a0 + b0;
            uint256 g1 = a1 + b1;
            uint256 g2 = a2 + b2;
            uint256 g3 = a3 + b3;
            return (
                a0 + g0, a1 + g1, a2 + g2, a3 + g3,
                b0 + g0, b1 + g1, b2 + g2, b3 + g3
            );
        }
    }

    /// @dev Internal linear layer: out_i = (Σ_j s_j) + μ_i·s_i with μ = (1,…,8).
    ///      μ_i·s_i is one mulmod (== (i+1) repeated adds in the Rust reference,
    ///      identical result mod P); the Σ is left unreduced.
    function _matI(
        uint256 s0, uint256 s1, uint256 s2, uint256 s3,
        uint256 s4, uint256 s5, uint256 s6, uint256 s7
    )
        private pure
        returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256)
    {
        unchecked {
            uint256 sum = s0 + s1 + s2 + s3 + s4 + s5 + s6 + s7;
            return (
                sum + (s0 % P),
                sum + mulmod(2, s1, P),
                sum + mulmod(3, s2, P),
                sum + mulmod(4, s3, P),
                sum + mulmod(5, s4, P),
                sum + mulmod(6, s5, P),
                sum + mulmod(7, s6, P),
                sum + mulmod(8, s7, P)
            );
        }
    }

    /// @dev One internal round: AddRC to cell 0 → SBox(cell 0) → M_I.
    function _int(
        uint256 s0, uint256 s1, uint256 s2, uint256 s3,
        uint256 s4, uint256 s5, uint256 s6, uint256 s7,
        uint256 c0
    )
        private pure
        returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256)
    {
        unchecked {
            return _matI(_sbox(s0 + c0), s1, s2, s3, s4, s5, s6, s7);
        }
    }

    /// @notice Apply the Poseidon2 t=8 permutation to a state held on the stack.
    /// @dev Inputs may exceed P (they are reduced through the first S-box layer);
    ///      every returned cell is < P.  This is the hot path — the array-based
    ///      `permute` below is a thin wrapper kept for callers/tests that already
    ///      hold a `uint256[8]`.
    function permute8(
        uint256 s0, uint256 s1, uint256 s2, uint256 s3,
        uint256 s4, uint256 s5, uint256 s6, uint256 s7
    )
        internal pure
        returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256)
    {
        unchecked {
            (s0, s1, s2, s3, s4, s5, s6, s7) = _matE(s0, s1, s2, s3, s4, s5, s6, s7);

            // External rounds 0..3 — RC[0..32).
            (s0, s1, s2, s3, s4, s5, s6, s7) = _matE(
                _sbox(s0 + 2012176458), _sbox(s1 + 1849299961), _sbox(s2 + 1732939933), _sbox(s3 + 390435213),
                _sbox(s4 + 1583598125), _sbox(s5 + 1521506328), _sbox(s6 + 1850315157), _sbox(s7 + 593064883)
            );
            (s0, s1, s2, s3, s4, s5, s6, s7) = _matE(
                _sbox(s0 + 442979704), _sbox(s1 + 49299287), _sbox(s2 + 668322884), _sbox(s3 + 1478447923),
                _sbox(s4 + 2117627097), _sbox(s5 + 894462472), _sbox(s6 + 335092600), _sbox(s7 + 304090409)
            );
            (s0, s1, s2, s3, s4, s5, s6, s7) = _matE(
                _sbox(s0 + 1725083656), _sbox(s1 + 1823780446), _sbox(s2 + 1589693490), _sbox(s3 + 336928399),
                _sbox(s4 + 1533176076), _sbox(s5 + 1472808391), _sbox(s6 + 1197491867), _sbox(s7 + 1980232791)
            );
            (s0, s1, s2, s3, s4, s5, s6, s7) = _matE(
                _sbox(s0 + 1332985942), _sbox(s1 + 553469441), _sbox(s2 + 542603061), _sbox(s3 + 145062400),
                _sbox(s4 + 1801771230), _sbox(s5 + 501797052), _sbox(s6 + 191408558), _sbox(s7 + 124556117)
            );

            // Internal rounds 0..13 — RC[64..78).
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 672534258);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 1626884035);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 1258567472);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 1521030780);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 609641534);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 426249300);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 1360556010);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 668676905);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 453695314);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 178868843);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 1293599881);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 595916213);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 1841032014);
            (s0, s1, s2, s3, s4, s5, s6, s7) = _int(s0, s1, s2, s3, s4, s5, s6, s7, 29885509);

            // External rounds 4..7 — RC[32..64).
            (s0, s1, s2, s3, s4, s5, s6, s7) = _matE(
                _sbox(s0 + 767378382), _sbox(s1 + 870276988), _sbox(s2 + 2046892345), _sbox(s3 + 12605708),
                _sbox(s4 + 1937961243), _sbox(s5 + 903615558), _sbox(s6 + 781360720), _sbox(s7 + 458985484)
            );
            (s0, s1, s2, s3, s4, s5, s6, s7) = _matE(
                _sbox(s0 + 768021800), _sbox(s1 + 1017409239), _sbox(s2 + 1219264179), _sbox(s3 + 1642454766),
                _sbox(s4 + 518313705), _sbox(s5 + 101708341), _sbox(s6 + 1618375810), _sbox(s7 + 1323121046)
            );
            (s0, s1, s2, s3, s4, s5, s6, s7) = _matE(
                _sbox(s0 + 1721228118), _sbox(s1 + 339098950), _sbox(s2 + 1976827842), _sbox(s3 + 1756100371),
                _sbox(s4 + 1309626382), _sbox(s5 + 451150501), _sbox(s6 + 491114795), _sbox(s7 + 994585973)
            );
            (s0, s1, s2, s3, s4, s5, s6, s7) = _matE(
                _sbox(s0 + 1034786474), _sbox(s1 + 575533575), _sbox(s2 + 1809299734), _sbox(s3 + 1497205669),
                _sbox(s4 + 961538106), _sbox(s5 + 1152123009), _sbox(s6 + 606500650), _sbox(s7 + 2046687220)
            );

            // The only place reduction is owed: on the way out.
            return (s0 % P, s1 % P, s2 % P, s3 % P, s4 % P, s5 % P, s6 % P, s7 % P);
        }
    }

    /// @notice Array-shaped wrapper around `permute8`.
    /// @dev Inputs need not be < P; outputs are < P.
    function permute(uint256[8] memory s) internal pure returns (uint256[8] memory) {
        (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]) =
            permute8(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
        return s;
    }

    /// @notice Two-to-one compression for 124-bit wide Merkle nodes.
    /// @dev Node = 4 M31 words.  state = (l0..l3, r0..r3) → permute → (s0..s3).
    ///      Matches compress_t8 in poseidon2_t8.rs.
    function compress4(
        uint256 l0, uint256 l1, uint256 l2, uint256 l3,
        uint256 r0, uint256 r1, uint256 r2, uint256 r3
    )
        internal pure
        returns (uint256 o0, uint256 o1, uint256 o2, uint256 o3)
    {
        (o0, o1, o2, o3, , , , ) = permute8(l0, l1, l2, l3, r0, r1, r2, r3);
    }

    /// @notice Array-shaped wrapper around `compress4`.
    function compress(uint256[4] memory left, uint256[4] memory right)
        internal pure
        returns (uint256[4] memory out)
    {
        (out[0], out[1], out[2], out[3]) = compress4(
            left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3]
        );
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
    /// @param values Array of M31 field elements. Inputs are reduced mod P on
    ///        absorption so the on-chain hash matches the Rust `sponge_t8`
    ///        reference (which reduces every word) bit-for-bit even for
    ///        non-canonical words ≥ P — a defense-in-depth parity guard; in the
    ///        VFRI pipeline every word is already a QM31 limb < P.
    /// @return out   The 4-word (124-bit) node: state cells 0..3 after absorption.
    function sponge(uint256[] memory values) internal pure returns (uint256[4] memory out) {
        (out[0], out[1], out[2], out[3]) = sponge4(values);
    }

    /// @notice `sponge` returning the node's four words on the stack.
    function sponge4(uint256[] memory values)
        internal pure
        returns (uint256 n0, uint256 n1, uint256 n2, uint256 n3)
    {
        unchecked {
            uint256 s0;
            uint256 s1;
            uint256 s2;
            uint256 s3;
            uint256 s4;
            uint256 s5;
            uint256 s6;
            uint256 s7;
            uint256 n = values.length;
            uint256 i = 0;
            for (; i + 4 <= n; i += 4) {
                // Absorbed sums stay < 2^32; permute8 tolerates unreduced inputs.
                s0 += values[i] % P;
                s1 += values[i + 1] % P;
                s2 += values[i + 2] % P;
                s3 += values[i + 3] % P;
                (s0, s1, s2, s3, s4, s5, s6, s7) = permute8(s0, s1, s2, s3, s4, s5, s6, s7);
            }
            if (i < n) {
                s0 += values[i] % P;
                if (i + 1 < n) s1 += values[i + 1] % P;
                if (i + 2 < n) s2 += values[i + 2] % P;
                s7 += 1;
                (s0, s1, s2, s3, s4, s5, s6, s7) = permute8(s0, s1, s2, s3, s4, s5, s6, s7);
            }
            return (s0, s1, s2, s3);
        }
    }
}
