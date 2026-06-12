// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./M31.sol";

/// @title Poseidon2M31T4 — Poseidon2 permutation over M31 with state width t = 4 (MVP-6)
///
/// Parameters — exactly match stark_stwo/src/poseidon2_t4.rs (research instance,
/// same constant-derivation convention as the t=2 library):
///   field:     M31 = GF(2^31-1 = 2_147_483_647)
///   t = 4      state width (four M31 elements)
///   α = 5      S-box exponent (x ↦ x^5 mod P)
///   R_F = 8    external (full) rounds, split 4 + 4
///   R_P = 21   internal (partial) rounds, S-box on cell 0 only
///   M_E:       M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]  (Poseidon2 §5.1)
///   M_I:       J + diag(1,2,3,4)  (all-ones plus diagonal; invertible over M31)
///   RC:        SHA-256 K[0..53] reduced mod P
///              (external rounds use K[0..32] — 4 per round; internal K[32..53])
///
/// Permutation layout (Poseidon2 spec):
///   state ← M_E·state
///   4 × (AddRC → SBox(all) → M_E)        external rounds 0..3, K[0..16)
///   21 × (AddRC[0] → SBox(cell 0) → M_I) internal rounds,      K[32..53)
///   4 × (AddRC → SBox(all) → M_E)        external rounds 4..7, K[16..32)
///
/// Motivation: t=2 sponge capacity and Merkle node content are 62 bits
/// (collision ~2^31).  Width 4 enables a capacity-2 sponge and 124-bit
/// wide nodes — node collision cost ~2^62.
///
/// Cross-check vectors (frozen in stark_stwo poseidon2_t4.rs test_reference_vectors):
///   permute(0,0,0,0)        → (201_095_161, 440_871_427, 944_955_487, 992_273_343)
///   permute(1,2,3,4)        → (1_706_601_437, 1_471_208_702, 244_698_605, 2_091_016_348)
///   sponge([1..8])          → (1_315_656_215, 594_434_174, 137_860_571, 1_608_246_984)
///   compress([1,2],[3,4])   → (1_706_601_437, 1_471_208_702)
library Poseidon2M31T4 {

    uint256 internal constant P = M31.P;  // 2^31 - 1

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

    /// @dev External linear layer: state ← M4·state via the 8-addition fast path
    ///      (matches mat_external in poseidon2_t4.rs):
    ///        t0 = s0+s1;  t1 = s2+s3
    ///        t2 = 2·s1 + t1;  t3 = 2·s3 + t0
    ///        t4 = 4·t1 + t3;  t5 = 4·t0 + t2
    ///        out = (t3+t5, t5, t2+t4, t4)
    function _matE(uint256 s0, uint256 s1, uint256 s2, uint256 s3)
        private pure
        returns (uint256, uint256, uint256, uint256)
    {
        uint256 t0 = _add(s0, s1);
        uint256 t1 = _add(s2, s3);
        uint256 t2 = _add(_add(s1, s1), t1);
        uint256 t3 = _add(_add(s3, s3), t0);
        uint256 t4 = _add(_add(_add(t1, t1), _add(t1, t1)), t3);
        uint256 t5 = _add(_add(_add(t0, t0), _add(t0, t0)), t2);
        return (_add(t3, t5), t5, _add(t2, t4), t4);
    }

    /// @dev Internal linear layer: out_i = (Σ_j s_j) + μ_i·s_i with μ = (1,2,3,4).
    function _matI(uint256 s0, uint256 s1, uint256 s2, uint256 s3)
        private pure
        returns (uint256, uint256, uint256, uint256)
    {
        uint256 sum = _add(_add(s0, s1), _add(s2, s3));
        return (
            _add(sum, s0),
            _add(sum, _add(s1, s1)),
            _add(sum, _add(_add(s2, s2), s2)),
            _add(sum, _add(_add(s3, s3), _add(s3, s3)))
        );
    }

    /// @dev One external round: AddRC → SBox(all 4) → M_E.
    function _ext(
        uint256 s0, uint256 s1, uint256 s2, uint256 s3,
        uint256 rc0, uint256 rc1, uint256 rc2, uint256 rc3
    ) private pure returns (uint256, uint256, uint256, uint256) {
        s0 = _sbox(_add(s0, rc0));
        s1 = _sbox(_add(s1, rc1));
        s2 = _sbox(_add(s2, rc2));
        s3 = _sbox(_add(s3, rc3));
        return _matE(s0, s1, s2, s3);
    }

    /// @dev One internal round: AddRC to cell 0 → SBox(cell 0) → M_I.
    function _int(
        uint256 s0, uint256 s1, uint256 s2, uint256 s3,
        uint256 rc0
    ) private pure returns (uint256, uint256, uint256, uint256) {
        s0 = _sbox(_add(s0, rc0));
        return _matI(s0, s1, s2, s3);
    }

    /// @notice Apply the Poseidon2 t=4 permutation to state (s0, s1, s2, s3).
    /// @dev All inputs must be < P; outputs are < P.
    function permute(uint256 s0, uint256 s1, uint256 s2, uint256 s3)
        internal pure
        returns (uint256, uint256, uint256, uint256)
    {
        (s0, s1, s2, s3) = _matE(s0, s1, s2, s3);

        // External rounds 0..3 — K[0..16) reduced mod P.
        (s0, s1, s2, s3) = _ext(s0, s1, s2, s3, 1116352408, 1899447441, 901839824, 1773525926);
        (s0, s1, s2, s3) = _ext(s0, s1, s2, s3, 961987163, 1508970993, 306152101, 723279574);
        (s0, s1, s2, s3) = _ext(s0, s1, s2, s3, 1476897433, 310598401, 607225278, 1426881987);
        (s0, s1, s2, s3) = _ext(s0, s1, s2, s3, 1925078388, 14594559, 467404456, 1100738933);

        // Internal rounds 0..20 — K[32..53) reduced mod P.
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 666307205);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 773529912);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 1294757372);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 1396182291);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 1695183700);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 1986661051);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 29542703);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 309472390);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 583002274);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 672818764);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 1112247153);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 1198281124);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 1368582170);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 1452869157);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 1947088262);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 275423344);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 430227734);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 506948616);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 659060556);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 883997877);
        (s0, s1, s2, s3) = _int(s0, s1, s2, s3, 958139571);

        // External rounds 4..7 — K[16..32) reduced mod P.
        (s0, s1, s2, s3) = _ext(s0, s1, s2, s3, 1687906754, 1874741127, 264347078, 604807628);
        (s0, s1, s2, s3) = _ext(s0, s1, s2, s3, 770255983, 1249150122, 1555081692, 1996064986);
        (s0, s1, s2, s3) = _ext(s0, s1, s2, s3, 406737235, 674350702, 805513161, 1062830024);
        (s0, s1, s2, s3) = _ext(s0, s1, s2, s3, 1189088244, 1437045064, 113926993, 338241895);

        return (s0, s1, s2, s3);
    }

    /// @notice Two-to-one compression for 124-bit wide Merkle nodes.
    /// @dev Node = 2 M31 words.  state = (l0, l1, r0, r1) → permute → (s0, s1).
    ///      Matches compress_t4 in poseidon2_t4.rs.
    function compress(uint256 l0, uint256 l1, uint256 r0, uint256 r1)
        internal pure
        returns (uint256 out0, uint256 out1)
    {
        (out0, out1, , ) = permute(l0, l1, r0, r1);
    }

    /// @notice Rate-2 capacity-2 sponge over a sequence of M31 field elements.
    ///
    /// Protocol (matches sponge_t4 in poseidon2_t4.rs):
    ///   state ← (0, 0, 0, 0)
    ///   for each pair (v0, v1):  s0 += v0; s1 += v1; permute
    ///   odd trailing word v:     s0 += v;  s3 += 1;  permute
    /// The odd-length flag lives in capacity cell 3 — outside the rate — so no
    /// choice of data words can imitate a padded final block.
    ///
    /// @param values  Array of M31 field elements (each < P).
    /// @return s0 First state element after absorption (< P).
    /// @return s1 Second state element after absorption (< P).
    function sponge(uint256[] memory values)
        internal pure
        returns (uint256 s0, uint256 s1)
    {
        uint256 s2 = 0;
        uint256 s3 = 0;
        uint256 n = values.length;
        uint256 i = 0;
        for (; i + 1 < n; i += 2) {
            s0 = _add(s0, values[i]);
            s1 = _add(s1, values[i + 1]);
            (s0, s1, s2, s3) = permute(s0, s1, s2, s3);
        }
        if (i < n) {
            s0 = _add(s0, values[i]);
            s3 = _add(s3, 1);
            (s0, s1, s2, s3) = permute(s0, s1, s2, s3);
        }
    }
}
