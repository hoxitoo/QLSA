// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Poseidon2M31T4.sol";

/// @title Poseidon2ChannelT4 — Poseidon2 t=4 duplex Fiat-Shamir channel (VFRI10)
///
/// Structural analogue of Poseidon2Channel (t=2) widened to the t=4
/// permutation.  Poseidon2Channel's state is two M31 cells with a single
/// capacity cell — transcript binding tops out at ~2^31 (limitation #6).
/// This channel runs the t=4 permutation: absorb is rate-1 into cell 0
/// (cells 1–3 form a 93-bit capacity), and each draw squeezes the two
/// rate-adjacent cells (s0, s1).
///
/// State: (s0, s1, s2, s3: uint32, nDraws: uint32) — four M31 cells + counter.
///
/// Absorb protocol (matches struct P2T4Channel in vfri2_bridge.rs):
///   absorb(word):  s0 = (s0 + reduce(word)) mod P; permute_t4
///   mixRoot:       absorb(bytes[28..32]); nDraws = 0
///   mixRootW:      absorb(bytes[24..28]); absorb(bytes[28..32]); nDraws = 0
///   mixRootFull:   absorb each of the 8 BE u32 words; nDraws = 0
///   mixU32s:       absorb each word; nDraws = 0
///
/// Squeeze protocol (matches P2T4Channel::draw_pair):
///   _drawPair: save (w0,w1)=(s0,s1); s0=(s0+nDraws)%P; permute_t4; nDraws++
///   drawSecureFelt: two _drawPair calls → QM31 = (CM31(w0,w1)<<64)|CM31(w2,w3)
///   drawQueries: repeated _drawPair calls; each yields 2 candidate indices
library Poseidon2ChannelT4 {

    uint256 private constant P = 2_147_483_647; // 2^31 - 1

    struct State {
        uint32 s0;
        uint32 s1;
        uint32 s2;
        uint32 s3;
        uint32 nDraws;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    /// @notice Return a fresh channel state (all-zero state, zero counter).
    function init() internal pure returns (State memory s) {
        s.s0 = 0;
        s.s1 = 0;
        s.s2 = 0;
        s.s3 = 0;
        s.nDraws = 0;
    }

    // ── Absorb operations ─────────────────────────────────────────────────────

    /// @notice Absorb the low 4 bytes (bytes[28..32]) of a root; reset counter.
    function mixRoot(State memory s, bytes32 root) internal pure {
        _absorb(s, uint32(uint256(root)));
        s.nDraws = 0;
    }

    /// @notice Absorb a wide t=4/t=2 node root (62-bit content) as two BE u32
    ///         words: bytes[24..28] then bytes[28..32]; reset counter.
    function mixRootW(State memory s, bytes32 root) internal pure {
        _absorb(s, uint32(uint256(root) >> 32));
        _absorb(s, uint32(uint256(root)));
        s.nDraws = 0;
    }

    /// @notice Absorb ALL 32 bytes of a root as 8 big-endian u32 words; reset
    ///         counter.  Binds the full 256 bits (embedded trace root, batch
    ///         merkle root) into the transcript.
    function mixRootFull(State memory s, bytes32 root) internal pure {
        for (uint256 i = 0; i < 8; i++) {
            _absorb(s, uint32(uint256(root) >> (224 - 32 * i)));
        }
        s.nDraws = 0;
    }

    /// @notice Absorb an array of uint32 words, then reset the draw counter.
    function mixU32s(State memory s, uint32[] memory words) internal pure {
        for (uint256 i = 0; i < words.length; i++) {
            _absorb(s, words[i]);
        }
        s.nDraws = 0;
    }

    // ── Squeeze operations ────────────────────────────────────────────────────

    /// @notice Squeeze one QM31 secure-field element (two _drawPair calls).
    function drawSecureFelt(State memory s) internal pure returns (uint128) {
        (uint32 w0, uint32 w1) = _drawPair(s);
        (uint32 w2, uint32 w3) = _drawPair(s);
        uint64 c0 = (uint64(w0) << 32) | uint64(w1);
        uint64 c1 = (uint64(w2) << 32) | uint64(w3);
        return (uint128(c0) << 64) | uint128(c1);
    }

    /// @notice Squeeze n FRI query indices for a domain of size 2^logDomainSize.
    function drawQueries(
        State memory s,
        uint256 logDomainSize,
        uint256 nQueries
    ) internal pure returns (uint256[] memory queries) {
        require(logDomainSize <= 31, "Poseidon2ChannelT4: logDomainSize > 31");
        uint256 mask = (1 << logDomainSize) - 1;
        queries = new uint256[](nQueries);
        uint256 filled = 0;
        while (filled < nQueries) {
            (uint32 w0, uint32 w1) = _drawPair(s);
            queries[filled++] = uint256(w0) & mask;
            if (filled < nQueries) {
                queries[filled++] = uint256(w1) & mask;
            }
        }
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// @dev Absorb one uint32 word into cell 0, then permute.
    ///
    /// Reduces word to M31 first (two conditional subtractions) so arbitrary
    /// u32 values (e.g. low 4 bytes of a keccak256 hash) are safe: a u32 is
    /// < 2^32 = 2*P+2, so at most two subtractions are needed.
    function _absorb(State memory s, uint32 word) private pure {
        uint256 w = uint256(word);
        if (w >= P) w -= P;
        if (w >= P) w -= P;
        uint256 s0;
        unchecked { s0 = uint256(s.s0) + w; }
        if (s0 >= P) s0 -= P;
        (uint256 o0, uint256 o1, uint256 o2, uint256 o3) =
            Poseidon2M31T4.permute(s0, uint256(s.s1), uint256(s.s2), uint256(s.s3));
        s.s0 = uint32(o0);
        s.s1 = uint32(o1);
        s.s2 = uint32(o2);
        s.s3 = uint32(o3);
    }

    /// @dev Squeeze one pair of M31 words (s0, s1).
    ///
    /// Protocol (matches P2T4Channel::draw_pair):
    ///   1. Save current (s0, s1) as (w0, w1)
    ///   2. Mix nDraws counter: s0 = (s0 + nDraws) mod P; permute
    ///   3. Update internal state; nDraws++
    ///   4. Return SAVED (w0, w1) — not the updated state
    function _drawPair(State memory s) private pure returns (uint32 w0, uint32 w1) {
        w0 = s.s0;
        w1 = s.s1;
        uint256 s0;
        unchecked { s0 = uint256(s.s0) + uint256(s.nDraws); }
        if (s0 >= P) s0 -= P;
        (uint256 o0, uint256 o1, uint256 o2, uint256 o3) =
            Poseidon2M31T4.permute(s0, uint256(s.s1), uint256(s.s2), uint256(s.s3));
        s.s0 = uint32(o0);
        s.s1 = uint32(o1);
        s.s2 = uint32(o2);
        s.s3 = uint32(o3);
        s.nDraws++;
    }
}
