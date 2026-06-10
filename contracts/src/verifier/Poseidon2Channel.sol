// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Poseidon2M31.sol";

/// @title Poseidon2Channel — Poseidon2 duplex sponge Fiat-Shamir channel (VFRI8)
///
/// Replaces TwoChannel's Blake2sM31Channel with a Poseidon2 rate-1 duplex sponge.
///
/// State: (s0: uint32, s1: uint32, nDraws: uint32)
///   s0, s1 are M31 elements (< P = 2^31-1); nDraws is the squeeze counter.
///
/// Absorb protocol (matches struct P2Channel in vfri2_bridge.rs):
///   absorb(word):
///     s0 = (s0 + word) — one-shot conditional subtraction (matches Rust m31_add)
///     (s0, s1) = permute(s0, s1)
///   mixRoot(state, root):
///     absorb(uint32(uint256(root)))   — low 32 bits = bytes[28..31] as BE u32
///     nDraws = 0
///   mixU32s(state, words[]):
///     for w in words: absorb(w)
///     nDraws = 0
///
/// Squeeze protocol (matches P2Channel::draw_pair):
///   _drawPair: save (w0,w1)=(s0,s1); s0=(s0+nDraws)%P; permute; nDraws++; return (w0,w1)
///   drawSecureFelt: two _drawPair calls → QM31 as uint128 = (CM31(w0,w1) << 64) | CM31(w2,w3)
///   drawQueries: repeated _drawPair calls; each call yields 2 candidate indices
library Poseidon2Channel {

    uint256 private constant P = 2_147_483_647; // 2^31 - 1

    struct State {
        uint32 s0;
        uint32 s1;
        uint32 nDraws;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    /// @notice Return a fresh channel state (all-zero digest, zero counter).
    function init() internal pure returns (State memory s) {
        s.s0     = 0;
        s.s1     = 0;
        s.nDraws = 0;
    }

    // ── Absorb operations ─────────────────────────────────────────────────────

    /// @notice Absorb a 32-byte Merkle root and reset the draw counter.
    ///
    /// Extracts the M31 value from bytes[28..31] (big-endian uint32 = low 32 bits
    /// of the bytes32 interpreted as uint256), then absorbs it.
    ///
    /// Matches P2Channel::mix_root: `u32::from_be_bytes(root[28..32])`.
    function mixRoot(State memory s, bytes32 root) internal pure {
        _absorb(s, uint32(uint256(root)));
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

    /// @notice Squeeze one QM31 secure-field element.
    ///
    /// Calls _drawPair twice → words w0, w1, w2, w3.
    /// QM31 encoding: c0 = CM31(w0, w1) = (w0 << 32) | w1,
    ///                c1 = CM31(w2, w3) = (w2 << 32) | w3,
    ///                result = (c0 << 64) | c1 as uint128.
    function drawSecureFelt(State memory s) internal pure returns (uint128) {
        (uint32 w0, uint32 w1) = _drawPair(s);
        (uint32 w2, uint32 w3) = _drawPair(s);
        uint64 c0 = (uint64(w0) << 32) | uint64(w1);
        uint64 c1 = (uint64(w2) << 32) | uint64(w3);
        return (uint128(c0) << 64) | uint128(c1);
    }

    /// @notice Squeeze n FRI query indices for a domain of size 2^logDomainSize.
    ///
    /// Each _drawPair yields two candidate indices via w & mask.
    /// Matches P2Channel::draw_queries.
    function drawQueries(
        State memory s,
        uint256 logDomainSize,
        uint256 nQueries
    ) internal pure returns (uint256[] memory queries) {
        require(logDomainSize <= 31, "Poseidon2Channel: logDomainSize > 31");
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

    /// @dev Absorb one uint32 word into the sponge state.
    ///
    /// Reduces word to M31 first (two conditional subtractions) so that
    /// arbitrary u32 values (e.g. last 4 bytes of a keccak256 hash) are safe.
    /// A u32 < 2^32 = 2*P+2, so at most two subtractions are needed.
    function _absorb(State memory s, uint32 word) private pure {
        uint256 w = uint256(word);
        if (w >= P) w -= P;
        if (w >= P) w -= P;
        uint256 s0;
        unchecked { s0 = uint256(s.s0) + w; }
        if (s0 >= P) s0 -= P;
        (uint256 out0, uint256 out1) = Poseidon2M31.permute(s0, uint256(s.s1));
        s.s0 = uint32(out0);
        s.s1 = uint32(out1);
    }

    /// @dev Squeeze one pair of M31 words.
    ///
    /// Protocol (matches P2Channel::draw_pair):
    ///   1. Save current (s0, s1) as (w0, w1)
    ///   2. Mix nDraws counter: s0 = (s0 + nDraws) with one-shot sub; permute
    ///   3. Update internal state; nDraws++
    ///   4. Return SAVED (w0, w1) — not the updated state
    function _drawPair(State memory s) private pure returns (uint32 w0, uint32 w1) {
        w0 = s.s0;
        w1 = s.s1;
        uint256 s0;
        unchecked { s0 = uint256(s.s0) + uint256(s.nDraws); }
        if (s0 >= P) s0 -= P;
        (uint256 out0, uint256 out1) = Poseidon2M31.permute(s0, uint256(s.s1));
        s.s0 = uint32(out0);
        s.s1 = uint32(out1);
        s.nDraws++;
    }
}
