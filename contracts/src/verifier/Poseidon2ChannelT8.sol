// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Poseidon2M31T8.sol";

/// @title Poseidon2ChannelT8 — Poseidon2 t=8 duplex Fiat-Shamir channel
///
/// The t=8 analogue of Poseidon2ChannelT4, widened from 4 to 8 state cells.
/// Absorb is rate-1 into cell 0 (cells 1–7 form a 217-bit capacity); each draw
/// squeezes the two rate-adjacent cells (s0, s1).  The wider capacity lifts the
/// transcript-binding wall above the t=4 ceiling, toward 128-bit binding.
///
/// State: (s0..s7: uint32, nDraws: uint32) — eight M31 cells + a squeeze counter.
///
/// Absorb protocol (matches struct P2T8Channel in vfri2_bridge.rs):
///   absorb(word):  s0 = (s0 + reduce(word)) mod P; permute_t8
///   mixRoot:       absorb(bytes[28..32]); nDraws = 0
///   mixRootW:      absorb the 4 node words (bytes[16..32]); nDraws = 0
///   mixRootFull:   absorb each of the 8 BE u32 words; nDraws = 0
///   mixU32s:       absorb each word; nDraws = 0
///
/// Squeeze protocol (matches P2T8Channel::draw_pair):
///   _drawPair: save (w0,w1)=(s0,s1); s0=(s0+nDraws)%P; permute_t8; nDraws++
///   drawSecureFelt: two _drawPair calls → QM31 = (CM31(w0,w1)<<64)|CM31(w2,w3)
///   drawQueries: repeated _drawPair calls; each yields 2 candidate indices
library Poseidon2ChannelT8 {

    uint256 private constant P = 2_147_483_647; // 2^31 - 1
    uint256 private constant MASK32 = 0xFFFFFFFF;

    struct State {
        uint32 s0;
        uint32 s1;
        uint32 s2;
        uint32 s3;
        uint32 s4;
        uint32 s5;
        uint32 s6;
        uint32 s7;
        uint32 nDraws;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    /// @notice Return a fresh channel state (all-zero state, zero counter).
    function init() internal pure returns (State memory s) {
        // default-initialised to all zero
    }

    // ── Absorb operations ─────────────────────────────────────────────────────

    /// @notice Absorb the low 4 bytes (bytes[28..32]) of a root; reset counter.
    function mixRoot(State memory s, bytes32 root) internal pure {
        _absorb(s, uint32(uint256(root) & MASK32));
        s.nDraws = 0;
    }

    /// @notice Absorb a wide t=8 node root (124-bit content) as four BE u32 words
    ///         (bytes[16..32]); reset counter.
    function mixRootW(State memory s, bytes32 root) internal pure {
        uint256 r = uint256(root);
        _absorb(s, uint32((r >> 96) & MASK32));
        _absorb(s, uint32((r >> 64) & MASK32));
        _absorb(s, uint32((r >> 32) & MASK32));
        _absorb(s, uint32(r & MASK32));
        s.nDraws = 0;
    }

    /// @notice Absorb ALL 32 bytes of a root as 8 big-endian u32 words; reset
    ///         counter.  Binds the full 256 bits into the transcript.
    function mixRootFull(State memory s, bytes32 root) internal pure {
        for (uint256 i = 0; i < 8; i++) {
            _absorb(s, uint32((uint256(root) >> (224 - 32 * i)) & MASK32));
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
        require(logDomainSize <= 31, "Poseidon2ChannelT8: logDomainSize > 31");
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

    /// @dev Absorb one uint32 word into cell 0, then permute.  Reduces word to
    ///      M31 first (two conditional subtractions; a u32 is < 2^32 = 2·P+2).
    function _absorb(State memory st, uint32 word) private pure {
        uint256 w = uint256(word);
        if (w >= P) w -= P;
        if (w >= P) w -= P;
        uint256 s0;
        unchecked { s0 = uint256(st.s0) + w; }
        if (s0 >= P) s0 -= P;
        uint256[8] memory s;
        s[0] = s0;
        s[1] = uint256(st.s1);
        s[2] = uint256(st.s2);
        s[3] = uint256(st.s3);
        s[4] = uint256(st.s4);
        s[5] = uint256(st.s5);
        s[6] = uint256(st.s6);
        s[7] = uint256(st.s7);
        s = Poseidon2M31T8.permute(s);
        _store(st, s);
    }

    /// @dev Squeeze one pair of M31 words (s0, s1): save (s0,s1), mix nDraws into
    ///      cell 0, permute, increment nDraws; return the SAVED pair.
    function _drawPair(State memory st) private pure returns (uint32 w0, uint32 w1) {
        w0 = st.s0;
        w1 = st.s1;
        uint256 s0;
        unchecked { s0 = uint256(st.s0) + uint256(st.nDraws); }
        if (s0 >= P) s0 -= P;
        uint256[8] memory s;
        s[0] = s0;
        s[1] = uint256(st.s1);
        s[2] = uint256(st.s2);
        s[3] = uint256(st.s3);
        s[4] = uint256(st.s4);
        s[5] = uint256(st.s5);
        s[6] = uint256(st.s6);
        s[7] = uint256(st.s7);
        s = Poseidon2M31T8.permute(s);
        _store(st, s);
        st.nDraws++;
    }

    function _store(State memory st, uint256[8] memory s) private pure {
        st.s0 = uint32(s[0]);
        st.s1 = uint32(s[1]);
        st.s2 = uint32(s[2]);
        st.s3 = uint32(s[3]);
        st.s4 = uint32(s[4]);
        st.s5 = uint32(s[5]);
        st.s6 = uint32(s[6]);
        st.s7 = uint32(s[7]);
    }
}
