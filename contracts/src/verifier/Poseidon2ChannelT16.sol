// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Poseidon2M31T16.sol";

/// @title Poseidon2ChannelT16 — Poseidon2 t=16 duplex Fiat-Shamir channel
///
/// The t=16 analogue of Poseidon2ChannelT8, widened from 8 to 16 state cells.
/// Absorb stays rate-1 into cell 0 — cells 1–15 form a 465-bit capacity — and a
/// draw squeezes the two rate-adjacent cells (s0, s1).
///
/// Keeping rate 1 rather than widening it alongside the state is deliberate: the
/// transcript's ORDER and COUNT of absorb/draw calls then match t=8 exactly, so a
/// verifier swapping this in changes only the permutation. It still produces
/// different query indices (as it must — VFRI11 hints are not VFRI12 hints), but
/// no protocol-shape reasoning has to be redone to see that it is sound.
///
/// State: (s[0..16]: M31 cells, nDraws: uint32).
///
/// Absorb protocol (matches struct P2T16Channel in vfri2_bridge.rs):
///   absorb(word):  s0 = (s0 + reduce(word)) mod P; permute_t16
///   mixRoot:       absorb(bytes[28..32]); nDraws = 0
///   mixRootW:      absorb the 8 node words; nDraws = 0
///   mixRootFull:   absorb each of the 8 BE u32 words; nDraws = 0
///   mixU32s:       absorb each word; nDraws = 0
///
/// At this width a node is the full 32 bytes, so `mixRootW` and `mixRootFull`
/// absorb the same eight words. Both names are kept because the CALLERS mean
/// different things by them — a t=16 node root versus a foreign 32-byte root
/// (an embedded Stwo trace root, a batch merkle root) — and a future width
/// change would separate them again.
///
/// Squeeze protocol (matches P2T16Channel::draw_pair):
///   _drawPair: save (w0,w1)=(s0,s1); s0=(s0+nDraws)%P; permute_t16; nDraws++
///   drawSecureFelt: two _drawPair calls → QM31 = (CM31(w0,w1)<<64)|CM31(w2,w3)
///   drawQueries: repeated _drawPair calls; each yields 2 candidate indices
library Poseidon2ChannelT16 {

    uint256 private constant P = 2_147_483_647; // 2^31 - 1
    uint256 private constant MASK32 = 0xFFFFFFFF;

    /// @dev The state is a fixed memory array rather than sixteen named fields:
    ///      `Poseidon2M31T16.permute` operates in place on exactly this shape, so
    ///      a draw costs no copy in or out.
    struct State {
        uint256[16] s;
        uint32 nDraws;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    /// @notice Return a fresh channel state (all-zero state, zero counter).
    function init() internal pure returns (State memory s) {
        // default-initialised to all zero
    }

    // ── Absorb operations ─────────────────────────────────────────────────────

    /// @notice Absorb the low 4 bytes (bytes[28..32]) of a root; reset counter.
    function mixRoot(State memory st, bytes32 root) internal pure {
        _absorb(st, uint256(root) & MASK32);
        st.nDraws = 0;
    }

    /// @notice Absorb a wide t=16 node root (248-bit content) as eight BE u32
    ///         words; reset counter.
    function mixRootW(State memory st, bytes32 root) internal pure {
        _absorbAll8(st, root);
    }

    /// @notice Absorb ALL 32 bytes of a root as 8 big-endian u32 words; reset
    ///         counter. Binds the full 256 bits into the transcript.
    function mixRootFull(State memory st, bytes32 root) internal pure {
        _absorbAll8(st, root);
    }

    /// @notice Absorb an array of uint32 words, then reset the draw counter.
    function mixU32s(State memory st, uint32[] memory words) internal pure {
        for (uint256 i = 0; i < words.length; i++) {
            _absorb(st, uint256(words[i]));
        }
        st.nDraws = 0;
    }

    // ── Squeeze operations ────────────────────────────────────────────────────

    /// @notice Squeeze one QM31 secure-field element (two _drawPair calls).
    function drawSecureFelt(State memory st) internal pure returns (uint128) {
        (uint256 w0, uint256 w1) = _drawPair(st);
        (uint256 w2, uint256 w3) = _drawPair(st);
        uint64 c0 = uint64((w0 << 32) | w1);
        uint64 c1 = uint64((w2 << 32) | w3);
        return (uint128(c0) << 64) | uint128(c1);
    }

    /// @notice Squeeze n FRI query indices for a domain of size 2^logDomainSize.
    function drawQueries(
        State memory st,
        uint256 logDomainSize,
        uint256 nQueries
    ) internal pure returns (uint256[] memory queries) {
        require(logDomainSize <= 31, "Poseidon2ChannelT16: logDomainSize > 31");
        uint256 mask = (1 << logDomainSize) - 1;
        queries = new uint256[](nQueries);
        uint256 filled = 0;
        while (filled < nQueries) {
            (uint256 w0, uint256 w1) = _drawPair(st);
            queries[filled++] = w0 & mask;
            if (filled < nQueries) {
                queries[filled++] = w1 & mask;
            }
        }
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _absorbAll8(State memory st, bytes32 root) private pure {
        uint256 v = uint256(root);
        for (uint256 i = 0; i < 8; i++) {
            _absorb(st, (v >> (224 - 32 * i)) & MASK32);
        }
        st.nDraws = 0;
    }

    /// @dev Absorb one uint32 word into cell 0, then permute. Reduces the word to
    ///      M31 first with TWO conditional subtractions: a u32 reaches 2^32-1 =
    ///      2P+1, so one subtraction is not enough.
    function _absorb(State memory st, uint256 word) private pure {
        unchecked {
            uint256 w = word;
            if (w >= P) w -= P;
            if (w >= P) w -= P;
            uint256 s0 = st.s[0] + w;
            if (s0 >= P) s0 -= P;
            st.s[0] = s0;
            Poseidon2M31T16.permute(st.s);
        }
    }

    /// @dev Squeeze one pair of M31 words (s0, s1): save (s0,s1), mix nDraws into
    ///      cell 0, permute, increment nDraws; return the SAVED pair.
    function _drawPair(State memory st) private pure returns (uint256 w0, uint256 w1) {
        unchecked {
            w0 = st.s[0];
            w1 = st.s[1];
            uint256 s0 = st.s[0] + uint256(st.nDraws);
            if (s0 >= P) s0 -= P;
            st.s[0] = s0;
            Poseidon2M31T16.permute(st.s);
            st.nDraws++;
        }
    }
}
