// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Poseidon2M31T16.sol";

/// @title Poseidon2ChannelT16 — Poseidon2 t=16 duplex Fiat-Shamir channel
///
/// The t=16 analogue of Poseidon2ChannelT8, widened from 8 to 16 state cells.
/// Absorb is RATE-8: up to eight words go into cells 0–7 and the state is
/// permuted ONCE per block. Cells 8–15 are an eight-cell (248-bit) capacity, so
/// transcript-collision cost is ~2^124 — the same 128-bit level as the node
/// width, and the same rate/capacity split the leaf sponge already uses.
///
/// The narrower channels (t=2/t=4/t=8) absorb one word per permutation. Carrying
/// that over to t=16 would cost EIGHT permutations per 8-word root instead of
/// one, and measurably did: a full-V23 t=16 group came out at 3.57x a t=8 one
/// against a 3.04x permutation ratio, and the gap was the absorb count.
/// Rate-1 at t=16 wastes seven eighths of the sponge's bandwidth for no security
/// — capacity, not rate, sets the collision bound.
///
/// State: (s[0..16]: M31 cells, nDraws: uint32).
///
/// Absorb protocol (matches struct P2T16Channel in vfri2_bridge.rs):
///   absorbBlock(w[0..k]): s_i += reduce(w_i) for i<k; if k<8 then s15 += 8-k
///                         (length-encoding pad); permute_t16
///   mixRoot:       absorbBlock([bytes[28..32]]); nDraws = 0
///   mixRootW:      absorbBlock(the 8 node words); nDraws = 0
///   mixRootFull:   absorbBlock(the 8 BE u32 words); nDraws = 0
///   mixU32s:       absorb in blocks of 8; nDraws = 0
///
/// The pad must encode the block LENGTH, not merely that it was short: a constant
/// flag would leave `[1,2,3]` and `[1,2,3,0]` absorbing to the same state, since
/// both pad to the same eight cells. An empty array absorbs nothing at all, as in
/// the rate-1 channels.
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
        uint256[8] memory w;
        w[0] = uint256(root) & MASK32;
        _absorbBlock(st, w, 1);
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

    /// @notice Absorb an array of uint32 words in rate-8 blocks, then reset the
    ///         draw counter.
    function mixU32s(State memory st, uint32[] memory words) internal pure {
        // An empty array absorbs nothing, exactly as in the rate-1 channels.
        uint256 n = words.length;
        for (uint256 i = 0; i < n; i += 8) {
            uint256 k = n - i < 8 ? n - i : 8;
            uint256[8] memory blk;
            for (uint256 j = 0; j < k; j++) {
                blk[j] = uint256(words[i + j]);
            }
            _absorbBlock(st, blk, k);
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

    /// @dev A 32-byte root is exactly one rate block: eight BE u32 words, one
    ///      permutation.
    function _absorbAll8(State memory st, bytes32 root) private pure {
        unchecked {
            uint256 v = uint256(root);
            uint256[8] memory w;
            for (uint256 i = 0; i < 8; i++) {
                w[i] = (v >> (224 - 32 * i)) & MASK32;
            }
            _absorbBlock(st, w, 8);
            st.nDraws = 0;
        }
    }

    /// @dev Absorb `k <= 8` words into cells 0..k, then permute once.
    ///
    ///      Each word is reduced to M31 with TWO conditional subtractions: a u32
    ///      reaches 2^32-1 = 2P+1, so one is not enough. A short block adds
    ///      `8 - k` to capacity cell 15, so the pad encodes the block's length.
    function _absorbBlock(State memory st, uint256[8] memory words, uint256 k) private pure {
        unchecked {
            for (uint256 i = 0; i < k; i++) {
                uint256 w = words[i];
                if (w >= P) w -= P;
                if (w >= P) w -= P;
                uint256 si = st.s[i] + w;
                if (si >= P) si -= P;
                st.s[i] = si;
            }
            if (k < 8) {
                uint256 s15 = st.s[15] + (8 - k);
                if (s15 >= P) s15 -= P;
                st.s[15] = s15;
            }
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
