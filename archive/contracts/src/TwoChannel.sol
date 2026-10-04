// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Blake2sYul.sol";
import "./M31.sol";

/// @title TwoChannel — Stwo's Blake2sM31Channel replicated in Solidity
///
/// Implements the Fiat-Shamir transcript channel used in Stwo Circle STARK.
/// Matches stwo/src/core/channel/blake2s.rs (Blake2sM31Channel).
///
/// State: 32-byte digest (8 LE-packed M31 uint32 words) + uint32 draw counter.
///
/// Operations:
///   mixRoot(state, root)               — absorb 32-byte commitment root; reset counter
///   mixU32s(state, words)              — absorb raw LE u32 words; reset counter
///   drawU32sRaw(state)                 — squeeze 8 M31 words as bytes32; increment counter
///   drawSecureFelt(state)              — squeeze one QM31 (packed uint128 c0‖c1)
///   drawQueries(state, logSize, n)     — squeeze n FRI query positions
///
/// Blake2sM31Hash(data):
///   1. h = Blake2s-256(data)
///   2. For each 4-byte LE chunk x of h: r = (x & P) + (x >> 31); if r >= P: r -= P
///   3. Return modified 32 bytes (M31-reduced LE words)
library TwoChannel {

    uint256 private constant P = M31.P; // 2^31 − 1

    struct State {
        bytes32 digest;  // 8 LE-packed M31 words = reduced Blake2s output
        uint32  nDraws;  // incremented by each drawU32sRaw call; reset by mix ops
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    /// @notice Return a fresh channel state (all-zero digest, zero counter).
    function init() internal pure returns (State memory s) {
        s.digest = bytes32(0);
        s.nDraws = 0;
    }

    // ── Absorb operations ─────────────────────────────────────────────────────

    /// @notice Absorb a 32-byte commitment root into the channel.
    /// Stwo: `self.digest = Blake2sM31Hash(self.digest ‖ root); self.n_draws = 0`
    function mixRoot(State memory s, bytes32 root) internal pure {
        bytes memory buf = new bytes(64);
        _put32(buf, 0, s.digest);
        _put32(buf, 32, root);
        s.digest = _blake2sM31(buf);
        s.nDraws = 0;
    }

    /// @notice Absorb an array of uint32 words (LE-encoded) into the channel.
    /// Stwo: `self.digest = Blake2sM31Hash(self.digest ‖ words_le); self.n_draws = 0`
    function mixU32s(State memory s, uint32[] memory words) internal pure {
        bytes memory buf = new bytes(32 + words.length * 4);
        _put32(buf, 0, s.digest);
        for (uint256 i = 0; i < words.length; i++) {
            _putLeU32(buf, 32 + i * 4, words[i]);
        }
        s.digest = _blake2sM31(buf);
        s.nDraws = 0;
    }

    // ── Squeeze operations ────────────────────────────────────────────────────

    /// @notice Squeeze 8 M31 words from the channel (as LE-packed bytes32).
    /// Increments nDraws; does NOT change the digest.
    ///
    /// Stwo: `hash_input = digest ‖ n_draws.to_le_bytes(4) ‖ 0x00; n_draws++`
    function drawU32sRaw(State memory s) internal pure returns (bytes32) {
        bytes memory buf = new bytes(37); // 32 + 4 + 1 (last byte stays 0)
        _put32(buf, 0, s.digest);
        _putLeU32(buf, 32, s.nDraws);
        // buf[36] == 0x00 by default (new bytes zero-initialises)
        s.nDraws++;
        return _blake2sM31(buf);
    }

    /// @notice Squeeze one QM31 secure-field element.
    /// Takes words [0..3] from drawU32sRaw:  c0 = CM31(w0, w1), c1 = CM31(w2, w3).
    /// Returns QM31 packed as uint128 = (c0 << 64) | c1, matching QM31.sol encoding.
    function drawSecureFelt(State memory s) internal pure returns (uint128) {
        bytes32 raw = drawU32sRaw(s);
        uint256 w0 = _leU32(raw, 0);
        uint256 w1 = _leU32(raw, 1);
        uint256 w2 = _leU32(raw, 2);
        uint256 w3 = _leU32(raw, 3);
        uint64 c0 = uint64((w0 << 32) | w1); // CM31: re=w0, im=w1
        uint64 c1 = uint64((w2 << 32) | w3); // CM31: re=w2, im=w3
        return (uint128(c0) << 64) | uint128(c1);
    }

    /// @notice Squeeze n FRI query positions for a domain of size 2^logDomainSize.
    /// Calls drawU32sRaw() repeatedly, taking `word & ((1 << logDomainSize) - 1)`.
    function drawQueries(
        State memory s,
        uint256 logDomainSize,
        uint256 nQueries
    ) internal pure returns (uint256[] memory queries) {
        require(logDomainSize <= 31, "TwoChannel: logDomainSize > 31 overflows mask");
        uint256 mask = (1 << logDomainSize) - 1;
        queries = new uint256[](nQueries);
        uint256 filled = 0;
        while (filled < nQueries) {
            bytes32 raw = drawU32sRaw(s);
            for (uint256 i = 0; i < 8 && filled < nQueries; i++) {
                queries[filled++] = _leU32(raw, i) & mask;
            }
        }
    }

    // ── Internal: Blake2sM31Hash ──────────────────────────────────────────────

    /// @dev Blake2s-256(data) followed by M31 reduction of each LE uint32 word.
    /// Matching Stwo's Blake2sM31Hash (blake2_hash.rs reduce_to_m31).
    function _blake2sM31(bytes memory data) private pure returns (bytes32) {
        bytes32 h = Blake2sYul.hash(data);
        uint256 acc;
        for (uint256 i = 0; i < 8; i++) {
            // Read word i as LE uint32 from the Blake2s output bytes32.
            uint256 w = _leU32(h, i);
            // M31 reduce: r = (w & 0x7FFFFFFF) + (w >> 31); if r >= P: r -= P
            uint256 r = (w & P) + (w >> 31);
            if (r >= P) { unchecked { r -= P; } }
            // Encode r back as LE uint32 at position i in the output bytes32.
            // bytes32 is BE in Solidity, so byte-swap r and shift to the right slot.
            uint256 be = ((r & 0xFF) << 24) | (((r >> 8) & 0xFF) << 16)
                       | (((r >> 16) & 0xFF) << 8) | (r >> 24);
            acc |= be << (224 - 32 * i);
        }
        return bytes32(acc);
    }

    // ── Internal: byte helpers ────────────────────────────────────────────────

    /// @dev Read bytes [i*4 .. i*4+3] of a bytes32 as a LE uint32.
    /// bytes32 is big-endian (byte 0 = MSB), so the LE value is the byte-swap
    /// of the 4-byte group at offset i.
    function _leU32(bytes32 h, uint256 i) private pure returns (uint256) {
        uint256 be = (uint256(h) >> (224 - 32 * i)) & 0xFFFFFFFF;
        return ((be & 0xFF) << 24) | (((be >> 8) & 0xFF) << 16)
             | (((be >> 16) & 0xFF) << 8) | (be >> 24);
    }

    /// @dev Copy a bytes32 value into a bytes buffer at byte offset `off`.
    function _put32(bytes memory buf, uint256 off, bytes32 val) private pure {
        assembly ("memory-safe") { mstore(add(add(buf, 32), off), val) }
    }

    /// @dev Write a uint32 into a bytes buffer at offset `off` as 4 LE bytes.
    function _putLeU32(bytes memory buf, uint256 off, uint32 val) private pure {
        buf[off]     = bytes1(uint8(val));
        buf[off + 1] = bytes1(uint8(val >> 8));
        buf[off + 2] = bytes1(uint8(val >> 16));
        buf[off + 3] = bytes1(uint8(val >> 24));
    }
}
