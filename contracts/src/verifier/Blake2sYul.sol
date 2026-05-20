// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title Blake2sYul — RFC 7693 Blake2s-256 (keyless, 32-byte output)
///
/// Yul-assembly optimised implementation. The compression function keeps all
/// 16 working-state words and 16 message words as EVM stack variables, which
/// eliminates:
///   - 80 JUMP/RETURN pairs for the _G function calls
///   - 160 JUMP/RETURN pairs for the _rotr helpers
///   - All runtime memory-address calculations (MUL+ADD per _G index)
///
/// External interface identical to Blake2s.sol so callers can be swapped with
/// a one-line import change.
///
/// Tested against the same six RFC 7693 / Python-hashlib vectors as Blake2s.sol.
library Blake2sYul {

    // ── Initialisation vector (SHA-256 fractional primes) ─────────────────────
    uint32 private constant IV0 = 0x6A09E667;
    uint32 private constant IV1 = 0xBB67AE85;
    uint32 private constant IV2 = 0x3C6EF372;
    uint32 private constant IV3 = 0xA54FF53A;
    uint32 private constant IV4 = 0x510E527F;
    uint32 private constant IV5 = 0x9B05688C;
    uint32 private constant IV6 = 0x1F83D9AB;
    uint32 private constant IV7 = 0x5BE0CD19;

    // Keyless Blake2s-256 parameter block: digest_len=32, key_len=0, fanout=1, max_depth=1
    uint32 private constant PARAM_XOR = 0x01010020;

    // ── Public interface ──────────────────────────────────────────────────────

    /// @notice Compute the Blake2s-256 hash of `data`.
    /// @return A bytes32 matching Python's `hashlib.blake2s(data).digest()`.
    function hash(bytes memory data) internal pure returns (bytes32) {
        uint32[8] memory h;
        h[0] = IV0 ^ PARAM_XOR;
        h[1] = IV1; h[2] = IV2; h[3] = IV3;
        h[4] = IV4; h[5] = IV5; h[6] = IV6; h[7] = IV7;

        uint256 len = data.length;
        if (len == 0) {
            uint32[16] memory empty;
            _compress(h, empty, 0, true);
        } else {
            uint256 offset = 0;
            while (len - offset > 64) {
                _compress(h, _block(data, offset), uint32(offset + 64), false);
                offset += 64;
            }
            _compress(h, _lastBlock(data, offset, len - offset), uint32(len), true);
        }

        return bytes32(
            (uint256(_rev32(h[0])) << 224) | (uint256(_rev32(h[1])) << 192) |
            (uint256(_rev32(h[2])) << 160) | (uint256(_rev32(h[3])) << 128) |
            (uint256(_rev32(h[4])) << 96)  | (uint256(_rev32(h[5])) << 64)  |
            (uint256(_rev32(h[6])) << 32)  |  uint256(_rev32(h[7]))
        );
    }

    // ── Compression function — fully inlined Yul assembly ────────────────────

    /// @dev Blake2s compression F (RFC 7693 §3.2). Modifies h[] in place.
    ///
    /// All 16 working-state words (v0..v15) live on the EVM stack throughout.
    /// The G mixing function and all four rotations are inlined — no function
    /// call overhead in the hot path.
    function _compress(
        uint32[8]  memory h,
        uint32[16] memory m,
        uint32 t0,
        bool last
    ) private pure {
        // solhint-disable no-inline-assembly
        assembly ("memory-safe") {
            // -----------------------------------------------------------------
            // Load all 16 message words from the uint32[16] memory array.
            // Each element occupies one 32-byte slot (Solidity ABI for fixed
            // arrays in memory pads each element to 32 bytes).
            // -----------------------------------------------------------------
            let m0  := and(mload(m),              0xFFFFFFFF)
            let m1  := and(mload(add(m, 0x020)),  0xFFFFFFFF)
            let m2  := and(mload(add(m, 0x040)),  0xFFFFFFFF)
            let m3  := and(mload(add(m, 0x060)),  0xFFFFFFFF)
            let m4  := and(mload(add(m, 0x080)),  0xFFFFFFFF)
            let m5  := and(mload(add(m, 0x0a0)),  0xFFFFFFFF)
            let m6  := and(mload(add(m, 0x0c0)),  0xFFFFFFFF)
            let m7  := and(mload(add(m, 0x0e0)),  0xFFFFFFFF)
            let m8  := and(mload(add(m, 0x100)),  0xFFFFFFFF)
            let m9  := and(mload(add(m, 0x120)),  0xFFFFFFFF)
            let m10 := and(mload(add(m, 0x140)),  0xFFFFFFFF)
            let m11 := and(mload(add(m, 0x160)),  0xFFFFFFFF)
            let m12 := and(mload(add(m, 0x180)),  0xFFFFFFFF)
            let m13 := and(mload(add(m, 0x1a0)),  0xFFFFFFFF)
            let m14 := and(mload(add(m, 0x1c0)),  0xFFFFFFFF)
            let m15 := and(mload(add(m, 0x1e0)),  0xFFFFFFFF)

            // -----------------------------------------------------------------
            // Load current state words h[0..7].
            // -----------------------------------------------------------------
            let h0 := and(mload(h),              0xFFFFFFFF)
            let h1 := and(mload(add(h, 0x020)),  0xFFFFFFFF)
            let h2 := and(mload(add(h, 0x040)),  0xFFFFFFFF)
            let h3 := and(mload(add(h, 0x060)),  0xFFFFFFFF)
            let h4 := and(mload(add(h, 0x080)),  0xFFFFFFFF)
            let h5 := and(mload(add(h, 0x0a0)),  0xFFFFFFFF)
            let h6 := and(mload(add(h, 0x0c0)),  0xFFFFFFFF)
            let h7 := and(mload(add(h, 0x0e0)),  0xFFFFFFFF)

            // -----------------------------------------------------------------
            // Initialise working state v[0..15] from h[0..7] and the IVs.
            // -----------------------------------------------------------------
            let v0  := h0
            let v1  := h1
            let v2  := h2
            let v3  := h3
            let v4  := h4
            let v5  := h5
            let v6  := h6
            let v7  := h7
            let v8  := 0x6A09E667
            let v9  := 0xBB67AE85
            let v10 := 0x3C6EF372
            let v11 := 0xA54FF53A
            let v12 := xor(0x510E527F, t0)
            let v13 := 0x9B05688C
            // v14: XOR with 0xFFFFFFFF for the last block flag
            let v14 := 0x1F83D9AB
            let v15 := 0x5BE0CD19
            if last { v14 := xor(0x1F83D9AB, 0xFFFFFFFF) }

            // -----------------------------------------------------------------
            // G mixing function (RFC 7693 §3.1), inlined as a Yul function.
            //
            // Takes (a, b, c, d, x, y) → (ra, rb, rc, rd).
            // All rotations are inlined; mask kept as a literal to avoid the
            // extra ADD for a named constant slot.
            // -----------------------------------------------------------------
            function G(a, b, c, d, x, y) -> ra, rb, rc, rd {
                // a = (a + b + x) mod 2^32
                a := and(add(add(a, b), x), 0xFFFFFFFF)
                // d = rotr32(d ^ a, 16)
                let td := xor(d, a)
                d := or(shr(16, td), and(shl(16, td), 0xFFFFFFFF))
                // c = (c + d) mod 2^32
                c := and(add(c, d), 0xFFFFFFFF)
                // b = rotr32(b ^ c, 12)
                let tb := xor(b, c)
                b := or(shr(12, tb), and(shl(20, tb), 0xFFFFFFFF))
                // a = (a + b + y) mod 2^32
                a := and(add(add(a, b), y), 0xFFFFFFFF)
                // d = rotr32(d ^ a, 8)
                td := xor(d, a)
                d := or(shr(8, td), and(shl(24, td), 0xFFFFFFFF))
                // c = (c + d) mod 2^32
                c := and(add(c, d), 0xFFFFFFFF)
                // b = rotr32(b ^ c, 7)
                tb := xor(b, c)
                b := or(shr(7, tb), and(shl(25, tb), 0xFFFFFFFF))
                ra := a
                rb := b
                rc := c
                rd := d
            }

            // =================================================================
            // 10 rounds with the RFC 7693 §2.7 sigma permutation schedule.
            // Column mixing: (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15)
            // Diagonal mixing:(0,5,10,15),(1,6,11,12),(2,7,8,13), (3,4,9,14)
            // =================================================================

            // Round 0 — sigma = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}
            v0, v4, v8,  v12 := G(v0, v4, v8,  v12, m0,  m1)
            v1, v5, v9,  v13 := G(v1, v5, v9,  v13, m2,  m3)
            v2, v6, v10, v14 := G(v2, v6, v10, v14, m4,  m5)
            v3, v7, v11, v15 := G(v3, v7, v11, v15, m6,  m7)
            v0, v5, v10, v15 := G(v0, v5, v10, v15, m8,  m9)
            v1, v6, v11, v12 := G(v1, v6, v11, v12, m10, m11)
            v2, v7, v8,  v13 := G(v2, v7, v8,  v13, m12, m13)
            v3, v4, v9,  v14 := G(v3, v4, v9,  v14, m14, m15)

            // Round 1 — sigma = {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3}
            v0, v4, v8,  v12 := G(v0, v4, v8,  v12, m14, m10)
            v1, v5, v9,  v13 := G(v1, v5, v9,  v13, m4,  m8)
            v2, v6, v10, v14 := G(v2, v6, v10, v14, m9,  m15)
            v3, v7, v11, v15 := G(v3, v7, v11, v15, m13, m6)
            v0, v5, v10, v15 := G(v0, v5, v10, v15, m1,  m12)
            v1, v6, v11, v12 := G(v1, v6, v11, v12, m0,  m2)
            v2, v7, v8,  v13 := G(v2, v7, v8,  v13, m11, m7)
            v3, v4, v9,  v14 := G(v3, v4, v9,  v14, m5,  m3)

            // Round 2 — sigma = {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4}
            v0, v4, v8,  v12 := G(v0, v4, v8,  v12, m11, m8)
            v1, v5, v9,  v13 := G(v1, v5, v9,  v13, m12, m0)
            v2, v6, v10, v14 := G(v2, v6, v10, v14, m5,  m2)
            v3, v7, v11, v15 := G(v3, v7, v11, v15, m15, m13)
            v0, v5, v10, v15 := G(v0, v5, v10, v15, m10, m14)
            v1, v6, v11, v12 := G(v1, v6, v11, v12, m3,  m6)
            v2, v7, v8,  v13 := G(v2, v7, v8,  v13, m7,  m1)
            v3, v4, v9,  v14 := G(v3, v4, v9,  v14, m9,  m4)

            // Round 3 — sigma = {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8}
            v0, v4, v8,  v12 := G(v0, v4, v8,  v12, m7,  m9)
            v1, v5, v9,  v13 := G(v1, v5, v9,  v13, m3,  m1)
            v2, v6, v10, v14 := G(v2, v6, v10, v14, m13, m12)
            v3, v7, v11, v15 := G(v3, v7, v11, v15, m11, m14)
            v0, v5, v10, v15 := G(v0, v5, v10, v15, m2,  m6)
            v1, v6, v11, v12 := G(v1, v6, v11, v12, m5,  m10)
            v2, v7, v8,  v13 := G(v2, v7, v8,  v13, m4,  m0)
            v3, v4, v9,  v14 := G(v3, v4, v9,  v14, m15, m8)

            // Round 4 — sigma = {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13}
            v0, v4, v8,  v12 := G(v0, v4, v8,  v12, m9,  m0)
            v1, v5, v9,  v13 := G(v1, v5, v9,  v13, m5,  m7)
            v2, v6, v10, v14 := G(v2, v6, v10, v14, m2,  m4)
            v3, v7, v11, v15 := G(v3, v7, v11, v15, m10, m15)
            v0, v5, v10, v15 := G(v0, v5, v10, v15, m14, m1)
            v1, v6, v11, v12 := G(v1, v6, v11, v12, m11, m12)
            v2, v7, v8,  v13 := G(v2, v7, v8,  v13, m6,  m8)
            v3, v4, v9,  v14 := G(v3, v4, v9,  v14, m3,  m13)

            // Round 5 — sigma = {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9}
            v0, v4, v8,  v12 := G(v0, v4, v8,  v12, m2,  m12)
            v1, v5, v9,  v13 := G(v1, v5, v9,  v13, m6,  m10)
            v2, v6, v10, v14 := G(v2, v6, v10, v14, m0,  m11)
            v3, v7, v11, v15 := G(v3, v7, v11, v15, m8,  m3)
            v0, v5, v10, v15 := G(v0, v5, v10, v15, m4,  m13)
            v1, v6, v11, v12 := G(v1, v6, v11, v12, m7,  m5)
            v2, v7, v8,  v13 := G(v2, v7, v8,  v13, m15, m14)
            v3, v4, v9,  v14 := G(v3, v4, v9,  v14, m1,  m9)

            // Round 6 — sigma = {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11}
            v0, v4, v8,  v12 := G(v0, v4, v8,  v12, m12, m5)
            v1, v5, v9,  v13 := G(v1, v5, v9,  v13, m1,  m15)
            v2, v6, v10, v14 := G(v2, v6, v10, v14, m14, m13)
            v3, v7, v11, v15 := G(v3, v7, v11, v15, m4,  m10)
            v0, v5, v10, v15 := G(v0, v5, v10, v15, m0,  m7)
            v1, v6, v11, v12 := G(v1, v6, v11, v12, m6,  m3)
            v2, v7, v8,  v13 := G(v2, v7, v8,  v13, m9,  m2)
            v3, v4, v9,  v14 := G(v3, v4, v9,  v14, m8,  m11)

            // Round 7 — sigma = {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10}
            v0, v4, v8,  v12 := G(v0, v4, v8,  v12, m13, m11)
            v1, v5, v9,  v13 := G(v1, v5, v9,  v13, m7,  m14)
            v2, v6, v10, v14 := G(v2, v6, v10, v14, m12, m1)
            v3, v7, v11, v15 := G(v3, v7, v11, v15, m3,  m9)
            v0, v5, v10, v15 := G(v0, v5, v10, v15, m5,  m0)
            v1, v6, v11, v12 := G(v1, v6, v11, v12, m15, m4)
            v2, v7, v8,  v13 := G(v2, v7, v8,  v13, m8,  m6)
            v3, v4, v9,  v14 := G(v3, v4, v9,  v14, m2,  m10)

            // Round 8 — sigma = {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5}
            v0, v4, v8,  v12 := G(v0, v4, v8,  v12, m6,  m15)
            v1, v5, v9,  v13 := G(v1, v5, v9,  v13, m14, m9)
            v2, v6, v10, v14 := G(v2, v6, v10, v14, m11, m3)
            v3, v7, v11, v15 := G(v3, v7, v11, v15, m0,  m8)
            v0, v5, v10, v15 := G(v0, v5, v10, v15, m12, m2)
            v1, v6, v11, v12 := G(v1, v6, v11, v12, m13, m7)
            v2, v7, v8,  v13 := G(v2, v7, v8,  v13, m1,  m4)
            v3, v4, v9,  v14 := G(v3, v4, v9,  v14, m10, m5)

            // Round 9 — sigma = {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0}
            v0, v4, v8,  v12 := G(v0, v4, v8,  v12, m10, m2)
            v1, v5, v9,  v13 := G(v1, v5, v9,  v13, m8,  m4)
            v2, v6, v10, v14 := G(v2, v6, v10, v14, m7,  m6)
            v3, v7, v11, v15 := G(v3, v7, v11, v15, m1,  m5)
            v0, v5, v10, v15 := G(v0, v5, v10, v15, m15, m11)
            v1, v6, v11, v12 := G(v1, v6, v11, v12, m9,  m14)
            v2, v7, v8,  v13 := G(v2, v7, v8,  v13, m3,  m12)
            v3, v4, v9,  v14 := G(v3, v4, v9,  v14, m13, m0)

            // -----------------------------------------------------------------
            // Finalise: h[i] ^= v[i] ^ v[i+8]  (write back to memory).
            // -----------------------------------------------------------------
            let mask := 0xFFFFFFFF
            mstore(h,              and(xor(xor(h0, v0), v8),  mask))
            mstore(add(h, 0x020),  and(xor(xor(h1, v1), v9),  mask))
            mstore(add(h, 0x040),  and(xor(xor(h2, v2), v10), mask))
            mstore(add(h, 0x060),  and(xor(xor(h3, v3), v11), mask))
            mstore(add(h, 0x080),  and(xor(xor(h4, v4), v12), mask))
            mstore(add(h, 0x0a0),  and(xor(xor(h5, v5), v13), mask))
            mstore(add(h, 0x0c0),  and(xor(xor(h6, v6), v14), mask))
            mstore(add(h, 0x0e0),  and(xor(xor(h7, v7), v15), mask))
        }
    }

    // ── Helpers (unchanged from Blake2s.sol) ─────────────────────────────────

    function _loadWord(bytes memory data, uint256 p, uint256 end) private pure returns (uint32 w) {
        unchecked {
            if (p     < end) w  = uint32(uint8(data[p]));
            if (p + 1 < end) w |= uint32(uint8(data[p + 1])) << 8;
            if (p + 2 < end) w |= uint32(uint8(data[p + 2])) << 16;
            if (p + 3 < end) w |= uint32(uint8(data[p + 3])) << 24;
        }
    }

    function _block(bytes memory data, uint256 off) private pure returns (uint32[16] memory m) {
        uint256 end = off + 64;
        for (uint8 i = 0; i < 16; i++) {
            m[i] = _loadWord(data, off + uint256(i) * 4, end);
        }
    }

    function _lastBlock(
        bytes memory data,
        uint256 off,
        uint256 blockLen
    ) private pure returns (uint32[16] memory m) {
        uint256 end = off + blockLen;
        for (uint8 i = 0; i < 16; i++) {
            m[i] = _loadWord(data, off + uint256(i) * 4, end);
        }
    }

    function _rev32(uint32 w) private pure returns (uint32) {
        unchecked {
            return ((w & 0x000000FF) << 24)
                 | ((w & 0x0000FF00) << 8)
                 | ((w & 0x00FF0000) >> 8)
                 |  (w >> 24);
        }
    }
}
