// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title Blake2s — RFC 7693 Blake2s-256 (keyless, 32-byte output)
///
/// Pure Solidity implementation for on-chain FRI commitment verification.
/// Stwo (Circle STARK) uses Blake2s for all Merkle tree hashing.
///
/// Gas: ~50k–200k per call depending on input length.
/// Production: replace with a precompile or Yul-optimised version.
library Blake2s {

    // ── Initialisation vector (same as SHA-256) ───────────────────────────────
    uint32 private constant IV0 = 0x6A09E667;
    uint32 private constant IV1 = 0xBB67AE85;
    uint32 private constant IV2 = 0x3C6EF372;
    uint32 private constant IV3 = 0xA54FF53A;
    uint32 private constant IV4 = 0x510E527F;
    uint32 private constant IV5 = 0x9B05688C;
    uint32 private constant IV6 = 0x1F83D9AB;
    uint32 private constant IV7 = 0x5BE0CD19;

    // Keyless Blake2s-256 parameter block XOR: digest_len=32, key_len=0, fanout=1, max_depth=1
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

        // Serialise state as little-endian bytes (Blake2s output convention).
        // Each state word is stored LE, but Solidity bytes32 is big-endian memory,
        // so _rev32 reverses each word's byte order before packing.
        return bytes32(
            (uint256(_rev32(h[0])) << 224) | (uint256(_rev32(h[1])) << 192) |
            (uint256(_rev32(h[2])) << 160) | (uint256(_rev32(h[3])) << 128) |
            (uint256(_rev32(h[4])) << 96)  | (uint256(_rev32(h[5])) << 64)  |
            (uint256(_rev32(h[6])) << 32)  |  uint256(_rev32(h[7]))
        );
    }

    // ── Compression function ──────────────────────────────────────────────────

    /// @dev Blake2s compression F (RFC 7693 §3.2). Modifies h[] in place.
    ///      t0 is the byte counter (lower 32 bits); t1 is always 0 for inputs
    ///      that fit in 32 bits, which is all practical Ethereum calldata.
    function _compress(
        uint32[8]  memory h,
        uint32[16] memory m,
        uint32 t0,
        bool last
    ) private pure {
        uint32[16] memory v;
        v[0] = h[0]; v[1] = h[1]; v[2] = h[2]; v[3]  = h[3];
        v[4] = h[4]; v[5] = h[5]; v[6] = h[6]; v[7]  = h[7];
        v[8]  = IV0; v[9]  = IV1; v[10] = IV2; v[11] = IV3;
        v[12] = IV4 ^ t0;
        v[13] = IV5;
        v[14] = last ? IV6 ^ 0xFFFFFFFF : IV6;
        v[15] = IV7;

        // 10 rounds with inlined sigma permutation schedule (RFC 7693 §2.7)
        _G(v,0,4, 8,12,m[ 0],m[ 1]); _G(v,1,5, 9,13,m[ 2],m[ 3]);
        _G(v,2,6,10,14,m[ 4],m[ 5]); _G(v,3,7,11,15,m[ 6],m[ 7]);
        _G(v,0,5,10,15,m[ 8],m[ 9]); _G(v,1,6,11,12,m[10],m[11]);
        _G(v,2,7, 8,13,m[12],m[13]); _G(v,3,4, 9,14,m[14],m[15]);

        _G(v,0,4, 8,12,m[14],m[10]); _G(v,1,5, 9,13,m[ 4],m[ 8]);
        _G(v,2,6,10,14,m[ 9],m[15]); _G(v,3,7,11,15,m[13],m[ 6]);
        _G(v,0,5,10,15,m[ 1],m[12]); _G(v,1,6,11,12,m[ 0],m[ 2]);
        _G(v,2,7, 8,13,m[11],m[ 7]); _G(v,3,4, 9,14,m[ 5],m[ 3]);

        _G(v,0,4, 8,12,m[11],m[ 8]); _G(v,1,5, 9,13,m[12],m[ 0]);
        _G(v,2,6,10,14,m[ 5],m[ 2]); _G(v,3,7,11,15,m[15],m[13]);
        _G(v,0,5,10,15,m[10],m[14]); _G(v,1,6,11,12,m[ 3],m[ 6]);
        _G(v,2,7, 8,13,m[ 7],m[ 1]); _G(v,3,4, 9,14,m[ 9],m[ 4]);

        _G(v,0,4, 8,12,m[ 7],m[ 9]); _G(v,1,5, 9,13,m[ 3],m[ 1]);
        _G(v,2,6,10,14,m[13],m[12]); _G(v,3,7,11,15,m[11],m[14]);
        _G(v,0,5,10,15,m[ 2],m[ 6]); _G(v,1,6,11,12,m[ 5],m[10]);
        _G(v,2,7, 8,13,m[ 4],m[ 0]); _G(v,3,4, 9,14,m[15],m[ 8]);

        _G(v,0,4, 8,12,m[ 9],m[ 0]); _G(v,1,5, 9,13,m[ 5],m[ 7]);
        _G(v,2,6,10,14,m[ 2],m[ 4]); _G(v,3,7,11,15,m[10],m[15]);
        _G(v,0,5,10,15,m[14],m[ 1]); _G(v,1,6,11,12,m[11],m[12]);
        _G(v,2,7, 8,13,m[ 6],m[ 8]); _G(v,3,4, 9,14,m[ 3],m[13]);

        _G(v,0,4, 8,12,m[ 2],m[12]); _G(v,1,5, 9,13,m[ 6],m[10]);
        _G(v,2,6,10,14,m[ 0],m[11]); _G(v,3,7,11,15,m[ 8],m[ 3]);
        _G(v,0,5,10,15,m[ 4],m[13]); _G(v,1,6,11,12,m[ 7],m[ 5]);
        _G(v,2,7, 8,13,m[15],m[14]); _G(v,3,4, 9,14,m[ 1],m[ 9]);

        _G(v,0,4, 8,12,m[12],m[ 5]); _G(v,1,5, 9,13,m[ 1],m[15]);
        _G(v,2,6,10,14,m[14],m[13]); _G(v,3,7,11,15,m[ 4],m[10]);
        _G(v,0,5,10,15,m[ 0],m[ 7]); _G(v,1,6,11,12,m[ 6],m[ 3]);
        _G(v,2,7, 8,13,m[ 9],m[ 2]); _G(v,3,4, 9,14,m[ 8],m[11]);

        _G(v,0,4, 8,12,m[13],m[11]); _G(v,1,5, 9,13,m[ 7],m[14]);
        _G(v,2,6,10,14,m[12],m[ 1]); _G(v,3,7,11,15,m[ 3],m[ 9]);
        _G(v,0,5,10,15,m[ 5],m[ 0]); _G(v,1,6,11,12,m[15],m[ 4]);
        _G(v,2,7, 8,13,m[ 8],m[ 6]); _G(v,3,4, 9,14,m[ 2],m[10]);

        _G(v,0,4, 8,12,m[ 6],m[15]); _G(v,1,5, 9,13,m[14],m[ 9]);
        _G(v,2,6,10,14,m[11],m[ 3]); _G(v,3,7,11,15,m[ 0],m[ 8]);
        _G(v,0,5,10,15,m[12],m[ 2]); _G(v,1,6,11,12,m[13],m[ 7]);
        _G(v,2,7, 8,13,m[ 1],m[ 4]); _G(v,3,4, 9,14,m[10],m[ 5]);

        _G(v,0,4, 8,12,m[10],m[ 2]); _G(v,1,5, 9,13,m[ 8],m[ 4]);
        _G(v,2,6,10,14,m[ 7],m[ 6]); _G(v,3,7,11,15,m[ 1],m[ 5]);
        _G(v,0,5,10,15,m[15],m[11]); _G(v,1,6,11,12,m[ 9],m[14]);
        _G(v,2,7, 8,13,m[ 3],m[12]); _G(v,3,4, 9,14,m[13],m[ 0]);

        h[0] ^= v[0] ^ v[8];  h[1] ^= v[1] ^ v[9];
        h[2] ^= v[2] ^ v[10]; h[3] ^= v[3] ^ v[11];
        h[4] ^= v[4] ^ v[12]; h[5] ^= v[5] ^ v[13];
        h[6] ^= v[6] ^ v[14]; h[7] ^= v[7] ^ v[15];
    }

    // ── G mixing function (RFC 7693 §3.1) ────────────────────────────────────

    function _G(
        uint32[16] memory v,
        uint8 a, uint8 b, uint8 c, uint8 d,
        uint32 x, uint32 y
    ) private pure {
        uint32 va = v[a]; uint32 vb = v[b];
        uint32 vc = v[c]; uint32 vd = v[d];
        unchecked {
            va += vb + x;  vd = _rotr(vd ^ va, 16);
            vc += vd;      vb = _rotr(vb ^ vc, 12);
            va += vb + y;  vd = _rotr(vd ^ va,  8);
            vc += vd;      vb = _rotr(vb ^ vc,  7);
        }
        v[a] = va; v[b] = vb; v[c] = vc; v[d] = vd;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _rotr(uint32 w, uint8 n) private pure returns (uint32) {
        unchecked { return uint32((w >> n) | (w << (32 - n))); }
    }

    /// @dev Load a single LE uint32 word from `data` starting at byte `p`,
    ///      reading only bytes strictly before `end` (zero-padding the rest).
    function _loadWord(bytes memory data, uint256 p, uint256 end) private pure returns (uint32 w) {
        unchecked {
            if (p     < end) w  = uint32(uint8(data[p]));
            if (p + 1 < end) w |= uint32(uint8(data[p + 1])) << 8;
            if (p + 2 < end) w |= uint32(uint8(data[p + 2])) << 16;
            if (p + 3 < end) w |= uint32(uint8(data[p + 3])) << 24;
        }
    }

    /// @dev Load a full 64-byte block as 16 little-endian uint32 words.
    function _block(bytes memory data, uint256 off) private pure returns (uint32[16] memory m) {
        uint256 end = off + 64;
        for (uint8 i = 0; i < 16; i++) {
            m[i] = _loadWord(data, off + uint256(i) * 4, end);
        }
    }

    /// @dev Load the final (possibly partial) block, zero-padding to 64 bytes.
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

    /// @dev Reverse the byte order of a 32-bit word (for LE output encoding).
    function _rev32(uint32 w) private pure returns (uint32) {
        unchecked {
            return ((w & 0x000000FF) << 24)
                 | ((w & 0x0000FF00) << 8)
                 | ((w & 0x00FF0000) >> 8)
                 |  (w >> 24);
        }
    }
}
