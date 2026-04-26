// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title Blake2s — RFC 7693 Blake2s-256 (keyless, 32-byte output)
///
/// Pure Solidity implementation intended for on-chain FRI commitment
/// verification in the QLSA Phase 3++ verifier.  Stwo (Circle STARK)
/// uses Blake2s for all Merkle tree hashing in its commitment scheme.
///
/// Gas note: each call to `hash()` costs roughly 50k–200k gas depending
/// on input length.  Suitable for prototype / low-frequency verification;
/// production should use a precompile or Yul-optimised version.
///
/// Test vectors (RFC 7693 / Python hashlib):
///   hash("")    = 0x69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9
///   hash("abc") = 0x508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982
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

    // Parameter block XOR for keyless Blake2s-256:
    //   digest_len=0x20, key_len=0, fanout=1, max_depth=1  → LE32 = 0x01010020
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
            _compress(h, empty, 0, 0, true);
        } else {
            uint256 offset = 0;
            // Process all complete blocks except the last
            while (len - offset > 64) {
                _compress(h, _block(data, offset), uint32(offset + 64), 0, false);
                offset += 64;
            }
            // Final block (1–64 bytes, zero-padded)
            _compress(h, _lastBlock(data, offset, len - offset), uint32(len), 0, true);
        }

        // Output: state words serialised as little-endian bytes
        return bytes32(
            (uint256(_rev32(h[0])) << 224) | (uint256(_rev32(h[1])) << 192) |
            (uint256(_rev32(h[2])) << 160) | (uint256(_rev32(h[3])) << 128) |
            (uint256(_rev32(h[4])) << 96)  | (uint256(_rev32(h[5])) << 64)  |
            (uint256(_rev32(h[6])) << 32)  |  uint256(_rev32(h[7]))
        );
    }

    // ── Compression function ──────────────────────────────────────────────────

    /// @dev Blake2s compression F.  Modifies h[] in place.
    function _compress(
        uint32[8]  memory h,
        uint32[16] memory m,
        uint32 t0, uint32 t1,
        bool last
    ) private pure {
        uint32[16] memory v;
        v[0] = h[0]; v[1] = h[1]; v[2] = h[2]; v[3]  = h[3];
        v[4] = h[4]; v[5] = h[5]; v[6] = h[6]; v[7]  = h[7];
        v[8]  = IV0; v[9]  = IV1; v[10] = IV2; v[11] = IV3;
        v[12] = IV4 ^ t0;
        v[13] = IV5 ^ t1;
        v[14] = last ? IV6 ^ 0xFFFFFFFF : IV6;
        v[15] = IV7;

        // 10 rounds — unrolled with inlined sigma schedule (RFC 7693)
        // Round 0: sigma = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
        _G(v,0,4, 8,12,m[ 0],m[ 1]); _G(v,1,5, 9,13,m[ 2],m[ 3]);
        _G(v,2,6,10,14,m[ 4],m[ 5]); _G(v,3,7,11,15,m[ 6],m[ 7]);
        _G(v,0,5,10,15,m[ 8],m[ 9]); _G(v,1,6,11,12,m[10],m[11]);
        _G(v,2,7, 8,13,m[12],m[13]); _G(v,3,4, 9,14,m[14],m[15]);

        // Round 1: sigma = [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3]
        _G(v,0,4, 8,12,m[14],m[10]); _G(v,1,5, 9,13,m[ 4],m[ 8]);
        _G(v,2,6,10,14,m[ 9],m[15]); _G(v,3,7,11,15,m[13],m[ 6]);
        _G(v,0,5,10,15,m[ 1],m[12]); _G(v,1,6,11,12,m[ 0],m[ 2]);
        _G(v,2,7, 8,13,m[11],m[ 7]); _G(v,3,4, 9,14,m[ 5],m[ 3]);

        // Round 2: sigma = [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4]
        _G(v,0,4, 8,12,m[11],m[ 8]); _G(v,1,5, 9,13,m[12],m[ 0]);
        _G(v,2,6,10,14,m[ 5],m[ 2]); _G(v,3,7,11,15,m[15],m[13]);
        _G(v,0,5,10,15,m[10],m[14]); _G(v,1,6,11,12,m[ 3],m[ 6]);
        _G(v,2,7, 8,13,m[ 7],m[ 1]); _G(v,3,4, 9,14,m[ 9],m[ 4]);

        // Round 3: sigma = [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8]
        _G(v,0,4, 8,12,m[ 7],m[ 9]); _G(v,1,5, 9,13,m[ 3],m[ 1]);
        _G(v,2,6,10,14,m[13],m[12]); _G(v,3,7,11,15,m[11],m[14]);
        _G(v,0,5,10,15,m[ 2],m[ 6]); _G(v,1,6,11,12,m[ 5],m[10]);
        _G(v,2,7, 8,13,m[ 4],m[ 0]); _G(v,3,4, 9,14,m[15],m[ 8]);

        // Round 4: sigma = [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13]
        _G(v,0,4, 8,12,m[ 9],m[ 0]); _G(v,1,5, 9,13,m[ 5],m[ 7]);
        _G(v,2,6,10,14,m[ 2],m[ 4]); _G(v,3,7,11,15,m[10],m[15]);
        _G(v,0,5,10,15,m[14],m[ 1]); _G(v,1,6,11,12,m[11],m[12]);
        _G(v,2,7, 8,13,m[ 6],m[ 8]); _G(v,3,4, 9,14,m[ 3],m[13]);

        // Round 5: sigma = [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9]
        _G(v,0,4, 8,12,m[ 2],m[12]); _G(v,1,5, 9,13,m[ 6],m[10]);
        _G(v,2,6,10,14,m[ 0],m[11]); _G(v,3,7,11,15,m[ 8],m[ 3]);
        _G(v,0,5,10,15,m[ 4],m[13]); _G(v,1,6,11,12,m[ 7],m[ 5]);
        _G(v,2,7, 8,13,m[15],m[14]); _G(v,3,4, 9,14,m[ 1],m[ 9]);

        // Round 6: sigma = [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11]
        _G(v,0,4, 8,12,m[12],m[ 5]); _G(v,1,5, 9,13,m[ 1],m[15]);
        _G(v,2,6,10,14,m[14],m[13]); _G(v,3,7,11,15,m[ 4],m[10]);
        _G(v,0,5,10,15,m[ 0],m[ 7]); _G(v,1,6,11,12,m[ 6],m[ 3]);
        _G(v,2,7, 8,13,m[ 9],m[ 2]); _G(v,3,4, 9,14,m[ 8],m[11]);

        // Round 7: sigma = [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10]
        _G(v,0,4, 8,12,m[13],m[11]); _G(v,1,5, 9,13,m[ 7],m[14]);
        _G(v,2,6,10,14,m[12],m[ 1]); _G(v,3,7,11,15,m[ 3],m[ 9]);
        _G(v,0,5,10,15,m[ 5],m[ 0]); _G(v,1,6,11,12,m[15],m[ 4]);
        _G(v,2,7, 8,13,m[ 8],m[ 6]); _G(v,3,4, 9,14,m[ 2],m[10]);

        // Round 8: sigma = [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5]
        _G(v,0,4, 8,12,m[ 6],m[15]); _G(v,1,5, 9,13,m[14],m[ 9]);
        _G(v,2,6,10,14,m[11],m[ 3]); _G(v,3,7,11,15,m[ 0],m[ 8]);
        _G(v,0,5,10,15,m[12],m[ 2]); _G(v,1,6,11,12,m[13],m[ 7]);
        _G(v,2,7, 8,13,m[ 1],m[ 4]); _G(v,3,4, 9,14,m[10],m[ 5]);

        // Round 9: sigma = [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]
        _G(v,0,4, 8,12,m[10],m[ 2]); _G(v,1,5, 9,13,m[ 8],m[ 4]);
        _G(v,2,6,10,14,m[ 7],m[ 6]); _G(v,3,7,11,15,m[ 1],m[ 5]);
        _G(v,0,5,10,15,m[15],m[11]); _G(v,1,6,11,12,m[ 9],m[14]);
        _G(v,2,7, 8,13,m[ 3],m[12]); _G(v,3,4, 9,14,m[13],m[ 0]);

        // Finalise
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

    /// @dev Right-rotate a 32-bit word by n bits.
    function _rotr(uint32 w, uint8 n) private pure returns (uint32) {
        return (w >> n) | (w << (32 - n));
    }

    /// @dev Load a full 64-byte block as 16 little-endian uint32 words.
    function _block(bytes memory data, uint256 off) private pure returns (uint32[16] memory m) {
        for (uint8 i = 0; i < 16; i++) {
            uint256 p = off + uint256(i) * 4;
            m[i] = uint32(uint8(data[p]))
                 | (uint32(uint8(data[p + 1])) << 8)
                 | (uint32(uint8(data[p + 2])) << 16)
                 | (uint32(uint8(data[p + 3])) << 24);
        }
    }

    /// @dev Load the final (possibly partial) block, zero-padding to 64 bytes.
    ///      `blockLen` is 1–64.
    function _lastBlock(
        bytes memory data,
        uint256 off,
        uint256 blockLen
    ) private pure returns (uint32[16] memory m) {
        uint256 end = off + blockLen;
        for (uint8 i = 0; i < 16; i++) {
            uint256 p = off + uint256(i) * 4;
            uint32 w = 0;
            if (p     < end) w  = uint32(uint8(data[p]));
            if (p + 1 < end) w |= uint32(uint8(data[p + 1])) << 8;
            if (p + 2 < end) w |= uint32(uint8(data[p + 2])) << 16;
            if (p + 3 < end) w |= uint32(uint8(data[p + 3])) << 24;
            m[i] = w;
        }
    }

    /// @dev Reverse the byte order of a 32-bit word (for LE output encoding).
    function _rev32(uint32 w) private pure returns (uint32) {
        return ((w & 0x000000FF) << 24)
             | ((w & 0x0000FF00) << 8)
             | ((w & 0x00FF0000) >> 8)
             |  (w >> 24);
    }
}
