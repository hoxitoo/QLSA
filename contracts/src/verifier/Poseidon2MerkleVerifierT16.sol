// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Poseidon2M31T16.sol";

/// @title Poseidon2MerkleVerifierT16 — Poseidon2 t=16 Merkle verification
///
/// The last rung of the node-width ladder. Each backend so far has truncated the
/// Merkle node to part of a word:
///
///   t=2 / t=4   2 M31 words   62 bits   node collision ~2^31
///   t=8         4 M31 words  124 bits   node collision ~2^62
///   t=16        8 M31 words  248 bits   node collision ~2^124  ← this file
///
/// ~2^124 is the 128-bit level the project targets, and 8 M31 words is exactly
/// 32 bytes, so a t=16 node fills a whole `bytes32` with no padding left over —
/// unlike t=8 (content in bytes[16..32]) or t=4 (bytes[24..32]).
///
/// Node encoding: word k occupies bytes[4k..4k+4], big-endian, i.e.
///   uint256(node) = Σ_k w_k << (224 - 32k).
/// Leaves use the rate-8 capacity-8 sponge; pairs use the 16→8 compression.
/// Matches Rust hash_leaf_cols_p2t16 / hash_pair_p2t16 in vfri2_bridge.rs.
library Poseidon2MerkleVerifierT16 {

    uint256 private constant MASK32 = 0xFFFFFFFF;

    // ── Node packing ──────────────────────────────────────────────────────────

    function _pack8(uint256[8] memory w) private pure returns (bytes32) {
        unchecked {
            return bytes32(
                (w[0] << 224) | (w[1] << 192) | (w[2] << 160) | (w[3] << 128) |
                (w[4] << 96)  | (w[5] << 64)  | (w[6] << 32)  |  w[7]
            );
        }
    }

    function _unpack8(bytes32 node) private pure returns (uint256[8] memory w) {
        unchecked {
            uint256 v = uint256(node);
            for (uint256 k = 0; k < 8; k++) {
                w[k] = (v >> (224 - 32 * k)) & MASK32;
            }
        }
    }

    // ── Leaf / pair hashing ───────────────────────────────────────────────────

    /// @notice Rate-8 capacity-8 Poseidon2 t=16 sponge hash of M31 column values.
    function hashLeaf(uint32[] memory colValues) internal pure returns (bytes32) {
        uint256[] memory vals = new uint256[](colValues.length);
        for (uint256 i = 0; i < colValues.length; i++) {
            vals[i] = uint256(colValues[i]);
        }
        return _pack8(Poseidon2M31T16.sponge8(vals));
    }

    /// @notice Poseidon2 t=16 Merkle pair hash (16→8 compression).
    function hashPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return _pack8(Poseidon2M31T16.compress8(_unpack8(left), _unpack8(right)));
    }

    // ── Proof verification ────────────────────────────────────────────────────

    /// @notice Verify a Merkle inclusion proof (calldata siblings).
    function verify(
        bytes32 root,
        bytes32 leafHash,
        uint256 index,
        uint256 depth,
        bytes32[] calldata siblings
    ) internal pure returns (bool) {
        return _verify(root, leafHash, index, depth, siblings);
    }

    /// @notice Verify a Merkle inclusion proof (memory siblings).
    function verifyMem(
        bytes32 root,
        bytes32 leafHash,
        uint256 index,
        uint256 depth,
        bytes32[] memory siblings
    ) internal pure returns (bool) {
        return _verify(root, leafHash, index, depth, siblings);
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _verify(
        bytes32 root,
        bytes32 leafHash,
        uint256 index,
        uint256 depth,
        bytes32[] memory siblings
    ) private pure returns (bool) {
        if (siblings.length != depth) return false;
        if (depth > 32) return false;
        if (depth > 0 && index >= (1 << depth)) return false;

        bytes32 current = leafHash;
        uint256 idx = index;

        for (uint256 d = 0; d < depth; d++) {
            bytes32 sibling = siblings[d];
            if (idx & 1 == 0) {
                current = hashPair(current, sibling);
            } else {
                current = hashPair(sibling, current);
            }
            idx >>= 1;
        }

        return current == root;
    }
}
