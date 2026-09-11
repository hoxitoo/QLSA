// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Poseidon2M31.sol";

/// @title Poseidon2MerkleVerifierW — WIDE Poseidon2 Merkle verification (VFRI9)
///
/// VFRI8's Poseidon2MerkleVerifier truncates every node to a single M31 word
/// (31 bits) — birthday collisions on a node cost only ~2^15.5 sponge calls.
/// This library carries BOTH sponge words in every node, raising the node
/// collision bound to ~2^31 (the maximum achievable with the t=2 permutation;
/// full 128-bit binding requires t>=4 / RPO256 — see known limitations).
///
/// Node encoding: bytes32 where bytes[24..28] = s0 (BE u32) and
/// bytes[28..32] = s1 (BE u32), i.e. uint256(node) = (s0 << 32) | s1.
/// Matches Rust hash_leaf_cols_p2w / hash_pair_p2w in vfri2_bridge.rs.
///
/// Leaf hashing (matches hash_leaf_cols_p2w):
///   state = (0, 0)
///   for v in colValues: s0 = (s0 + v) mod P; (s0, s1) = permute(s0, s1)
///   return bytes32((s0 << 32) | s1)
///
/// Pair hashing (matches hash_pair_p2w — duplex compress):
///   state = (l0, l1)
///   s0 = (s0 + r0) mod P; permute
///   s0 = (s0 + r1) mod P; permute
///   return bytes32((s0 << 32) | s1)
library Poseidon2MerkleVerifierW {

    uint256 private constant P = 2_147_483_647; // 2^31 - 1

    // ── Leaf hashing ──────────────────────────────────────────────────────────

    /// @notice Rate-1 Poseidon2 sponge hash of M31 column values (wide output).
    function hashLeaf(uint32[] memory colValues) internal pure returns (bytes32) {
        uint256 s0 = 0;
        uint256 s1 = 0;
        for (uint256 i = 0; i < colValues.length; i++) {
            unchecked { s0 = s0 + uint256(colValues[i]); }
            if (s0 >= P) s0 -= P;
            (s0, s1) = Poseidon2M31.permute(s0, s1);
        }
        return bytes32((s0 << 32) | s1);
    }

    /// @notice Wide Poseidon2 Merkle pair hash (duplex compress of 4 M31 words).
    function hashPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        uint256 s0 = (uint256(left) >> 32) & 0xFFFFFFFF;  // l0
        uint256 s1 = uint256(left) & 0xFFFFFFFF;          // l1
        uint256 r0 = (uint256(right) >> 32) & 0xFFFFFFFF;
        uint256 r1 = uint256(right) & 0xFFFFFFFF;

        unchecked { s0 = s0 + r0; }
        if (s0 >= P) s0 -= P;
        (s0, s1) = Poseidon2M31.permute(s0, s1);

        unchecked { s0 = s0 + r1; }
        if (s0 >= P) s0 -= P;
        (s0, s1) = Poseidon2M31.permute(s0, s1);

        return bytes32((s0 << 32) | s1);
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
