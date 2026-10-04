// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Poseidon2M31T4.sol";

/// @title Poseidon2MerkleVerifierT4 — Poseidon2 t=4 wide Merkle verification (VFRI10)
///
/// VFRI9's Poseidon2MerkleVerifierW carries two M31 words per node but is built
/// on the t=2 permutation, whose capacity is a single cell — node collision
/// cost bottoms out at ~2^31 (the t=2 maximum; limitation #6).  This library
/// keeps the same 2-word node encoding but hashes with the t=4 permutation:
/// leaves use the capacity-2 rate-2 sponge and pairs use the 4→2 compression,
/// so the underlying state is 124 bits with a 2-cell capacity.  This is the
/// hash-backend step toward 128-bit Fiat-Shamir / Merkle binding (VFRI10).
///
/// Node encoding (identical to Poseidon2MerkleVerifierW): bytes32 where
/// bytes[24..28] = s0 (BE u32) and bytes[28..32] = s1 (BE u32), i.e.
/// uint256(node) = (s0 << 32) | s1.
/// Matches Rust hash_leaf_cols_p2t4 / hash_pair_p2t4 in vfri2_bridge.rs.
///
/// Leaf hashing (matches hash_leaf_cols_p2t4):
///   (s0, s1) = Poseidon2M31T4.sponge(colValues)   // rate-2 capacity-2 sponge
///   return bytes32((s0 << 32) | s1)
///
/// Pair hashing (matches hash_pair_p2t4 — single t=4 compression):
///   (s0, s1) = Poseidon2M31T4.compress(l0, l1, r0, r1)
///   return bytes32((s0 << 32) | s1)
library Poseidon2MerkleVerifierT4 {

    // ── Leaf hashing ──────────────────────────────────────────────────────────

    /// @notice Rate-2 capacity-2 Poseidon2 t=4 sponge hash of M31 column values.
    function hashLeaf(uint32[] memory colValues) internal pure returns (bytes32) {
        uint256[] memory vals = new uint256[](colValues.length);
        for (uint256 i = 0; i < colValues.length; i++) {
            vals[i] = uint256(colValues[i]);
        }
        (uint256 s0, uint256 s1) = Poseidon2M31T4.sponge(vals);
        return bytes32((s0 << 32) | s1);
    }

    /// @notice Wide Poseidon2 t=4 Merkle pair hash (4→2 compression).
    function hashPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        uint256 l0 = (uint256(left) >> 32) & 0xFFFFFFFF;
        uint256 l1 = uint256(left) & 0xFFFFFFFF;
        uint256 r0 = (uint256(right) >> 32) & 0xFFFFFFFF;
        uint256 r1 = uint256(right) & 0xFFFFFFFF;
        (uint256 o0, uint256 o1) = Poseidon2M31T4.compress(l0, l1, r0, r1);
        return bytes32((o0 << 32) | o1);
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
