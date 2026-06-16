// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Poseidon2M31T8.sol";

/// @title Poseidon2MerkleVerifierT8 — Poseidon2 t=8 wide Merkle verification
///
/// The t=4 backend (Poseidon2MerkleVerifierT4) still truncates each Merkle node
/// to 2 M31 words (62 bits → node collision ~2^31).  This library carries FOUR
/// M31 words per node (124 bits → node collision ~2^62) by hashing with the t=8
/// permutation: leaves use the rate-4 capacity-4 sponge and pairs use the 8→4
/// compression.  It is the next rung toward 128-bit Merkle binding (t=16 →
/// 8-word nodes → ~2^124).
///
/// Node encoding: bytes32 where the four BE u32 words occupy bytes[16..32]:
///   bytes[16..20]=w0, [20..24]=w1, [24..28]=w2, [28..32]=w3, i.e.
///   uint256(node) = (w0 << 96) | (w1 << 64) | (w2 << 32) | w3.
/// Matches Rust hash_leaf_cols_p2t8 / hash_pair_p2t8 in vfri2_bridge.rs.
library Poseidon2MerkleVerifierT8 {

    uint256 private constant MASK32 = 0xFFFFFFFF;

    // ── Node packing ──────────────────────────────────────────────────────────

    function _pack(uint256[4] memory n) private pure returns (bytes32) {
        return bytes32((n[0] << 96) | (n[1] << 64) | (n[2] << 32) | n[3]);
    }

    function _unpack(bytes32 node) private pure returns (uint256[4] memory n) {
        uint256 v = uint256(node);
        n[0] = (v >> 96) & MASK32;
        n[1] = (v >> 64) & MASK32;
        n[2] = (v >> 32) & MASK32;
        n[3] = v & MASK32;
    }

    // ── Leaf / pair hashing ───────────────────────────────────────────────────

    /// @notice Rate-4 capacity-4 Poseidon2 t=8 sponge hash of M31 column values.
    function hashLeaf(uint32[] memory colValues) internal pure returns (bytes32) {
        uint256[] memory vals = new uint256[](colValues.length);
        for (uint256 i = 0; i < colValues.length; i++) {
            vals[i] = uint256(colValues[i]);
        }
        return _pack(Poseidon2M31T8.sponge(vals));
    }

    /// @notice Wide Poseidon2 t=8 Merkle pair hash (8→4 compression).
    function hashPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return _pack(Poseidon2M31T8.compress(_unpack(left), _unpack(right)));
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
