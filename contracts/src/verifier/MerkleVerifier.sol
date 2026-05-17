// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Blake2s.sol";

/// @title MerkleVerifier — Blake2s Merkle proof verification
///
/// Verifies inclusion proofs for Stwo's Blake2s Merkle tree.
///
/// Stwo leaf hashing: Blake2s(left_child ‖ right_child) for internal nodes.
/// Leaf values: Blake2s(column_values...) — verified against the provided root.
///
/// This library verifies standard binary Merkle proofs where:
/// - Each proof step provides the sibling hash.
/// - The path is described by the query index (bit i = left/right at depth i).
library MerkleVerifier {

    // ── Leaf hashing ──────────────────────────────────────────────────────────

    /// @notice Hash a set of M31 column values into a Merkle leaf.
    /// Stwo packs M31 values as little-endian uint32 words, then hashes with Blake2s.
    /// @param colValues  Array of M31 values at a single row position.
    function hashLeaf(uint32[] memory colValues) internal pure returns (bytes32) {
        bytes memory buf = new bytes(colValues.length * 4);
        for (uint256 i = 0; i < colValues.length; i++) {
            uint32 v = colValues[i];
            buf[i * 4]     = bytes1(uint8(v));
            buf[i * 4 + 1] = bytes1(uint8(v >> 8));
            buf[i * 4 + 2] = bytes1(uint8(v >> 16));
            buf[i * 4 + 3] = bytes1(uint8(v >> 24));
        }
        return Blake2s.hash(buf);
    }

    /// @notice Hash two child hashes to form a parent node.
    function hashPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        bytes memory buf = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            buf[i]      = left[i];
            buf[32 + i] = right[i];
        }
        return Blake2s.hash(buf);
    }

    // ── Proof verification ────────────────────────────────────────────────────

    /// @notice Verify a Merkle inclusion proof.
    ///
    /// @param root        Expected Merkle root (bytes32).
    /// @param leafHash    Hash of the leaf to verify (pre-computed from column values).
    /// @param index       Leaf index in the tree (0-based, left-to-right).
    /// @param depth       Tree depth (number of hashing levels; leaves at depth 0).
    /// @param siblings    Sibling hashes from leaf to root (length == depth).
    ///                    siblings[0] is the leaf-level sibling, siblings[depth-1]
    ///                    is the child of the root.
    /// @return True iff the reconstructed root matches `root`.
    function verify(
        bytes32 root,
        bytes32 leafHash,
        uint256 index,
        uint256 depth,
        bytes32[] calldata siblings
    ) internal pure returns (bool) {
        require(siblings.length == depth, "MerkleVerifier: wrong sibling count");

        bytes32 current = leafHash;
        uint256 idx = index;

        for (uint256 d = 0; d < depth; d++) {
            bytes32 sibling = siblings[d];
            if (idx & 1 == 0) {
                // current is left child
                current = hashPair(current, sibling);
            } else {
                // current is right child
                current = hashPair(sibling, current);
            }
            idx >>= 1;
        }

        return current == root;
    }

    /// @notice Verify a Merkle proof where the leaf is a set of column values.
    /// Hashes the column values to a leaf, then delegates to verify().
    function verifyColumns(
        bytes32 root,
        uint32[] memory colValues,
        uint256 index,
        uint256 depth,
        bytes32[] calldata siblings
    ) internal pure returns (bool) {
        bytes32 leafHash = hashLeaf(colValues);
        return verify(root, leafHash, index, depth, siblings);
    }
}
