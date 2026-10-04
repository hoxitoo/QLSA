// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Poseidon2M31.sol";

/// @title Poseidon2MerkleVerifier — Poseidon2 Merkle proof verification (VFRI8)
///
/// Replaces Blake2s with Poseidon2 for VFRI8 trace commitment.
///
/// Leaf hashing (matches hash_leaf_cols_p2 in vfri2_bridge.rs):
///   state = (0, 0)
///   for each v in colValues: s0 = (s0 + v) mod P; (s0, s1) = permute(s0, s1)
///   return bytes32(uint256(s0))
///
/// Node hashing (matches hash_pair_p2):
///   hashPair(left, right) = bytes32(compress(uint256(left), uint256(right)))
///
/// Merkle node encoding: bytes32 where the M31 value is in the low 32 bits
/// (big-endian bytes32 with 28 leading zero bytes, then the 4-byte u32 M31 value).
/// Matches Rust: out[28..32] = s[0].to_be_bytes().
library Poseidon2MerkleVerifier {

    uint256 private constant P = 2_147_483_647; // 2^31 - 1

    // ── Leaf hashing ──────────────────────────────────────────────────────────

    /// @notice Rate-1 Poseidon2 sponge hash of M31 column values.
    ///
    /// Column values are M31 elements (< P), so one-shot subtraction suffices.
    /// The add s0 += v stays valid because both s0 < P and v < P, so s0+v < 2P.
    function hashLeaf(uint32[] memory colValues) internal pure returns (bytes32) {
        uint256 s0 = 0;
        uint256 s1 = 0;
        for (uint256 i = 0; i < colValues.length; i++) {
            unchecked { s0 = s0 + uint256(colValues[i]); }
            if (s0 >= P) s0 -= P;
            (s0, s1) = Poseidon2M31.permute(s0, s1);
        }
        return bytes32(s0);
    }

    /// @notice Poseidon2 Merkle pair hash: compress(left_m31, right_m31).
    ///
    /// The M31 value of each node is uint256(nodeBytes32) (low 32 bits in
    /// big-endian representation = bytes[28..31] of the bytes32).
    function hashPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return bytes32(Poseidon2M31.compress(uint256(left), uint256(right)));
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
