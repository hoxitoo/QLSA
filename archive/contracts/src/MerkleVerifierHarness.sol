// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Test helper — NOT for deployment.
import "../verifier/MerkleVerifier.sol";

contract MerkleVerifierHarness {
    function hashLeaf(uint32[] calldata colValues) external pure returns (bytes32) {
        return MerkleVerifier.hashLeaf(colValues);
    }

    function hashPair(bytes32 left, bytes32 right) external pure returns (bytes32) {
        return MerkleVerifier.hashPair(left, right);
    }

    function verify(
        bytes32 root,
        bytes32 leafHash,
        uint256 index,
        uint256 depth,
        bytes32[] calldata siblings
    ) external pure returns (bool) {
        return MerkleVerifier.verify(root, leafHash, index, depth, siblings);
    }

    function verifyColumns(
        bytes32 root,
        uint32[] calldata colValues,
        uint256 index,
        uint256 depth,
        bytes32[] calldata siblings
    ) external pure returns (bool) {
        return MerkleVerifier.verifyColumns(root, colValues, index, depth, siblings);
    }
}
