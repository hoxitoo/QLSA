// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Test helper — NOT for deployment.
import "../verifier/Poseidon2MerkleVerifierT16.sol";
import "../verifier/Poseidon2ChannelT16.sol";

/// @dev Exposes the t=16 hash backend (248-bit-node Merkle + Fiat-Shamir
///      channel) for cross-checking against the Rust references in
///      vfri2_bridge.rs.
contract Poseidon2T16BackendHarness {

    // ── Poseidon2MerkleVerifierT16 ────────────────────────────────────────────

    function hashLeaf(uint32[] calldata colValues) external pure returns (bytes32) {
        uint32[] memory v = new uint32[](colValues.length);
        for (uint256 i = 0; i < colValues.length; i++) v[i] = colValues[i];
        return Poseidon2MerkleVerifierT16.hashLeaf(v);
    }

    function hashPair(bytes32 left, bytes32 right) external pure returns (bytes32) {
        return Poseidon2MerkleVerifierT16.hashPair(left, right);
    }

    function verify(
        bytes32 root,
        bytes32 leafHash,
        uint256 index,
        uint256 depth,
        bytes32[] calldata siblings
    ) external pure returns (bool) {
        return Poseidon2MerkleVerifierT16.verify(root, leafHash, index, depth, siblings);
    }

    // ── Poseidon2ChannelT16 (whole-transcript helpers) ────────────────────────

    /// @notice init → mixRoot(root) → drawQueries(log, n).
    function mixRootDrawQueries(
        bytes32 root,
        uint256 logDomainSize,
        uint256 nQueries
    ) external pure returns (uint256[] memory) {
        Poseidon2ChannelT16.State memory s = Poseidon2ChannelT16.init();
        Poseidon2ChannelT16.mixRoot(s, root);
        return Poseidon2ChannelT16.drawQueries(s, logDomainSize, nQueries);
    }

    /// @notice init → mixRootW(root) → drawQueries(log, n).
    function mixRootWDrawQueries(
        bytes32 root,
        uint256 logDomainSize,
        uint256 nQueries
    ) external pure returns (uint256[] memory) {
        Poseidon2ChannelT16.State memory s = Poseidon2ChannelT16.init();
        Poseidon2ChannelT16.mixRootW(s, root);
        return Poseidon2ChannelT16.drawQueries(s, logDomainSize, nQueries);
    }

    /// @notice init → mixRootFull(root) → drawQueries(log, n).
    function mixRootFullDrawQueries(
        bytes32 root,
        uint256 logDomainSize,
        uint256 nQueries
    ) external pure returns (uint256[] memory) {
        Poseidon2ChannelT16.State memory s = Poseidon2ChannelT16.init();
        Poseidon2ChannelT16.mixRootFull(s, root);
        return Poseidon2ChannelT16.drawQueries(s, logDomainSize, nQueries);
    }

    /// @notice init → mixU32s(words) → drawSecureFelt.
    function mixU32sDrawSecureFelt(uint32[] calldata words) external pure returns (uint128) {
        uint32[] memory w = new uint32[](words.length);
        for (uint256 i = 0; i < words.length; i++) w[i] = words[i];
        Poseidon2ChannelT16.State memory s = Poseidon2ChannelT16.init();
        Poseidon2ChannelT16.mixU32s(s, w);
        return Poseidon2ChannelT16.drawSecureFelt(s);
    }
}
