// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Test helper — NOT for deployment.
import "../verifier/Poseidon2MerkleVerifierT8.sol";
import "../verifier/Poseidon2ChannelT8.sol";

/// @dev Exposes the t=8 hash backend (wide Merkle + Fiat-Shamir channel) for
///      cross-checking against the Rust references in vfri2_bridge.rs.
contract Poseidon2T8BackendHarness {

    // ── Poseidon2MerkleVerifierT8 ─────────────────────────────────────────────

    function hashLeaf(uint32[] calldata colValues) external pure returns (bytes32) {
        uint32[] memory v = new uint32[](colValues.length);
        for (uint256 i = 0; i < colValues.length; i++) v[i] = colValues[i];
        return Poseidon2MerkleVerifierT8.hashLeaf(v);
    }

    function hashPair(bytes32 left, bytes32 right) external pure returns (bytes32) {
        return Poseidon2MerkleVerifierT8.hashPair(left, right);
    }

    function verify(
        bytes32 root,
        bytes32 leafHash,
        uint256 index,
        uint256 depth,
        bytes32[] calldata siblings
    ) external pure returns (bool) {
        return Poseidon2MerkleVerifierT8.verify(root, leafHash, index, depth, siblings);
    }

    // ── Poseidon2ChannelT8 (whole-transcript helpers) ─────────────────────────

    /// @notice init → mixRoot(root) → drawQueries(log, n).
    function mixRootDrawQueries(
        bytes32 root,
        uint256 logDomainSize,
        uint256 nQueries
    ) external pure returns (uint256[] memory) {
        Poseidon2ChannelT8.State memory s = Poseidon2ChannelT8.init();
        Poseidon2ChannelT8.mixRoot(s, root);
        return Poseidon2ChannelT8.drawQueries(s, logDomainSize, nQueries);
    }

    /// @notice init → mixRootW(root) → drawQueries(log, n).
    function mixRootWDrawQueries(
        bytes32 root,
        uint256 logDomainSize,
        uint256 nQueries
    ) external pure returns (uint256[] memory) {
        Poseidon2ChannelT8.State memory s = Poseidon2ChannelT8.init();
        Poseidon2ChannelT8.mixRootW(s, root);
        return Poseidon2ChannelT8.drawQueries(s, logDomainSize, nQueries);
    }

    /// @notice init → mixRootFull(root) → drawQueries(log, n).
    function mixRootFullDrawQueries(
        bytes32 root,
        uint256 logDomainSize,
        uint256 nQueries
    ) external pure returns (uint256[] memory) {
        Poseidon2ChannelT8.State memory s = Poseidon2ChannelT8.init();
        Poseidon2ChannelT8.mixRootFull(s, root);
        return Poseidon2ChannelT8.drawQueries(s, logDomainSize, nQueries);
    }

    /// @notice init → mixU32s(words) → drawSecureFelt.
    function mixU32sDrawSecureFelt(uint32[] calldata words) external pure returns (uint128) {
        uint32[] memory w = new uint32[](words.length);
        for (uint256 i = 0; i < words.length; i++) w[i] = words[i];
        Poseidon2ChannelT8.State memory s = Poseidon2ChannelT8.init();
        Poseidon2ChannelT8.mixU32s(s, w);
        return Poseidon2ChannelT8.drawSecureFelt(s);
    }
}
