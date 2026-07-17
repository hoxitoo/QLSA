// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Test helper — NOT for deployment.
import "../verifier/RecursiveChannelReplay.sol";

/// @dev Exposes RecursiveChannelReplay.replay for cross-checking against the Rust
///      reference vectors (vfri11_channel_replay.json / RecursiveChannelReplay.test.js).
contract RecursiveChannelReplayHarness {
    function replay(
        bytes32 traceRoot,
        uint128 oodsComboPos,
        uint128 oodsComboNeg,
        bytes32 compRoot,
        bytes32[] calldata friLayerRoots,
        bytes32 batchRoot,
        uint256 treeDepth,
        uint256 nQueries
    )
        external
        pure
        returns (
            uint128 zX,
            uint128 compAlpha,
            uint128 friAlpha,
            uint128[] memory friAlphas,
            uint256[] memory queryIndices
        )
    {
        bytes32[] memory roots = new bytes32[](friLayerRoots.length);
        for (uint256 i = 0; i < friLayerRoots.length; i++) roots[i] = friLayerRoots[i];
        RecursiveChannelReplay.Challenges memory ch = RecursiveChannelReplay.replay(
            traceRoot, oodsComboPos, oodsComboNeg, compRoot, roots, batchRoot, treeDepth, nQueries
        );
        return (ch.zX, ch.compAlpha, ch.friAlpha, ch.friAlphas, ch.queryIndices);
    }
}
