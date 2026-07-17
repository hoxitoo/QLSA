// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Poseidon2ChannelT8.sol";

/// @title RecursiveChannelReplay — on-chain VFRI11 Fiat-Shamir channel replay (R4.3)
///
/// The Solidity mirror of `vfri11_replay_channel` in `stark_stwo/src/vfri2_bridge.rs`.
/// Per the R3.10 design decision, the cheap Poseidon2 t=8 channel stays ON-CHAIN:
/// from the PUBLIC committed roots alone (no trace/witness) it re-derives the FRI
/// challenges + query indices, which then become the public inputs the recursive
/// STARK proof is bound to.  This is the first self-contained piece of
/// `QLSAVerifierRecursive.sol`.
///
/// Op order is byte-identical to `vfri11_fri_chain` / `vfri11_replay_channel`
/// (same `Poseidon2ChannelT8`), cross-checked against the Rust reference vectors
/// in `contracts/test/fixtures/vfri11_channel_replay.json`
/// (RecursiveChannelReplay.test.js).
library RecursiveChannelReplay {
    using Poseidon2ChannelT8 for Poseidon2ChannelT8.State;

    /// @notice The challenges + query indices drawn by the replay — exactly the
    ///         verifier-fixed public inputs the recursive proof pins.
    struct Challenges {
        uint128 zX; // OODS line point
        uint128 compAlpha; // composition combination challenge
        uint128 friAlpha; // circle-fold challenge
        uint128[] friAlphas; // per-fold line-fold challenges (length = numFolds)
        uint256[] queryIndices; // FRI query positions in [0, 2^treeDepth)
    }

    /// @notice Split a QM31 (uint128) into its four M31 words, MSB-first —
    ///         matches `qm31_words` (v>>96, v>>64, v>>32, v).
    function qm31Words(uint128 v) internal pure returns (uint32[4] memory w) {
        w[0] = uint32(v >> 96);
        w[1] = uint32(v >> 64);
        w[2] = uint32(v >> 32);
        w[3] = uint32(v);
    }

    /// @notice Replay the VFRI11 channel from public roots + OODS combos.
    /// @param traceRoot     the embedded Stwo trace root (mixRootFull, 32 bytes)
    /// @param oodsComboPos  Σ αʲ·oodsEvalPos_j  (QM31)
    /// @param oodsComboNeg  Σ αʲ·oodsEvalNeg_j  (QM31)
    /// @param compRoot      composition-polynomial Merkle root (mixRootW, wide node)
    /// @param friLayerRoots friLayerRoots[0..=numFolds]: layer-1 root then one per fold
    /// @param batchRoot     the batch Merkle root (mixRootFull)
    /// @param treeDepth     log2 of the FRI domain size
    /// @param nQueries      number of FRI queries to draw
    function replay(
        bytes32 traceRoot,
        uint128 oodsComboPos,
        uint128 oodsComboNeg,
        bytes32 compRoot,
        bytes32[] memory friLayerRoots,
        bytes32 batchRoot,
        uint256 treeDepth,
        uint256 nQueries
    ) internal pure returns (Challenges memory ch) {
        require(treeDepth >= 2 && treeDepth <= 30, "RCR: treeDepth out of range");
        require(nQueries >= 1 && nQueries <= 64, "RCR: nQueries out of range");
        require(friLayerRoots.length >= 1, "RCR: need >= 1 fri layer root");
        uint256 numFolds = friLayerRoots.length - 1;

        Poseidon2ChannelT8.State memory s = Poseidon2ChannelT8.init();

        s.mixRootFull(traceRoot);
        ch.zX = s.drawSecureFelt();
        ch.compAlpha = s.drawSecureFelt();

        // combo words = qm31Words(pos) ‖ qm31Words(neg) — 8 u32 words.
        uint32[4] memory p = qm31Words(oodsComboPos);
        uint32[4] memory nw = qm31Words(oodsComboNeg);
        uint32[] memory combo = new uint32[](8);
        combo[0] = p[0];
        combo[1] = p[1];
        combo[2] = p[2];
        combo[3] = p[3];
        combo[4] = nw[0];
        combo[5] = nw[1];
        combo[6] = nw[2];
        combo[7] = nw[3];
        s.mixU32s(combo);

        s.mixRootW(compRoot);
        ch.friAlpha = s.drawSecureFelt();

        s.mixRootW(friLayerRoots[0]);
        ch.friAlphas = new uint128[](numFolds);
        for (uint256 k = 0; k < numFolds; k++) {
            ch.friAlphas[k] = s.drawSecureFelt();
            s.mixRootW(friLayerRoots[k + 1]);
        }

        s.mixRootFull(batchRoot);
        ch.queryIndices = s.drawQueries(treeDepth, nQueries);
    }
}
