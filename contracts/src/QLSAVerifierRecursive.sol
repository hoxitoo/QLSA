// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV4.sol";
import "./verifier/RecursiveChannelReplay.sol";

/// @title QLSAVerifierRecursive — on-chain entry point for the recursive proof (R4.5, MVP)
///
/// Assembles the two on-chain halves of the recursion design (R3.10/R4.2–R4.4):
///
///  1. **Channel replay** (`RecursiveChannelReplay`, R4.3): from the INNER
///     VFRI11 proof's PUBLIC committed roots alone, re-derive the FRI
///     challenges + query indices — the public inputs the recursive proof is
///     bound to.  Byte-identical to the Rust reference `vfri11_replay_channel`.
///  2. **Outer-proof verification** (R4.4): the OUTER recursive trace (the
///     trace of the STARK that proves "I verified the inner proof's per-query
///     decommitments") is tiny (87 columns), so it is FRI-committed with the
///     SAME VFRI11 hint pipeline and verified by the already-deployed
///     `QLSAVerifierVFRI11` at small constant gas.  The outer proof is
///     cross-bound to the inner publics: its binding root is
///     `keccak256(innerTraceRoot ‖ innerLastLayerRootWords)`, mixed into the
///     outer Fiat-Shamir channel before its query draw — an outer proof cannot
///     be replayed against different inner publics.
///
/// # Trust model (stated honestly)
///
/// The outer verification is VFRI-partial — FRI low-degree + Fiat-Shamir +
/// Merkle binding of the outer trace — the SAME semantics as the deployed
/// production `BatchRegistryV6` path.  The recursion AIR's constraint
/// satisfaction and the pinned-preprocessed (challenge/final) equality are
/// enforced by the Rust verifier (`verify_queries_membership_t8`, C1/C2
/// canonical-root pinning) off-chain; bringing the full constraint check
/// on-chain remains the documented limitation of the whole VFRI line.  The
/// replayed challenges are exposed to callers so upper layers (registry,
/// clients) consume channel-derived — not prover-chosen — values.
contract QLSAVerifierRecursive {
    /// @notice The deployed outer verifier (QLSAVerifierVFRI11, t=8 backend).
    IQLSAVerifierV4 public immutable outerVerifier;

    constructor(address vfri11) {
        require(vfri11 != address(0), "QVR: zero verifier");
        outerVerifier = IQLSAVerifierV4(vfri11);
    }

    /// @notice The inner VFRI11 proof's public inputs — every committed root /
    ///         OODS combo the channel replay consumes (see Vfri11ChannelInputs
    ///         in vfri2_bridge.rs).
    struct InnerPublics {
        bytes32 traceRoot; // embedded Stwo trace root (inner proof[8..40])
        uint128 oodsComboPos;
        uint128 oodsComboNeg;
        bytes32 compRoot;
        bytes32[] friLayerRoots; // [0..=numFolds]: layer-1 root, then one per fold
        bytes32 batchRoot; // the ML-DSA batch Merkle root
        uint256 treeDepth;
        uint256 nQueries;
    }

    /// @notice The outer proof's cross-binding root: keccak256 of the inner
    ///         trace root and the inner LAST FRI-layer root's four wide-node
    ///         words (bytes[16..32] of the packed node) — exactly the R4.4
    ///         Rust binding `keccak(trace_root ‖ last_layer_root words BE)`.
    function outerBindingRoot(bytes32 innerTraceRoot, bytes32 innerLastLayerRoot)
        public
        pure
        returns (bytes32)
    {
        // The wide t=8 node occupies bytes[16..32] = the low 128 bits.
        bytes16 nodeWords = bytes16(uint128(uint256(innerLastLayerRoot)));
        return keccak256(abi.encodePacked(innerTraceRoot, nodeWords));
    }

    /// @notice Replay ONLY the inner VFRI11 channel from its public roots and
    ///         return the derived challenges + query indices — the recursion's
    ///         channel-derived public inputs, with no outer-proof verification.
    ///         This half is fully on-chain today (R4.3); it is the sound source of
    ///         the query positions/challenges upper layers must pin.
    function replayChallenges(InnerPublics calldata inner)
        external
        pure
        returns (RecursiveChannelReplay.Challenges memory ch)
    {
        bytes32[] memory roots = new bytes32[](inner.friLayerRoots.length);
        for (uint256 i = 0; i < inner.friLayerRoots.length; i++) {
            roots[i] = inner.friLayerRoots[i];
        }
        ch = RecursiveChannelReplay.replay(
            inner.traceRoot,
            inner.oodsComboPos,
            inner.oodsComboNeg,
            inner.compRoot,
            roots,
            inner.batchRoot,
            inner.treeDepth,
            inner.nQueries
        );
    }

    /// @notice Verify the recursive proof for one inner VFRI11 statement.
    ///
    /// NOTE (R4.5 status): the outer recursive trace has tree_depth ≥ 6 (the t=8
    /// Merkle-path compressions dominate its row count), which exceeds the gas
    /// profile the deployed `QLSAVerifierVFRI11` was validated against (depth 4).
    /// The channel-replay + binding-root halves are verified on-chain
    /// (`replayChallenges`, `outerBindingRoot`); driving the OUTER proof through
    /// the deployed VFRI11 at this depth is pending a gas-appropriate outer
    /// verifier (a per-fold-split registry, à la BatchRegistryV6, or a smaller
    /// outer trace).  Kept for wiring completeness and off-chain (Rust) E2E.
    /// @param inner           the inner proof's public committed roots/combos
    /// @param outerProof      VFRI11-pipeline proof bytes over the OUTER trace
    /// @param outerCommitment Blake2s(outerProof[0:32] ‖ bindingRoot)[0:16]
    /// @param outerHints      VFRI11 ABI query hints for the outer proof
    /// @return ok  true iff the outer proof verifies against the binding root
    /// @return ch  the replayed challenges + query indices (channel-derived
    ///             public inputs of the recursion) for upper-layer consumption
    function verifyRecursive(
        InnerPublics calldata inner,
        bytes calldata outerProof,
        bytes16 outerCommitment,
        bytes calldata outerHints
    ) external view returns (bool ok, RecursiveChannelReplay.Challenges memory ch) {
        // 1. Replay the inner Fiat-Shamir channel from public roots alone —
        //    validates the inner publics' shape and derives the challenges the
        //    recursion is bound to (R4.2/R4.3).
        bytes32[] memory roots = new bytes32[](inner.friLayerRoots.length);
        for (uint256 i = 0; i < inner.friLayerRoots.length; i++) {
            roots[i] = inner.friLayerRoots[i];
        }
        ch = RecursiveChannelReplay.replay(
            inner.traceRoot,
            inner.oodsComboPos,
            inner.oodsComboNeg,
            inner.compRoot,
            roots,
            inner.batchRoot,
            inner.treeDepth,
            inner.nQueries
        );

        // 2. Cross-binding root from the inner publics (R4.4).
        bytes32 bound = outerBindingRoot(
            inner.traceRoot,
            inner.friLayerRoots[inner.friLayerRoots.length - 1]
        );

        // 3. Verify the outer FRI-committed recursive trace, bound to `bound`
        //    (the outer channel mixed it before drawing ITS queries, so these
        //    hints only verify for exactly these inner publics).
        ok = outerVerifier.verify(outerProof, outerCommitment, bound, outerHints);
    }
}
