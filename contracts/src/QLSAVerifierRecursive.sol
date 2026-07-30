// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV4.sol";
import "./verifier/RecursiveChannelReplay.sol";
import "./verifier/Poseidon2MerkleVerifierT8.sol";

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

    /// @notice Cross-binding root for the outer proof — hashes EVERY public
    ///         field of the inner statement (R4.7 audit fix). Binding only the
    ///         trace root and last FRI-layer root let an attacker swap the OODS
    ///         combos, comp root, interior fold roots, batch root, tree depth or
    ///         query count while keeping a valid outer proof; now any change
    ///         moves `bound` and the outer proof no longer verifies.
    ///         Layout mirrors Rust `outer_binding_root` byte-for-byte:
    ///         traceRoot(32) ‖ oodsPos(16) ‖ oodsNeg(16) ‖ compRoot(32)
    ///         ‖ nRoots(4) ‖ root_i(32)* ‖ batchRoot(32) ‖ treeDepth(4) ‖ nQueries(4)
    function outerBindingRoot(InnerPublics calldata inner) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                inner.traceRoot,
                bytes16(inner.oodsComboPos),
                bytes16(inner.oodsComboNeg),
                inner.compRoot,
                uint32(inner.friLayerRoots.length),
                inner.friLayerRoots,
                inner.batchRoot,
                uint32(inner.treeDepth),
                uint32(inner.nQueries)
            )
        );
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
        ch = RecursiveChannelReplay.replay(
            inner.traceRoot,
            inner.oodsComboPos,
            inner.oodsComboNeg,
            inner.compRoot,
            inner.friLayerRoots,
            inner.batchRoot,
            inner.treeDepth,
            inner.nQueries
        );
    }

    /// @notice Largest last FRI layer accepted (mirrors QLSAVerifierVFRI11).
    uint256 public constant MAX_LAST_LAYER_SIZE = 1 << 16;

    /// @dev Split a QM31 into its four M31 words, MSB-first (matches qm31Words).
    function _qm31ToWords(uint128 v) private pure returns (uint32[] memory w) {
        w = new uint32[](4);
        w[0] = uint32(v >> 96);
        w[1] = uint32(v >> 64);
        w[2] = uint32(v >> 32);
        w[3] = uint32(v);
    }

    /// @notice Bounded-degree check on the final FRI layer.
    ///
    /// Rebuilds the last layer's Merkle tree from the supplied evaluations and
    /// compares it with the committed `friLayerRoots[K]`.  Combined with the
    /// recursion — which proves every query's fold chain terminates in that same
    /// committed root — this pins each query's final fold to a layer that is
    /// demonstrably a committed, bounded-degree polynomial.
    ///
    /// This stays ON-CHAIN rather than going in-circuit for the same reason the
    /// channel replay does (R3.10): it is cheap and CONSTANT, while the per-query
    /// work is what scales.  Production last layers are 16 evaluations (LOG=10)
    /// and 4 (LOG=8) — 15 and 3 compressions — against the recursion's
    /// 3 paths x depth x nQueries.  Moving it into the circuit would cost prover
    /// time to save a few hundred thousand gas.
    ///
    /// Mirrors `QLSAVerifierVFRI11._checkLastLayer` exactly, so the two agree by
    /// construction.
    function checkLastLayer(
        uint128[] memory evals,
        bytes32 expectedRoot,
        uint256 lastDepth
    ) public pure returns (bool) {
        if (lastDepth > 30) return false;
        uint256 lastLayerSize = uint256(1) << lastDepth;
        if (evals.length != lastLayerSize)       return false;
        if (lastLayerSize > MAX_LAST_LAYER_SIZE) return false;

        bytes32[] memory nodes = new bytes32[](lastLayerSize);
        for (uint256 i = 0; i < lastLayerSize; i++) {
            nodes[i] = Poseidon2MerkleVerifierT8.hashLeaf(_qm31ToWords(evals[i]));
        }
        uint256 sz = lastLayerSize;
        while (sz > 1) {
            sz >>= 1;
            for (uint256 i = 0; i < sz; i++) {
                nodes[i] = Poseidon2MerkleVerifierT8.hashPair(nodes[2 * i], nodes[2 * i + 1]);
            }
        }
        return nodes[0] == expectedRoot;
    }

    /// @notice Verify the recursive proof for one inner VFRI11 statement.
    ///
    /// GAS (MEASURED, R4.6): this full path does NOT fit on-chain today. The
    /// outer verification cost is dominated by Poseidon2-t8 Merkle/channel work
    /// and was measured to exceed a **29M-gas call** (Ethereum's block ceiling)
    /// BOTH with the original outer trace (log_size 7, 6 folds) AND with the
    /// compacted one (log_size 5, 1 query, 2 folds; hints 4.6 KB -> 2.6 KB).
    /// An earlier analytic estimate suggested the compact bundle would fit; the
    /// CI measurement refuted it, so do NOT build a submission pipeline on this
    /// entry point yet.
    ///
    /// What IS verified on-chain today: `replayChallenges` (the channel replay,
    /// byte-identical to the Rust reference) and `outerBindingRoot`; and this
    /// function correctly returns `false` for tampered inner publics or a wrong
    /// outer commitment, because VFRI11 short-circuits those before the
    /// expensive work.
    ///
    /// To make the honest path fit, the outer proof needs either a per-fold /
    /// per-transaction split registry (à la `BatchRegistryV6`, which solved the
    /// same wall for V23) or a cheaper outer backend (e.g. committing the outer
    /// trace with the t=4 `QLSAVerifierVFRI10` — the outer commitment's hash
    /// width is independent of the inner proof's t=8 backend).
    /// @param inner           the inner proof's public committed roots/combos
    /// @param outerProof      VFRI11-pipeline proof bytes over the OUTER trace
    /// @param outerCommitment Blake2s(outerProof[0:32] ‖ bindingRoot)[0:16]
    /// @param outerHints      VFRI11 ABI query hints for the outer proof
    /// @param lastLayerEvals  all 2^(treeDepth − numFolds) evaluations of the final
    ///        FRI layer, checked against the committed friLayerRoots[K]
    /// @return ok  true iff the outer proof verifies against the binding root
    /// @return ch  the replayed challenges + query indices (channel-derived
    ///             public inputs of the recursion) for upper-layer consumption
    function verifyRecursive(
        InnerPublics calldata inner,
        bytes calldata outerProof,
        bytes16 outerCommitment,
        bytes calldata outerHints,
        uint128[] calldata lastLayerEvals
    ) external view returns (bool ok, RecursiveChannelReplay.Challenges memory ch) {
        // 1. Replay the inner Fiat-Shamir channel from public roots alone —
        //    validates the inner publics' shape and derives the challenges the
        //    recursion is bound to (R4.2/R4.3).
        ch = RecursiveChannelReplay.replay(
            inner.traceRoot,
            inner.oodsComboPos,
            inner.oodsComboNeg,
            inner.compRoot,
            inner.friLayerRoots,
            inner.batchRoot,
            inner.treeDepth,
            inner.nQueries
        );

        // 2. Cross-binding root from the inner publics (R4.4).
        bytes32 bound = outerBindingRoot(inner);

        // 3. Bounded-degree check on the final FRI layer.  The recursion proves
        //    each query's fold chain lands on friLayerRoots[K]; this proves that
        //    root commits a small, low-degree layer rather than arbitrary data.
        //    numFolds = friLayerRoots.length - 1, so the last layer has
        //    2^(treeDepth - numFolds) evaluations.
        uint256 numFolds = inner.friLayerRoots.length - 1;
        if (inner.treeDepth < numFolds) return (false, ch);
        if (!checkLastLayer(
                lastLayerEvals,
                inner.friLayerRoots[numFolds],
                inner.treeDepth - numFolds
            )) {
            return (false, ch);
        }

        // 4. Verify the outer FRI-committed recursive trace, bound to `bound`
        //    (the outer channel mixed it before drawing ITS queries, so these
        //    hints only verify for exactly these inner publics).
        ok = outerVerifier.verify(outerProof, outerCommitment, bound, outerHints);
    }
}
