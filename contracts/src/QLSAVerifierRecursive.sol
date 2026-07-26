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

        // 3. Verify the outer FRI-committed recursive trace, bound to `bound`
        //    (the outer channel mixed it before drawing ITS queries, so these
        //    hints only verify for exactly these inner publics).
        ok = outerVerifier.verify(outerProof, outerCommitment, bound, outerHints);
    }
}
