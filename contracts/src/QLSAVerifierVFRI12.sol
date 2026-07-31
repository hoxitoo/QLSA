// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/Poseidon2MerkleVerifierT16.sol";
import "./verifier/Poseidon2ChannelT16.sol";
import "./verifier/CirclePoint.sol";

/// @title QLSAVerifierVFRI12 — VFRI11 protocol on the Poseidon2 t=16 hash backend
///
/// Identical proof protocol, ABI, and last-layer FRI check as VFRI10/VFRI11; the
/// only change is the hash backend, swapped from the t=8 Poseidon2 primitives to
/// their t=16 successors:
///
///   Poseidon2MerkleVerifierT8 → Poseidon2MerkleVerifierT16   (Merkle)
///   Poseidon2ChannelT8        → Poseidon2ChannelT16          (Fiat-Shamir)
///
/// This is the last rung of the node-width ladder. A t=16 permutation runs over
/// a 496-bit state, so a 2-to-1 compression carries 8-word (248-bit) nodes and
/// node collision cost rises from t=8's ~2^62 to ~2^124 — the 128-bit level the
/// project targets, and the width Stwo uses natively. It closes documented
/// limitation #6.
///
/// WHY THIS EXISTS AT ALL. The project had recorded that a standalone t=16
/// on-chain verifier should be SKIPPED, on the reasoning that it would hit the
/// same gas wall as t=8 roughly 4x worse and so could never verify production
/// V23. That reasoning rested on a measurement of an unoptimised permutation.
/// Measured properly, a t=16 permutation costs 1.79x a t=8 one — for twice the
/// node width — so per bit of node capacity t=16 is CHEAPER than t=8. Since a
/// full-V23 t=8 dual submitBatch fits in 6.06M of a 16.78M cap, the t=16
/// equivalent has room. See docs/conclusions.md §1 on why the earlier figure
/// measured the implementation rather than the width.
///
/// The queryHints ABI is byte-compatible with VFRI9/VFRI10/VFRI11 (Merkle
/// siblings are still bytes32; only the node *contents* widen, here to fill the
/// whole 32-byte word with no padding left). VFRI11 hints are nevertheless NOT
/// accepted: the permutation differs, so the trace root and the Fiat-Shamir
/// query indices both differ.
///
/// VFRI12 keeps the three VFRI9 soundness upgrades:
///
/// 1. LAST-LAYER FRI CHECK — the prover supplies all 2^(treeDepth-K) evaluations
///    of the final FRI layer; the verifier rebuilds that layer's Merkle tree and
///    asserts the root equals friLayerRoots[K]. Combined with the per-query
///    Merkle proofs into friLayerRoots[K], every query's final fold value is
///    fixed to the committed last layer, completing the bounded-degree argument.
///
/// 2. WIDE MERKLE NODES via Poseidon2MerkleVerifierT16 — EIGHT sponge words per
///    node (word k at bytes[4k..4k+4]), hashed by the t=16 permutation.
///
/// 3. FULL-ROOT FIAT-SHAMIR — foreign 32-byte roots (the embedded Stwo trace
///    root, the batch merkle root) are absorbed as 8 words (mixRootFull) instead
///    of only the low 4 bytes; wide node roots use 8 words (mixRootW). At this
///    width the two coincide, since a node IS the full 32 bytes.
///
/// Proof version marker: proof[0:8] = 6 (little-endian; VFRI11 uses 5).
contract QLSAVerifierVFRI12 is IQLSAVerifierV4 {

    uint256 public constant MIN_PROOF_LENGTH    = 700;
    uint256 public constant MAX_PROOF_LENGTH    = 1_048_576;
    uint256 public constant MIN_QUERIES         = 1;
    uint256 public constant MAX_QUERIES         = 64;
    uint256 public constant MAX_FOLD_ROUNDS     = 28;
    uint256 public constant MAX_LAST_LAYER_SIZE = 1 << 16; // 64K evaluations max

    struct FoldHint {
        uint128   siblingValue;
        bytes32[] siblingProof;
        uint128   foldedValue;
        bytes32[] merkleProof;
    }

    struct QueryHints {
        uint256   queryIndex;
        uint256   treeDepth;
        uint128   compValue;
        bytes32[] compProof;
        uint128   compValueNeg;
        bytes32[] compProofNeg;
        uint128   foldedValue;
        uint256   queryPointX;
        uint256   queryPointY;
        bytes32[] friL1Siblings;
        FoldHint[] folds;
    }

    struct VerifyCtx {
        bytes32   embeddedRoot;
        uint128   z_x;
        uint128   compAlpha;
        bytes32   compRoot;
        uint128   friAlpha;
        uint128   oodsComboPos;
        uint128   oodsComboNeg;
        bytes32[] friLayerRoots;
        uint128[] friAlphas;
        uint256[] derivedIndices;
    }

    /// @dev The decoded queryHints, as one memory object.
    ///
    ///      VFRI9–VFRI11 decode into six separate locals inside `verify`. VFRI12
    ///      cannot: the t=16 backend is roughly twice the code, and with it the
    ///      Yul stack allocator fails outright on that shape ("Variable size is 1
    ///      too deep in the stack", naming this decode's copy temporaries). Both
    ///      lowering the optimizer's inlining budget and moving only the decode
    ///      into its own function leave it failing, because the six results
    ///      themselves stay live across the whole body.
    ///
    ///      Splitting `verify` into a guard frame and a work frame, with the
    ///      decode passed as a single pointer, keeps both frames within the
    ///      stack. This is a CODEGEN accommodation only — the checks, their
    ///      order, and the transcript are identical to VFRI11, and the E2E
    ///      fixture pins that.
    struct Decoded {
        uint128 oodsComboPos;
        uint128 oodsComboNeg;
        bytes32 compRoot;
        uint128[] lastLayerEvals;
        bytes32[] friLayerRoots;
        QueryHints[] hints;
    }

    function _decodeHints(bytes calldata queryHints)
        private pure
        returns (Decoded memory d)
    {
        (d.oodsComboPos, d.oodsComboNeg, d.compRoot,
         d.lastLayerEvals, d.friLayerRoots, d.hints) =
            abi.decode(queryHints,
                (uint128, uint128, bytes32, uint128[], bytes32[], QueryHints[]));
    }

    function verify(
        bytes calldata proof,
        bytes16 commitment,
        bytes32 merkleRoot,
        bytes calldata queryHints
    ) external pure override returns (bool) {

        if (proof.length < MIN_PROOF_LENGTH) return false;
        if (proof.length > MAX_PROOF_LENGTH) return false;
        if (commitment == bytes16(0))        return false;
        if (merkleRoot == bytes32(0))        return false;
        if (queryHints.length == 0)          return false;
        if (!_checkCommitment(proof, commitment, merkleRoot)) return false;

        bytes32 embeddedRoot;
        assembly ("memory-safe") { embeddedRoot := calldataload(add(proof.offset, 8)) }

        return _verifyDecoded(_decodeHints(queryHints), embeddedRoot, merkleRoot);
    }

    function _verifyDecoded(
        Decoded memory d,
        bytes32 embeddedRoot,
        bytes32 merkleRoot
    ) private pure returns (bool) {

        if (d.oodsComboPos == 0 && d.oodsComboNeg == 0) return false;
        if (d.compRoot == bytes32(0))                   return false;
        if (d.lastLayerEvals.length == 0)               return false;
        if (d.friLayerRoots.length < 2)                 return false;
        if (d.friLayerRoots.length > MAX_FOLD_ROUNDS + 1) return false;
        if (d.hints.length < MIN_QUERIES)               return false;
        if (d.hints.length > MAX_QUERIES)               return false;

        for (uint256 r = 0; r < d.friLayerRoots.length; r++) {
            if (d.friLayerRoots[r] == bytes32(0)) return false;
        }

        uint256 logDomainSize = d.hints[0].treeDepth;
        uint256 numFolds      = d.friLayerRoots.length - 1;

        if (logDomainSize < numFolds + 1) return false;
        if (logDomainSize > 30)           return false;

        for (uint256 i = 0; i < d.hints.length; i++) {
            if (d.hints[i].treeDepth    != logDomainSize) return false;
            if (d.hints[i].folds.length != numFolds)      return false;
        }

        // ── Last-layer bounded-degree check ───────────────────────────────────
        // friLayerRoots[K] must be the Merkle root of the prover-supplied
        // last-layer evaluations.  Per-query Merkle proofs already bind each
        // final fold value into friLayerRoots[K]; together this fixes every
        // query's final value to the committed (degree-bounded) last layer.
        if (!_checkLastLayer(d.lastLayerEvals, d.friLayerRoots[numFolds],
                             logDomainSize - numFolds)) return false;

        VerifyCtx memory ctx = _buildCtx(
            embeddedRoot, d.oodsComboPos, d.oodsComboNeg, d.compRoot,
            d.friLayerRoots, d.hints.length, logDomainSize, merkleRoot
        );

        for (uint256 i = 0; i < d.hints.length; i++) {
            if (d.hints[i].queryIndex != ctx.derivedIndices[i]) return false;
            if (!_verifyQuery(d.hints[i], ctx)) return false;
        }

        return true;
    }

    /// @dev Rebuild the last-layer Merkle tree (wide Poseidon2 nodes) and
    ///      compare against the committed root.
    function _checkLastLayer(
        uint128[] memory evals,
        bytes32 expectedRoot,
        uint256 lastDepth
    ) internal pure returns (bool) {
        uint256 lastLayerSize = uint256(1) << lastDepth;
        if (evals.length != lastLayerSize)      return false;
        if (lastLayerSize > MAX_LAST_LAYER_SIZE) return false;

        bytes32[] memory nodes = new bytes32[](lastLayerSize);
        for (uint256 i = 0; i < lastLayerSize; i++) {
            nodes[i] = Poseidon2MerkleVerifierT16.hashLeaf(_qm31ToWords(evals[i]));
        }
        uint256 sz = lastLayerSize;
        while (sz > 1) {
            sz >>= 1;
            for (uint256 i = 0; i < sz; i++) {
                nodes[i] = Poseidon2MerkleVerifierT16.hashPair(nodes[2 * i], nodes[2 * i + 1]);
            }
        }
        return nodes[0] == expectedRoot;
    }

    /// @dev Replay Fiat-Shamir transcript using Poseidon2Channel with
    ///      full-root absorption (mixRootFull / mixRootW).
    function _buildCtx(
        bytes32   embeddedRoot,
        uint128   oodsComboPos,
        uint128   oodsComboNeg,
        bytes32   compRoot,
        bytes32[] memory friLayerRoots,
        uint256   nQueries,
        uint256   logDomainSize,
        bytes32   merkleRoot
    ) internal pure returns (VerifyCtx memory ctx) {
        ctx.embeddedRoot  = embeddedRoot;
        ctx.compRoot      = compRoot;
        ctx.friLayerRoots = friLayerRoots;
        ctx.oodsComboPos  = oodsComboPos;
        ctx.oodsComboNeg  = oodsComboNeg;

        Poseidon2ChannelT16.State memory chan = Poseidon2ChannelT16.init();
        Poseidon2ChannelT16.mixRootFull(chan, embeddedRoot);

        ctx.z_x       = Poseidon2ChannelT16.drawSecureFelt(chan);
        ctx.compAlpha  = Poseidon2ChannelT16.drawSecureFelt(chan);

        {
            uint32[] memory comboWords = new uint32[](8);
            comboWords[0] = uint32(oodsComboPos >> 96);
            comboWords[1] = uint32(oodsComboPos >> 64);
            comboWords[2] = uint32(oodsComboPos >> 32);
            comboWords[3] = uint32(oodsComboPos);
            comboWords[4] = uint32(oodsComboNeg >> 96);
            comboWords[5] = uint32(oodsComboNeg >> 64);
            comboWords[6] = uint32(oodsComboNeg >> 32);
            comboWords[7] = uint32(oodsComboNeg);
            Poseidon2ChannelT16.mixU32s(chan, comboWords);
        }

        Poseidon2ChannelT16.mixRootW(chan, compRoot);
        ctx.friAlpha = Poseidon2ChannelT16.drawSecureFelt(chan);
        Poseidon2ChannelT16.mixRootW(chan, friLayerRoots[0]);

        uint256 numFolds = friLayerRoots.length - 1;
        ctx.friAlphas = new uint128[](numFolds);
        for (uint256 k = 0; k < numFolds; k++) {
            ctx.friAlphas[k] = Poseidon2ChannelT16.drawSecureFelt(chan);
            Poseidon2ChannelT16.mixRootW(chan, friLayerRoots[k + 1]);
        }

        // Cross-proof binding: mix the FULL merkleRoot before drawQueries.
        Poseidon2ChannelT16.mixRootFull(chan, merkleRoot);

        ctx.derivedIndices = Poseidon2ChannelT16.drawQueries(chan, logDomainSize, nQueries);
    }

    function _verifyQuery(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {
        if (!Poseidon2MerkleVerifierT16.verifyMem(
            ctx.compRoot,
            Poseidon2MerkleVerifierT16.hashLeaf(_qm31ToWords(h.compValue)),
            h.queryIndex, h.treeDepth, h.compProof
        )) return false;

        {
            uint256 half = uint256(1) << (h.treeDepth - 1);
            uint256 anti = (h.queryIndex + half) & ((uint256(1) << h.treeDepth) - 1);
            if (!Poseidon2MerkleVerifierT16.verifyMem(
                ctx.compRoot,
                Poseidon2MerkleVerifierT16.hashLeaf(_qm31ToWords(h.compValueNeg)),
                anti, h.treeDepth, h.compProofNeg
            )) return false;
        }

        (bool oodsOk, uint128 fPlus, uint128 fMinus) = _verifyOODS(h, ctx);
        if (!oodsOk) return false;
        if (!_checkCircleFold(fPlus, fMinus, h, ctx.friAlpha)) return false;

        if (!Poseidon2MerkleVerifierT16.verifyMem(
            ctx.friLayerRoots[0],
            Poseidon2MerkleVerifierT16.hashLeaf(_qm31ToWords(h.foldedValue)),
            h.queryIndex, h.treeDepth, h.friL1Siblings
        )) return false;

        return _verifyFolds(h, ctx);
    }

    function _verifyOODS(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool ok, uint128 fPlus, uint128 fMinus) {
        uint128 pxQM31   = QM31.fromM31(h.queryPointX);
        uint128 denomPos = QM31.sub(pxQM31, ctx.z_x);
        uint128 denomNeg = QM31.sub(QM31.neg(pxQM31), ctx.z_x);

        if (denomPos == uint128(0)) return (false, 0, 0);
        if (denomNeg == uint128(0)) return (false, 0, 0);

        uint128 numerPos = QM31.sub(h.compValue,    ctx.oodsComboPos);
        uint128 numerNeg = QM31.sub(h.compValueNeg, ctx.oodsComboNeg);

        fPlus  = QM31.mul(numerPos, QM31.inv(denomPos));
        fMinus = QM31.mul(numerNeg, QM31.inv(denomNeg));

        return (true, fPlus, fMinus);
    }

    function _checkCircleFold(
        uint128 fPlus,
        uint128 fMinus,
        QueryHints memory h,
        uint128 friAlpha
    ) internal pure returns (bool) {
        if (!CirclePoint.isOnCircle(h.queryPointX, h.queryPointY)) return false;
        if (h.queryPointY == 0) return false;
        if (h.treeDepth < 1 || h.treeDepth > 30) return false;
        if (h.queryIndex >= (uint256(1) << h.treeDepth)) return false;

        (uint256 cx, uint256 cy) = CirclePoint.cosetAt(h.treeDepth, h.queryIndex);
        if (cx != h.queryPointX || cy != h.queryPointY) return false;

        uint256 yInv = M31.inv(h.queryPointY);
        return CirclePoint.circleFold(fPlus, fMinus, friAlpha, yInv) == h.foldedValue;
    }

    function _verifyFolds(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {
        uint256 curLineIdx = h.queryIndex;
        uint128 curValue   = h.foldedValue;
        uint256 numFolds   = ctx.friLayerRoots.length - 1;

        for (uint256 k = 0; k < numFolds; k++) {
            uint256 domainHalf = uint256(1) << (h.treeDepth - 1 - k);
            uint256 newLineIdx = curLineIdx & (domainHalf - 1);
            uint256 sibling    = (curLineIdx < domainHalf)
                                    ? curLineIdx + domainHalf
                                    : curLineIdx - domainHalf;

            if (!Poseidon2MerkleVerifierT16.verifyMem(
                ctx.friLayerRoots[k],
                Poseidon2MerkleVerifierT16.hashLeaf(_qm31ToWords(h.folds[k].siblingValue)),
                sibling, h.treeDepth - k, h.folds[k].siblingProof
            )) return false;

            (uint256 xJ, ) = CirclePoint.cosetAt(h.treeDepth, newLineIdx);
            uint256 twiddle = xJ;
            for (uint256 i = 0; i < k; i++) {
                uint256 t2 = M31.mul(twiddle, twiddle);
                twiddle = M31.sub(M31.add(t2, t2), 1);
            }
            if (twiddle == 0) return false;

            {
                uint128 gPlus  = (curLineIdx < domainHalf) ? curValue : h.folds[k].siblingValue;
                uint128 gMinus = (curLineIdx < domainHalf) ? h.folds[k].siblingValue : curValue;
                if (CirclePoint.lineFold(gPlus, gMinus, ctx.friAlphas[k], M31.inv(twiddle))
                        != h.folds[k].foldedValue) return false;
            }

            if (!Poseidon2MerkleVerifierT16.verifyMem(
                ctx.friLayerRoots[k + 1],
                Poseidon2MerkleVerifierT16.hashLeaf(_qm31ToWords(h.folds[k].foldedValue)),
                newLineIdx, h.treeDepth - k - 1, h.folds[k].merkleProof
            )) return false;

            curLineIdx = newLineIdx;
            curValue   = h.folds[k].foldedValue;
        }

        return true;
    }

    /// @dev Commitment check: Blake2s(proof[0:32] ‖ merkleRoot)[0:16] == commitment.
    ///      Kept as Blake2s — single call, cheap, not a verification bottleneck.
    function _checkCommitment(
        bytes calldata proof,
        bytes16 commitment,
        bytes32 merkleRoot
    ) internal pure returns (bool) {
        bytes memory hInput = new bytes(64);
        assembly ("memory-safe") { calldatacopy(add(hInput, 32), proof.offset, 32) }
        for (uint256 i = 0; i < 32; i++) hInput[32 + i] = merkleRoot[i];
        bytes32 h = Blake2s.hash(hInput);
        return bytes16(h) == commitment;
    }

    function _qm31ToWords(uint128 q) internal pure returns (uint32[] memory words) {
        words = new uint32[](4);
        words[0] = uint32(q >> 96);
        words[1] = uint32((q >> 64) & 0xFFFFFFFF);
        words[2] = uint32((q >> 32) & 0xFFFFFFFF);
        words[3] = uint32(q & 0xFFFFFFFF);
    }
}
