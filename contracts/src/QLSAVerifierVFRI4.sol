// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";
import "./verifier/CirclePoint.sol";
import "./verifier/TwoChannel.sol";
import "./verifier/Poseidon2M31.sol";

/// @title QLSAVerifierVFRI4 — VFRI3 with Poseidon2 OODS sponge commitment (MVP-4)
///
/// Extends QLSAVerifierVFRI3 by replacing the Blake2s bulk channel mixing of all
/// OODS evaluations with a Poseidon2 sponge commitment.
///
/// Transcript change (vs VFRI3):
///   VFRI3: mixRoot → z_x → mixU32s(allOodsPos) → mixU32s(allOodsNeg) → compAlpha
///   VFRI4: mixRoot → z_x → mixU32s([p2sponge(oodsPos_m31s).s0,
///                                   p2sponge(oodsPos_m31s).s1,
///                                   p2sponge(oodsNeg_m31s).s0,
///                                   p2sponge(oodsNeg_m31s).s1]) → compAlpha
///
/// where each QM31 eval is expanded into 4 M31 values (c0.re, c0.im, c1.re, c1.im)
/// before sponge absorption. The channel receives exactly 4 M31 words (16 bytes)
/// regardless of the number of columns.
///
/// Security: Poseidon2 sponge over M31 is collision-resistant under standard
/// assumptions (algebraic hash function, 128-bit security at t=2, α=5, R_F=8).
/// The OODS commitment is binding: the prover cannot change any eval after the
/// Poseidon2 hash is mixed into the channel without invalidating compAlpha.
///
/// queryHints ABI encoding: identical to VFRI3.
///   abi.encode(uint128[] lastLayerCoeffs,
///              uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg,
///              bytes32[] friLayerRoots, QueryHints[])
contract QLSAVerifierVFRI4 is IQLSAVerifierV4 {

    uint256 public constant MIN_PROOF_LENGTH   = 700;
    uint256 public constant MAX_PROOF_LENGTH   = 1_048_576;
    uint256 public constant MIN_QUERIES        = 1;
    uint256 public constant MAX_QUERIES        = 64;
    uint256 public constant MAX_FOLD_ROUNDS    = 28;
    uint256 public constant MAX_LAST_LAYER_SIZE = 1 << 16; // 64 K evaluations max

    struct FoldHint {
        uint128   siblingValue;
        bytes32[] siblingProof;
        uint128   foldedValue;
        bytes32[] merkleProof;
    }

    struct QueryHints {
        bytes32   traceRoot;
        uint32[]  queryValues;
        uint32[]  queryValuesNeg;
        uint256   queryIndex;
        uint256   treeDepth;
        bytes32[] merkleSiblings;
        bytes32[] merkleSiblingsNeg;
        uint128   friAlpha;
        uint128   fPlus;
        uint128   fMinus;
        uint128   foldedValue;    // circle fold result; FRI L1 value at queryIndex
        uint256   queryPointX;
        uint256   queryPointY;
        bytes32[] friL1Siblings;  // Merkle proof for foldedValue in friLayerRoots[0]
        FoldHint[] folds;         // folds[k] for k = 0..numFolds−1
    }

    // All derived values from one transcript replay.
    struct VerifyCtx {
        bytes32   embeddedRoot;
        uint128   z_x;
        uint128   compAlpha;
        uint128   friAlpha;
        uint128   oodsComboPos;
        uint128   oodsComboNeg;
        bytes32[] friLayerRoots;
        uint128[] friAlphas;
        uint256[] derivedIndices;
    }

    // ── Public interface ──────────────────────────────────────────────────────

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

        (uint128[] memory lastLayerCoeffs,
         uint128[] memory oodsEvalsPos, uint128[] memory oodsEvalsNeg,
         bytes32[] memory friLayerRoots,
         QueryHints[] memory hints) =
            abi.decode(queryHints,
                (uint128[], uint128[], uint128[], bytes32[], QueryHints[]));

        if (friLayerRoots.length < 2)                   return false;
        if (friLayerRoots.length > MAX_FOLD_ROUNDS + 1) return false;
        if (hints.length < MIN_QUERIES)                 return false;
        if (hints.length > MAX_QUERIES)                 return false;
        if (oodsEvalsPos.length == 0)                   return false;
        if (oodsEvalsNeg.length != oodsEvalsPos.length) return false;
        if (lastLayerCoeffs.length == 0)                return false;

        for (uint256 r = 0; r < friLayerRoots.length; r++) {
            if (friLayerRoots[r] == bytes32(0)) return false;
        }

        bytes32 embeddedRoot;
        assembly ("memory-safe") { embeddedRoot := calldataload(add(proof.offset, 8)) }

        uint256 logDomainSize = hints[0].treeDepth;
        uint256 numFolds      = friLayerRoots.length - 1;

        if (logDomainSize < numFolds + 1) return false;
        if (logDomainSize > 30)           return false;

        {
            uint256 nCols = oodsEvalsPos.length;
            for (uint256 i = 0; i < hints.length; i++) {
                if (hints[i].treeDepth             != logDomainSize) return false;
                if (hints[i].queryValues.length    != nCols)         return false;
                if (hints[i].queryValuesNeg.length != nCols)         return false;
                if (hints[i].folds.length          != numFolds)      return false;
            }
        }

        // ── Last-layer polynomial check (MVP-4) ───────────────────────────────
        // Verify that friLayerRoots[K] is the Merkle root of the last-layer
        // polynomial evaluations supplied by the prover.
        {
            uint256 lastDepth     = logDomainSize - numFolds;
            uint256 lastLayerSize = uint256(1) << lastDepth;

            if (lastLayerCoeffs.length == 1) {
                // Constant polynomial: all leaves equal — use efficient constant-tree.
                bytes32 node = MerkleVerifier.hashLeaf(_qm31ToWords(lastLayerCoeffs[0]));
                for (uint256 i = 0; i < lastDepth; i++) {
                    node = MerkleVerifier.hashPair(node, node);
                }
                if (node != friLayerRoots[numFolds]) return false;
            } else {
                // Non-constant polynomial: build actual Merkle tree from all evaluations.
                if (lastLayerCoeffs.length != lastLayerSize) return false;
                if (lastLayerSize > MAX_LAST_LAYER_SIZE)     return false;

                bytes32[] memory nodes = new bytes32[](lastLayerSize);
                for (uint256 i = 0; i < lastLayerSize; i++) {
                    nodes[i] = MerkleVerifier.hashLeaf(_qm31ToWords(lastLayerCoeffs[i]));
                }
                uint256 sz = lastLayerSize;
                while (sz > 1) {
                    sz >>= 1;
                    for (uint256 i = 0; i < sz; i++) {
                        nodes[i] = MerkleVerifier.hashPair(nodes[2 * i], nodes[2 * i + 1]);
                    }
                }
                if (nodes[0] != friLayerRoots[numFolds]) return false;
            }
        }

        // Build context — single transcript replay, includes drawQueries.
        VerifyCtx memory ctx = _buildCtx(
            embeddedRoot, oodsEvalsPos, oodsEvalsNeg,
            friLayerRoots, hints.length, logDomainSize
        );

        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].friAlpha   != ctx.friAlpha)          return false;
            if (hints[i].queryIndex != ctx.derivedIndices[i]) return false;
            if (!_verifyQuery(hints[i], ctx)) return false;
        }

        return true;
    }

    // ── Transcript ────────────────────────────────────────────────────────────

    function _buildCtx(
        bytes32 embeddedRoot,
        uint128[] memory oodsEvalsPos,
        uint128[] memory oodsEvalsNeg,
        bytes32[] memory friLayerRoots,
        uint256 nQueries,
        uint256 logDomainSize
    ) internal pure returns (VerifyCtx memory ctx) {
        ctx.embeddedRoot  = embeddedRoot;
        ctx.friLayerRoots = friLayerRoots;

        TwoChannel.State memory chan = TwoChannel.init();
        TwoChannel.mixRoot(chan, embeddedRoot);
        ctx.z_x       = TwoChannel.drawSecureFelt(chan);
        {
            uint256[] memory posM31s = _qm31ArrayToM31s(oodsEvalsPos);
            uint256[] memory negM31s = _qm31ArrayToM31s(oodsEvalsNeg);
            (uint256 ps0, uint256 ps1) = Poseidon2M31.sponge(posM31s);
            (uint256 ns0, uint256 ns1) = Poseidon2M31.sponge(negM31s);
            uint32[] memory oodsHash = new uint32[](4);
            oodsHash[0] = uint32(ps0); oodsHash[1] = uint32(ps1);
            oodsHash[2] = uint32(ns0); oodsHash[3] = uint32(ns1);
            TwoChannel.mixU32s(chan, oodsHash);
        }
        ctx.compAlpha = TwoChannel.drawSecureFelt(chan);
        ctx.friAlpha  = TwoChannel.drawSecureFelt(chan);

        ctx.oodsComboPos = _compositionQM31(oodsEvalsPos, ctx.compAlpha);
        ctx.oodsComboNeg = _compositionQM31(oodsEvalsNeg, ctx.compAlpha);

        TwoChannel.mixRoot(chan, friLayerRoots[0]);

        uint256 numFolds = friLayerRoots.length - 1;
        ctx.friAlphas = new uint128[](numFolds);
        for (uint256 k = 0; k < numFolds; k++) {
            ctx.friAlphas[k] = TwoChannel.drawSecureFelt(chan);
            TwoChannel.mixRoot(chan, friLayerRoots[k + 1]);
        }

        ctx.derivedIndices = TwoChannel.drawQueries(chan, logDomainSize, nQueries);
    }

    // ── Query verification ────────────────────────────────────────────────────

    function _verifyQuery(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {

        if (h.traceRoot != ctx.embeddedRoot) return false;

        if (!MerkleVerifier.verifyColumnsMem(
            h.traceRoot, h.queryValues, h.queryIndex, h.treeDepth, h.merkleSiblings
        )) return false;

        {
            uint256 half = 1 << (h.treeDepth - 1);
            uint256 anti = (h.queryIndex + half) & ((1 << h.treeDepth) - 1);
            if (!MerkleVerifier.verifyColumnsMem(
                h.traceRoot, h.queryValuesNeg, anti, h.treeDepth, h.merkleSiblingsNeg
            )) return false;
        }

        if (!_verifyOODS(h, ctx))  return false;
        if (!_checkCircleFold(h))  return false;

        if (!MerkleVerifier.verifyMem(
            ctx.friLayerRoots[0],
            MerkleVerifier.hashLeaf(_qm31ToWords(h.foldedValue)),
            h.queryIndex, h.treeDepth, h.friL1Siblings
        )) return false;

        return _verifyFolds(h, ctx);
    }

    function _verifyOODS(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {
        uint128 rawComp    = _compositionM31(h.queryValues,    ctx.compAlpha);
        uint128 rawCompNeg = _compositionM31(h.queryValuesNeg, ctx.compAlpha);

        uint128 pxQM31   = QM31.fromM31(h.queryPointX);
        uint128 denomPos = QM31.sub(pxQM31, ctx.z_x);
        uint128 denomNeg = QM31.sub(QM31.neg(pxQM31), ctx.z_x);
        if (denomPos == uint128(0)) return false;
        if (denomNeg == uint128(0)) return false;

        if (QM31.mul(h.fPlus,  denomPos) != QM31.sub(rawComp,    ctx.oodsComboPos)) return false;
        if (QM31.mul(h.fMinus, denomNeg) != QM31.sub(rawCompNeg, ctx.oodsComboNeg)) return false;
        return true;
    }

    function _verifyFolds(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {
        uint256 curLineIdx = h.queryIndex;
        uint128 curValue   = h.foldedValue;
        uint256 numFolds   = ctx.friLayerRoots.length - 1;

        for (uint256 k = 0; k < numFolds; k++) {
            uint256 domainHalf = 1 << (h.treeDepth - 1 - k);
            uint256 newLineIdx = curLineIdx & (domainHalf - 1);
            uint256 sibling    = (curLineIdx < domainHalf)
                                    ? curLineIdx + domainHalf
                                    : curLineIdx - domainHalf;

            // Verify sibling in FRI L(k+1) at depth treeDepth−k.
            if (!MerkleVerifier.verifyMem(
                ctx.friLayerRoots[k],
                MerkleVerifier.hashLeaf(_qm31ToWords(h.folds[k].siblingValue)),
                sibling, h.treeDepth - k, h.folds[k].siblingProof
            )) return false;

            // Twiddle T_{2^k}(xJ) via k squarings.
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

            // Verify fold result in FRI L(k+2) at depth treeDepth−k−1.
            if (!MerkleVerifier.verifyMem(
                ctx.friLayerRoots[k + 1],
                MerkleVerifier.hashLeaf(_qm31ToWords(h.folds[k].foldedValue)),
                newLineIdx, h.treeDepth - k - 1, h.folds[k].merkleProof
            )) return false;

            curLineIdx = newLineIdx;
            curValue   = h.folds[k].foldedValue;
        }

        return true;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

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

    function _checkCircleFold(QueryHints memory h) internal pure returns (bool) {
        if (!CirclePoint.isOnCircle(h.queryPointX, h.queryPointY)) return false;
        if (h.treeDepth < 1 || h.treeDepth > 30) return false;
        if (h.queryIndex >= (1 << h.treeDepth))  return false;

        (uint256 cx, uint256 cy) = CirclePoint.cosetAt(h.treeDepth, h.queryIndex);
        if (cx != h.queryPointX || cy != h.queryPointY) return false;

        uint256 yInv = M31.inv(h.queryPointY);
        return CirclePoint.circleFold(h.fPlus, h.fMinus, h.friAlpha, yInv) == h.foldedValue;
    }

    function _compositionM31(uint32[] memory vals, uint128 alpha)
        internal pure returns (uint128 r)
    {
        uint128 ap = QM31.fromM31(1);
        for (uint256 j = 0; j < vals.length; j++) {
            r  = QM31.add(r, QM31.mul(ap, QM31.fromM31(vals[j])));
            ap = QM31.mul(ap, alpha);
        }
    }

    function _compositionQM31(uint128[] memory evals, uint128 alpha)
        internal pure returns (uint128 r)
    {
        uint128 ap = QM31.fromM31(1);
        for (uint256 j = 0; j < evals.length; j++) {
            r  = QM31.add(r, QM31.mul(ap, evals[j]));
            ap = QM31.mul(ap, alpha);
        }
    }

    function _qm31ArrayToWords(uint128[] memory evals)
        internal pure returns (uint32[] memory words)
    {
        words = new uint32[](evals.length * 4);
        for (uint256 i = 0; i < evals.length; i++) {
            uint128 q = evals[i];
            words[i * 4 + 0] = uint32(q >> 96);
            words[i * 4 + 1] = uint32((q >> 64) & 0xFFFFFFFF);
            words[i * 4 + 2] = uint32((q >> 32) & 0xFFFFFFFF);
            words[i * 4 + 3] = uint32(q & 0xFFFFFFFF);
        }
    }

    function _qm31ToWords(uint128 q) internal pure returns (uint32[] memory words) {
        words = new uint32[](4);
        words[0] = uint32(q >> 96);
        words[1] = uint32((q >> 64) & 0xFFFFFFFF);
        words[2] = uint32((q >> 32) & 0xFFFFFFFF);
        words[3] = uint32(q & 0xFFFFFFFF);
    }

    /// @dev Unpack uint128[] QM31 values into uint256[] M31 components.
    /// Each QM31 q = (c0.re, c0.im, c1.re, c1.im) → 4 M31 values in the array.
    function _qm31ArrayToM31s(uint128[] memory evals)
        internal pure returns (uint256[] memory m31s)
    {
        m31s = new uint256[](evals.length * 4);
        for (uint256 i = 0; i < evals.length; i++) {
            uint128 q = evals[i];
            m31s[i * 4 + 0] = uint32(q >> 96);
            m31s[i * 4 + 1] = uint32(q >> 64);
            m31s[i * 4 + 2] = uint32(q >> 32);
            m31s[i * 4 + 3] = uint32(q);
        }
    }
}
