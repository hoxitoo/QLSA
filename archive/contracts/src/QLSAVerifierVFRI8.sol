// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// NOTE: Compile with viaIR: true — the ABI decode in verify() uses multiple
// static fields which would otherwise exceed Solidity's stack-depth limit.

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/Poseidon2MerkleVerifier.sol";
import "./verifier/Poseidon2Channel.sol";
import "./verifier/CirclePoint.sol";

/// @title QLSAVerifierVFRI8 — VFRI7 with Poseidon2 trace commitment (MVP-5 VFRI8)
///
/// Protocol change vs VFRI7:
///   VFRI7 uses Blake2s for Merkle tree hashing and the Fiat-Shamir channel.
///   VFRI8 replaces both with Poseidon2 over M31 (t=2, α=5, 8 full rounds).
///
/// Gas reduction:
///   Blake2s Merkle path at depth=10: ~800K gas/path
///   Poseidon2 Merkle path at depth=10: 10 × ~1000 gas = ~10K gas/path
///   20 queries × 2 paths × 10K ≈ 400K gas (vs ~160M gas for Blake2s)
///
/// Commitment check (_checkCommitment) is kept as Blake2s — single call, cheap.
///
/// Transcript (identical to VFRI7 but using Poseidon2Channel):
///   Poseidon2Channel.mixRoot(traceRoot)               ← proof[8:40]
///   z_x       = drawSecureFelt
///   compAlpha = drawSecureFelt
///   mixU32s([c0re(comboPos),c0im,c1re,c1im, c0re(comboNeg),c0im,c1re,c1im])
///   mixRoot(compRoot)
///   friAlpha = drawSecureFelt
///   mixRoot(friLayerRoots[0])
///   for k in 0..numFolds-1:
///     friAlphas[k] = drawSecureFelt
///     mixRoot(friLayerRoots[k+1])
///   mixRoot(merkleRoot)                               ← cross-proof binding
///   drawQueries(treeDepth, nQueries)
///
/// queryHints ABI encoding: identical to VFRI6/VFRI7 (5 head slots = 160 bytes):
///   abi.encode(uint128 oodsComboPos, uint128 oodsComboNeg,
///              bytes32 compRoot, bytes32[] friLayerRoots, QueryHints[])
///
/// Merkle nodes: bytes32 where the M31 value is in the low 32 bits.
///   Leaf: Poseidon2 rate-1 sponge over column uint32 values.
///   Pair: bytes32(compress(uint256(left), uint256(right))).
contract QLSAVerifierVFRI8 is IQLSAVerifierV4 {

    uint256 public constant MIN_PROOF_LENGTH = 700;
    uint256 public constant MAX_PROOF_LENGTH = 1_048_576;
    uint256 public constant MIN_QUERIES      = 1;
    uint256 public constant MAX_QUERIES      = 64;
    uint256 public constant MAX_FOLD_ROUNDS  = 28;

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

        (uint128          oodsComboPos,
         uint128          oodsComboNeg,
         bytes32          compRoot,
         bytes32[] memory friLayerRoots,
         QueryHints[] memory hints) =
            abi.decode(queryHints,
                (uint128, uint128, bytes32, bytes32[], QueryHints[]));

        if (oodsComboPos == 0 && oodsComboNeg == 0) return false;
        if (compRoot == bytes32(0))                 return false;
        if (friLayerRoots.length < 2)               return false;
        if (friLayerRoots.length > MAX_FOLD_ROUNDS + 1) return false;
        if (hints.length < MIN_QUERIES)             return false;
        if (hints.length > MAX_QUERIES)             return false;

        for (uint256 r = 0; r < friLayerRoots.length; r++) {
            if (friLayerRoots[r] == bytes32(0)) return false;
        }

        bytes32 embeddedRoot;
        assembly ("memory-safe") { embeddedRoot := calldataload(add(proof.offset, 8)) }

        uint256 logDomainSize = hints[0].treeDepth;
        uint256 numFolds      = friLayerRoots.length - 1;

        if (logDomainSize < numFolds + 1) return false;
        if (logDomainSize > 30)           return false;

        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].treeDepth    != logDomainSize) return false;
            if (hints[i].folds.length != numFolds)      return false;
        }

        VerifyCtx memory ctx = _buildCtx(
            embeddedRoot, oodsComboPos, oodsComboNeg, compRoot,
            friLayerRoots, hints.length, logDomainSize, merkleRoot
        );

        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].queryIndex != ctx.derivedIndices[i]) return false;
            if (!_verifyQuery(hints[i], ctx)) return false;
        }

        return true;
    }

    /// @dev Replay Fiat-Shamir transcript using Poseidon2Channel.
    ///      Identical to VFRI7's _buildCtx but with Poseidon2Channel replacing TwoChannel.
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

        Poseidon2Channel.State memory chan = Poseidon2Channel.init();
        Poseidon2Channel.mixRoot(chan, embeddedRoot);

        ctx.z_x       = Poseidon2Channel.drawSecureFelt(chan);
        ctx.compAlpha  = Poseidon2Channel.drawSecureFelt(chan);

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
            Poseidon2Channel.mixU32s(chan, comboWords);
        }

        Poseidon2Channel.mixRoot(chan, compRoot);
        ctx.friAlpha = Poseidon2Channel.drawSecureFelt(chan);
        Poseidon2Channel.mixRoot(chan, friLayerRoots[0]);

        uint256 numFolds = friLayerRoots.length - 1;
        ctx.friAlphas = new uint128[](numFolds);
        for (uint256 k = 0; k < numFolds; k++) {
            ctx.friAlphas[k] = Poseidon2Channel.drawSecureFelt(chan);
            Poseidon2Channel.mixRoot(chan, friLayerRoots[k + 1]);
        }

        // Cross-proof binding: mix merkleRoot before drawQueries (same as VFRI7)
        Poseidon2Channel.mixRoot(chan, merkleRoot);

        ctx.derivedIndices = Poseidon2Channel.drawQueries(chan, logDomainSize, nQueries);
    }

    function _verifyQuery(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {
        if (!Poseidon2MerkleVerifier.verifyMem(
            ctx.compRoot,
            Poseidon2MerkleVerifier.hashLeaf(_qm31ToWords(h.compValue)),
            h.queryIndex, h.treeDepth, h.compProof
        )) return false;

        {
            uint256 half = uint256(1) << (h.treeDepth - 1);
            uint256 anti = (h.queryIndex + half) & ((uint256(1) << h.treeDepth) - 1);
            if (!Poseidon2MerkleVerifier.verifyMem(
                ctx.compRoot,
                Poseidon2MerkleVerifier.hashLeaf(_qm31ToWords(h.compValueNeg)),
                anti, h.treeDepth, h.compProofNeg
            )) return false;
        }

        (bool oodsOk, uint128 fPlus, uint128 fMinus) = _verifyOODS(h, ctx);
        if (!oodsOk) return false;
        if (!_checkCircleFold(fPlus, fMinus, h, ctx.friAlpha)) return false;

        if (!Poseidon2MerkleVerifier.verifyMem(
            ctx.friLayerRoots[0],
            Poseidon2MerkleVerifier.hashLeaf(_qm31ToWords(h.foldedValue)),
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

            if (!Poseidon2MerkleVerifier.verifyMem(
                ctx.friLayerRoots[k],
                Poseidon2MerkleVerifier.hashLeaf(_qm31ToWords(h.folds[k].siblingValue)),
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

            if (!Poseidon2MerkleVerifier.verifyMem(
                ctx.friLayerRoots[k + 1],
                Poseidon2MerkleVerifier.hashLeaf(_qm31ToWords(h.folds[k].foldedValue)),
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
