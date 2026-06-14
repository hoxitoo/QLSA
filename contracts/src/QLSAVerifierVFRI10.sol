// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// NOTE: Compile with viaIR: true — the ABI decode in verify() uses multiple
// static fields which would otherwise exceed Solidity's stack-depth limit.

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/Poseidon2MerkleVerifierT4.sol";
import "./verifier/Poseidon2ChannelT4.sol";
import "./verifier/CirclePoint.sol";

/// @title QLSAVerifierVFRI10 — VFRI9 with the Poseidon2 t=4 hash backend
///
/// Identical proof protocol, ABI, and last-layer FRI check as VFRI9; the only
/// change is the hash backend, swapped from the t=2 Poseidon2 primitives to
/// their t=4 successors:
///
///   Poseidon2MerkleVerifierW  → Poseidon2MerkleVerifierT4   (Merkle)
///   Poseidon2Channel          → Poseidon2ChannelT4          (Fiat-Shamir)
///
/// Both keep VFRI9's 2-word node encoding ((s0 << 32) | s1) and the same
/// transcript shape, so VFRI10's queryHints ABI is byte-compatible with VFRI9.
/// The difference is the underlying permutation: t=4 runs over a 124-bit state
/// with a 2-cell (Merkle) / 3-cell (channel) capacity, versus t=2's single
/// capacity cell.  This lifts the node/transcript collision wall above the t=2
/// ceiling (~2^31) toward the 128-bit target — the final MVP-6 step for
/// on-chain binding (documented limitation #6).
///
/// VFRI10 keeps the three VFRI9 soundness upgrades:
///
/// 1. LAST-LAYER FRI CHECK (closes the bounded-degree soundness gap left open
///    in VFRI5..VFRI8): the prover supplies all 2^(treeDepth−K) evaluations of
///    the final FRI layer; the verifier rebuilds the Merkle tree from them and
///    asserts root == friLayerRoots[K].  Combined with the per-query Merkle
///    proofs that bind each final fold into friLayerRoots[K], every query's
///    final value is cryptographically fixed to the committed last layer.
///
/// 2. WIDE MERKLE NODES via Poseidon2MerkleVerifierT4 — both sponge words per
///    node ((s0 << 32) | s1), hashed by the t=4 permutation.
///
/// 3. FULL-ROOT FIAT-SHAMIR ABSORPTION: 32-byte roots (embedded trace root,
///    batch merkle root) are absorbed as 8 BE u32 words (mixRootFull) instead
///    of only the low 4 bytes; wide node roots use 2 words (mixRootW).
///
/// Proof version marker: proof[0:8] = 4 (little-endian; VFRI9 uses 3).
///
/// Transcript:
///   Poseidon2ChannelT4.mixRootFull(traceRoot)           ← proof[8:40], 8 words
///   z_x       = drawSecureFelt
///   compAlpha = drawSecureFelt
///   mixU32s([c0re(comboPos),c0im,c1re,c1im, c0re(comboNeg),c0im,c1re,c1im])
///   mixRootW(compRoot)                                ← 2 words
///   friAlpha = drawSecureFelt
///   mixRootW(friLayerRoots[0])
///   for k in 0..numFolds-1:
///     friAlphas[k] = drawSecureFelt
///     mixRootW(friLayerRoots[k+1])
///   mixRootFull(merkleRoot)                           ← cross-proof binding, 8 words
///   drawQueries(treeDepth, nQueries)
///
/// queryHints ABI encoding (6 head slots = 192 bytes):
///   abi.encode(uint128 oodsComboPos, uint128 oodsComboNeg, bytes32 compRoot,
///              uint128[] lastLayerEvals, bytes32[] friLayerRoots, QueryHints[])
contract QLSAVerifierVFRI10 is IQLSAVerifierV4 {

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
         uint128[] memory lastLayerEvals,
         bytes32[] memory friLayerRoots,
         QueryHints[] memory hints) =
            abi.decode(queryHints,
                (uint128, uint128, bytes32, uint128[], bytes32[], QueryHints[]));

        if (oodsComboPos == 0 && oodsComboNeg == 0) return false;
        if (compRoot == bytes32(0))                 return false;
        if (lastLayerEvals.length == 0)             return false;
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

        // ── Last-layer bounded-degree check ───────────────────────────────────
        // friLayerRoots[K] must be the Merkle root of the prover-supplied
        // last-layer evaluations.  Per-query Merkle proofs already bind each
        // final fold value into friLayerRoots[K]; together this fixes every
        // query's final value to the committed (degree-bounded) last layer.
        if (!_checkLastLayer(lastLayerEvals, friLayerRoots[numFolds],
                             logDomainSize - numFolds)) return false;

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
            nodes[i] = Poseidon2MerkleVerifierT4.hashLeaf(_qm31ToWords(evals[i]));
        }
        uint256 sz = lastLayerSize;
        while (sz > 1) {
            sz >>= 1;
            for (uint256 i = 0; i < sz; i++) {
                nodes[i] = Poseidon2MerkleVerifierT4.hashPair(nodes[2 * i], nodes[2 * i + 1]);
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

        Poseidon2ChannelT4.State memory chan = Poseidon2ChannelT4.init();
        Poseidon2ChannelT4.mixRootFull(chan, embeddedRoot);

        ctx.z_x       = Poseidon2ChannelT4.drawSecureFelt(chan);
        ctx.compAlpha  = Poseidon2ChannelT4.drawSecureFelt(chan);

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
            Poseidon2ChannelT4.mixU32s(chan, comboWords);
        }

        Poseidon2ChannelT4.mixRootW(chan, compRoot);
        ctx.friAlpha = Poseidon2ChannelT4.drawSecureFelt(chan);
        Poseidon2ChannelT4.mixRootW(chan, friLayerRoots[0]);

        uint256 numFolds = friLayerRoots.length - 1;
        ctx.friAlphas = new uint128[](numFolds);
        for (uint256 k = 0; k < numFolds; k++) {
            ctx.friAlphas[k] = Poseidon2ChannelT4.drawSecureFelt(chan);
            Poseidon2ChannelT4.mixRootW(chan, friLayerRoots[k + 1]);
        }

        // Cross-proof binding: mix the FULL merkleRoot before drawQueries.
        Poseidon2ChannelT4.mixRootFull(chan, merkleRoot);

        ctx.derivedIndices = Poseidon2ChannelT4.drawQueries(chan, logDomainSize, nQueries);
    }

    function _verifyQuery(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {
        if (!Poseidon2MerkleVerifierT4.verifyMem(
            ctx.compRoot,
            Poseidon2MerkleVerifierT4.hashLeaf(_qm31ToWords(h.compValue)),
            h.queryIndex, h.treeDepth, h.compProof
        )) return false;

        {
            uint256 half = uint256(1) << (h.treeDepth - 1);
            uint256 anti = (h.queryIndex + half) & ((uint256(1) << h.treeDepth) - 1);
            if (!Poseidon2MerkleVerifierT4.verifyMem(
                ctx.compRoot,
                Poseidon2MerkleVerifierT4.hashLeaf(_qm31ToWords(h.compValueNeg)),
                anti, h.treeDepth, h.compProofNeg
            )) return false;
        }

        (bool oodsOk, uint128 fPlus, uint128 fMinus) = _verifyOODS(h, ctx);
        if (!oodsOk) return false;
        if (!_checkCircleFold(fPlus, fMinus, h, ctx.friAlpha)) return false;

        if (!Poseidon2MerkleVerifierT4.verifyMem(
            ctx.friLayerRoots[0],
            Poseidon2MerkleVerifierT4.hashLeaf(_qm31ToWords(h.foldedValue)),
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

            if (!Poseidon2MerkleVerifierT4.verifyMem(
                ctx.friLayerRoots[k],
                Poseidon2MerkleVerifierT4.hashLeaf(_qm31ToWords(h.folds[k].siblingValue)),
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

            if (!Poseidon2MerkleVerifierT4.verifyMem(
                ctx.friLayerRoots[k + 1],
                Poseidon2MerkleVerifierT4.hashLeaf(_qm31ToWords(h.folds[k].foldedValue)),
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
