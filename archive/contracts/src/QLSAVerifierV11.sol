// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";
import "./verifier/CirclePoint.sol";
import "./verifier/TwoChannel.sol";

/// @title QLSAVerifierV11 — FRI layer 2: line fold + second Merkle decommitment
///
/// Advances beyond V10 by executing one line fold step: adjacent pairs in the
/// FRI layer 1 domain (positions j and j + N/2) are folded with channel-derived
/// challenge friAlpha2, and the result is committed in a FRI layer 2 Merkle tree.
///
/// For a circle query at index `idx` (domain size N = 2^treeDepth):
///   lineIdx        = idx % (N/2)  = idx & ((N/2)−1)
///   siblingCircle  = idx + N/2   (if idx < N/2)  or  idx − N/2  (if idx ≥ N/2)
///   gPlus          = foldedValue[idx]           if idx < N/2
///                    foldedValue[siblingCircle] if idx ≥ N/2
///   gMinus         = foldedValue[siblingCircle] if idx < N/2
///                    foldedValue[idx]           if idx ≥ N/2
///   lineX          = cosetAt(treeDepth, lineIdx).x
///   lineFolded     = lineFold(gPlus, gMinus, friAlpha2, M31.inv(lineX))
///
/// Both the sibling's foldedValue and the lineFoldedValue are Merkle-verified:
///   MerkleVerify(friLayer1Root, hash(friL1SiblingValue), siblingCircle, treeDepth, ...)
///   MerkleVerify(friLayer2Root, hash(lineFoldedValue),   lineIdx,        treeDepth−1, ...)
///
/// Updated channel transcript:
///   chan.init()
///   chan.mixRoot(embeddedRoot)
///   z_x       = chan.drawSecureFelt()
///   chan.mixU32s(qm31Words(oodsEvalsPos))
///   chan.mixU32s(qm31Words(oodsEvalsNeg))
///   compAlpha = chan.drawSecureFelt()
///   friAlpha  = chan.drawSecureFelt()
///   chan.mixRoot(friLayer1Root)
///   friAlpha2 = chan.drawSecureFelt()       ← NEW (line fold challenge)
///   chan.mixRoot(friLayer2Root)             ← NEW
///   queries[] = chan.drawQueries(treeDepth, N)
///
/// queryHints ABI encoding:
///   abi.encode(uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg,
///              bytes32 friLayer1Root, bytes32 friLayer2Root, QueryHints[])
///
/// QueryHints: 18 fields (adds friL1SiblingValue + friL1SiblingProof +
///             lineFoldedValue + friL2Siblings over V10's 14).
contract QLSAVerifierV11 is IQLSAVerifierV4 {

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 public constant MIN_PROOF_LENGTH = 700;
    uint256 public constant MAX_PROOF_LENGTH = 1_048_576;
    uint256 public constant MIN_QUERIES = 1;
    uint256 public constant MAX_QUERIES = 64;

    // ── Structs ───────────────────────────────────────────────────────────────

    struct QueryHints {
        // ── inherited from V10 (14 fields) ──
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
        uint128   foldedValue;
        uint256   queryPointX;
        uint256   queryPointY;
        bytes32[] friL1Siblings;
        // ── new in V11 (4 fields) ──
        uint128   friL1SiblingValue;  // foldedValue at sibling circle position
        bytes32[] friL1SiblingProof;  // Merkle proof for sibling in friLayer1Root
        uint128   lineFoldedValue;    // line fold result at lineIdx
        bytes32[] friL2Siblings;      // Merkle proof for lineFoldedValue in friLayer2Root
    }

    // ── Public interface ──────────────────────────────────────────────────────

    function verify(
        bytes calldata proof,
        bytes16 commitment,
        bytes32 merkleRoot,
        bytes calldata queryHints
    ) external pure override returns (bool) {

        // 1. Proof length bounds.
        if (proof.length < MIN_PROOF_LENGTH) return false;
        if (proof.length > MAX_PROOF_LENGTH) return false;

        // 2. Non-zero inputs.
        if (commitment == bytes16(0)) return false;
        if (merkleRoot == bytes32(0)) return false;
        if (queryHints.length == 0) return false;

        // 3. Commitment binding.
        if (!_checkCommitment(proof, commitment, merkleRoot)) return false;

        // 4. Decode.
        (uint128[] memory oodsEvalsPos, uint128[] memory oodsEvalsNeg,
         bytes32 friLayer1Root, bytes32 friLayer2Root,
         QueryHints[] memory hints) =
            abi.decode(queryHints, (uint128[], uint128[], bytes32, bytes32, QueryHints[]));

        // 5. Query count bounds.
        if (hints.length < MIN_QUERIES) return false;
        if (hints.length > MAX_QUERIES) return false;

        // 6. OODS eval arrays.
        if (oodsEvalsPos.length == 0) return false;
        if (oodsEvalsNeg.length != oodsEvalsPos.length) return false;

        // 7. FRI roots must be non-zero.
        if (friLayer1Root == bytes32(0)) return false;
        if (friLayer2Root == bytes32(0)) return false;

        // 8. Extract embedded trace root from proof[8:40].
        bytes32 embeddedRoot;
        assembly ("memory-safe") { embeddedRoot := calldataload(add(proof.offset, 8)) }

        // 9. All queries must share the same treeDepth and it must be ≥ 2
        //    (needed for FRI layer 2 tree of depth treeDepth−1 ≥ 1).
        uint256 logDomainSize = hints[0].treeDepth;
        if (logDomainSize < 2 || logDomainSize > 30) return false;
        for (uint256 i = 1; i < hints.length; i++) {
            if (hints[i].treeDepth != logDomainSize) return false;
        }

        // 10. Column count consistency.
        uint256 nCols = oodsEvalsPos.length;
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].queryValues.length    != nCols) return false;
            if (hints[i].queryValuesNeg.length != nCols) return false;
        }

        // 11. Build Fiat-Shamir transcript (V11 order).
        TwoChannel.State memory chan = TwoChannel.init();
        TwoChannel.mixRoot(chan, embeddedRoot);

        uint128 z_x = TwoChannel.drawSecureFelt(chan);

        TwoChannel.mixU32s(chan, _qm31ArrayToWords(oodsEvalsPos));
        TwoChannel.mixU32s(chan, _qm31ArrayToWords(oodsEvalsNeg));

        uint128 compAlpha = TwoChannel.drawSecureFelt(chan);
        uint128 friAlpha  = TwoChannel.drawSecureFelt(chan);

        TwoChannel.mixRoot(chan, friLayer1Root);
        uint128 friAlpha2 = TwoChannel.drawSecureFelt(chan);   // line fold challenge ← NEW
        TwoChannel.mixRoot(chan, friLayer2Root);               // ← NEW

        uint256[] memory derivedIdx = TwoChannel.drawQueries(chan, logDomainSize, hints.length);

        // 12. Precompute OODS combinations.
        uint128 oodsComboPos = _compositionQM31(oodsEvalsPos, compAlpha);
        uint128 oodsComboNeg = _compositionQM31(oodsEvalsNeg, compAlpha);

        // 13. Verify each query.
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].friAlpha   != friAlpha)      return false;
            if (hints[i].queryIndex != derivedIdx[i]) return false;
            if (!_verifyQuery(hints[i], embeddedRoot, z_x, compAlpha,
                              oodsComboPos, oodsComboNeg,
                              friLayer1Root, friLayer2Root, friAlpha2)) return false;
        }

        return true;
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

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

    function _verifyQuery(
        QueryHints memory h,
        bytes32 embeddedRoot,
        uint128 z_x,
        uint128 compAlpha,
        uint128 oodsComboPos,
        uint128 oodsComboNeg,
        bytes32 friLayer1Root,
        bytes32 friLayer2Root,
        uint128 friAlpha2
    ) internal pure returns (bool) {

        // a. Trace root consistency.
        if (h.traceRoot != embeddedRoot) return false;

        // b. Merkle inclusion at queryIndex.
        if (!MerkleVerifier.verifyColumnsMem(
            h.traceRoot, h.queryValues, h.queryIndex, h.treeDepth, h.merkleSiblings
        )) return false;

        // c. Antipodal index.
        uint256 half = 1 << (h.treeDepth - 1);
        uint256 antipodalIdx = (h.queryIndex + half) & ((1 << h.treeDepth) - 1);

        // d. Merkle inclusion at antipodalIdx.
        if (!MerkleVerifier.verifyColumnsMem(
            h.traceRoot, h.queryValuesNeg, antipodalIdx, h.treeDepth, h.merkleSiblingsNeg
        )) return false;

        // e. Raw compositions.
        uint128 rawComp    = _compositionM31(h.queryValues,    compAlpha);
        uint128 rawCompNeg = _compositionM31(h.queryValuesNeg, compAlpha);

        // f. OODS quotient denominators.
        uint128 pxQM31   = QM31.fromM31(h.queryPointX);
        uint128 denomPos = QM31.sub(pxQM31, z_x);
        uint128 denomNeg = QM31.sub(QM31.neg(pxQM31), z_x);

        if (denomPos == uint128(0)) return false;
        if (denomNeg == uint128(0)) return false;

        // g. OODS quotient check.
        if (QM31.mul(h.fPlus,  denomPos) != QM31.sub(rawComp,    oodsComboPos)) return false;
        if (QM31.mul(h.fMinus, denomNeg) != QM31.sub(rawCompNeg, oodsComboNeg)) return false;

        // h. Circle fold check.
        if (!_checkCircleFold(h)) return false;

        // i. FRI layer 1 decommitment at queryIndex (inherited from V10).
        if (!MerkleVerifier.verifyMem(
            friLayer1Root,
            MerkleVerifier.hashLeaf(_qm31ToWords(h.foldedValue)),
            h.queryIndex, h.treeDepth, h.friL1Siblings
        )) return false;

        // j. FRI layer 1 sibling decommitment.  ← NEW
        uint256 lineIdx        = h.queryIndex & (half - 1);
        uint256 siblingCircle  = (h.queryIndex < half) ? h.queryIndex + half : h.queryIndex - half;

        if (!MerkleVerifier.verifyMem(
            friLayer1Root,
            MerkleVerifier.hashLeaf(_qm31ToWords(h.friL1SiblingValue)),
            siblingCircle, h.treeDepth, h.friL1SiblingProof
        )) return false;

        // k. Line fold check.  ← NEW
        (uint256 lineX, ) = CirclePoint.cosetAt(h.treeDepth, lineIdx);
        if (lineX == 0) return false;
        uint256 xInv = M31.inv(lineX);

        uint128 gPlus  = (h.queryIndex < half) ? h.foldedValue : h.friL1SiblingValue;
        uint128 gMinus = (h.queryIndex < half) ? h.friL1SiblingValue : h.foldedValue;

        if (CirclePoint.lineFold(gPlus, gMinus, friAlpha2, xInv) != h.lineFoldedValue) return false;

        // l. FRI layer 2 decommitment at lineIdx (depth = treeDepth−1).  ← NEW
        if (!MerkleVerifier.verifyMem(
            friLayer2Root,
            MerkleVerifier.hashLeaf(_qm31ToWords(h.lineFoldedValue)),
            lineIdx, h.treeDepth - 1, h.friL2Siblings
        )) return false;

        return true;
    }

    function _compositionM31(uint32[] memory vals, uint128 compAlpha)
        internal pure returns (uint128 result)
    {
        uint128 alphaPow = QM31.fromM31(1);
        for (uint256 j = 0; j < vals.length; j++) {
            result   = QM31.add(result, QM31.mul(alphaPow, QM31.fromM31(vals[j])));
            alphaPow = QM31.mul(alphaPow, compAlpha);
        }
    }

    function _compositionQM31(uint128[] memory evals, uint128 compAlpha)
        internal pure returns (uint128 result)
    {
        uint128 alphaPow = QM31.fromM31(1);
        for (uint256 j = 0; j < evals.length; j++) {
            result   = QM31.add(result, QM31.mul(alphaPow, evals[j]));
            alphaPow = QM31.mul(alphaPow, compAlpha);
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

    function _checkCircleFold(QueryHints memory h) internal pure returns (bool) {
        if (!CirclePoint.isOnCircle(h.queryPointX, h.queryPointY)) return false;
        if (h.treeDepth < 1 || h.treeDepth > 30) return false;
        if (h.queryIndex >= (1 << h.treeDepth)) return false;

        (uint256 cx, uint256 cy) = CirclePoint.cosetAt(h.treeDepth, h.queryIndex);
        if (cx != h.queryPointX || cy != h.queryPointY) return false;

        uint256 yInv = M31.inv(h.queryPointY);
        uint128 derived = CirclePoint.circleFold(h.fPlus, h.fMinus, h.friAlpha, yInv);
        return derived == h.foldedValue;
    }
}
