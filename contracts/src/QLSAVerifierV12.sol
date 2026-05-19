// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";
import "./verifier/CirclePoint.sol";
import "./verifier/TwoChannel.sol";

/// @title QLSAVerifierV12 — FRI layer 3: second line fold with doubled-x twiddle
///
/// Advances beyond V11 by executing a second line fold step, reducing the FRI
/// layer 2 domain (N/2 values) to FRI layer 3 (N/4 values).
///
/// Second fold pairing: for lineIdx j in [0, N/2), pair j with j+N/4 (if j < N/4)
/// or j with j−N/4 (if j ≥ N/4). The correct x-coordinate for this fold is
/// the DOUBLED x-coordinate of circle position lineIdx2 = j mod (N/4):
///
///   doubleX(lineIdx2) = 2·cosetAt(treeDepth, lineIdx2).x² − 1
///
/// Mathematical correctness: since cosetAt(logN, j+N/4) = (−y_j, x_j) (the
/// quarter-period group action), one can show:
///   doubleX(j) + doubleX(j+N/4) = 2·x_j² − 1 + 2·y_j² − 1 = 2·1 − 2 = 0
/// so they are negatives in M31, exactly what lineFold needs.
///
/// Updated channel transcript:
///   ... → mixRoot(friLayer2Root) → friAlpha2             (V11)
///   → friAlpha3 = drawSecureFelt()                      ← NEW (second line fold α)
///   → mixRoot(friLayer3Root)                            ← NEW
///   → queries[] = drawQueries(treeDepth, N)
///
/// queryHints ABI encoding:
///   abi.encode(uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg,
///              bytes32 friLayer1Root, bytes32 friLayer2Root, bytes32 friLayer3Root,
///              QueryHints[])
///
/// QueryHints: 22 fields (adds l2SiblingValue, l2SiblingProof, lineFoldedValue2,
///             friL3Siblings over V11's 18).
///
/// Requires treeDepth ≥ 3 (FRI L3 tree has at least 2 leaves).
contract QLSAVerifierV12 is IQLSAVerifierV4 {

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 public constant MIN_PROOF_LENGTH = 700;
    uint256 public constant MAX_PROOF_LENGTH = 1_048_576;
    uint256 public constant MIN_QUERIES = 1;
    uint256 public constant MAX_QUERIES = 64;

    // ── Structs ───────────────────────────────────────────────────────────────

    struct QueryHints {
        // ── V10 / V11 inherited fields (18) ──
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
        uint128   friL1SiblingValue;
        bytes32[] friL1SiblingProof;
        uint128   lineFoldedValue;
        bytes32[] friL2Siblings;
        // ── new in V12 (4 fields) ──
        uint128   l2SiblingValue;    // lineFolded at sibling in FRI L2
        bytes32[] l2SiblingProof;    // Merkle proof for sibling in friLayer2Root
        uint128   lineFoldedValue2;  // second line fold result at lineIdx2
        bytes32[] friL3Siblings;     // Merkle proof for lineFoldedValue2 in friLayer3Root
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
         bytes32 friLayer1Root, bytes32 friLayer2Root, bytes32 friLayer3Root,
         QueryHints[] memory hints) =
            abi.decode(queryHints, (uint128[], uint128[], bytes32, bytes32, bytes32, QueryHints[]));

        // 5. Query count bounds.
        if (hints.length < MIN_QUERIES) return false;
        if (hints.length > MAX_QUERIES) return false;

        // 6. OODS eval arrays.
        if (oodsEvalsPos.length == 0) return false;
        if (oodsEvalsNeg.length != oodsEvalsPos.length) return false;

        // 7. FRI roots must be non-zero.
        if (friLayer1Root == bytes32(0)) return false;
        if (friLayer2Root == bytes32(0)) return false;
        if (friLayer3Root == bytes32(0)) return false;

        // 8. Extract embedded trace root from proof[8:40].
        bytes32 embeddedRoot;
        assembly ("memory-safe") { embeddedRoot := calldataload(add(proof.offset, 8)) }

        // 9. treeDepth must be ≥ 3 (FRI L3 needs ≥ 2 leaves at depth treeDepth−2 ≥ 1).
        uint256 logDomainSize = hints[0].treeDepth;
        if (logDomainSize < 3) return false;
        for (uint256 i = 1; i < hints.length; i++) {
            if (hints[i].treeDepth != logDomainSize) return false;
        }

        // 10. Column count consistency.
        uint256 nCols = oodsEvalsPos.length;
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].queryValues.length    != nCols) return false;
            if (hints[i].queryValuesNeg.length != nCols) return false;
        }

        // 11. Build Fiat-Shamir transcript.
        TwoChannel.State memory chan = TwoChannel.init();
        TwoChannel.mixRoot(chan, embeddedRoot);

        uint128 z_x = TwoChannel.drawSecureFelt(chan);

        TwoChannel.mixU32s(chan, _qm31ArrayToWords(oodsEvalsPos));
        TwoChannel.mixU32s(chan, _qm31ArrayToWords(oodsEvalsNeg));

        uint128 compAlpha = TwoChannel.drawSecureFelt(chan);
        uint128 friAlpha  = TwoChannel.drawSecureFelt(chan);

        TwoChannel.mixRoot(chan, friLayer1Root);
        uint128 friAlpha2 = TwoChannel.drawSecureFelt(chan);
        TwoChannel.mixRoot(chan, friLayer2Root);
        uint128 friAlpha3 = TwoChannel.drawSecureFelt(chan);   // ← NEW second line fold α
        TwoChannel.mixRoot(chan, friLayer3Root);               // ← NEW

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
                              friLayer1Root, friLayer2Root, friLayer3Root,
                              friAlpha2, friAlpha3)) return false;
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
        bytes32 friLayer3Root,
        uint128 friAlpha2,
        uint128 friAlpha3
    ) internal pure returns (bool) {

        // a. Trace root consistency.
        if (h.traceRoot != embeddedRoot) return false;

        // b–d. Merkle inclusion at queryIndex and antipodalIdx.
        if (!MerkleVerifier.verifyColumnsMem(
            h.traceRoot, h.queryValues, h.queryIndex, h.treeDepth, h.merkleSiblings
        )) return false;

        uint256 half = 1 << (h.treeDepth - 1);
        uint256 antipodalIdx = (h.queryIndex + half) & ((1 << h.treeDepth) - 1);

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

        // i. FRI L1 decommitment at queryIndex.
        if (!MerkleVerifier.verifyMem(
            friLayer1Root,
            MerkleVerifier.hashLeaf(_qm31ToWords(h.foldedValue)),
            h.queryIndex, h.treeDepth, h.friL1Siblings
        )) return false;

        // j. First line fold: FRI L1 sibling + fold → lineFoldedValue.
        uint256 lineIdx = h.queryIndex & (half - 1);
        uint256 siblingCircle = (h.queryIndex < half) ? h.queryIndex + half : h.queryIndex - half;

        if (!MerkleVerifier.verifyMem(
            friLayer1Root,
            MerkleVerifier.hashLeaf(_qm31ToWords(h.friL1SiblingValue)),
            siblingCircle, h.treeDepth, h.friL1SiblingProof
        )) return false;

        {
            (uint256 lineX, ) = CirclePoint.cosetAt(h.treeDepth, lineIdx);
            if (lineX == 0) return false;
            uint256 xInv1 = M31.inv(lineX);
            uint128 gPlus1  = (h.queryIndex < half) ? h.foldedValue : h.friL1SiblingValue;
            uint128 gMinus1 = (h.queryIndex < half) ? h.friL1SiblingValue : h.foldedValue;
            if (CirclePoint.lineFold(gPlus1, gMinus1, friAlpha2, xInv1) != h.lineFoldedValue) return false;
        }

        // k. FRI L2 decommitment at lineIdx.
        if (!MerkleVerifier.verifyMem(
            friLayer2Root,
            MerkleVerifier.hashLeaf(_qm31ToWords(h.lineFoldedValue)),
            lineIdx, h.treeDepth - 1, h.friL2Siblings
        )) return false;

        // l. Second line fold: FRI L2 sibling + fold → lineFoldedValue2.  ← NEW
        uint256 quarter    = 1 << (h.treeDepth - 2);
        uint256 lineIdx2   = lineIdx & (quarter - 1);
        uint256 siblingL2  = (lineIdx < quarter) ? lineIdx + quarter : lineIdx - quarter;

        if (!MerkleVerifier.verifyMem(
            friLayer2Root,
            MerkleVerifier.hashLeaf(_qm31ToWords(h.l2SiblingValue)),
            siblingL2, h.treeDepth - 1, h.l2SiblingProof
        )) return false;

        {
            // doubleX = 2·x_j² − 1 where x_j = cosetAt(treeDepth, lineIdx2).x
            // This is the x-coordinate of the doubled circle point (the correct twiddle
            // for the second line fold). Proof: for j and j+N/4 in the original coset,
            // doubleX(j) + doubleX(j+N/4) = 2(x_j² + y_j²) − 2 = 0, so they are negatives.
            (uint256 xJ, ) = CirclePoint.cosetAt(h.treeDepth, lineIdx2);
            uint256 xJSq   = M31.mul(xJ, xJ);
            uint256 doubleX = M31.sub(M31.add(xJSq, xJSq), 1);
            if (doubleX == 0) return false;
            uint256 xInv2 = M31.inv(doubleX);

            uint128 gPlus2  = (lineIdx < quarter) ? h.lineFoldedValue : h.l2SiblingValue;
            uint128 gMinus2 = (lineIdx < quarter) ? h.l2SiblingValue  : h.lineFoldedValue;

            if (CirclePoint.lineFold(gPlus2, gMinus2, friAlpha3, xInv2) != h.lineFoldedValue2) return false;
        }

        // m. FRI L3 decommitment at lineIdx2 (depth = treeDepth−2).  ← NEW
        if (!MerkleVerifier.verifyMem(
            friLayer3Root,
            MerkleVerifier.hashLeaf(_qm31ToWords(h.lineFoldedValue2)),
            lineIdx2, h.treeDepth - 2, h.friL3Siblings
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
