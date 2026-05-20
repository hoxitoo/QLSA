// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";
import "./verifier/CirclePoint.sol";
import "./verifier/TwoChannel.sol";

/// @title QLSAVerifierV10 — FRI layer 1 decommitment: circle-fold outputs committed in a Merkle tree
///
/// Advances beyond QLSAVerifierV9 by verifying that the circle-fold output (foldedValue)
/// at each query is committed in a dedicated FRI layer 1 Merkle tree. In V9, foldedValue
/// was correctly derived from the OODS quotient but had no binding to any committed
/// polynomial — a prover could present a self-consistent OODS quotient that doesn't
/// correspond to any committed circle-fold evaluation.
///
/// V10 adds: the prover must commit to the full set of circle-fold outputs over the circle
/// domain (one per domain position) in a dedicated FRI layer 1 Merkle tree, and each
/// query's foldedValue must be Merkle-provable in that tree:
///
///   MerkleVerify(friLayer1Root, Blake2s(qm31Words(foldedValue)), queryIndex, treeDepth, friL1Siblings)
///
/// The FRI layer 1 tree has 2^treeDepth leaves (same domain size as the trace tree).
/// Leaf j stores the circle-fold output of the OODS quotient polynomial at circle position j.
///
/// Updated channel transcript:
///   chan.init()
///   chan.mixRoot(embeddedRoot)               // absorb trace commitment
///   z_x        = chan.drawSecureFelt()      // OODS x-coordinate
///   chan.mixU32s(qm31Words(oodsEvalsPos))   // absorb positive OODS evaluations
///   chan.mixU32s(qm31Words(oodsEvalsNeg))   // absorb negative OODS evaluations
///   compAlpha  = chan.drawSecureFelt()      // composition coefficient
///   friAlpha   = chan.drawSecureFelt()      // FRI folding challenge
///   chan.mixRoot(friLayer1Root)             // absorb FRI layer 1 commitment  ← NEW
///   queries[]  = chan.drawQueries(treeDepth, N)
///
/// queryHints ABI encoding:
///   abi.encode(uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg, bytes32 friLayer1Root, QueryHints[])
///
/// QueryHints: 14 fields (adds friL1Siblings over V9's 13).
contract QLSAVerifierV10 is IQLSAVerifierV4 {

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 public constant MIN_PROOF_LENGTH = 700;
    uint256 public constant MAX_PROOF_LENGTH = 1_048_576;
    uint256 public constant MIN_QUERIES = 1;
    uint256 public constant MAX_QUERIES = 64;

    // ── Structs ───────────────────────────────────────────────────────────────

    struct QueryHints {
        bytes32   traceRoot;
        uint32[]  queryValues;        // col values at queryIndex
        uint32[]  queryValuesNeg;     // col values at antipodalIdx
        uint256   queryIndex;
        uint256   treeDepth;
        bytes32[] merkleSiblings;
        bytes32[] merkleSiblingsNeg;
        uint128   friAlpha;           // must == channel-derived friAlpha
        uint128   fPlus;              // OODS quotient at queryIndex
        uint128   fMinus;             // OODS quotient at antipodalIdx
        uint128   foldedValue;        // circle-fold output at queryIndex
        uint256   queryPointX;
        uint256   queryPointY;
        bytes32[] friL1Siblings;      // Merkle proof for foldedValue in friLayer1Root  ← NEW
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

        // 4. Decode: global OODS evaluations, FRI layer 1 root, per-query hints.
        (uint128[] memory oodsEvalsPos, uint128[] memory oodsEvalsNeg,
         bytes32 friLayer1Root, QueryHints[] memory hints) =
            abi.decode(queryHints, (uint128[], uint128[], bytes32, QueryHints[]));

        // 5. Query count bounds.
        if (hints.length < MIN_QUERIES) return false;
        if (hints.length > MAX_QUERIES) return false;

        // 6. OODS eval arrays must be non-empty and consistent in length.
        if (oodsEvalsPos.length == 0) return false;
        if (oodsEvalsNeg.length != oodsEvalsPos.length) return false;

        // 7. FRI layer 1 root must be non-zero.
        if (friLayer1Root == bytes32(0)) return false;

        // 8. Extract embedded trace root from proof[8:40].
        bytes32 embeddedRoot;
        assembly ("memory-safe") { embeddedRoot := calldataload(add(proof.offset, 8)) }

        // 9. All queries must share the same treeDepth.
        uint256 logDomainSize = hints[0].treeDepth;
        for (uint256 i = 1; i < hints.length; i++) {
            if (hints[i].treeDepth != logDomainSize) return false;
        }

        // 10. All queries must have column count equal to OODS eval count.
        uint256 nCols = oodsEvalsPos.length;
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].queryValues.length    != nCols) return false;
            if (hints[i].queryValuesNeg.length != nCols) return false;
        }

        // 11. Build Fiat-Shamir transcript (V10 order: absorb friLayer1Root before queries).
        TwoChannel.State memory chan = TwoChannel.init();
        TwoChannel.mixRoot(chan, embeddedRoot);

        uint128 z_x = TwoChannel.drawSecureFelt(chan);            // OODS x-coordinate

        TwoChannel.mixU32s(chan, _qm31ArrayToWords(oodsEvalsPos));  // absorb pos evals
        TwoChannel.mixU32s(chan, _qm31ArrayToWords(oodsEvalsNeg));  // absorb neg evals

        uint128 compAlpha = TwoChannel.drawSecureFelt(chan);      // composition coefficient
        uint128 friAlpha  = TwoChannel.drawSecureFelt(chan);      // FRI folding challenge

        TwoChannel.mixRoot(chan, friLayer1Root);                  // absorb FRI layer 1 ← NEW

        uint256[] memory derivedIdx = TwoChannel.drawQueries(chan, logDomainSize, hints.length);

        // 12. Precompute OODS combinations (shared across all queries).
        uint128 oodsComboPos = _compositionQM31(oodsEvalsPos, compAlpha);
        uint128 oodsComboNeg = _compositionQM31(oodsEvalsNeg, compAlpha);

        // 13. Verify each query.
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].friAlpha   != friAlpha)      return false;
            if (hints[i].queryIndex != derivedIdx[i]) return false;
            if (!_verifyQuery(hints[i], embeddedRoot, z_x, compAlpha,
                              oodsComboPos, oodsComboNeg, friLayer1Root)) return false;
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
        bytes32 friLayer1Root
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

        // e. Raw compositions of column values.
        uint128 rawComp    = _compositionM31(h.queryValues,    compAlpha);
        uint128 rawCompNeg = _compositionM31(h.queryValuesNeg, compAlpha);

        // f. OODS quotient denominators.
        uint128 pxQM31   = QM31.fromM31(h.queryPointX);
        uint128 denomPos = QM31.sub(pxQM31, z_x);
        uint128 denomNeg = QM31.sub(QM31.neg(pxQM31), z_x);

        if (denomPos == uint128(0)) return false;
        if (denomNeg == uint128(0)) return false;

        // g. OODS quotient check (multiplication form).
        if (QM31.mul(h.fPlus,  denomPos) != QM31.sub(rawComp,    oodsComboPos)) return false;
        if (QM31.mul(h.fMinus, denomNeg) != QM31.sub(rawCompNeg, oodsComboNeg)) return false;

        // h. Circle fold check.
        if (!_checkCircleFold(h)) return false;

        // i. FRI layer 1 decommitment: foldedValue committed at queryIndex.  ← NEW
        bytes32 l1Leaf = MerkleVerifier.hashLeaf(_qm31ToWords(h.foldedValue));
        if (!MerkleVerifier.verifyMem(
            friLayer1Root, l1Leaf, h.queryIndex, h.treeDepth, h.friL1Siblings
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
