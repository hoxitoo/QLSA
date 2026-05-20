// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";
import "./verifier/CirclePoint.sol";
import "./verifier/TwoChannel.sol";

/// @title QLSAVerifierV9 — OODS quotient check: fPlus/fMinus derived from OODS polynomial evaluations
///
/// Advances beyond QLSAVerifierV8 by adding the Out-Of-Domain Sampling (OODS) quotient
/// check. In V8, fPlus/fMinus were proved to be the correct composition of committed column
/// values, but there was no link to the claimed polynomial evaluations at the OODS point z.
/// A prover could commit to arbitrary column values at the queried positions without them
/// being consistent with any low-degree polynomial.
///
/// V9 adds: for each query at domain point p,
///   fPlus  · (p.x − z_x)  ==  Σ_j [α_comp^j · col_j(p)]  −  Σ_j [α_comp^j · oods_pos_j]
///   fMinus · (−p.x − z_x) ==  Σ_j [α_comp^j · col_j(−p)] −  Σ_j [α_comp^j · oods_neg_j]
///
/// where z_x is the channel-derived OODS x-coordinate (QM31), oods_pos_j / oods_neg_j are
/// the claimed polynomial evaluations at z and conj(z) = (z_x, −z_y) respectively, and the
/// check uses the multiplication form to avoid an on-chain QM31 inversion.
///
/// queryHints ABI encoding (DIFFERENT from V5–V8):
///   abi.encode(uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg, QueryHints[])
/// where oodsEvalsPos/Neg are per-column QM31 OODS evaluations (global, not per-query).
///
/// Updated channel transcript:
///   chan.init()
///   chan.mixRoot(embeddedRoot)              // absorb trace commitment
///   z_x = chan.drawSecureFelt()            // OODS x-coordinate (QM31)
///   chan.mixU32s(qm31Words(oodsEvalsPos))  // absorb positive OODS evaluations
///   chan.mixU32s(qm31Words(oodsEvalsNeg))  // absorb negative OODS evaluations
///   compAlpha = chan.drawSecureFelt()      // composition coefficient
///   friAlpha  = chan.drawSecureFelt()      // FRI folding challenge
///   queries[] = chan.drawQueries(treeDepth, N)
///
/// QueryHints struct: identical 13 fields as V8 (queryValuesNeg + merkleSiblingsNeg kept).
/// Meaning of fPlus/fMinus changes: they are now OODS quotient values, not raw compositions.
contract QLSAVerifierV9 is IQLSAVerifierV4 {

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 public constant MIN_PROOF_LENGTH = 700;
    uint256 public constant MAX_PROOF_LENGTH = 1_048_576; // 1 MiB
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
        uint128   foldedValue;
        uint256   queryPointX;
        uint256   queryPointY;
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

        // 4. Decode: global OODS evaluations + per-query hints.
        (uint128[] memory oodsEvalsPos, uint128[] memory oodsEvalsNeg,
         QueryHints[] memory hints) =
            abi.decode(queryHints, (uint128[], uint128[], QueryHints[]));

        // 5. Query count bounds.
        if (hints.length < MIN_QUERIES) return false;
        if (hints.length > MAX_QUERIES) return false;

        // 6. OODS eval arrays must be non-empty and consistent in length.
        if (oodsEvalsPos.length == 0) return false;
        if (oodsEvalsNeg.length != oodsEvalsPos.length) return false;

        // 7. Extract embedded trace root from proof[8:40].
        bytes32 embeddedRoot;
        assembly ("memory-safe") { embeddedRoot := calldataload(add(proof.offset, 8)) }

        // 8. All queries must share the same treeDepth.
        uint256 logDomainSize = hints[0].treeDepth;
        for (uint256 i = 1; i < hints.length; i++) {
            if (hints[i].treeDepth != logDomainSize) return false;
        }

        // 9. All queries must have column count equal to OODS eval count.
        uint256 nCols = oodsEvalsPos.length;
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].queryValues.length    != nCols) return false;
            if (hints[i].queryValuesNeg.length != nCols) return false;
        }

        // 10. Build Fiat-Shamir transcript.
        TwoChannel.State memory chan = TwoChannel.init();
        TwoChannel.mixRoot(chan, embeddedRoot);

        uint128 z_x = TwoChannel.drawSecureFelt(chan);           // OODS x-coordinate

        TwoChannel.mixU32s(chan, _qm31ArrayToWords(oodsEvalsPos)); // absorb pos evals
        TwoChannel.mixU32s(chan, _qm31ArrayToWords(oodsEvalsNeg)); // absorb neg evals

        uint128 compAlpha = TwoChannel.drawSecureFelt(chan);      // composition coefficient
        uint128 friAlpha  = TwoChannel.drawSecureFelt(chan);      // FRI folding challenge
        uint256[] memory derivedIdx = TwoChannel.drawQueries(chan, logDomainSize, hints.length);

        // 11. Precompute OODS combinations (shared across all queries).
        uint128 oodsComboPos = _compositionQM31(oodsEvalsPos, compAlpha);
        uint128 oodsComboNeg = _compositionQM31(oodsEvalsNeg, compAlpha);

        // 12. Verify each query.
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].friAlpha    != friAlpha)      return false;
            if (hints[i].queryIndex  != derivedIdx[i]) return false;
            if (!_verifyQuery(hints[i], embeddedRoot, z_x, compAlpha, oodsComboPos, oodsComboNeg)) return false;
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
        uint128 oodsComboNeg
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
        //    denomPos =   p.x − z_x    (QM31)
        //    denomNeg = − p.x − z_x    (QM31)  [antipodal has x = −p.x]
        uint128 pxQM31  = QM31.fromM31(h.queryPointX);
        uint128 denomPos = QM31.sub(pxQM31, z_x);
        uint128 denomNeg = QM31.sub(QM31.neg(pxQM31), z_x);

        // Non-degenerate denominators (would be zero if z_x equals ±p.x, vanishingly rare).
        if (denomPos == uint128(0)) return false;
        if (denomNeg == uint128(0)) return false;

        // g. OODS quotient check (multiplication form — avoids QM31.inv in hot path):
        //    fPlus  · denomPos == rawComp    − oodsComboPos
        //    fMinus · denomNeg == rawCompNeg − oodsComboNeg
        if (QM31.mul(h.fPlus,  denomPos) != QM31.sub(rawComp,    oodsComboPos)) return false;
        if (QM31.mul(h.fMinus, denomNeg) != QM31.sub(rawCompNeg, oodsComboNeg)) return false;

        // h. Circle fold check.
        if (!_checkCircleFold(h)) return false;

        return true;
    }

    /// @dev Σ_j [compAlpha^j · QM31.fromM31(vals[j])].
    function _compositionM31(uint32[] memory vals, uint128 compAlpha)
        internal pure returns (uint128 result)
    {
        uint128 alphaPow = QM31.fromM31(1);
        for (uint256 j = 0; j < vals.length; j++) {
            result   = QM31.add(result, QM31.mul(alphaPow, QM31.fromM31(vals[j])));
            alphaPow = QM31.mul(alphaPow, compAlpha);
        }
    }

    /// @dev Σ_j [compAlpha^j · evals[j]] where evals[j] are QM31 elements.
    function _compositionQM31(uint128[] memory evals, uint128 compAlpha)
        internal pure returns (uint128 result)
    {
        uint128 alphaPow = QM31.fromM31(1);
        for (uint256 j = 0; j < evals.length; j++) {
            result   = QM31.add(result, QM31.mul(alphaPow, evals[j]));
            alphaPow = QM31.mul(alphaPow, compAlpha);
        }
    }

    /// @dev Convert an array of QM31 elements to uint32 words for mixU32s.
    ///      Each QM31 uint128 → [c0.re, c0.im, c1.re, c1.im] (all M31 values).
    function _qm31ArrayToWords(uint128[] memory evals)
        internal pure returns (uint32[] memory words)
    {
        words = new uint32[](evals.length * 4);
        for (uint256 i = 0; i < evals.length; i++) {
            uint128 q = evals[i];
            words[i * 4 + 0] = uint32(q >> 96);                    // c0.re
            words[i * 4 + 1] = uint32((q >> 64) & 0xFFFFFFFF);     // c0.im
            words[i * 4 + 2] = uint32((q >> 32) & 0xFFFFFFFF);     // c1.re
            words[i * 4 + 3] = uint32(q & 0xFFFFFFFF);             // c1.im
        }
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
