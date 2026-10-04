// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";
import "./verifier/CirclePoint.sol";
import "./verifier/TwoChannel.sol";

/// @title QLSAVerifierV8 — Composition binding: fPlus/fMinus derived from committed columns
///
/// Advances beyond QLSAVerifierV7 by proving that the FRI fold inputs (fPlus, fMinus)
/// are the correct linear combination of the Merkle-committed trace column values.
///
/// Gap closed: in V7, the prover could supply arbitrary fPlus/fMinus as long as the
/// fold equation held.  V8 requires fPlus = Σ_j [α_comp^j · col_j(p)] and
/// fMinus = Σ_j [α_comp^j · col_j(−p)], where α_comp is drawn from the channel
/// and col_j(−p) are column values at the antipodal domain index (Merkle-verified).
///
/// Antipodal index: for domain size n = 2^treeDepth and query index i:
///   antipodalIdx = (i + n/2) mod n
/// This gives the circle-group complement with the same y-coordinate (-x, y),
/// matching the fMinus convention in the circle fold.
///
/// Updated channel transcript:
///   chan.init()
///   chan.mixRoot(embeddedRoot)          // absorb trace commitment
///   compAlpha  = chan.drawSecureFelt()  // composition polynomial coefficient
///   friAlpha   = chan.drawSecureFelt()  // FRI folding challenge
///   queries[]  = chan.drawQueries(treeDepth, N)
///
/// Updated hint struct (adds queryValuesNeg and merkleSiblingsNeg):
///   bytes32   traceRoot
///   uint32[]  queryValues        column values at queryIndex
///   uint32[]  queryValuesNeg     column values at antipodalIdx
///   uint256   queryIndex
///   uint256   treeDepth
///   bytes32[] merkleSiblings     Merkle proof for queryIndex
///   bytes32[] merkleSiblingsNeg  Merkle proof for antipodalIdx
///   uint128   friAlpha           must equal channel-derived friAlpha
///   uint128   fPlus              must equal composition at queryIndex
///   uint128   fMinus             must equal composition at antipodalIdx
///   uint128   foldedValue
///   uint256   queryPointX
///   uint256   queryPointY
contract QLSAVerifierV8 is IQLSAVerifierV4 {

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 public constant MIN_PROOF_LENGTH = 700;
    uint256 public constant MAX_PROOF_LENGTH = 1_048_576; // 1 MiB
    uint256 public constant MIN_QUERIES = 1;
    uint256 public constant MAX_QUERIES = 64;

    // ── Structs ───────────────────────────────────────────────────────────────

    struct QueryHints {
        bytes32   traceRoot;
        uint32[]  queryValues;        // col values at queryIndex
        uint32[]  queryValuesNeg;     // col values at antipodalIdx  (NEW)
        uint256   queryIndex;
        uint256   treeDepth;
        bytes32[] merkleSiblings;
        bytes32[] merkleSiblingsNeg;  // Merkle proof for antipodalIdx (NEW)
        uint128   friAlpha;           // must == channel-derived friAlpha
        uint128   fPlus;              // must == composition at queryIndex
        uint128   fMinus;             // must == composition at antipodalIdx
        uint128   foldedValue;
        uint256   queryPointX;
        uint256   queryPointY;
    }

    // ── Public interface ──────────────────────────────────────────────────────

    /// @notice Verify a QLSA STARK proof with full composition binding.
    ///
    /// queryHints must be ABI-encoded as QueryHints[] (array of structs).
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

        // 3. Commitment binding: commitment = Blake2s(proof[0:32] ‖ merkleRoot)[0:16]
        if (!_checkCommitment(proof, commitment, merkleRoot)) return false;

        // 4. Decode query hints array.
        QueryHints[] memory hints = abi.decode(queryHints, (QueryHints[]));

        // 5. Query count bounds.
        if (hints.length < MIN_QUERIES) return false;
        if (hints.length > MAX_QUERIES) return false;

        // 6. Extract embedded trace root from proof[8:40].
        bytes32 embeddedRoot;
        assembly ("memory-safe") { embeddedRoot := calldataload(add(proof.offset, 8)) }

        // 7. All queries must share the same treeDepth.
        uint256 logDomainSize = hints[0].treeDepth;
        for (uint256 i = 1; i < hints.length; i++) {
            if (hints[i].treeDepth != logDomainSize) return false;
        }

        // 8. Derive compAlpha, friAlpha and query indices via Fiat-Shamir.
        TwoChannel.State memory chan = TwoChannel.init();
        TwoChannel.mixRoot(chan, embeddedRoot);
        uint128 compAlpha = TwoChannel.drawSecureFelt(chan);  // composition coefficient
        uint128 friAlpha  = TwoChannel.drawSecureFelt(chan);  // FRI folding challenge
        uint256[] memory derivedIdx = TwoChannel.drawQueries(chan, logDomainSize, hints.length);

        // 9. Verify each query.
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].friAlpha   != friAlpha)        return false;
            if (hints[i].queryIndex != derivedIdx[i])   return false;
            if (!_verifyQuery(hints[i], embeddedRoot, compAlpha)) return false;
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
        uint128 compAlpha
    ) internal pure returns (bool) {
        if (h.queryValues.length == 0) return false;
        if (h.queryValues.length != h.queryValuesNeg.length) return false;

        // a. Trace root consistency.
        if (h.traceRoot != embeddedRoot) return false;

        // b. Merkle inclusion at queryIndex.
        if (!MerkleVerifier.verifyColumnsMem(
            h.traceRoot, h.queryValues, h.queryIndex, h.treeDepth, h.merkleSiblings
        )) return false;

        // c. Antipodal index: (queryIndex + domainSize/2) mod domainSize.
        uint256 half = 1 << (h.treeDepth - 1);
        uint256 antipodalIdx = (h.queryIndex + half) & ((1 << h.treeDepth) - 1);

        // d. Merkle inclusion at antipodalIdx.
        if (!MerkleVerifier.verifyColumnsMem(
            h.traceRoot, h.queryValuesNeg, antipodalIdx, h.treeDepth, h.merkleSiblingsNeg
        )) return false;

        // e. Composition check: fPlus / fMinus must be the linear combination
        //    Σ_j [compAlpha^j · QM31.fromM31(col_j)] over all columns.
        uint128 expectedFPlus  = _computeComposition(h.queryValues,    compAlpha);
        uint128 expectedFMinus = _computeComposition(h.queryValuesNeg, compAlpha);
        if (h.fPlus  != expectedFPlus)  return false;
        if (h.fMinus != expectedFMinus) return false;

        // f. Circle fold check.
        if (!_checkCircleFold(h)) return false;

        return true;
    }

    /// @dev Σ_j [compAlpha^j · QM31.fromM31(vals[j])], starting at j=0.
    function _computeComposition(uint32[] memory vals, uint128 compAlpha)
        internal pure returns (uint128 result)
    {
        uint128 alphaPow = QM31.fromM31(1); // compAlpha^0 = 1
        for (uint256 j = 0; j < vals.length; j++) {
            result = QM31.add(result, QM31.mul(alphaPow, QM31.fromM31(vals[j])));
            alphaPow = QM31.mul(alphaPow, compAlpha);
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
