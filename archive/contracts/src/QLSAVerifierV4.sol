// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifier.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/CM31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";
import "./verifier/CirclePoint.sol";

/// @title QLSAVerifierV4 — Merkle query verification + correct circle FRI fold
///
/// Advances beyond QLSAVerifierFull (which only checks commitment binding)
/// by verifying actual STARK proof structure:
///
///   1. Proof length bounds.
///   2. Blake2s commitment binding: commitment = Blake2s(proof[0:32] ‖ merkleRoot)[0:16]
///   3. Trace root consistency: proof[8:40] must match the hinted traceRoot.
///   4. Merkle query verification: column values at queryIndex must be in traceRoot.
///   5. Circle fold check (Stwo fold_circle_into_line):
///        foldedValue = (f+ + f−) + α·(f+ − f−)·y⁻¹
///      where y is the y-coordinate of the circle domain point at queryIndex,
///      verified to lie on CanonicCoset(treeDepth) at position queryIndex.
///
/// Proof format: Stwo bincode standard encoding.
///   proof[0:8]   = u64 LE count of commitment roots
///   proof[8:40]  = first Blake2s commitment root (preprocessed or trace tree)
///
/// `queryHints` ABI encoding:
///   abi.encode(
///     bytes32   traceRoot,       // must match proof[8:40]
///     uint32[]  queryValues,     // M31 trace column values at queried row (for Merkle check)
///     uint256   queryIndex,      // leaf index in the trace Merkle tree
///     uint256   treeDepth,       // log2 of domain size = CanonicCoset log size
///     bytes32[] merkleSiblings,  // Merkle sibling path from leaf to root
///     uint128   friAlpha,        // QM31 FRI folding challenge
///     uint128   fPlus,           // f(p) as QM31: evaluation at the query circle point
///     uint128   fMinus,          // f(−p) as QM31: evaluation at the conjugate point
///     uint128   foldedValue,     // expected QM31 result of the circle fold
///     uint256   queryPointX,     // x-coordinate of circle domain point (M31, hint)
///     uint256   queryPointY      // y-coordinate of circle domain point (M31, hint)
///   )
///
/// The circle domain point (queryPointX, queryPointY) is a hint verified on-chain:
///   a) it must satisfy x² + y² ≡ 1 (mod P)  — on-circle check
///   b) it must equal CanonicCoset(treeDepth).at(queryIndex) — domain position check
contract QLSAVerifierV4 {

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 public constant MIN_PROOF_LENGTH = 700;
    uint256 public constant MAX_PROOF_LENGTH = 1_048_576; // 1 MiB

    // ── Structs ───────────────────────────────────────────────────────────────

    struct QueryHints {
        bytes32   traceRoot;
        uint32[]  queryValues;
        uint256   queryIndex;
        uint256   treeDepth;
        bytes32[] merkleSiblings;
        uint128   friAlpha;
        uint128   fPlus;          // f(p) as QM31
        uint128   fMinus;         // f(conjugate(p)) as QM31
        uint128   foldedValue;    // expected folded QM31
        uint256   queryPointX;    // hint: circle domain x-coordinate (M31)
        uint256   queryPointY;    // hint: circle domain y-coordinate (M31)
    }

    // ── Public interface ──────────────────────────────────────────────────────

    /// @notice Verify a QLSA STARK proof with on-chain Merkle query + circle FRI fold.
    function verify(
        bytes calldata proof,
        bytes16 commitment,
        bytes32 merkleRoot,
        bytes calldata queryHints
    ) external pure returns (bool) {

        // 1. Proof length bounds.
        if (proof.length < MIN_PROOF_LENGTH) return false;
        if (proof.length > MAX_PROOF_LENGTH) return false;

        // 2. Non-zero inputs.
        if (commitment == bytes16(0)) return false;
        if (merkleRoot == bytes32(0)) return false;
        if (queryHints.length == 0) return false;

        // 3. Commitment binding.
        if (!_checkCommitment(proof, commitment, merkleRoot)) return false;

        // 4. Decode hints.
        QueryHints memory h = _decode(queryHints);

        // 5. Trace root consistency: proof[8:40] == h.traceRoot.
        if (!_checkTraceRoot(proof, h.traceRoot)) return false;

        // 6. Merkle inclusion proof.
        if (!MerkleVerifier.verifyColumnsMem(
            h.traceRoot, h.queryValues, h.queryIndex, h.treeDepth, h.merkleSiblings
        )) return false;

        // 7. Circle FRI fold check.
        if (!_checkCircleFold(h)) return false;

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

    function _checkTraceRoot(bytes calldata proof, bytes32 traceRoot) internal pure returns (bool) {
        bytes32 embedded;
        assembly ("memory-safe") { embedded := calldataload(add(proof.offset, 8)) }
        return embedded == traceRoot;
    }

    function _decode(bytes calldata hints) internal pure returns (QueryHints memory h) {
        (h.traceRoot, h.queryValues, h.queryIndex, h.treeDepth,
         h.merkleSiblings, h.friAlpha,
         h.fPlus, h.fMinus, h.foldedValue,
         h.queryPointX, h.queryPointY)
            = abi.decode(hints,
                (bytes32, uint32[], uint256, uint256, bytes32[], uint128,
                 uint128, uint128, uint128, uint256, uint256));
    }

    function _checkCircleFold(QueryHints memory h) internal pure returns (bool) {
        if (h.queryValues.length == 0) return false;

        // a) Circle point must be valid (x² + y² = 1 mod P).
        if (!CirclePoint.isOnCircle(h.queryPointX, h.queryPointY)) return false;

        // b) Circle point must match CanonicCoset(treeDepth).at(queryIndex).
        //    This binds the fold to the correct FRI domain position.
        if (h.treeDepth < 1 || h.treeDepth > 30) return false;
        if (h.queryIndex >= (1 << h.treeDepth)) return false; // idx must be in [0, 2^treeDepth)
        (uint256 cx, uint256 cy) = CirclePoint.cosetAt(h.treeDepth, h.queryIndex);
        if (cx != h.queryPointX || cy != h.queryPointY) return false;

        // c) Circle fold: foldedValue = (f+ + f−) + α·(f+ − f−)·y⁻¹
        uint256 yInv = M31.inv(h.queryPointY);
        uint128 derived = CirclePoint.circleFold(h.fPlus, h.fMinus, h.friAlpha, yInv);
        return derived == h.foldedValue;
    }
}
