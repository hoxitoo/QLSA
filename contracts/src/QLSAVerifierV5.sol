// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";
import "./verifier/CirclePoint.sol";

/// @title QLSAVerifierV5 — Multi-query Merkle + circle FRI fold verification
///
/// Advances beyond QLSAVerifierV4 (single query) by verifying N independent
/// FRI queries in a single call.  Real FRI soundness requires multiple queries:
///   security_bits ≈ N × log2(blowup)
/// For blowup=16 (LOG_BLOWUP=4) and N=8 queries: ~32 bits (dev/testnet grade).
/// For mainnet-grade 128-bit soundness: N=32 queries with blowup=16.
///
/// Each query in the array is independently verified:
///   1. traceRoot must equal proof[8:40] (same for all queries).
///   2. Column values must be in traceRoot at queryIndex (Merkle inclusion).
///   3. Circle fold: foldedValue = (f+ + f−) + α·(f+ − f−)·y⁻¹
///      where (qpX, qpY) = CanonicCoset(treeDepth).at(queryIndex).
///
/// `queryHints` ABI encoding (QueryHints[] array of structs):
///   abi.encode(
///     (bytes32,uint32[],uint256,uint256,bytes32[],uint128,uint128,uint128,uint128,uint256,uint256)[]
///   )
///
/// Each element:
///   bytes32   traceRoot       // must match proof[8:40] for every element
///   uint32[]  queryValues     // M31 column values at queried row
///   uint256   queryIndex      // leaf index in trace Merkle tree
///   uint256   treeDepth       // log2 of domain size = CanonicCoset log size
///   bytes32[] merkleSiblings  // Merkle sibling path leaf → root
///   uint128   friAlpha        // QM31 FRI folding challenge
///   uint128   fPlus           // f(p) as QM31
///   uint128   fMinus          // f(-p) as QM31
///   uint128   foldedValue     // expected QM31 result of circle fold
///   uint256   queryPointX     // circle domain point x-coordinate (M31, hint)
///   uint256   queryPointY     // circle domain point y-coordinate (M31, hint)
contract QLSAVerifierV5 is IQLSAVerifierV4 {

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 public constant MIN_PROOF_LENGTH = 700;
    uint256 public constant MAX_PROOF_LENGTH = 1_048_576; // 1 MiB
    uint256 public constant MIN_QUERIES = 1;
    uint256 public constant MAX_QUERIES = 64;

    // ── Structs ───────────────────────────────────────────────────────────────

    struct QueryHints {
        bytes32   traceRoot;
        uint32[]  queryValues;
        uint256   queryIndex;
        uint256   treeDepth;
        bytes32[] merkleSiblings;
        uint128   friAlpha;
        uint128   fPlus;
        uint128   fMinus;
        uint128   foldedValue;
        uint256   queryPointX;
        uint256   queryPointY;
    }

    // ── Public interface ──────────────────────────────────────────────────────

    /// @notice Verify a QLSA STARK proof with N on-chain Merkle queries + circle FRI fold.
    ///
    /// queryHints must be ABI-encoded as QueryHints[] (array of structs).
    /// All queries must share the same traceRoot embedded at proof[8:40].
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

        // 6. Extract embedded trace root from proof[8:40] once (shared by all queries).
        bytes32 embeddedRoot;
        assembly ("memory-safe") { embeddedRoot := calldataload(add(proof.offset, 8)) }

        // 7. Verify each query independently.
        for (uint256 i = 0; i < hints.length; i++) {
            if (!_verifyQuery(hints[i], embeddedRoot)) return false;
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

    function _verifyQuery(QueryHints memory h, bytes32 embeddedRoot) internal pure returns (bool) {
        if (h.queryValues.length == 0) return false;

        // a. Trace root consistency: hint must match proof[8:40].
        if (h.traceRoot != embeddedRoot) return false;

        // b. Merkle inclusion: column values at queryIndex must be in traceRoot.
        if (!MerkleVerifier.verifyColumnsMem(
            h.traceRoot, h.queryValues, h.queryIndex, h.treeDepth, h.merkleSiblings
        )) return false;

        // c. Circle fold check.
        if (!_checkCircleFold(h)) return false;

        return true;
    }

    function _checkCircleFold(QueryHints memory h) internal pure returns (bool) {
        // i. Circle point on-circle validation.
        if (!CirclePoint.isOnCircle(h.queryPointX, h.queryPointY)) return false;

        // ii. treeDepth bounds (CanonicCoset logN in [1, 30]).
        if (h.treeDepth < 1 || h.treeDepth > 30) return false;

        // iii. queryIndex in [0, 2^treeDepth).
        if (h.queryIndex >= (1 << h.treeDepth)) return false;

        // iv. Circle domain point must equal CanonicCoset(treeDepth).at(queryIndex).
        (uint256 cx, uint256 cy) = CirclePoint.cosetAt(h.treeDepth, h.queryIndex);
        if (cx != h.queryPointX || cy != h.queryPointY) return false;

        // v. Circle fold: foldedValue = (f+ + f−) + α·(f+ − f−)·y⁻¹
        uint256 yInv = M31.inv(h.queryPointY);
        uint128 derived = CirclePoint.circleFold(h.fPlus, h.fMinus, h.friAlpha, yInv);
        return derived == h.foldedValue;
    }
}
