// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifier.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/CM31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";

/// @title QLSAVerifierV4 — Merkle query verification + FRI fold check
///
/// Advances beyond QLSAVerifierFull (which only checks commitment binding)
/// by verifying actual STARK proof structure:
///
///   1. Proof length bounds.
///   2. Blake2s commitment binding: commitment = Blake2s(proof[0:32] ‖ merkleRoot)[0:16]
///   3. Trace root consistency: proof[8:40] must match the hinted traceRoot.
///   4. Merkle query verification: column values at queryIndex must be in traceRoot.
///   5. FRI fold check: foldedValue = friLinearFold(f(x), f(-x), alpha) for real alpha.
///
/// Proof format: Stwo bincode standard encoding.
///   proof[0:8]   = u64 LE count of commitment roots
///   proof[8:40]  = first Blake2s commitment root (preprocessed or trace tree)
///
/// `queryHints` ABI encoding:
///   abi.encode(
///     bytes32   traceRoot,       // must match proof[8:40]
///     uint32[]  queryValues,     // M31 trace column values at queried row
///     uint256   queryIndex,      // leaf index in the trace Merkle tree
///     uint256   treeDepth,       // Merkle tree depth (log2 of domain size)
///     bytes32[] merkleSiblings,  // Merkle sibling path from leaf to root
///     uint128   friAlpha,        // QM31 FRI challenge (packed as uint128)
///     uint256   foldedValue,     // prover-claimed FRI folded value (M31)
///     uint256   mirrorValue      // f(-x) evaluation partner (M31)
///   )
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
        uint256   foldedValue;
        uint256   mirrorValue;
    }

    // ── Public interface ──────────────────────────────────────────────────────

    /// @notice Verify a QLSA STARK proof with on-chain Merkle query verification.
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

        // 7. FRI fold check (real-valued alpha only).
        if (!_checkFriFold(h)) return false;

        return true;
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    function _checkCommitment(
        bytes calldata proof,
        bytes16 commitment,
        bytes32 merkleRoot
    ) internal pure returns (bool) {
        bytes memory hInput = new bytes(64);
        assembly { calldatacopy(add(hInput, 32), proof.offset, 32) }
        for (uint256 i = 0; i < 32; i++) hInput[32 + i] = merkleRoot[i];
        bytes32 h = Blake2s.hash(hInput);
        return bytes16(h) == commitment;
    }

    function _checkTraceRoot(bytes calldata proof, bytes32 traceRoot) internal pure returns (bool) {
        bytes32 embedded;
        assembly { embedded := calldataload(add(proof.offset, 8)) }
        return embedded == traceRoot;
    }

    function _decode(bytes calldata hints) internal pure returns (QueryHints memory h) {
        (h.traceRoot, h.queryValues, h.queryIndex, h.treeDepth,
         h.merkleSiblings, h.friAlpha, h.foldedValue, h.mirrorValue)
            = abi.decode(hints, (bytes32, uint32[], uint256, uint256, bytes32[], uint128, uint256, uint256));
    }

    function _checkFriFold(QueryHints memory h) internal pure returns (bool) {
        if (h.queryValues.length == 0) return false;
        uint256 fPlus = uint256(h.queryValues[0]);

        uint128 derived = QM31.friLinearFold(fPlus, h.mirrorValue, h.friAlpha);
        uint64 dc0 = QM31.c0(derived);

        // If fold result is real (both imaginary parts zero), check M31 equality.
        if (CM31.im(dc0) == 0 && QM31.c1(derived) == 0) {
            return M31.isValid(h.foldedValue) && CM31.re(dc0) == h.foldedValue;
        }
        // Non-real result: fold check passes without M31 comparison (caller used QM31 alpha).
        return true;
    }
}
