// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";
import "./verifier/CirclePoint.sol";
import "./verifier/TwoChannel.sol";

/// @title QLSAVerifierV6 — Multi-query FRI with Fiat-Shamir query derivation
///
/// Advances beyond QLSAVerifierV5 by deriving FRI query positions on-chain from
/// the embedded trace root using TwoChannel (Stwo's Blake2sM31Channel).
///
/// Security gap closed: in V5 the caller supplies queryIndex values, allowing a
/// cheating prover to cherry-pick favorable positions after committing.  In V6
/// positions are determined by the trace root hash and cannot be influenced after
/// the commitment is fixed.
///
/// Query derivation (Fiat-Shamir):
///   chan = TwoChannel.init()
///   chan.mixRoot(embeddedRoot)                        // absorb trace commitment
///   derived[] = chan.drawQueries(treeDepth, N)        // deterministic indices
///   require hints[i].queryIndex == derived[i]  ∀ i
///
/// Constraints added vs V5:
///   • All queries must share the same treeDepth (single FRI domain).
///   • Each hint's queryIndex must match the channel-derived index for that slot.
///
/// All other checks (commitment binding, Merkle inclusion, circle fold) are
/// identical to QLSAVerifierV5.
///
/// `queryHints` ABI encoding: same as QLSAVerifierV5 — QueryHints[] struct array.
contract QLSAVerifierV6 is IQLSAVerifierV4 {

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

    /// @notice Verify a QLSA STARK proof with Fiat-Shamir FRI query derivation.
    ///
    /// queryHints must be ABI-encoded as QueryHints[] (array of structs).
    /// Query positions are derived from the embedded trace root via TwoChannel —
    /// the caller cannot manipulate which positions are checked.
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

        // 6. Extract embedded trace root from proof[8:40] (shared by all queries).
        bytes32 embeddedRoot;
        assembly ("memory-safe") { embeddedRoot := calldataload(add(proof.offset, 8)) }

        // 7. All queries must share the same treeDepth (single FRI domain).
        uint256 logDomainSize = hints[0].treeDepth;
        for (uint256 i = 1; i < hints.length; i++) {
            if (hints[i].treeDepth != logDomainSize) return false;
        }

        // 8. Derive query indices via Fiat-Shamir (TwoChannel absorbs trace root).
        TwoChannel.State memory chan = TwoChannel.init();
        TwoChannel.mixRoot(chan, embeddedRoot);
        uint256[] memory derivedIdx = TwoChannel.drawQueries(chan, logDomainSize, hints.length);

        // 9. Verify each query: index must match derived, then Merkle + circle fold.
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].queryIndex != derivedIdx[i]) return false;
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
