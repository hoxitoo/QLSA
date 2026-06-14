// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./IQLSAVerifierV4.sol";

/// @title BatchRegistryV6 — per-group (split) V23 batch registry
/// @notice Finalizes a V23 batch from its TWO trace-group proofs (LOG=10 and
///         LOG=8), but verifies each group in its OWN transaction instead of
///         both in a single call.
///
/// Motivation (gas): with the Poseidon2 t=4 backend (QLSAVerifierVFRI10) each
/// V23 group `verify()` fits within the ~16.7M per-transaction gas budget
/// individually (~8–10M), but BatchRegistryV5.submitBatch runs BOTH t=4 verifies
/// in one transaction and overruns the cap.  BatchRegistryV6 splits the work:
///
///   submitGroup10(...)  → one verify() (≤16.7M), stores the group, no finalize
///   submitGroup8(...)   → one verify() (≤16.7M), finalizes once both groups are
///                         present AND mutually cross-consistent
///
/// Cross-proof binding (identical guarantee to BatchRegistryV5, enforced lazily):
///   boundRoot10 = keccak256(merkleRoot ‖ crossTraceRoot8)   verified at submit
///   boundRoot8  = keccak256(merkleRoot ‖ crossTraceRoot10)  verified at submit
/// At finalization the registry asserts that the cross trace root each proof was
/// bound to equals the OTHER proof's actual embedded trace root (proof[8:40]):
///   crossRoot8For10 == traceRoot8   (group10 was bound to group8's real root)
///   crossRoot10For8 == traceRoot10  (group8 was bound to group10's real root)
/// So mixing groups from different witnesses cannot finalize — the same
/// soundness BatchRegistryV5 gets from its atomic dual-verify, recovered here
/// across two transactions.
///
/// Submission is order-independent and a not-yet-finalized group may be
/// overwritten by a later (also-valid) submission, so a third party cannot grief
/// a Merkle root by front-running one group with a mismatched cross root.
///
/// Replay protection: `submitGroup8WithNonces` finalizes with per-sender nonce
/// enforcement (the completing call carries the nonces); it requires the LOG=10
/// group to already be present and cross-consistent.
contract BatchRegistryV6 is ReentrancyGuard, Ownable {

    // ── State ──────────────────────────────────────────────────────────────────

    /// @notice The verifier used for BOTH group checks (typically QLSAVerifierVFRI10).
    IQLSAVerifierV4 public verifier;

    /// @notice Maximum senders per nonce-enforced finalization (caps O(n²) dedup).
    uint256 public constant MAX_SENDERS = 3000;

    /// @notice Per-group submission state for a not-yet-finalized batch.
    struct PendingGroups {
        bool    has10;
        bool    has8;
        bytes16 commitment10;
        bytes16 commitment8;
        bytes32 traceRoot10;      // proof10[8:40]  (group10's real trace root)
        bytes32 traceRoot8;       // proof8[8:40]   (group8's real trace root)
        bytes32 crossRoot8For10;  // crossTraceRoot8 that proof10 was bound to
        bytes32 crossRoot10For8;  // crossTraceRoot10 that proof8 was bound to
    }

    mapping(bytes32 => PendingGroups) internal _pending;

    mapping(bytes32 => bool)    public finalizedBatches;
    mapping(bytes32 => uint256) public batchTimestamps;
    mapping(bytes32 => bytes16) public batchCommitmentsLog10;
    mapping(bytes32 => bytes16) public batchCommitmentsLog8;
    mapping(bytes32 => uint64)  public senderNonces;

    // ── Events ─────────────────────────────────────────────────────────────────

    /// @notice Emitted when one group's proof is verified and stored. `log` is
    ///         the group's LOG-domain size (10 or 8).
    event GroupVerified(bytes32 indexed merkleRoot, uint8 log, bytes16 commitment);

    event BatchFinalized(
        bytes32 indexed merkleRoot,
        bytes16  indexed commitmentLog10,
        bytes16          commitmentLog8,
        uint256          timestamp
    );

    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event NonceAdvanced(bytes32 indexed sender, uint64 newNonce);

    // ── Errors ─────────────────────────────────────────────────────────────────

    error InvalidMerkleRoot();
    error BatchAlreadyFinalized(bytes32 merkleRoot);
    error Log10ProofInvalid();
    error Log8ProofInvalid();
    error ZeroAddressVerifier();
    error NotReadyToFinalize();
    error SenderNonceTooLow(bytes32 sender, uint64 provided, uint64 expected);
    error NoncesLengthMismatch();
    error SenderCountExceedsLimit();

    // ── Constructor ────────────────────────────────────────────────────────────

    constructor(address initialOwner, address _verifier) Ownable(initialOwner) {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        verifier = IQLSAVerifierV4(_verifier);
    }

    // ── Per-group submission ─────────────────────────────────────────────────────

    /// @notice Submit and verify the LOG=10 trace-group proof.
    /// @param crossTraceRoot8 The LOG=8 group's trace root (proof8[8:40]) that
    ///        the LOG=10 proof's Fiat-Shamir transcript was bound to.
    function submitGroup10(
        bytes32        merkleRoot,
        bytes32        crossTraceRoot8,
        bytes16        commitmentLog10,
        bytes calldata proofLog10,
        bytes calldata hintsLog10
    ) external nonReentrant {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (finalizedBatches[merkleRoot]) revert BatchAlreadyFinalized(merkleRoot);
        if (proofLog10.length < 40) revert Log10ProofInvalid();

        bytes32 traceRoot10;
        assembly ("memory-safe") { traceRoot10 := calldataload(add(proofLog10.offset, 8)) }
        bytes32 boundRoot10 = keccak256(abi.encodePacked(merkleRoot, crossTraceRoot8));
        if (!verifier.verify(proofLog10, commitmentLog10, boundRoot10, hintsLog10))
            revert Log10ProofInvalid();

        PendingGroups storage p = _pending[merkleRoot];
        p.has10           = true;
        p.commitment10    = commitmentLog10;
        p.traceRoot10     = traceRoot10;
        p.crossRoot8For10 = crossTraceRoot8;
        emit GroupVerified(merkleRoot, 10, commitmentLog10);

        _tryFinalize(merkleRoot);
    }

    /// @notice Submit and verify the LOG=8 trace-group proof; auto-finalizes
    ///         (without nonce enforcement) once both groups are cross-consistent.
    /// @param crossTraceRoot10 The LOG=10 group's trace root (proof10[8:40]) that
    ///        the LOG=8 proof's Fiat-Shamir transcript was bound to.
    function submitGroup8(
        bytes32        merkleRoot,
        bytes32        crossTraceRoot10,
        bytes16        commitmentLog8,
        bytes calldata proofLog8,
        bytes calldata hintsLog8
    ) external nonReentrant {
        _verifyGroup8(merkleRoot, crossTraceRoot10, commitmentLog8, proofLog8, hintsLog8);
        _tryFinalize(merkleRoot);
    }

    /// @notice Submit the LOG=8 group AND finalize with per-sender nonce
    ///         enforcement.  Requires the LOG=10 group to already be present and
    ///         cross-consistent (submit LOG=10 first, then this completing call).
    function submitGroup8WithNonces(
        bytes32            merkleRoot,
        bytes32            crossTraceRoot10,
        bytes16            commitmentLog8,
        bytes calldata     proofLog8,
        bytes calldata     hintsLog8,
        bytes32[] calldata senders,
        uint64[]  calldata newNonces
    ) external nonReentrant {
        if (senders.length != newNonces.length) revert NoncesLengthMismatch();
        if (senders.length > MAX_SENDERS) revert SenderCountExceedsLimit();

        // Validate all nonces before any state change.
        for (uint256 i = 0; i < senders.length; ++i) {
            uint64 current = senderNonces[senders[i]];
            if (newNonces[i] <= current) {
                revert SenderNonceTooLow(senders[i], newNonces[i], current + 1);
            }
            for (uint256 j = i + 1; j < senders.length; ++j) {
                if (senders[i] == senders[j] && newNonces[j] <= newNonces[i]) {
                    revert SenderNonceTooLow(senders[j], newNonces[j], newNonces[i] + 1);
                }
            }
        }

        _verifyGroup8(merkleRoot, crossTraceRoot10, commitmentLog8, proofLog8, hintsLog8);

        // The nonce-bearing call must be the finalizing one.
        if (!_readyToFinalize(merkleRoot)) revert NotReadyToFinalize();

        for (uint256 i = 0; i < senders.length; ++i) {
            senderNonces[senders[i]] = newNonces[i];
            emit NonceAdvanced(senders[i], newNonces[i]);
        }
        _finalize(merkleRoot);
    }

    // ── Internal ─────────────────────────────────────────────────────────────────

    function _verifyGroup8(
        bytes32        merkleRoot,
        bytes32        crossTraceRoot10,
        bytes16        commitmentLog8,
        bytes calldata proofLog8,
        bytes calldata hintsLog8
    ) internal {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (finalizedBatches[merkleRoot]) revert BatchAlreadyFinalized(merkleRoot);
        if (proofLog8.length < 40) revert Log8ProofInvalid();

        bytes32 traceRoot8;
        assembly ("memory-safe") { traceRoot8 := calldataload(add(proofLog8.offset, 8)) }
        bytes32 boundRoot8 = keccak256(abi.encodePacked(merkleRoot, crossTraceRoot10));
        if (!verifier.verify(proofLog8, commitmentLog8, boundRoot8, hintsLog8))
            revert Log8ProofInvalid();

        PendingGroups storage p = _pending[merkleRoot];
        p.has8            = true;
        p.commitment8     = commitmentLog8;
        p.traceRoot8      = traceRoot8;
        p.crossRoot10For8 = crossTraceRoot10;
        emit GroupVerified(merkleRoot, 8, commitmentLog8);
    }

    /// @dev True when both groups are present and each was bound to the other's
    ///      actual embedded trace root (the cross-proof-binding consistency).
    function _readyToFinalize(bytes32 merkleRoot) internal view returns (bool) {
        PendingGroups storage p = _pending[merkleRoot];
        return p.has10 && p.has8
            && p.crossRoot8For10 == p.traceRoot8
            && p.crossRoot10For8 == p.traceRoot10;
    }

    function _tryFinalize(bytes32 merkleRoot) internal {
        if (_readyToFinalize(merkleRoot)) _finalize(merkleRoot);
    }

    function _finalize(bytes32 merkleRoot) internal {
        PendingGroups storage p = _pending[merkleRoot];
        finalizedBatches[merkleRoot]      = true;
        batchTimestamps[merkleRoot]       = block.timestamp;
        batchCommitmentsLog10[merkleRoot] = p.commitment10;
        batchCommitmentsLog8[merkleRoot]  = p.commitment8;
        bytes16 c10 = p.commitment10;
        bytes16 c8  = p.commitment8;
        delete _pending[merkleRoot]; // reclaim storage; finalized maps retain the record
        emit BatchFinalized(merkleRoot, c10, c8, block.timestamp);
    }

    // ── Views ──────────────────────────────────────────────────────────────────

    function isBatchFinalized(bytes32 merkleRoot) external view returns (bool) {
        return finalizedBatches[merkleRoot];
    }

    /// @notice Inspect the pending per-group state for a not-yet-finalized batch.
    function pendingGroups(bytes32 merkleRoot)
        external view returns (bool has10, bool has8, bool readyToFinalize)
    {
        PendingGroups storage p = _pending[merkleRoot];
        return (p.has10, p.has8, _readyToFinalize(merkleRoot));
    }

    function getCommitmentsLog10(bytes32 merkleRoot) external view returns (bytes16) {
        return batchCommitmentsLog10[merkleRoot];
    }

    function getCommitmentsLog8(bytes32 merkleRoot) external view returns (bytes16) {
        return batchCommitmentsLog8[merkleRoot];
    }

    // ── Admin ──────────────────────────────────────────────────────────────────

    function setVerifier(address _verifier) external onlyOwner {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        address old = address(verifier);
        verifier = IQLSAVerifierV4(_verifier);
        emit VerifierUpdated(old, _verifier);
    }
}
