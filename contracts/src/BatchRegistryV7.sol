// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import "./QLSAVerifierRecursive.sol";

/// @title BatchRegistryV7 — recursive-proof batch registry (MVP-8)
///
/// Finalizes a V23 batch from RECURSIVE proofs: instead of verifying each trace
/// group's VFRI11 proof directly (BatchRegistryV5), it verifies, per group, a
/// STARK attesting that the inner VFRI11 proof was verified — plus the cheap
/// on-chain half the recursion deliberately leaves outside the circuit.
///
/// # What actually gets checked
///
/// `QLSAVerifierRecursive.verifyRecursive` covers, for one group:
///
///   on-chain   channel replay        -> the FRI challenges and query indices are
///                                       Fiat-Shamir-derived, not prover-chosen
///   on-chain   last-layer check      -> friLayerRoots[K] commits a bounded-degree
///                                       final layer (cheap + constant, so it stays
///                                       out of the circuit — see R4.13)
///   in-circuit compRoot -> compValue -> f_p -> fold chain -> finalFold -> hashLeaf
///              -> path -> friLayerRoots[K]   (R4.10 / R4.12 / C1)
///
/// # Cross-proof binding
///
/// A V23 batch is two trace groups, so two recursive bundles are submitted and
/// each is bound to the OTHER's trace root, exactly as BatchRegistryV5 does:
///
///     bundle10.inner.batchRoot == keccak256(merkleRoot | bundle8.inner.traceRoot)
///     bundle8.inner.batchRoot  == keccak256(merkleRoot | bundle10.inner.traceRoot)
///
/// `batchRoot` is mixed into the inner channel before its queries are drawn, so a
/// bundle assembled from a different witness draws different query indices and
/// fails. The binding is tighter here than in V5: there the registry read the
/// trace root out of raw proof bytes, whereas `traceRoot` is an explicit public
/// field that `outerBindingRoot` already commits to — an outer proof cannot be
/// replayed against a different trace root.
///
/// This rejects the case that matters — one group submitted as BOTH bundles,
/// since its `batchRoot` commits to the other group's trace root. Note the
/// constraint pair is SYMMETRIC under exchanging the bundles, so submitting them
/// in the opposite order is accepted: both remain valid proofs bound to this
/// `merkleRoot`, and neither can be duplicated, so it is not a soundness break —
/// but it does mean `batchCommitmentsLog10` / `batchCommitmentsLog8` are
/// POSITIONAL labels rather than enforced group identities. BatchRegistryV5's
/// binding has the same property. Enforcing the label would need a group tag in
/// the bound root (`keccak(merkleRoot | otherTraceRoot | groupId)`), which would
/// diverge from the V5 scheme and require regenerating every cross-bound fixture.
contract BatchRegistryV7 is Ownable, ReentrancyGuard {
    /// @notice One group's recursive bundle.
    struct RecursiveBundle {
        QLSAVerifierRecursive.InnerPublics inner;
        bytes outerProof;
        bytes16 outerCommitment;
        bytes outerHints;
        uint128[] lastLayerEvals;
    }

    /// @notice The recursive verifier used for BOTH groups.
    QLSAVerifierRecursive public verifier;

    /// @notice Hard backstop on senders per call — NOT a reachable capability: the
    ///         O(n²) duplicate scan bounds a call at n ~ 212 (measured; see
    ///         BatchRegistryV5 for the full gas table). Exceeding that is OUT OF
    ///         GAS, not a clean revert. Keep batches under ~150 senders.
    uint256 public constant MAX_SENDERS = 3000;

    mapping(bytes32 => bool) public finalizedBatches;
    mapping(bytes32 => uint256) public batchTimestamps;
    mapping(bytes32 => bytes16) public batchCommitmentsLog10;
    mapping(bytes32 => bytes16) public batchCommitmentsLog8;
    mapping(bytes32 => uint64) public senderNonces;

    event BatchFinalized(
        bytes32 indexed merkleRoot,
        bytes16 indexed commitmentLog10,
        bytes16 commitmentLog8,
        uint256 timestamp
    );
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event NonceAdvanced(bytes32 indexed sender, uint64 newNonce);

    error InvalidMerkleRoot();
    error BatchAlreadyFinalized(bytes32 merkleRoot);
    error Log10ProofInvalid();
    error Log8ProofInvalid();
    error ZeroAddressVerifier();
    error SenderNonceTooLow(bytes32 sender, uint64 provided, uint64 expected);
    error NoncesLengthMismatch();
    error SenderCountExceedsLimit();
    /// @notice A bundle's `inner.batchRoot` is not the cross-bound root for this batch.
    error CrossBindingMismatch();

    constructor(address initialOwner, address _verifier) Ownable(initialOwner) {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        verifier = QLSAVerifierRecursive(_verifier);
    }

    function setVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddressVerifier();
        address old = address(verifier);
        verifier = QLSAVerifierRecursive(newVerifier);
        emit VerifierUpdated(old, newVerifier);
    }

    /// @notice The root a group's bundle must carry, given the OTHER group's trace root.
    function crossBoundRoot(bytes32 merkleRoot, bytes32 otherTraceRoot)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(merkleRoot, otherTraceRoot));
    }

    /// @notice Finalize a batch from two recursive bundles.
    function submitBatch(
        bytes32 merkleRoot,
        RecursiveBundle calldata bundle10,
        RecursiveBundle calldata bundle8
    ) external nonReentrant {
        _finalize(merkleRoot, bundle10, bundle8);
    }

    /// @notice Finalize a batch and advance per-sender nonces (replay protection).
    /// @dev Nonces are 1-based on-chain: an unseen sender reads 0 and `newNonce`
    ///      must exceed it, so the smallest submittable value is 1.
    function submitBatchWithNonces(
        bytes32 merkleRoot,
        RecursiveBundle calldata bundle10,
        RecursiveBundle calldata bundle8,
        bytes32[] calldata senders,
        uint64[] calldata newNonces
    ) external nonReentrant {
        if (senders.length != newNonces.length) revert NoncesLengthMismatch();
        if (senders.length > MAX_SENDERS) revert SenderCountExceedsLimit();

        // Validate every nonce before touching state.
        for (uint256 i = 0; i < senders.length; ++i) {
            uint64 current = senderNonces[senders[i]];
            if (newNonces[i] <= current) {
                revert SenderNonceTooLow(senders[i], newNonces[i], current + 1);
            }
            // Duplicate senders within the call must be strictly increasing.
            for (uint256 j = i + 1; j < senders.length; ++j) {
                if (senders[i] == senders[j] && newNonces[j] <= newNonces[i]) {
                    revert SenderNonceTooLow(senders[j], newNonces[j], newNonces[i] + 1);
                }
            }
        }

        _finalize(merkleRoot, bundle10, bundle8);

        for (uint256 i = 0; i < senders.length; ++i) {
            senderNonces[senders[i]] = newNonces[i];
            emit NonceAdvanced(senders[i], newNonces[i]);
        }
    }

    function isBatchFinalized(bytes32 merkleRoot) external view returns (bool) {
        return finalizedBatches[merkleRoot];
    }

    // ──────────────────────────────────────────────────────────────────────────

    function _finalize(
        bytes32 merkleRoot,
        RecursiveBundle calldata bundle10,
        RecursiveBundle calldata bundle8
    ) private {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (finalizedBatches[merkleRoot]) revert BatchAlreadyFinalized(merkleRoot);

        // Cross-proof binding: each bundle must have been produced against the
        // OTHER group's trace root, so the two cannot come from different witnesses.
        if (bundle10.inner.batchRoot != crossBoundRoot(merkleRoot, bundle8.inner.traceRoot)) {
            revert CrossBindingMismatch();
        }
        if (bundle8.inner.batchRoot != crossBoundRoot(merkleRoot, bundle10.inner.traceRoot)) {
            revert CrossBindingMismatch();
        }

        (bool ok10, ) = verifier.verifyRecursive(
            bundle10.inner,
            bundle10.outerProof,
            bundle10.outerCommitment,
            bundle10.outerHints,
            bundle10.lastLayerEvals
        );
        if (!ok10) revert Log10ProofInvalid();

        (bool ok8, ) = verifier.verifyRecursive(
            bundle8.inner,
            bundle8.outerProof,
            bundle8.outerCommitment,
            bundle8.outerHints,
            bundle8.lastLayerEvals
        );
        if (!ok8) revert Log8ProofInvalid();

        finalizedBatches[merkleRoot] = true;
        batchTimestamps[merkleRoot] = block.timestamp;
        batchCommitmentsLog10[merkleRoot] = bundle10.outerCommitment;
        batchCommitmentsLog8[merkleRoot] = bundle8.outerCommitment;

        emit BatchFinalized(
            merkleRoot,
            bundle10.outerCommitment,
            bundle8.outerCommitment,
            block.timestamp
        );
    }
}
