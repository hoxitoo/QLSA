// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./IQLSAVerifierV4.sol";

/// @title BatchRegistryV4
/// @notice On-chain registry of QLSA-finalized batches requiring BOTH a LOG=10
///         and a LOG=8 VFRI7 proof, enabling full V23 ML-DSA STARK verification.
///
/// The V23 ML-DSA trace has two distinct sub-groups of columns:
///   - LOG=10 group (1024 rows): NttBatch (649 cols) + InttBatch (649 cols) = 1298 cols
///   - LOG=8  group  (256 rows): AzFull (1523) + Ct1Full (295) + RangeQBatch (288)
///                               + WPrimeFull (24) + NormCheckBatch (15)
///                               + UseHintBatchV2 (61 + 1 preproc) = 2206 cols + 1 preproc
///
/// Each group requires a separate VFRI7 FRI commitment tree because the trace
/// domains have different sizes (LOG=10 vs LOG=8).  BatchRegistryV4 accepts two
/// (proof, commitment, hints) pairs and verifies both before finalizing a batch.
///
/// Cross-proof binding (MVP-5 Priority 2, implemented in VFRI7):
///   QLSAVerifierVFRI7 mixes `merkleRoot` into the Fiat-Shamir transcript before
///   drawing FRI query indices.  BatchRegistryV4 uses cross-bound roots:
///
///     boundRoot10 = keccak256(merkleRoot ‖ traceRoot8)   (traceRoot8  = proofLog8[8:40])
///     boundRoot8  = keccak256(merkleRoot ‖ traceRoot10)  (traceRoot10 = proofLog10[8:40])
///
///   The LOG=10 proof is verified against boundRoot10, so its FRI query indices
///   depend on the LOG=8 trace commitment; and vice versa.  An adversary who mixes
///   proofs from different witnesses would get mismatched query indices and fail
///   Merkle verification.  This closes the cross-proof cherry-pick vulnerability.
///
/// Flow:
///   1. Aggregator builds SHA3-512 Merkle tree over N transactions.
///   2. Stwo prover generates V23 proof → two VFRI7 hint sets (LOG=10, LOG=8).
///   3. Aggregator derives:
///        commitmentLog10 = Blake2s(proofLog10[:32] || merkleRoot)[:16]
///        commitmentLog8  = Blake2s(proofLog8[:32]  || merkleRoot)[:16]
///   4. Aggregator calls submitBatch(merkleRoot, ...).
///   5. BatchRegistryV4 calls verifier.verify() for the LOG=10 proof, then again
///      for the LOG=8 proof.  Both must return true.
///   6. On success, merkleRoot is stored as finalized forever.
///
/// Nonce registry and replay protection are identical to BatchRegistryV3.
contract BatchRegistryV4 is ReentrancyGuard, Ownable {

    // ──────────────────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice The VFRI7 verifier used for BOTH the LOG=10 and LOG=8 proof checks.
    IQLSAVerifierV4 public verifier;

    /// @notice Maximum senders per submitBatchWithNonces call (caps O(n²) dedup loop).
    uint256 public constant MAX_SENDERS = 3000;

    /// @notice Returns true if the given Merkle root has been finalized.
    mapping(bytes32 => bool) public finalizedBatches;

    /// @notice Unix timestamp at which each batch was finalized.
    mapping(bytes32 => uint256) public batchTimestamps;

    /// @notice The LOG=10 commitment used to finalize each batch (for auditability).
    mapping(bytes32 => bytes16) public batchCommitmentsLog10;

    /// @notice The LOG=8 commitment used to finalize each batch (for auditability).
    mapping(bytes32 => bytes16) public batchCommitmentsLog8;

    /// @notice Last accepted nonce per sender address (replay protection).
    mapping(bytes32 => uint64) public senderNonces;

    // ──────────────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Emitted when a batch is successfully finalized with both proofs.
    event BatchFinalized(
        bytes32 indexed merkleRoot,
        bytes16  indexed commitmentLog10,
        bytes16          commitmentLog8,
        uint256          timestamp
    );

    /// @notice Emitted when the verifier contract is replaced by the owner.
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    /// @notice Emitted for each sender whose nonce was advanced in submitBatchWithNonces.
    event NonceAdvanced(bytes32 indexed sender, uint64 newNonce);

    // ──────────────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────────────

    error InvalidMerkleRoot();
    error BatchAlreadyFinalized(bytes32 merkleRoot);
    error Log10ProofInvalid();
    error Log8ProofInvalid();
    error ZeroAddressVerifier();
    error SenderNonceTooLow(bytes32 sender, uint64 provided, uint64 expected);
    error NoncesLengthMismatch();
    error SenderCountExceedsLimit();

    // ──────────────────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────────────────

    /// @param initialOwner Address that will own the registry (can update verifier).
    /// @param _verifier    Address of the initial IQLSAVerifierV4 implementation
    ///                     (typically QLSAVerifierVFRI7) used for both proof calls.
    constructor(address initialOwner, address _verifier) Ownable(initialOwner) {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        verifier = IQLSAVerifierV4(_verifier);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Core logic
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Submit a batch for on-chain finalization requiring two VFRI7 proofs.
    /// @dev Both proofs are verified against the same `merkleRoot`.
    ///      The VFRI7 commitment encodes: Blake2s(proof[:32] ‖ merkleRoot)[:16].
    /// @param merkleRoot       bytes32 SHA3-512 Merkle root of the batch.
    /// @param commitmentLog10  16-byte VFRI7 commitment for the LOG=10 trace group.
    /// @param proofLog10       Full serialized STARK proof for the LOG=10 group.
    /// @param hintsLog10       ABI-encoded VFRI7 hints for the LOG=10 group.
    /// @param commitmentLog8   16-byte VFRI7 commitment for the LOG=8 trace group.
    /// @param proofLog8        Full serialized STARK proof for the LOG=8 group.
    /// @param hintsLog8        ABI-encoded VFRI7 hints for the LOG=8 group.
    function submitBatch(
        bytes32        merkleRoot,
        bytes16        commitmentLog10,
        bytes calldata proofLog10,
        bytes calldata hintsLog10,
        bytes16        commitmentLog8,
        bytes calldata proofLog8,
        bytes calldata hintsLog8
    ) external nonReentrant {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (finalizedBatches[merkleRoot]) revert BatchAlreadyFinalized(merkleRoot);

        // Cross-proof binding: each proof's FRI queries depend on the other's trace root.
        bytes32 traceRoot10;
        bytes32 traceRoot8;
        assembly ("memory-safe") {
            traceRoot10 := calldataload(add(proofLog10.offset, 8))
            traceRoot8  := calldataload(add(proofLog8.offset,  8))
        }
        bytes32 boundRoot10 = keccak256(abi.encodePacked(merkleRoot, traceRoot8));
        bytes32 boundRoot8  = keccak256(abi.encodePacked(merkleRoot, traceRoot10));

        if (!verifier.verify(proofLog10, commitmentLog10, boundRoot10, hintsLog10))
            revert Log10ProofInvalid();

        if (!verifier.verify(proofLog8, commitmentLog8, boundRoot8, hintsLog8))
            revert Log8ProofInvalid();

        finalizedBatches[merkleRoot]        = true;
        batchTimestamps[merkleRoot]         = block.timestamp;
        batchCommitmentsLog10[merkleRoot]   = commitmentLog10;
        batchCommitmentsLog8[merkleRoot]    = commitmentLog8;

        emit BatchFinalized(merkleRoot, commitmentLog10, commitmentLog8, block.timestamp);
    }

    /// @notice Submit a batch with per-sender nonce enforcement (replay protection).
    /// @param merkleRoot       bytes32 SHA3-512 Merkle root of the batch.
    /// @param commitmentLog10  16-byte VFRI7 commitment for the LOG=10 trace group.
    /// @param proofLog10       Full serialized STARK proof for the LOG=10 group.
    /// @param hintsLog10       ABI-encoded VFRI7 hints for the LOG=10 group.
    /// @param commitmentLog8   16-byte VFRI7 commitment for the LOG=8 trace group.
    /// @param proofLog8        Full serialized STARK proof for the LOG=8 group.
    /// @param hintsLog8        ABI-encoded VFRI7 hints for the LOG=8 group.
    /// @param senders          Array of sender address hashes (bytes32 = SHA3-256 of ML-DSA pubkey).
    /// @param newNonces        New nonce values (must be strictly > current stored nonce for each sender).
    function submitBatchWithNonces(
        bytes32            merkleRoot,
        bytes16            commitmentLog10,
        bytes calldata     proofLog10,
        bytes calldata     hintsLog10,
        bytes16            commitmentLog8,
        bytes calldata     proofLog8,
        bytes calldata     hintsLog8,
        bytes32[] calldata senders,
        uint64[]  calldata newNonces
    ) external nonReentrant {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (finalizedBatches[merkleRoot]) revert BatchAlreadyFinalized(merkleRoot);
        if (senders.length != newNonces.length) revert NoncesLengthMismatch();
        if (senders.length > MAX_SENDERS) revert SenderCountExceedsLimit();

        // Validate all nonces before touching state.
        for (uint256 i = 0; i < senders.length; ++i) {
            uint64 current = senderNonces[senders[i]];
            if (newNonces[i] <= current) {
                revert SenderNonceTooLow(senders[i], newNonces[i], current + 1);
            }
            // Detect duplicate senders: require strictly increasing nonces within call.
            for (uint256 j = i + 1; j < senders.length; ++j) {
                if (senders[i] == senders[j]) {
                    if (newNonces[j] <= newNonces[i]) {
                        revert SenderNonceTooLow(senders[j], newNonces[j], newNonces[i] + 1);
                    }
                }
            }
        }

        // Cross-proof binding: each proof's FRI queries depend on the other's trace root.
        bytes32 traceRoot10w;
        bytes32 traceRoot8w;
        assembly ("memory-safe") {
            traceRoot10w := calldataload(add(proofLog10.offset, 8))
            traceRoot8w  := calldataload(add(proofLog8.offset,  8))
        }
        bytes32 boundRoot10w = keccak256(abi.encodePacked(merkleRoot, traceRoot8w));
        bytes32 boundRoot8w  = keccak256(abi.encodePacked(merkleRoot, traceRoot10w));

        if (!verifier.verify(proofLog10, commitmentLog10, boundRoot10w, hintsLog10))
            revert Log10ProofInvalid();

        if (!verifier.verify(proofLog8, commitmentLog8, boundRoot8w, hintsLog8))
            revert Log8ProofInvalid();

        finalizedBatches[merkleRoot]        = true;
        batchTimestamps[merkleRoot]         = block.timestamp;
        batchCommitmentsLog10[merkleRoot]   = commitmentLog10;
        batchCommitmentsLog8[merkleRoot]    = commitmentLog8;

        for (uint256 i = 0; i < senders.length; ++i) {
            senderNonces[senders[i]] = newNonces[i];
            emit NonceAdvanced(senders[i], newNonces[i]);
        }

        emit BatchFinalized(merkleRoot, commitmentLog10, commitmentLog8, block.timestamp);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // View helpers
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Check whether a Merkle root has been finalized.
    function isBatchFinalized(bytes32 merkleRoot) external view returns (bool) {
        return finalizedBatches[merkleRoot];
    }

    /// @notice Retrieve the LOG=10 commitment stored for a finalized batch.
    function getCommitmentsLog10(bytes32 merkleRoot) external view returns (bytes16) {
        return batchCommitmentsLog10[merkleRoot];
    }

    /// @notice Retrieve the LOG=8 commitment stored for a finalized batch.
    function getCommitmentsLog8(bytes32 merkleRoot) external view returns (bytes16) {
        return batchCommitmentsLog8[merkleRoot];
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Admin
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Replace the verifier contract (e.g. upgrade to a newer VFRI version).
    function setVerifier(address _verifier) external onlyOwner {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        address old = address(verifier);
        verifier = IQLSAVerifierV4(_verifier);
        emit VerifierUpdated(old, _verifier);
    }
}
