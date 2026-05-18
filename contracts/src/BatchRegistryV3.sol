// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./IQLSAVerifierV4.sol";

/// @title BatchRegistryV3
/// @notice On-chain registry of QLSA-finalized batches using the V4 verifier
///         interface — supports multi-query FRI hints (QLSAVerifierV5+).
///
/// Advances beyond BatchRegistryV2 by accepting the 4-parameter verifier interface
/// (IQLSAVerifierV4) that includes `queryHints`.  This makes multi-query on-chain
/// FRI verification (QLSAVerifierV5) deployable in the end-to-end workflow.
///
/// Flow:
///   1. Aggregator collects N transactions, builds SHA3-512 Merkle tree.
///   2. Aggregator runs Stwo Circle STARK prover → (proof, onchain_commitment).
///   3. Aggregator constructs FRI query hints (Merkle paths + fold inputs).
///   4. Aggregator calls submitBatch(merkleRoot, commitment, proof, queryHints).
///   5. BatchRegistryV3 calls verifier.verify(proof, commitment, merkleRoot, queryHints).
///   6. On success, merkleRoot is stored as finalized forever.
///
/// Nonce registry and replay protection are identical to BatchRegistryV2.
contract BatchRegistryV3 is ReentrancyGuard, Ownable {

    // ──────────────────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────────────────

    IQLSAVerifierV4 public verifier;

    /// @notice Returns true if the given Merkle root has been finalized.
    mapping(bytes32 => bool) public finalizedBatches;

    /// @notice Unix timestamp at which each batch was finalized.
    mapping(bytes32 => uint256) public batchTimestamps;

    /// @notice The commitment used to finalize each batch (for auditability).
    mapping(bytes32 => bytes16) public batchCommitments;

    /// @notice Last accepted nonce per sender address (replay protection).
    mapping(bytes32 => uint64) public senderNonces;

    // ──────────────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Emitted when a batch is successfully finalized.
    event BatchFinalized(
        bytes32 indexed merkleRoot,
        bytes16  indexed commitment,
        uint256         timestamp
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
    error InvalidProof();
    error ZeroAddressVerifier();
    error SenderNonceTooLow(bytes32 sender, uint64 provided, uint64 expected);
    error NoncesLengthMismatch();

    // ──────────────────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────────────────

    /// @param initialOwner Address that will own the registry (can update verifier).
    /// @param _verifier    Address of the initial IQLSAVerifierV4 implementation.
    constructor(address initialOwner, address _verifier) Ownable(initialOwner) {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        verifier = IQLSAVerifierV4(_verifier);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Core logic
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Submit a batch for on-chain finalization with FRI query hints.
    /// @param merkleRoot   bytes32 derived from the SHA3-512 Merkle root.
    /// @param commitment   16-byte Blake2s commitment.
    /// @param starkProof   Full serialized STARK proof bytes.
    /// @param queryHints   ABI-encoded FRI query hints (format defined by verifier).
    function submitBatch(
        bytes32        merkleRoot,
        bytes16        commitment,
        bytes calldata starkProof,
        bytes calldata queryHints
    ) external nonReentrant {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (finalizedBatches[merkleRoot]) revert BatchAlreadyFinalized(merkleRoot);

        if (!verifier.verify(starkProof, commitment, merkleRoot, queryHints)) revert InvalidProof();

        finalizedBatches[merkleRoot] = true;
        batchTimestamps[merkleRoot]  = block.timestamp;
        batchCommitments[merkleRoot] = commitment;

        emit BatchFinalized(merkleRoot, commitment, block.timestamp);
    }

    /// @notice Submit a batch with per-sender nonce enforcement (replay protection).
    /// @param merkleRoot   bytes32 from SHA3-512 Merkle root.
    /// @param commitment   16-byte Blake2s commitment.
    /// @param starkProof   Full serialized STARK proof.
    /// @param queryHints   ABI-encoded FRI query hints.
    /// @param senders      Array of sender address hashes (bytes32 = SHA3-256 of ML-DSA pubkey).
    /// @param newNonces    New nonce values (must be strictly > current stored nonce for each sender).
    function submitBatchWithNonces(
        bytes32          merkleRoot,
        bytes16          commitment,
        bytes calldata   starkProof,
        bytes calldata   queryHints,
        bytes32[] calldata senders,
        uint64[]  calldata newNonces
    ) external nonReentrant {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (finalizedBatches[merkleRoot]) revert BatchAlreadyFinalized(merkleRoot);
        if (senders.length != newNonces.length) revert NoncesLengthMismatch();

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

        if (!verifier.verify(starkProof, commitment, merkleRoot, queryHints)) revert InvalidProof();

        finalizedBatches[merkleRoot] = true;
        batchTimestamps[merkleRoot]  = block.timestamp;
        batchCommitments[merkleRoot] = commitment;

        for (uint256 i = 0; i < senders.length; ++i) {
            senderNonces[senders[i]] = newNonces[i];
            emit NonceAdvanced(senders[i], newNonces[i]);
        }

        emit BatchFinalized(merkleRoot, commitment, block.timestamp);
    }

    /// @notice Check whether a Merkle root has been finalized.
    function isBatchFinalized(bytes32 merkleRoot) external view returns (bool) {
        return finalizedBatches[merkleRoot];
    }

    /// @notice Retrieve the commitment stored for a finalized batch.
    function getCommitment(bytes32 merkleRoot) external view returns (bytes16) {
        return batchCommitments[merkleRoot];
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Admin
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Replace the verifier contract (e.g. upgrade to full FRI verifier).
    function setVerifier(address _verifier) external onlyOwner {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        address old = address(verifier);
        verifier = IQLSAVerifierV4(_verifier);
        emit VerifierUpdated(old, _verifier);
    }
}
