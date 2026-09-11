// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./IQLSAVerifier.sol";

/// @title BatchRegistry
/// @notice On-chain registry of QLSA-finalized transaction batches.
///
/// Each batch is identified by a bytes32 Merkle root (first 32 bytes of the
/// off-chain SHA3-512 Merkle root) and carries a STARK commitment that proves
/// the integrity of the hash-chain over the batch leaves.
///
/// Flow:
///   1. Aggregator collects N transactions, builds SHA3-512 Merkle tree.
///   2. Aggregator runs Winterfell STARK prover → (proof, commitment).
///   3. Aggregator calls submitBatch(merkleRoot, commitment, proof).
///   4. BatchRegistry delegates proof verification to IQLSAVerifier.
///   5. On success, merkleRoot is stored as finalized forever.
contract BatchRegistry is ReentrancyGuard, Ownable {

    // ──────────────────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────────────────

    IQLSAVerifier public verifier;

    /// @notice Returns true if the given Merkle root has been finalized.
    mapping(bytes32 => bool) public finalizedBatches;

    /// @notice Unix timestamp at which each batch was finalized.
    mapping(bytes32 => uint256) public batchTimestamps;

    // ──────────────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Emitted when a batch is successfully finalized.
    /// @param merkleRoot      First 32 bytes of the off-chain SHA3-512 Merkle root.
    /// @param starkCommitment 8-byte hash-chain commitment verified by the STARK proof.
    /// @param timestamp       Block timestamp of finalization.
    event BatchFinalized(
        bytes32 indexed merkleRoot,
        bytes8  indexed starkCommitment,
        uint256         timestamp
    );

    /// @notice Emitted when the verifier contract is replaced by the owner.
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    // ──────────────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────────────

    error InvalidMerkleRoot();
    error BatchAlreadyFinalized(bytes32 merkleRoot);
    error InvalidProof();
    error ZeroAddressVerifier();

    // ──────────────────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────────────────

    /// @param initialOwner Address that will own the registry (can update verifier).
    /// @param _verifier    Address of the initial IQLSAVerifier implementation.
    constructor(address initialOwner, address _verifier) Ownable(initialOwner) {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        verifier = IQLSAVerifier(_verifier);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Core logic
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Submit a batch for on-chain finalization.
    /// @param merkleRoot      bytes32 derived from the SHA3-512 Merkle root
    ///                        (Python: `batch.merkle_root[:32]`).
    /// @param starkCommitment 8-byte Winterfell commitment
    ///                        (Python: `bytes.fromhex(batch.stark_commitment)`).
    /// @param starkProof      Full serialized STARK proof bytes.
    function submitBatch(
        bytes32        merkleRoot,
        bytes8         starkCommitment,
        bytes calldata starkProof
    ) external nonReentrant {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (finalizedBatches[merkleRoot]) revert BatchAlreadyFinalized(merkleRoot);

        if (!verifier.verify(starkProof, starkCommitment)) revert InvalidProof();

        finalizedBatches[merkleRoot] = true;
        batchTimestamps[merkleRoot]  = block.timestamp;

        emit BatchFinalized(merkleRoot, starkCommitment, block.timestamp);
    }

    /// @notice Check whether a Merkle root has been finalized.
    function isBatchFinalized(bytes32 merkleRoot) external view returns (bool) {
        return finalizedBatches[merkleRoot];
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Admin
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Replace the verifier contract (e.g. upgrade stub → Stwo verifier).
    ///         Only callable by the owner.
    function setVerifier(address _verifier) external onlyOwner {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        address old = address(verifier);
        verifier = IQLSAVerifier(_verifier);
        emit VerifierUpdated(old, _verifier);
    }
}
