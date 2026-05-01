// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./IQLSAVerifierV2.sol";

/// @title BatchRegistryV2
/// @notice On-chain registry of QLSA-finalized transaction batches with
///         full Merkle-root-to-commitment binding (Phase 6).
///
/// Advances beyond BatchRegistry by using IQLSAVerifierV2: the verifier now
/// receives the Merkle root and can verify that the STARK commitment is bound
/// to this specific root. This closes the replay/substitution attack vector
/// where a valid proof+commitment could be submitted against an arbitrary root.
///
/// Flow:
///   1. Aggregator collects N transactions, builds SHA3-512 Merkle tree.
///   2. Aggregator runs Stwo Circle STARK prover → (proof, onchain_commitment).
///      onchain_commitment = Blake2s(proof[0:32] ∥ merkle_root[:32])[0:8]
///   3. Aggregator calls submitBatch(merkleRoot, commitment, proof).
///   4. BatchRegistryV2 calls verifier.verify(proof, commitment, merkleRoot).
///   5. On success, merkleRoot is stored as finalized forever.
///
/// Python counterpart (stark/prover.py):
///   onchain_commitment = hashlib.blake2s(proof_bytes[:32] + batch.merkle_root[:32]).digest()[:8]
///
/// @dev merkleRoot = batch.merkle_root[:32] (first 32 bytes of SHA3-512 root).
contract BatchRegistryV2 is ReentrancyGuard, Ownable {

    // ──────────────────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────────────────

    IQLSAVerifierV2 public verifier;

    /// @notice Returns true if the given Merkle root has been finalized.
    mapping(bytes32 => bool) public finalizedBatches;

    /// @notice Unix timestamp at which each batch was finalized.
    mapping(bytes32 => uint256) public batchTimestamps;

    /// @notice The commitment used to finalize each batch (for auditability).
    mapping(bytes32 => bytes8) public batchCommitments;

    // ──────────────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Emitted when a batch is successfully finalized.
    /// @param merkleRoot  First 32 bytes of the off-chain SHA3-512 Merkle root.
    /// @param commitment  Blake2s-bound 8-byte commitment (proof header ∥ Merkle root).
    /// @param timestamp   Block timestamp of finalization.
    event BatchFinalized(
        bytes32 indexed merkleRoot,
        bytes8  indexed commitment,
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
    /// @param _verifier    Address of the initial IQLSAVerifierV2 implementation.
    constructor(address initialOwner, address _verifier) Ownable(initialOwner) {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        verifier = IQLSAVerifierV2(_verifier);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Core logic
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Submit a batch for on-chain finalization.
    /// @param merkleRoot  bytes32 derived from the SHA3-512 Merkle root
    ///                    (Python: `batch.merkle_root[:32]`).
    /// @param commitment  8-byte bound commitment
    ///                    (Python: `hashlib.blake2s(proof[:32] + merkle_root[:32]).digest()[:8]`).
    /// @param starkProof  Full serialized STARK proof bytes.
    function submitBatch(
        bytes32        merkleRoot,
        bytes8         commitment,
        bytes calldata starkProof
    ) external nonReentrant {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (finalizedBatches[merkleRoot]) revert BatchAlreadyFinalized(merkleRoot);

        if (!verifier.verify(starkProof, commitment, merkleRoot)) revert InvalidProof();

        finalizedBatches[merkleRoot]  = true;
        batchTimestamps[merkleRoot]   = block.timestamp;
        batchCommitments[merkleRoot]  = commitment;

        emit BatchFinalized(merkleRoot, commitment, block.timestamp);
    }

    /// @notice Check whether a Merkle root has been finalized.
    function isBatchFinalized(bytes32 merkleRoot) external view returns (bool) {
        return finalizedBatches[merkleRoot];
    }

    /// @notice Retrieve the commitment stored for a finalized batch.
    function getCommitment(bytes32 merkleRoot) external view returns (bytes8) {
        return batchCommitments[merkleRoot];
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Admin
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Replace the verifier contract (e.g. upgrade to full FRI verifier).
    ///         Only callable by the owner.
    function setVerifier(address _verifier) external onlyOwner {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        address old = address(verifier);
        verifier = IQLSAVerifierV2(_verifier);
        emit VerifierUpdated(old, _verifier);
    }
}
