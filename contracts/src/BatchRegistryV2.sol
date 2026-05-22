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
///      onchain_commitment = Blake2s(proof[0:32] ∥ merkle_root[:32])[:16]  (16 bytes)
///   3. Aggregator calls submitBatch(merkleRoot, commitment, proof).
///   4. BatchRegistryV2 calls verifier.verify(proof, commitment, merkleRoot).
///   5. On success, merkleRoot is stored as finalized forever.
///
/// Python counterpart (stark/prover.py):
///   onchain_commitment = hashlib.blake2s(proof_bytes[:32] + batch.merkle_root[:32]).digest()[:16].hex()
///
/// commitment format (bytes16 = 16 bytes):
///   bytes  0–3  : M31 circuit output fingerprint word 0 (le-u32)
///   bytes  4–7  : M31 circuit output fingerprint word 1 (le-u32)
///   bytes  8–11 : M31 circuit output fingerprint word 2 (le-u32)
///   bytes 12–15 : M31 circuit output fingerprint word 3 (le-u32)
///
/// @dev merkleRoot = batch.merkle_root[:32] (first 32 bytes of SHA3-512 root).
contract BatchRegistryV2 is ReentrancyGuard, Ownable {

    // ──────────────────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────────────────

    IQLSAVerifierV2 public verifier;

    /// @notice Maximum senders per submitBatchWithNonces call (caps O(n²) dedup loop).
    uint256 public constant MAX_SENDERS = 3000;

    /// @notice Returns true if the given Merkle root has been finalized.
    mapping(bytes32 => bool) public finalizedBatches;

    /// @notice Unix timestamp at which each batch was finalized.
    mapping(bytes32 => uint256) public batchTimestamps;

    /// @notice The commitment used to finalize each batch (for auditability).
    mapping(bytes32 => bytes16) public batchCommitments;

    /// @notice Last accepted nonce per sender address (replay protection).
    /// @dev senderNonces[senderAddr] = highest nonce included in any finalized batch.
    mapping(bytes32 => uint64) public senderNonces;

    // ──────────────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Emitted when a batch is successfully finalized.
    /// @param merkleRoot  First 32 bytes of the off-chain SHA3-512 Merkle root.
    /// @param commitment  16-byte (128-bit) commitment binding the STARK proof to the batch output.
    /// @param timestamp   Block timestamp of finalization.
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
    error SenderCountExceedsLimit();

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
    /// @param commitment  16-byte (128-bit) commitment
    ///                    (Python: `hashlib.blake2s(proof[:32] + merkle_root[:32]).digest()[:16]`).
    /// @param starkProof  Full serialized STARK proof bytes.
    function submitBatch(
        bytes32        merkleRoot,
        bytes16         commitment,
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

    /// @notice Submit a batch with per-sender nonce enforcement (replay protection).
    /// @param merkleRoot   bytes32 from SHA3-512 Merkle root (first 32 bytes).
    /// @param commitment   16-byte Blake2s commitment.
    /// @param starkProof   Full serialized STARK proof.
    /// @param senders      Array of sender address hashes (bytes32, SHA3-256 of ML-DSA pubkey).
    /// @param newNonces    Array of new nonce values (must be > current stored nonce for each sender).
    ///
    /// Callers pass every unique sender in the batch together with the highest
    /// nonce for that sender included in this batch. The contract rejects any
    /// nonce that is not strictly greater than the last recorded nonce, preventing
    /// replay of any previously finalized transaction.
    function submitBatchWithNonces(
        bytes32          merkleRoot,
        bytes16          commitment,
        bytes calldata   starkProof,
        bytes32[] calldata senders,
        uint64[]  calldata newNonces
    ) external nonReentrant {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (finalizedBatches[merkleRoot]) revert BatchAlreadyFinalized(merkleRoot);
        if (senders.length != newNonces.length) revert NoncesLengthMismatch();
        if (senders.length > MAX_SENDERS) revert SenderCountExceedsLimit();

        // Validate all nonces before touching state (fail-fast).
        // Also detect duplicate senders in the same call to prevent nonce bypass.
        for (uint256 i = 0; i < senders.length; ++i) {
            uint64 current = senderNonces[senders[i]];
            if (newNonces[i] <= current) {
                revert SenderNonceTooLow(senders[i], newNonces[i], current + 1);
            }
            // Detect duplicates: within this call, treat the largest seen nonce as current.
            for (uint256 j = i + 1; j < senders.length; ++j) {
                if (senders[i] == senders[j]) {
                    // Require strictly increasing nonces for the same sender.
                    if (newNonces[j] <= newNonces[i]) {
                        revert SenderNonceTooLow(senders[j], newNonces[j], newNonces[i] + 1);
                    }
                }
            }
        }

        if (!verifier.verify(starkProof, commitment, merkleRoot)) revert InvalidProof();

        // Persist state.
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
    ///         Only callable by the owner.
    function setVerifier(address _verifier) external onlyOwner {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        address old = address(verifier);
        verifier = IQLSAVerifierV2(_verifier);
        emit VerifierUpdated(old, _verifier);
    }
}
