// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./IQLSAVerifierV4.sol";

/// @title BatchRegistryV4
/// @notice On-chain registry of QLSA-finalized batches requiring BOTH a LOG=10
///         and a LOG=8 VFRI6 proof, enabling full V23 ML-DSA STARK verification.
///
/// The V23 ML-DSA trace has two distinct sub-groups of columns:
///   - LOG=10 group (1024 rows): NttBatch (649 cols) + InttBatch (649 cols) = 1298 cols
///   - LOG=8  group  (256 rows): AzFull (1523) + Ct1Full (295) + RangeQBatch (288)
///                               + WPrimeFull (24) + NormCheckBatch (15)
///                               + UseHintBatchV2 (61 + 1 preproc) = 2206 cols + 1 preproc
///
/// Each group requires a separate VFRI6 FRI commitment tree because the trace
/// domains have different sizes (LOG=10 vs LOG=8).  BatchRegistryV4 accepts two
/// (proof, commitment, hints) pairs and verifies both before finalizing a batch.
///
/// NOTE (research prototype): There is currently no on-chain cross-proof binding
/// between the LOG=10 NTT outputs (z_hat, the NTT of the signature vector z) and
/// the LOG=8 AzFull inputs.  An adversary could, in principle, supply a valid
/// LOG=10 proof and an unrelated LOG=8 proof that both pass independently.  Full
/// binding requires either (a) a single FRI commitment tree spanning both trace
/// sizes (requires Stwo mixed-degree STARK, not yet wired on-chain) or (b) an
/// explicit cross-proof linking constraint committed in both proofs.  This is a
/// known open point tracked for MVP-5.
///
/// Flow:
///   1. Aggregator builds SHA3-512 Merkle tree over N transactions.
///   2. Stwo prover generates V23 proof → two VFRI6 hint sets (LOG=10, LOG=8).
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

    /// @notice The VFRI6 verifier used for BOTH the LOG=10 and LOG=8 proof checks.
    IQLSAVerifierV4 public verifier;

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

    // ──────────────────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────────────────

    /// @param initialOwner Address that will own the registry (can update verifier).
    /// @param _verifier    Address of the initial IQLSAVerifierV4 implementation
    ///                     (typically QLSAVerifierVFRI6) used for both proof calls.
    constructor(address initialOwner, address _verifier) Ownable(initialOwner) {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        verifier = IQLSAVerifierV4(_verifier);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Core logic
    // ──────────────────────────────────────────────────────────────────────────

    /// @notice Submit a batch for on-chain finalization requiring two VFRI6 proofs.
    /// @dev Both proofs are verified against the same `merkleRoot`.
    ///      The VFRI6 commitment encodes: Blake2s(proof[:32] ‖ merkleRoot)[:16].
    /// @param merkleRoot       bytes32 SHA3-512 Merkle root of the batch.
    /// @param commitmentLog10  16-byte VFRI6 commitment for the LOG=10 trace group.
    /// @param proofLog10       Full serialized STARK proof for the LOG=10 group.
    /// @param hintsLog10       ABI-encoded VFRI6 hints for the LOG=10 group.
    /// @param commitmentLog8   16-byte VFRI6 commitment for the LOG=8 trace group.
    /// @param proofLog8        Full serialized STARK proof for the LOG=8 group.
    /// @param hintsLog8        ABI-encoded VFRI6 hints for the LOG=8 group.
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

        if (!verifier.verify(proofLog10, commitmentLog10, merkleRoot, hintsLog10))
            revert Log10ProofInvalid();

        if (!verifier.verify(proofLog8, commitmentLog8, merkleRoot, hintsLog8))
            revert Log8ProofInvalid();

        finalizedBatches[merkleRoot]        = true;
        batchTimestamps[merkleRoot]         = block.timestamp;
        batchCommitmentsLog10[merkleRoot]   = commitmentLog10;
        batchCommitmentsLog8[merkleRoot]    = commitmentLog8;

        emit BatchFinalized(merkleRoot, commitmentLog10, commitmentLog8, block.timestamp);
    }

    /// @notice Submit a batch with per-sender nonce enforcement (replay protection).
    /// @param merkleRoot       bytes32 SHA3-512 Merkle root of the batch.
    /// @param commitmentLog10  16-byte VFRI6 commitment for the LOG=10 trace group.
    /// @param proofLog10       Full serialized STARK proof for the LOG=10 group.
    /// @param hintsLog10       ABI-encoded VFRI6 hints for the LOG=10 group.
    /// @param commitmentLog8   16-byte VFRI6 commitment for the LOG=8 trace group.
    /// @param proofLog8        Full serialized STARK proof for the LOG=8 group.
    /// @param hintsLog8        ABI-encoded VFRI6 hints for the LOG=8 group.
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

        if (!verifier.verify(proofLog10, commitmentLog10, merkleRoot, hintsLog10))
            revert Log10ProofInvalid();

        if (!verifier.verify(proofLog8, commitmentLog8, merkleRoot, hintsLog8))
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
