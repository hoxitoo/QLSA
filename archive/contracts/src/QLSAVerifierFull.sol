// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifier.sol";
import "./verifier/Blake2s.sol";

/// @title QLSAVerifierFull — Blake2s FRI Root Binding Verifier
///
/// Advances beyond the structural V3 verifier by cryptographically binding
/// the proof to its commitment via Blake2s hashing of the proof header.
///
/// Commitment format (bytes8):
///   bytes 0–7 = Blake2s(proof[0:32])[0:8]
///
/// The first 32 bytes of a Stwo bincode-serialised StarkProof contain the
/// beginning of the FRI commitment trees (serialised Blake2s Merkle roots).
/// Hashing this region with Blake2s and taking the first 8 bytes gives a
/// cryptographically strong binding: any tampering with proof[0:32] changes
/// the required commitment, and vice versa.
///
/// Security properties (relative to V3):
///   + Proof and commitment cannot be independently forged — forging a
///     commitment without knowing the proof prefix requires inverting Blake2s.
///   - Still not a full STARK verifier: FRI queries, OODS points, and
///     ML-DSA signature correctness inside the AIR are not checked.
///
/// @dev Replace with the full Circle STARK on-chain verifier before mainnet.
contract QLSAVerifierFull is IQLSAVerifier {

    // ── Constants ─────────────────────────────────────────────────────────────

    /// @notice Minimum proof length (bytes).
    uint256 public constant MIN_PROOF_LENGTH = 700;

    /// @notice Maximum proof length (bytes). Prevents gas-griefing.
    uint256 public constant MAX_PROOF_LENGTH = 1_048_576; // 1 MiB

    // ── IQLSAVerifier ─────────────────────────────────────────────────────────

    /// @inheritdoc IQLSAVerifier
    function verify(
        bytes calldata proof,
        bytes8 commitment
    ) external pure override returns (bool) {

        // 1. Proof length bounds.
        if (proof.length < MIN_PROOF_LENGTH) return false;
        if (proof.length > MAX_PROOF_LENGTH) return false;

        // 2. Non-zero commitment.
        if (commitment == bytes8(0)) return false;

        // 3. Blake2s FRI root binding.
        //    Hash proof[0:32] with Blake2s; commitment must equal the first 8 bytes.
        //    proof.length >= 700 so proof[0:32] is always in bounds.
        bytes memory proofHead = new bytes(32);
        assembly ("memory-safe") {
            // proofHead data starts at (proofHead + 32), skipping the length word.
            // proof.offset is the calldata offset of proof[0].
            calldatacopy(add(proofHead, 32), proof.offset, 32)
        }
        bytes32 rootHash = Blake2s.hash(proofHead);
        if (bytes8(rootHash) != commitment) return false;

        return true;
    }
}
