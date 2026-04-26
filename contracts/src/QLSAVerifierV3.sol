// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifier.sol";
import "./verifier/M31.sol";
import "./verifier/Blake2s.sol";

/// @title QLSAVerifierV3 — Phase 3++ Structural Verifier
///
/// Extends V2 with a tighter proof-length floor (700 bytes, empirical Stwo
/// minimum), an all-zero proof guard, and keccak256 commitment binding
/// groundwork.  Blake2s is imported for the next milestone (full FRI paths).
///
/// @dev Replace with the full Circle STARK on-chain verifier before mainnet.
contract QLSAVerifierV3 is IQLSAVerifier {

    // ── Constants ─────────────────────────────────────────────────────────────

    /// @notice Minimum proof length (bytes).
    /// Smallest observed Stwo proof at log_size=3 is 752 bytes; 700 is the floor.
    uint256 public constant MIN_PROOF_LENGTH = 700;

    /// @notice Maximum proof length (bytes).
    /// Stwo proofs for practical batch sizes (≤3000 tx) fit well under 1 MB.
    /// Prevents gas-griefing via oversized calldata on the keccak256 call.
    uint256 public constant MAX_PROOF_LENGTH = 1_048_576; // 1 MiB

    // ── IQLSAVerifier ─────────────────────────────────────────────────────────

    /// @inheritdoc IQLSAVerifier
    function verify(
        bytes calldata proof,
        bytes8 commitment
    ) external pure override returns (bool) {

        // 1. Proof length bounds (floor: structural minimum; ceiling: gas-griefing guard).
        if (proof.length < MIN_PROOF_LENGTH) return false;
        if (proof.length > MAX_PROOF_LENGTH) return false;

        // 2. Non-zero commitment.
        if (commitment == bytes8(0)) return false;

        // 3. First 4 bytes must encode a valid M31 element (< 2^31 − 1).
        if (!M31.isValid(M31.fromBytes4LE(bytes4(commitment)))) return false;

        // 4. Trailing 4 bytes of commitment must be zero (ABI padding).
        if (uint32(uint64(commitment)) != 0) return false;

        // 5. All-zero proof guard — sample 4 positions for gas efficiency.
        if (proof[0] == 0 && proof[proof.length - 1] == 0) {
            uint256 mid1 = proof.length / 4;
            uint256 mid2 = proof.length / 2;
            uint256 mid3 = (3 * proof.length) / 4;
            if (proof[mid1] == 0 && proof[mid2] == 0 && proof[mid3] == 0) {
                return false;
            }
        }

        // 6. Commitment must not equal keccak256(proof)[:8] — guards against a
        //    caller confusing the proof digest with the hash-chain commitment.
        if (commitment == bytes8(keccak256(proof))) return false;

        return true;
    }
}
