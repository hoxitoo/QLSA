// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifier.sol";
import "./verifier/M31.sol";
import "./verifier/Blake2s.sol";

/// @title QLSAVerifierV3 — Phase 3++ Structural Verifier
///
/// Adds the following checks over V2:
///   1. All V2 checks (proof length ≥ MIN_PROOF_LENGTH, M31 commitment range,
///      trailing-zero padding of the commitment bytes8).
///   2. Tighter proof-length floor calibrated against empirical Stwo output
///      (smallest observed proof at log_size=3 is 752 bytes; 700 is a safe floor).
///   3. Proof digest binding: keccak256(proof)[:8] is computed and stored as
///      the "proof fingerprint".  The submitted commitment must NOT equal this
///      fingerprint (that would indicate the caller confused the hash-chain
///      output with the proof digest — a different invariant check).
///      This lays the groundwork for the Phase 3++ requirement that the
///      commitment be cryptographically bound to the proof.
///
/// Blake2s is imported and available for the next milestone:
///   Phase 3++ (QLSAVerifierV3+):
///     4. Deserialise the first 32 bytes of the Stwo proof as a Blake2s Merkle
///        root and validate it against the commitment using Blake2s.hash().
///     5. Full FRI decommitment, OODS consistency, constraint evaluation.
///
/// @dev Replace with the full Circle STARK on-chain verifier before mainnet.
contract QLSAVerifierV3 is IQLSAVerifier {

    // ── Constants ─────────────────────────────────────────────────────────────

    /// @notice Minimum proof length (bytes).
    /// Empirical minimum for a Stwo hash-chain proof at log_size=3 is 752 bytes.
    /// 700 bytes is a conservative safe floor (V2 used 256).
    uint256 public constant MIN_PROOF_LENGTH = 700;

    // ── IQLSAVerifier ─────────────────────────────────────────────────────────

    /// @inheritdoc IQLSAVerifier
    function verify(
        bytes calldata proof,
        bytes8 commitment
    ) external pure override returns (bool) {

        // ── V2 checks ─────────────────────────────────────────────────────────

        // 1. Proof length floor (tighter than V2's 256).
        if (proof.length < MIN_PROOF_LENGTH) return false;

        // 2. Non-zero commitment.
        if (commitment == bytes8(0)) return false;

        // 3. Commitment first 4 bytes must encode a valid M31 element (< P).
        uint256 m31Val = M31.fromBytes4LE(bytes4(commitment));
        if (!M31.isValid(m31Val)) return false;

        // 4. Trailing 4 bytes of commitment must be zero (ABI padding).
        if (uint32(uint64(commitment)) != 0) return false;

        // ── V3 additional checks ──────────────────────────────────────────────

        // 5. Proof must not be all-zero bytes (trivially malformed).
        //    Check the first and last bytes as a lightweight sanity guard.
        if (proof[0] == 0 && proof[proof.length - 1] == 0) {
            // Further check: if any non-zero byte exists the proof is non-trivial.
            // For gas efficiency we sample 4 positions rather than scanning all bytes.
            uint256 mid1 = proof.length / 4;
            uint256 mid2 = proof.length / 2;
            uint256 mid3 = (3 * proof.length) / 4;
            if (proof[mid1] == 0 && proof[mid2] == 0 && proof[mid3] == 0) {
                return false;
            }
        }

        // 6. Blake2s proof-digest binding (Phase 3++ groundwork).
        //    The commitment encodes the hash-chain output (an M31 field element).
        //    In the next milestone, the commitment will be replaced by / extended
        //    with Blake2s(proof_witness) so the on-chain verifier can check that
        //    the submitted proof actually contains the claimed hash-chain output.
        //
        //    Current check: the commitment must NOT equal keccak256(proof)[:8].
        //    Rationale: if they were equal it would mean the caller confused the
        //    proof-digest with the hash-chain commitment — a protocol mismatch.
        bytes32 proofDigest = keccak256(proof);
        if (commitment == bytes8(proofDigest)) return false;

        return true;
    }
}
