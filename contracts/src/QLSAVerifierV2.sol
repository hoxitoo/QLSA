// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifier.sol";
import "./verifier/M31.sol";

/// @title QLSAVerifierV2 — Structural Verifier (Phase 3+)
///
/// Improvements over the Phase 3 stub (QLSAVerifier):
///   1. Proof length floor raised to 256 bytes (Stwo hash-chain proofs with
///      blowup=4 are >> 1 KB; 256 bytes is a conservative sanity floor).
///   2. Commitment is validated as a proper M31 field element (< 2^31 − 1),
///      not just a non-zero bytes8.
///
/// What this verifier does NOT do (Phase 3++ / MVP-3):
///   - Full FRI decommitment verification
///   - OODS (out-of-domain sampling) consistency check
///   - Algebraic constraint evaluation
///   - Blake2s-M31 Merkle decommitment paths
///
/// @dev Replace with the full Circle STARK on-chain verifier before mainnet.
contract QLSAVerifierV2 is IQLSAVerifier {
    /// @notice Minimum acceptable proof byte length.
    /// Stwo hash-chain proofs (blowup=4, ≥ 8 leaves) are typically > 5 KB.
    /// 256 bytes is a strict sanity floor that rejects obviously-malformed inputs.
    uint256 public constant MIN_PROOF_LENGTH = 256;

    /// @inheritdoc IQLSAVerifier
    function verify(
        bytes calldata proof,
        bytes8 commitment
    ) external pure override returns (bool) {
        // 1. Proof must meet minimum structural length.
        if (proof.length < MIN_PROOF_LENGTH) return false;

        // 2. Commitment must be non-zero (an all-zero commitment means
        //    the prover was never run or produced a trivially invalid output).
        if (commitment == bytes8(0)) return false;

        // 3. The first 4 bytes of commitment encode the M31 field element as
        //    a little-endian uint32 (Rust `M31::to_le_bytes()`).  Validate it
        //    is a fully-reduced element: value ∈ [0, 2^31 − 1).
        uint256 m31Val = M31.fromBytes4LE(bytes4(commitment));
        if (!M31.isValid(m31Val)) return false;

        // 4. The high 4 bytes of the bytes8 commitment must be zero (the
        //    commitment is only 4 bytes; the rest is ABI padding).
        if (uint32(uint64(commitment)) != 0) return false;

        return true;
    }
}
