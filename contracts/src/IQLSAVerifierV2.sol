// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IQLSAVerifierV2 — Extended verifier interface with Merkle root binding.
///
/// Extends the original IQLSAVerifier by including the `merkleRoot` parameter
/// so that the verifier can cryptographically bind the STARK proof to the
/// specific batch Merkle root being finalized.
///
/// This closes the architectural gap present in IQLSAVerifier: previously the
/// proof commitment was computed over proof bytes only, so a valid proof could
/// be replayed against an arbitrary Merkle root.
///
/// With this interface the commitment is derived as:
///   commitment = Blake2s(proof[0:32] ∥ merkleRoot)[0:8]
///
/// meaning a commitment is only valid for ONE specific (proof, merkleRoot) pair.
interface IQLSAVerifierV2 {
    /// @notice Verify a STARK proof against a batch Merkle root.
    /// @param proof       Full serialized STARK proof bytes.
    /// @param commitment  8-byte binding commitment (Blake2s of proof header + Merkle root).
    /// @param merkleRoot  The batch Merkle root this proof covers.
    /// @return True if the proof is valid for the given (commitment, merkleRoot) pair.
    function verify(
        bytes calldata proof,
        bytes8         commitment,
        bytes32        merkleRoot
    ) external pure returns (bool);
}
