// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IQLSAVerifierV2 — Extended verifier interface with Merkle root binding.
///
/// The commitment is now 128-bit (bytes16) to prevent birthday-bound collisions
/// that would be feasible with the previous 32-bit (bytes8) format.
///
/// Commitment scheme (matches stark/prover.py + Rust lib.rs):
///   commitment[0:4]  = M31 circuit output (le-u32)
///   commitment[4:16] = Blake2s(m31_le ∥ proof[0:32])[0:12]
///
/// meaning a commitment is cryptographically bound to ONE specific proof.
interface IQLSAVerifierV2 {
    /// @notice Verify a STARK proof against a batch Merkle root.
    /// @param proof       Full serialized STARK proof bytes.
    /// @param commitment  16-byte (128-bit) binding commitment.
    /// @param merkleRoot  The batch Merkle root this proof covers.
    /// @return True if the proof is valid for the given (commitment, merkleRoot) pair.
    function verify(
        bytes calldata proof,
        bytes16        commitment,
        bytes32        merkleRoot
    ) external pure returns (bool);
}
