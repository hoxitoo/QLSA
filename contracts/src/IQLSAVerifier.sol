// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IQLSAVerifier
/// @notice Interface for STARK proof verifiers in the QLSA protocol.
/// Phase 3 stub: QLSAVerifier.sol validates proof format only.
/// Phase 3+ production: replace with Stwo Circle STARK on-chain verifier.
interface IQLSAVerifier {
    /// @notice Verify a STARK proof against a batch commitment.
    /// @param proof      Raw STARK proof bytes (Stwo serialization).
    /// @param commitment 8-byte Stwo Circle STARK commitment:
    ///                   bytes 0–3: M31 field element (little-endian uint32, value < 2^31−1)
    ///                   bytes 4–7: zero padding (ABI convention)
    /// @return valid     True if the proof is accepted.
    function verify(
        bytes calldata proof,
        bytes8 commitment
    ) external view returns (bool valid);
}
