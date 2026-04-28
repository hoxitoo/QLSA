// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IQLSAVerifier
/// @notice Interface for STARK proof verifiers in the QLSA protocol.
/// Phase 3 stub: QLSAVerifier.sol validates proof format only.
/// Phase 3+ production: replace with Stwo Circle STARK on-chain verifier.
interface IQLSAVerifier {
    /// @notice Verify a STARK proof against a batch commitment.
    /// @param proof      Raw STARK proof bytes (Stwo serialization).
    /// @param commitment 8-byte batch commitment (encoding is verifier-version-specific):
    ///                   V2/V3: bytes 0–3 = M31 field element (LE uint32, value < 2^31−1),
    ///                          bytes 4–7 = zero padding
    ///                   Full:  bytes 0–7 = Blake2s(proof[0:32])[0:8]
    /// @return valid     True if the proof is accepted.
    function verify(
        bytes calldata proof,
        bytes8 commitment
    ) external view returns (bool valid);
}
