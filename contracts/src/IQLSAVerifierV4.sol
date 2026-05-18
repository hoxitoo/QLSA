// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IQLSAVerifierV4 — Verifier interface with ABI-encoded query hints.
///
/// Extends IQLSAVerifierV2 by adding a `queryHints` parameter that carries
/// off-chain witness data (Merkle siblings, FRI fold inputs, circle domain
/// points).  The verifier uses hints to check Merkle inclusion and circle
/// FRI fold correctness on-chain without re-executing the full proof.
///
/// `queryHints` is ABI-encoded and version-specific.  QLSAVerifierV4 encodes
/// a single QueryHints struct; QLSAVerifierV5 encodes QueryHints[].
interface IQLSAVerifierV4 {
    /// @notice Verify a STARK proof with on-chain query hints.
    /// @param proof        Full serialized STARK proof bytes.
    /// @param commitment   16-byte (128-bit) Blake2s commitment.
    /// @param merkleRoot   Batch Merkle root this proof covers.
    /// @param queryHints   ABI-encoded query hint(s) — format is verifier-specific.
    /// @return True if the proof and all hints are valid.
    function verify(
        bytes calldata proof,
        bytes16        commitment,
        bytes32        merkleRoot,
        bytes calldata queryHints
    ) external pure returns (bool);
}
