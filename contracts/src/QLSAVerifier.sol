// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifier.sol";

/// @title QLSAVerifier — Phase 3 stub
/// @notice Validates STARK proof format (length + non-zero commitment).
///
/// WARNING: This is a PROTOTYPE verifier. It does NOT cryptographically verify
/// the Winterfell STARK proof. Full on-chain verification requires porting the
/// FRI + STARK verification logic to Solidity, which is planned via the Stwo
/// Circle STARK verifier in Phase 3+.
///
/// Replace this contract with the Stwo on-chain verifier before mainnet deployment.
contract QLSAVerifier is IQLSAVerifier {
    /// @notice Minimum acceptable proof byte length (Winterfell serialised proofs
    ///         are typically 90–200 KB; 64 bytes is a sanity floor only).
    uint256 public constant MIN_PROOF_LENGTH = 64;

    /// @inheritdoc IQLSAVerifier
    function verify(
        bytes calldata proof,
        bytes8 commitment
    ) external pure override returns (bool) {
        if (commitment == bytes8(0)) return false;
        if (proof.length < MIN_PROOF_LENGTH) return false;
        return true;
    }
}
