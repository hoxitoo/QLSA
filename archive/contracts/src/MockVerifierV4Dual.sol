// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../IQLSAVerifierV4.sol";
import "../verifier/Blake2s.sol";

/// @notice Test verifier for BatchRegistryV4.
/// Performs commitment-binding check (Blake2s(proof[:32] ‖ merkleRoot)[:16]).
/// Matches the behaviour of MockVerifierV4 but is a separate deployable contract
/// so that BatchRegistryV4 tests can swap verifiers in setVerifier() tests.
///
/// The IQLSAVerifierV4 interface declares verify() as `pure`, so no state is read
/// here.  To test the "second call fails" scenario, use SentinelVerifier (below)
/// as the verifier and pass a sentinel commitment as commitmentLog8.
contract MockVerifierV4Dual is IQLSAVerifierV4 {

    uint256 public constant MIN_PROOF_LENGTH = 700;

    function verify(
        bytes calldata proof,
        bytes16 commitment,
        bytes32 merkleRoot,
        bytes calldata /* queryHints */
    ) external pure override returns (bool) {
        if (proof.length < MIN_PROOF_LENGTH) return false;
        if (commitment == bytes16(0)) return false;
        if (merkleRoot == bytes32(0)) return false;

        bytes memory hInput = new bytes(64);
        assembly ("memory-safe") { calldatacopy(add(hInput, 32), proof.offset, 32) }
        for (uint256 i = 0; i < 32; i++) hInput[32 + i] = merkleRoot[i];
        bytes32 h = Blake2s.hash(hInput);
        return bytes16(h) == commitment;
    }
}

/// @notice Verifier that rejects a hardcoded sentinel commitment value and
/// accepts all others via commitment-binding check.
///
/// SENTINEL = 0xdeadbeefdeadbeef0000000000000000
///
/// Use this as the registry verifier and pass SENTINEL as commitmentLog8 to
/// trigger Log8ProofInvalid while commitmentLog10 (a real binding value) passes.
/// Both verify() calls are pure (no storage reads).
contract SentinelVerifier is IQLSAVerifierV4 {

    uint256 public constant MIN_PROOF_LENGTH = 700;

    /// @dev Hardcoded sentinel — any call with this commitment returns false.
    bytes16 public constant SENTINEL = 0xdeadbeefdeadbeef0000000000000000;

    function verify(
        bytes calldata proof,
        bytes16 commitment,
        bytes32 merkleRoot,
        bytes calldata /* queryHints */
    ) external pure override returns (bool) {
        // Reject the sentinel commitment.
        if (commitment == SENTINEL) return false;

        if (proof.length < MIN_PROOF_LENGTH) return false;
        if (commitment == bytes16(0)) return false;
        if (merkleRoot == bytes32(0)) return false;

        bytes memory hInput = new bytes(64);
        assembly ("memory-safe") { calldatacopy(add(hInput, 32), proof.offset, 32) }
        for (uint256 i = 0; i < 32; i++) hInput[32 + i] = merkleRoot[i];
        bytes32 h = Blake2s.hash(hInput);
        return bytes16(h) == commitment;
    }
}

/// @notice Always-false verifier — every verify() call returns false.
contract AlwaysFalseVerifier is IQLSAVerifierV4 {
    function verify(
        bytes calldata,
        bytes16,
        bytes32,
        bytes calldata
    ) external pure override returns (bool) {
        return false;
    }
}
