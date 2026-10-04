// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../IQLSAVerifierV4.sol";
import "../verifier/Blake2s.sol";

/// @notice Test verifier implementing IQLSAVerifierV4.
/// Checks commitment binding only (same as QLSAVerifierBound extended with hints param).
/// Does NOT validate queryHints — purely for BatchRegistryV3 logic tests.
contract MockVerifierV4 is IQLSAVerifierV4 {

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
