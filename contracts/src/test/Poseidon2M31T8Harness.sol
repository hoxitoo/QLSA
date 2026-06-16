// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../verifier/Poseidon2M31T8.sol";

/// @dev Thin wrapper that exposes Poseidon2M31T8 library functions for testing.
contract Poseidon2M31T8Harness {
    function permute(uint256[8] calldata s) external pure returns (uint256[8] memory) {
        uint256[8] memory m;
        for (uint256 i = 0; i < 8; i++) {
            m[i] = s[i];
        }
        return Poseidon2M31T8.permute(m);
    }

    function compress(uint256[4] calldata left, uint256[4] calldata right)
        external pure returns (uint256[4] memory)
    {
        return Poseidon2M31T8.compress(left, right);
    }

    function sponge(uint256[] calldata values) external pure returns (uint256[4] memory) {
        return Poseidon2M31T8.sponge(values);
    }
}
