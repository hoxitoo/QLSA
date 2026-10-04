// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../verifier/Poseidon2M31.sol";

/// @dev Thin wrapper that exposes Poseidon2M31 library functions for testing.
contract Poseidon2M31Harness {
    function permute(uint256 s0, uint256 s1)
        external pure returns (uint256, uint256)
    {
        return Poseidon2M31.permute(s0, s1);
    }

    function compress(uint256 left, uint256 right)
        external pure returns (uint256)
    {
        return Poseidon2M31.compress(left, right);
    }

    function sponge(uint256[] calldata values)
        external pure returns (uint256, uint256)
    {
        return Poseidon2M31.sponge(values);
    }
}
