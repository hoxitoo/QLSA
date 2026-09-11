// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../verifier/Poseidon2M31T4.sol";

/// @dev Thin wrapper that exposes Poseidon2M31T4 library functions for testing.
contract Poseidon2M31T4Harness {
    function permute(uint256 s0, uint256 s1, uint256 s2, uint256 s3)
        external pure returns (uint256, uint256, uint256, uint256)
    {
        return Poseidon2M31T4.permute(s0, s1, s2, s3);
    }

    function compress(uint256 l0, uint256 l1, uint256 r0, uint256 r1)
        external pure returns (uint256, uint256)
    {
        return Poseidon2M31T4.compress(l0, l1, r0, r1);
    }

    function sponge(uint256[] calldata values)
        external pure returns (uint256, uint256)
    {
        return Poseidon2M31T4.sponge(values);
    }
}
