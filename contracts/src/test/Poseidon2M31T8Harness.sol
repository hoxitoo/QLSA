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

    /// @dev Apply the permutation `n` times. Measuring gas at n and n+1 and
    ///      subtracting gives the MARGINAL cost of one permutation, with the
    ///      21,000 transaction base and the calldata cost cancelling out. A
    ///      single-call measurement charges that shared base to both widths and
    ///      so understates the ratio between them.
    function permuteN(uint256[8] calldata s, uint256 n)
        external pure returns (uint256[8] memory m)
    {
        for (uint256 i = 0; i < 8; i++) {
            m[i] = s[i];
        }
        for (uint256 k = 0; k < n; k++) {
            m = Poseidon2M31T8.permute(m);
        }
    }
}
