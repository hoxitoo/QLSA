// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../verifier/Poseidon2M31T16.sol";

/// @dev Thin wrapper exposing Poseidon2M31T16 for cross-checking and gas measurement.
contract Poseidon2M31T16Harness {
    function permute(uint256[16] calldata s) external pure returns (uint256[16] memory) {
        uint256[16] memory m;
        for (uint256 i = 0; i < 16; i++) {
            m[i] = s[i];
        }
        return Poseidon2M31T16.permute(m);
    }

    function compress(uint256[8] calldata left, uint256[8] calldata right)
        external pure returns (uint256[8] memory)
    {
        uint256[8] memory l;
        uint256[8] memory r;
        for (uint256 i = 0; i < 8; i++) { l[i] = left[i]; r[i] = right[i]; }
        return Poseidon2M31T16.compress8(l, r);
    }

    /// @dev Apply the permutation `n` times. Measuring gas at n and n+1 and
    ///      subtracting gives the MARGINAL cost of one permutation, with the
    ///      21,000 transaction base and the calldata cost cancelling out. A
    ///      single-call measurement charges that shared base to both widths and
    ///      so understates the ratio between them.
    function permuteN(uint256[16] calldata s, uint256 n)
        external pure returns (uint256[16] memory m)
    {
        for (uint256 i = 0; i < 16; i++) {
            m[i] = s[i];
        }
        for (uint256 k = 0; k < n; k++) {
            m = Poseidon2M31T16.permute(m);
        }
    }
}
