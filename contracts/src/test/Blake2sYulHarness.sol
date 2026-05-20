// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../verifier/Blake2sYul.sol";

contract Blake2sYulHarness {
    function hash(bytes memory data) external pure returns (bytes32) {
        return Blake2sYul.hash(data);
    }
}
