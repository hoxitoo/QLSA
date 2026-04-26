// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Test helper — NOT for deployment.
import "../verifier/Blake2s.sol";

contract Blake2sHarness {
    function hash(bytes memory data) external pure returns (bytes32) {
        return Blake2s.hash(data);
    }
}
