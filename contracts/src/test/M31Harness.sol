// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Test helper — NOT for deployment.
import "../verifier/M31.sol";

contract M31Harness {
    function add(uint256 a, uint256 b) external pure returns (uint256) { return M31.add(a, b); }
    function sub(uint256 a, uint256 b) external pure returns (uint256) { return M31.sub(a, b); }
    function mul(uint256 a, uint256 b) external pure returns (uint256) { return M31.mul(a, b); }
    function mpow(uint256 base, uint256 exp) external pure returns (uint256) { return M31.pow(base, exp); }
    function inv(uint256 a) external pure returns (uint256) { return M31.inv(a); }
    function neg(uint256 a) external pure returns (uint256) { return M31.neg(a); }
    function isValid(uint256 a) external pure returns (bool) { return M31.isValid(a); }
    function fromBytes4LE(bytes4 b) external pure returns (uint256) { return M31.fromBytes4LE(b); }
    function toBytes4LE(uint256 a) external pure returns (bytes4) { return M31.toBytes4LE(a); }
    function P() external pure returns (uint256) { return M31.P; }
}
