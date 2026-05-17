// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Test helper — NOT for deployment.
import "../verifier/CM31.sol";

contract CM31Harness {
    function add(uint64 x, uint64 y) external pure returns (uint64) { return CM31.add(x, y); }
    function sub(uint64 x, uint64 y) external pure returns (uint64) { return CM31.sub(x, y); }
    function mul(uint64 x, uint64 y) external pure returns (uint64) { return CM31.mul(x, y); }
    function neg(uint64 x)           external pure returns (uint64) { return CM31.neg(x); }
    function inv(uint64 x)           external pure returns (uint64) { return CM31.inv(x); }
    function conj(uint64 x)          external pure returns (uint64) { return CM31.conj(x); }
    function scale(uint64 x, uint256 s) external pure returns (uint64) { return CM31.scale(x, s); }

    function pack(uint256 a, uint256 b) external pure returns (uint64)  { return CM31.pack(a, b); }
    function re(uint64 x)              external pure returns (uint256)  { return CM31.re(x); }
    function im(uint64 x)              external pure returns (uint256)  { return CM31.im(x); }
    function fromM31(uint256 a)        external pure returns (uint64)   { return CM31.fromM31(a); }
    function isValid(uint64 x)         external pure returns (bool)     { return CM31.isValid(x); }

    function fromBytes8LE(bytes calldata data, uint256 offset) external pure returns (uint64) {
        return CM31.fromBytes8LE(data, offset);
    }

    function P() external pure returns (uint256) { return CM31.P; }
}
