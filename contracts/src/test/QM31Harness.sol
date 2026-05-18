// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Test helper — NOT for deployment.
import "../verifier/QM31.sol";

contract QM31Harness {
    function add(uint128 x, uint128 y) external pure returns (uint128) { return QM31.add(x, y); }
    function sub(uint128 x, uint128 y) external pure returns (uint128) { return QM31.sub(x, y); }
    function mul(uint128 x, uint128 y) external pure returns (uint128) { return QM31.mul(x, y); }
    function neg(uint128 x)            external pure returns (uint128) { return QM31.neg(x); }
    function inv(uint128 x)            external pure returns (uint128) { return QM31.inv(x); }
    function scaleM31(uint128 x, uint256 s) external pure returns (uint128) { return QM31.scaleM31(x, s); }
    function scaleCM31(uint128 x, uint64 s) external pure returns (uint128) { return QM31.scaleCM31(x, s); }

    function pack(uint64 _c0, uint64 _c1) external pure returns (uint128) { return QM31.pack(_c0, _c1); }
    function c0(uint128 q)                external pure returns (uint64)  { return QM31.c0(q); }
    function c1(uint128 q)                external pure returns (uint64)  { return QM31.c1(q); }
    function fromCM31(uint64 e)           external pure returns (uint128) { return QM31.fromCM31(e); }
    function fromM31(uint256 a)           external pure returns (uint128) { return QM31.fromM31(a); }
    function isValid(uint128 x)           external pure returns (bool)    { return QM31.isValid(x); }

    function friLinearFold(uint256 fPlus, uint256 fMinus, uint128 alpha)
        external pure returns (uint128) { return QM31.friLinearFold(fPlus, fMinus, alpha); }

    function fromBytes16LE(bytes calldata data, uint256 offset) external pure returns (uint128) {
        return QM31.fromBytes16LE(data, offset);
    }

    function R() external pure returns (uint64) { return QM31.R; }
}
