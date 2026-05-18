// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Test helper — NOT for deployment.
import "../verifier/CirclePoint.sol";
import "../verifier/M31.sol";

contract CirclePointHarness {

    function isOnCircle(uint256 x, uint256 y) external pure returns (bool) {
        return CirclePoint.isOnCircle(x, y);
    }

    function pointAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2)
        external pure returns (uint256 rx, uint256 ry)
    {
        return CirclePoint.pointAdd(x1, y1, x2, y2);
    }

    function pointDouble(uint256 x, uint256 y)
        external pure returns (uint256 rx, uint256 ry)
    {
        return CirclePoint.pointDouble(x, y);
    }

    function genMul(uint256 scalar)
        external pure returns (uint256 rx, uint256 ry)
    {
        return CirclePoint.genMul(scalar);
    }

    function cosetAt(uint256 logN, uint256 idx)
        external pure returns (uint256 x, uint256 y)
    {
        return CirclePoint.cosetAt(logN, idx);
    }

    function circleFold(uint128 fPlus, uint128 fMinus, uint128 alpha, uint256 yInv)
        external pure returns (uint128)
    {
        return CirclePoint.circleFold(fPlus, fMinus, alpha, yInv);
    }

    function lineFold(uint128 fPlus, uint128 fMinus, uint128 alpha, uint256 xInv)
        external pure returns (uint128)
    {
        return CirclePoint.lineFold(fPlus, fMinus, alpha, xInv);
    }

    // Convenience: compute p.y for cosetAt(logN, idx), then M31.inv(p.y)
    function cosetYInv(uint256 logN, uint256 idx) external pure returns (uint256) {
        (, uint256 py) = CirclePoint.cosetAt(logN, idx);
        return M31.inv(py);
    }
}
