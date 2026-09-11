// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Test helper — NOT for deployment.
import "../verifier/TwoChannel.sol";

contract TwoChannelHarness {

    function init() external pure returns (bytes32 digest, uint32 nDraws) {
        TwoChannel.State memory s = TwoChannel.init();
        return (s.digest, s.nDraws);
    }

    function mixRoot(
        bytes32 digest,
        uint32  nDraws,
        bytes32 root
    ) external pure returns (bytes32 outDigest, uint32 outDraws) {
        TwoChannel.State memory s = TwoChannel.State(digest, nDraws);
        TwoChannel.mixRoot(s, root);
        return (s.digest, s.nDraws);
    }

    function mixU32s(
        bytes32   digest,
        uint32    nDraws,
        uint32[]  calldata words
    ) external pure returns (bytes32 outDigest, uint32 outDraws) {
        TwoChannel.State memory s = TwoChannel.State(digest, nDraws);
        uint32[] memory w = new uint32[](words.length);
        for (uint256 i = 0; i < words.length; i++) w[i] = words[i];
        TwoChannel.mixU32s(s, w);
        return (s.digest, s.nDraws);
    }

    function drawU32sRaw(
        bytes32 digest,
        uint32  nDraws
    ) external pure returns (bytes32 raw, uint32 outDraws) {
        TwoChannel.State memory s = TwoChannel.State(digest, nDraws);
        raw = TwoChannel.drawU32sRaw(s);
        return (raw, s.nDraws);
    }

    function drawSecureFelt(
        bytes32 digest,
        uint32  nDraws
    ) external pure returns (uint128 felt, uint32 outDraws) {
        TwoChannel.State memory s = TwoChannel.State(digest, nDraws);
        felt = TwoChannel.drawSecureFelt(s);
        return (felt, s.nDraws);
    }

    function drawQueries(
        bytes32 digest,
        uint32  nDraws,
        uint256 logDomainSize,
        uint256 nQueries
    ) external pure returns (uint256[] memory queries, uint32 outDraws) {
        TwoChannel.State memory s = TwoChannel.State(digest, nDraws);
        queries = TwoChannel.drawQueries(s, logDomainSize, nQueries);
        return (queries, s.nDraws);
    }
}
