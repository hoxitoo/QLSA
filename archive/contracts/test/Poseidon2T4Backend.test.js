const { expect } = require("chai");
const { ethers } = require("hardhat");

// Reference vectors frozen in stark_stwo/src/vfri2_bridge.rs
// (tests_vfri8::test_p2t4_reference_vectors + test_p2t4_print_reference_vectors).
const LEAF_1234 = [188265029n, 348838750n];          // hash_leaf_cols_p2t4([1,2,3,4])
const PAIR_12_34 = [1706601437n, 1471208702n];       // hash_pair_p2t4([1,2],[3,4])
const QUERIES_R11 = [674n, 500n, 407n, 375n];        // mixRoot(0x11..).drawQueries(10,4)
const SECURE_FELT_123 = 61579212343548856246129823755073713120n; // mixU32s([1,2,3]).drawSecureFelt

// Pack two M31 words into the wide-node bytes32: uint256(node) = (s0 << 32) | s1.
function node(s0, s1) {
  return "0x" + ((BigInt(s0) << 32n) | BigInt(s1)).toString(16).padStart(64, "0");
}

describe("Poseidon2T4Backend (VFRI10 hash backend)", function () {
  let h;

  before(async () => {
    const Factory = await ethers.getContractFactory("Poseidon2T4BackendHarness");
    h = await Factory.deploy();
  });

  describe("Poseidon2MerkleVerifierT4 — Rust cross-check", function () {
    it("hashLeaf([1,2,3,4]) matches hash_leaf_cols_p2t4", async () => {
      const leaf = await h.hashLeaf([1, 2, 3, 4]);
      expect(leaf).to.equal(node(LEAF_1234[0], LEAF_1234[1]));
    });

    it("hashLeaf content lives in the low 8 bytes (24 leading zero bytes)", async () => {
      const leaf = await h.hashLeaf([1, 2, 3, 4]);
      expect(leaf.slice(2, 50)).to.equal("0".repeat(48));
    });

    it("hashPair((1,2),(3,4)) matches hash_pair_p2t4 (== compress_t4)", async () => {
      const out = await h.hashPair(node(1, 2), node(3, 4));
      expect(out).to.equal(node(PAIR_12_34[0], PAIR_12_34[1]));
    });

    it("hashPair is order-sensitive", async () => {
      const ab = await h.hashPair(node(1, 2), node(3, 4));
      const ba = await h.hashPair(node(3, 4), node(1, 2));
      expect(ab).to.not.equal(ba);
    });

    it("hashPair uses BOTH node words (high-word change diffuses)", async () => {
      const sib = node(5, 5);
      const a = await h.hashPair(node(1, 7), sib);
      const b = await h.hashPair(node(2, 7), sib); // differ only in s0
      expect(a).to.not.equal(b);
    });

    it("verifies a depth-2 Merkle inclusion proof end-to-end", async () => {
      // Build a 4-leaf tree in JS using the on-chain hash primitives.
      const leaves = [];
      for (let j = 0; j < 4; j++) {
        leaves.push(await h.hashLeaf([j, j + 1, j + 2]));
      }
      const n01 = await h.hashPair(leaves[0], leaves[1]);
      const n23 = await h.hashPair(leaves[2], leaves[3]);
      const root = await h.hashPair(n01, n23);

      // Inclusion proof for leaf index 1: siblings = [leaf0, node23].
      const ok = await h.verify(root, leaves[1], 1, 2, [leaves[0], n23]);
      expect(ok).to.equal(true);

      // Wrong index must fail.
      const bad = await h.verify(root, leaves[1], 2, 2, [leaves[0], n23]);
      expect(bad).to.equal(false);
    });

    it("rejects a proof whose sibling length != depth", async () => {
      const leaf = await h.hashLeaf([1, 2, 3]);
      const ok = await h.verify(node(1, 2), leaf, 0, 2, [node(3, 4)]);
      expect(ok).to.equal(false);
    });
  });

  describe("Poseidon2ChannelT4 — Rust cross-check", function () {
    it("mixRoot(0x11..).drawQueries(10,4) matches P2T4Channel", async () => {
      const root = "0x" + "11".repeat(32);
      const q = await h.mixRootDrawQueries(root, 10, 4);
      expect(q.map(BigInt)).to.deep.equal(QUERIES_R11);
    });

    it("mixU32s([1,2,3]).drawSecureFelt matches P2T4Channel", async () => {
      const felt = await h.mixU32sDrawSecureFelt([1, 2, 3]);
      expect(BigInt(felt)).to.equal(SECURE_FELT_123);
    });

    it("query indices stay within the domain", async () => {
      const root = "0x" + "11".repeat(32);
      const q = await h.mixRootDrawQueries(root, 8, 16);
      for (const v of q.map(BigInt)) {
        expect(v).to.be.lessThan(1n << 8n);
      }
    });

    it("different roots give different query streams", async () => {
      const a = await h.mixRootDrawQueries("0x" + "11".repeat(32), 10, 8);
      const b = await h.mixRootDrawQueries("0x" + "12".repeat(32), 10, 8);
      expect(a.map(BigInt)).to.not.deep.equal(b.map(BigInt));
    });

    it("mixRootFull binds high bytes that mixRoot ignores", async () => {
      // Roots differing only in the HIGH byte (bytes[0]).
      const base = "0xaa" + "00".repeat(31);
      const alt = "0xbb" + "00".repeat(31);
      const full1 = await h.mixRootFullDrawQueries(base, 8, 4);
      const full2 = await h.mixRootFullDrawQueries(alt, 8, 4);
      expect(full1.map(BigInt)).to.not.deep.equal(full2.map(BigInt));

      // mixRoot only reads bytes[28..32] → the high-byte change is invisible.
      const lo1 = await h.mixRootDrawQueries(base, 8, 4);
      const lo2 = await h.mixRootDrawQueries(alt, 8, 4);
      expect(lo1.map(BigInt)).to.deep.equal(lo2.map(BigInt));
    });
  });
});
