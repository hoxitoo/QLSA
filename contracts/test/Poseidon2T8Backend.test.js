const { expect } = require("chai");
const { ethers } = require("hardhat");

// Reference vectors frozen in stark_stwo/src/vfri2_bridge.rs
// (tests_vfri8::test_p2t8_reference_vectors + test_p2t8_print_reference_vectors).
const LEAF_1234 = [1073120416n, 1930841549n, 67141568n, 840805313n];   // hash_leaf_cols_p2t8([1,2,3,4])
const PAIR = [890515421n, 531626735n, 2060583819n, 1311645369n];       // hash_pair_p2t8(node[1..4],node[5..8])
const QUERIES_R11 = [436n, 378n, 839n, 927n];                          // mixRoot(0x11..).drawQueries(10,4)
const QUERIES_W_NODE1234 = [301n, 134n, 1008n, 447n];                  // mixRootW(node[1..4]).drawQueries(10,4)
const SECURE_FELT_123 = 133164500022319262877528816935901679472n;     // mixU32s([1,2,3]).drawSecureFelt

// Pack four M31 words into the wide t=8 node: uint256(node) = (w0<<96)|(w1<<64)|(w2<<32)|w3.
function node(w0, w1, w2, w3) {
  const v = (BigInt(w0) << 96n) | (BigInt(w1) << 64n) | (BigInt(w2) << 32n) | BigInt(w3);
  return "0x" + v.toString(16).padStart(64, "0");
}

describe("Poseidon2T8Backend (t=8 hash backend)", function () {
  let h;

  before(async () => {
    const Factory = await ethers.getContractFactory("Poseidon2T8BackendHarness");
    h = await Factory.deploy();
  });

  describe("Poseidon2MerkleVerifierT8 — Rust cross-check", function () {
    it("hashLeaf([1,2,3,4]) matches hash_leaf_cols_p2t8", async () => {
      const leaf = await h.hashLeaf([1, 2, 3, 4]);
      expect(leaf).to.equal(node(...LEAF_1234));
    });

    it("hashLeaf content lives in bytes[16..32] (16 leading zero bytes)", async () => {
      const leaf = await h.hashLeaf([1, 2, 3, 4]);
      expect(leaf.slice(2, 34)).to.equal("0".repeat(32));
    });

    it("hashPair(node[1..4],node[5..8]) matches hash_pair_p2t8 (== compress_t8)", async () => {
      const out = await h.hashPair(node(1, 2, 3, 4), node(5, 6, 7, 8));
      expect(out).to.equal(node(...PAIR));
    });

    it("hashPair is order-sensitive", async () => {
      const ab = await h.hashPair(node(1, 2, 3, 4), node(5, 6, 7, 8));
      const ba = await h.hashPair(node(5, 6, 7, 8), node(1, 2, 3, 4));
      expect(ab).to.not.equal(ba);
    });

    it("hashPair diffuses a single-word change", async () => {
      const sib = node(5, 5, 5, 5);
      const a = await h.hashPair(node(1, 2, 3, 7), sib);
      const b = await h.hashPair(node(2, 2, 3, 7), sib); // differ only in w0
      expect(a).to.not.equal(b);
    });

    it("verifies a depth-2 Merkle inclusion proof end-to-end", async () => {
      const leaves = [];
      for (let j = 0; j < 4; j++) {
        leaves.push(await h.hashLeaf([j, j + 1, j + 2]));
      }
      const n01 = await h.hashPair(leaves[0], leaves[1]);
      const n23 = await h.hashPair(leaves[2], leaves[3]);
      const root = await h.hashPair(n01, n23);

      const ok = await h.verify(root, leaves[1], 1, 2, [leaves[0], n23]);
      expect(ok).to.equal(true);

      const bad = await h.verify(root, leaves[1], 2, 2, [leaves[0], n23]);
      expect(bad).to.equal(false);
    });

    it("rejects a proof whose sibling length != depth", async () => {
      const leaf = await h.hashLeaf([1, 2, 3]);
      const ok = await h.verify(node(1, 2, 3, 4), leaf, 0, 2, [node(3, 4, 5, 6)]);
      expect(ok).to.equal(false);
    });
  });

  describe("Poseidon2ChannelT8 — Rust cross-check", function () {
    it("mixRoot(0x11..).drawQueries(10,4) matches P2T8Channel", async () => {
      const root = "0x" + "11".repeat(32);
      const q = await h.mixRootDrawQueries(root, 10, 4);
      expect(q.map(BigInt)).to.deep.equal(QUERIES_R11);
    });

    it("mixRootW(node[1..4]).drawQueries(10,4) matches P2T8Channel", async () => {
      const q = await h.mixRootWDrawQueries(node(1, 2, 3, 4), 10, 4);
      expect(q.map(BigInt)).to.deep.equal(QUERIES_W_NODE1234);
    });

    it("mixU32s([1,2,3]).drawSecureFelt matches P2T8Channel", async () => {
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
      const base = "0xaa" + "00".repeat(31);
      const alt = "0xbb" + "00".repeat(31);
      const full1 = await h.mixRootFullDrawQueries(base, 8, 4);
      const full2 = await h.mixRootFullDrawQueries(alt, 8, 4);
      expect(full1.map(BigInt)).to.not.deep.equal(full2.map(BigInt));

      const lo1 = await h.mixRootDrawQueries(base, 8, 4);
      const lo2 = await h.mixRootDrawQueries(alt, 8, 4);
      expect(lo1.map(BigInt)).to.deep.equal(lo2.map(BigInt));
    });
  });
});
