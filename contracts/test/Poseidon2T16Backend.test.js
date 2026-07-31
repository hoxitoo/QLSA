const { expect } = require("chai");
const { ethers } = require("hardhat");

// Reference vectors frozen in stark_stwo/src/vfri2_bridge.rs
// (tests_vfri8::test_p2t16_reference_vectors + test_p2t16_print_reference_vectors).
const LEAF_1234 = [
  55566406n, 1875114541n, 1126231753n, 1747661633n,
  1062235343n, 1908581748n, 1128601005n, 1541813924n,
]; // hash_leaf_cols_p2t16([1,2,3,4])
const PAIR = [
  1896676506n, 1113082531n, 1826142252n, 1263581674n,
  694653155n, 1856461508n, 173489390n, 625083048n,
]; // hash_pair_p2t16(node[1..8], node[9..16])
const QUERIES_R11 = [821n, 259n, 182n, 183n];          // mixRoot(0x11..).drawQueries(10,4)
const QUERIES_W_NODE = [362n, 455n, 247n, 671n];       // mixRootW(node[1..8]).drawQueries(10,4)
const SECURE_FELT_123 = 1407887379921827972915931489114976420n; // mixU32s([1,2,3]).drawSecureFelt

// Pack eight M31 words into a t=16 node: word k at bytes[4k..4k+4], big-endian.
// Unlike t=8 (bytes[16..32]) and t=4 (bytes[24..32]) this fills the whole word.
function node(...w) {
  let v = 0n;
  for (let k = 0; k < 8; k++) v |= BigInt(w[k]) << BigInt(224 - 32 * k);
  return "0x" + v.toString(16).padStart(64, "0");
}

const N_1_8 = node(1, 2, 3, 4, 5, 6, 7, 8);
const N_9_16 = node(9, 10, 11, 12, 13, 14, 15, 16);

describe("Poseidon2T16Backend (t=16 hash backend — 128-bit nodes)", function () {
  let h, h8;

  before(async () => {
    h = await (await ethers.getContractFactory("Poseidon2T16BackendHarness")).deploy();
    h8 = await (await ethers.getContractFactory("Poseidon2T8BackendHarness")).deploy();
  });

  describe("Poseidon2MerkleVerifierT16 — Rust cross-check", function () {
    it("hashLeaf([1,2,3,4]) matches hash_leaf_cols_p2t16", async () => {
      expect(await h.hashLeaf([1, 2, 3, 4])).to.equal(node(...LEAF_1234));
    });

    it("hashPair(node[1..8],node[9..16]) matches hash_pair_p2t16 (== compress_t16)", async () => {
      expect(await h.hashPair(N_1_8, N_9_16)).to.equal(node(...PAIR));
    });

    // The whole point of t=16: 8 M31 words is 248 bits in a full 32-byte word,
    // where t=8 leaves 16 leading zero bytes and t=4 leaves 24. Node collision
    // cost rises from ~2^62 to ~2^124.
    it("a node uses the full 32 bytes, unlike the narrower backends", async () => {
      const leaf16 = await h.hashLeaf([1, 2, 3, 4]);
      expect(leaf16.slice(2, 34)).to.not.equal("0".repeat(32));

      const leaf8 = await h8.hashLeaf([1, 2, 3, 4]);
      expect(leaf8.slice(2, 34)).to.equal("0".repeat(32), "t=8 content is bytes[16..32]");
      expect(leaf16).to.not.equal(leaf8);
    });

    it("hashLeaf distinguishes every word position", async () => {
      // A packing that dropped or aliased a word would still pass the frozen
      // vector above if the dropped word happened to be zero.
      const base = [1, 2, 3, 4, 5, 6, 7, 8];
      const seen = new Set([await h.hashLeaf(base)]);
      for (let k = 0; k < 8; k++) {
        const v = base.slice();
        v[k] += 1;
        const got = await h.hashLeaf(v);
        expect(seen.has(got)).to.equal(false, `word ${k} is not distinguished`);
        seen.add(got);
      }
    });

    it("hashLeaf separates a padded block from an exact one", async () => {
      // The odd-block domain flag in capacity cell 15 is what stops
      // [1,2] and [1,2,0,0,0,0,0,0] from colliding.
      const short = await h.hashLeaf([1, 2]);
      const padded = await h.hashLeaf([1, 2, 0, 0, 0, 0, 0, 0]);
      expect(short).to.not.equal(padded);
    });

    it("hashPair is order-sensitive", async () => {
      expect(await h.hashPair(N_1_8, N_9_16)).to.not.equal(await h.hashPair(N_9_16, N_1_8));
    });

    it("hashPair diffuses a single-word change", async () => {
      const sib = node(5, 5, 5, 5, 5, 5, 5, 5);
      const a = await h.hashPair(node(1, 2, 3, 7, 0, 0, 0, 0), sib);
      const b = await h.hashPair(node(2, 2, 3, 7, 0, 0, 0, 0), sib);
      expect(a).to.not.equal(b);
    });

    it("verifies a depth-2 Merkle inclusion proof end-to-end", async () => {
      const leaves = [];
      for (let j = 0; j < 4; j++) leaves.push(await h.hashLeaf([j, j + 1, j + 2]));
      const n01 = await h.hashPair(leaves[0], leaves[1]);
      const n23 = await h.hashPair(leaves[2], leaves[3]);
      const root = await h.hashPair(n01, n23);

      expect(await h.verify(root, leaves[1], 1, 2, [leaves[0], n23])).to.equal(true);
      // Same siblings, wrong index — the left/right order changes, so it fails.
      expect(await h.verify(root, leaves[1], 2, 2, [leaves[0], n23])).to.equal(false);
    });

    it("rejects a proof whose sibling length != depth", async () => {
      const leaf = await h.hashLeaf([1, 2, 3]);
      expect(await h.verify(N_1_8, leaf, 0, 2, [N_9_16])).to.equal(false);
    });
  });

  describe("Poseidon2ChannelT16 — Rust cross-check", function () {
    it("mixRoot(0x11..).drawQueries(10,4) matches P2T16Channel", async () => {
      const q = await h.mixRootDrawQueries("0x" + "11".repeat(32), 10, 4);
      expect(q.map(BigInt)).to.deep.equal(QUERIES_R11);
    });

    it("mixRootW(node[1..8]).drawQueries(10,4) matches P2T16Channel", async () => {
      const q = await h.mixRootWDrawQueries(N_1_8, 10, 4);
      expect(q.map(BigInt)).to.deep.equal(QUERIES_W_NODE);
    });

    it("mixU32s([1,2,3]).drawSecureFelt matches P2T16Channel", async () => {
      expect(BigInt(await h.mixU32sDrawSecureFelt([1, 2, 3]))).to.equal(SECURE_FELT_123);
    });

    // At t=16 a node IS the full 32 bytes, so these two absorb the same words.
    // Pinning it stops a later width change from silently diverging them here
    // while the Rust side keeps them equal (or the reverse).
    it("mixRootW and mixRootFull coincide at this width", async () => {
      const r = "0x" + "5a".repeat(32);
      const a = await h.mixRootWDrawQueries(r, 10, 4);
      const b = await h.mixRootFullDrawQueries(r, 10, 4);
      expect(a.map(BigInt)).to.deep.equal(b.map(BigInt));
    });

    it("query indices stay within the domain", async () => {
      const q = await h.mixRootDrawQueries("0x" + "11".repeat(32), 8, 16);
      for (const v of q.map(BigInt)) expect(v).to.be.lessThan(1n << 8n);
    });

    it("different roots give different query streams", async () => {
      const a = await h.mixRootDrawQueries("0x" + "11".repeat(32), 10, 8);
      const b = await h.mixRootDrawQueries("0x" + "12".repeat(32), 10, 8);
      expect(a.map(BigInt)).to.not.deep.equal(b.map(BigInt));
    });

    it("mixRootFull binds high bytes that mixRoot ignores", async () => {
      const base = "0xaa" + "00".repeat(31);
      const alt = "0xbb" + "00".repeat(31);
      expect((await h.mixRootFullDrawQueries(base, 8, 4)).map(BigInt))
        .to.not.deep.equal((await h.mixRootFullDrawQueries(alt, 8, 4)).map(BigInt));
      expect((await h.mixRootDrawQueries(base, 8, 4)).map(BigInt))
        .to.deep.equal((await h.mixRootDrawQueries(alt, 8, 4)).map(BigInt));
    });

    // A VFRI12 must not accept VFRI11 hints. Same transcript shape, different
    // permutation ⇒ different query indices, so the Merkle paths won't land.
    it("draws a different query stream than the t=8 channel", async () => {
      const r = "0x" + "11".repeat(32);
      const q16 = await h.mixRootFullDrawQueries(r, 10, 8);
      const q8 = await h8.mixRootFullDrawQueries(r, 10, 8);
      expect(q16.map(BigInt)).to.not.deep.equal(q8.map(BigInt));
    });
  });

  describe("[gas] cost of the wider backend", function () {
    it("compares hashPair and a depth-10 path against t=8", async () => {
      const pair16 = await h.hashPair.estimateGas(N_1_8, N_9_16);
      const pair8 = await h8.hashPair.estimateGas(
        "0x" + (((1n << 96n) | (2n << 64n) | (3n << 32n) | 4n).toString(16).padStart(64, "0")),
        "0x" + (((5n << 96n) | (6n << 64n) | (7n << 32n) | 8n).toString(16).padStart(64, "0"))
      );
      console.log(`        [gas] t8.hashPair  = ${pair8}`);
      console.log(`        [gas] t16.hashPair = ${pair16}`);
      console.log(`        [gas] ratio        = ${(Number(pair16) / Number(pair8)).toFixed(2)}x`);
      // Both figures include the shared 21,000 transaction base, so this ratio
      // is a LOWER BOUND on the true one — the base inflates the smaller number.
      // Poseidon2M31T16.test.js measures the marginal permutation cost properly
      // (3.04x); do not quote this number as the width ratio.
      expect(Number(pair16) / Number(pair8)).to.be.lessThan(2.5);
    });
  });
});
