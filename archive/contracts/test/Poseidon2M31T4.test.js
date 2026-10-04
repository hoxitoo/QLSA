const { expect } = require("chai");
const { ethers } = require("hardhat");

const P = 2n ** 31n - 1n;

// Reference vectors frozen in stark_stwo/src/poseidon2_t4.rs::test_reference_vectors.
const VEC_ZERO = [201095161n, 440871427n, 944955487n, 992273343n];
const VEC_SEQ = [1706601437n, 1471208702n, 244698605n, 2091016348n];
const VEC_SPONGE_1_8 = [1315656215n, 594434174n];
const VEC_COMPRESS = [1706601437n, 1471208702n];

describe("Poseidon2M31T4", function () {
  let h;

  before(async () => {
    const Factory = await ethers.getContractFactory("Poseidon2M31T4Harness");
    h = await Factory.deploy();
  });

  describe("permute — Rust cross-check vectors", function () {
    it("permute(0,0,0,0) matches poseidon2_t4.rs", async () => {
      const out = await h.permute(0, 0, 0, 0);
      expect(out.map(BigInt)).to.deep.equal(VEC_ZERO);
    });

    it("permute(1,2,3,4) matches poseidon2_t4.rs", async () => {
      const out = await h.permute(1, 2, 3, 4);
      expect(out.map(BigInt)).to.deep.equal(VEC_SEQ);
    });

    it("outputs are in M31 field range", async () => {
      const out = await h.permute(P - 1n, P - 1n, P - 1n, P - 1n);
      for (const v of out.map(BigInt)) {
        expect(v).to.be.lessThan(P);
      }
    });

    it("is deterministic", async () => {
      const a = await h.permute(42, 7, 99, 3);
      const b = await h.permute(42, 7, 99, 3);
      expect(a.map(BigInt)).to.deep.equal(b.map(BigInt));
    });

    it("single-cell input change diffuses to every output cell", async () => {
      const a = (await h.permute(1, 2, 3, 4)).map(BigInt);
      const b = (await h.permute(1, 2, 3, 5)).map(BigInt);
      for (let i = 0; i < 4; i++) {
        expect(a[i]).to.not.equal(b[i]);
      }
    });
  });

  describe("compress — wide node hash", function () {
    it("compress([1,2],[3,4]) matches poseidon2_t4.rs", async () => {
      const out = await h.compress(1, 2, 3, 4);
      expect(out.map(BigInt)).to.deep.equal(VEC_COMPRESS);
    });

    it("is order-sensitive (left/right swap changes output)", async () => {
      const a = (await h.compress(11, 22, 33, 44)).map(BigInt);
      const b = (await h.compress(33, 44, 11, 22)).map(BigInt);
      expect(a).to.not.deep.equal(b);
    });
  });

  describe("sponge — rate-2 capacity-2", function () {
    it("sponge([1..8]) matches poseidon2_t4.rs", async () => {
      const out = await h.sponge([1, 2, 3, 4, 5, 6, 7, 8]);
      expect(out.map(BigInt)).to.deep.equal(VEC_SPONGE_1_8);
    });

    it("empty input returns the zero state untouched", async () => {
      const out = await h.sponge([]);
      expect(out.map(BigInt)).to.deep.equal([0n, 0n]);
    });

    it("odd-length padding is distinct from any 4th-word completion", async () => {
      // The capacity-cell flag means [1,2,3] cannot collide with [1,2,3,x].
      const padded = (await h.sponge([1, 2, 3])).map(BigInt);
      const completed1 = (await h.sponge([1, 2, 3, 1])).map(BigInt);
      const completed0 = (await h.sponge([1, 2, 3, 0])).map(BigInt);
      expect(padded).to.not.deep.equal(completed1);
      expect(padded).to.not.deep.equal(completed0);
    });

    it("different inputs give different digests", async () => {
      const a = (await h.sponge([1, 2, 3, 4, 5, 6, 7, 8])).map(BigInt);
      const b = (await h.sponge([1, 2, 3, 4, 5, 6, 7, 9])).map(BigInt);
      expect(a).to.not.deep.equal(b);
    });
  });

  // Frozen Rust vectors for both tail parities (mirrors
  // stark_stwo poseidon2_t4.rs::sponge_length_vectors).  The other cross-check
  // covers only n = 8, an exact multiple of the rate, so without these the
  // odd-tail branch (absorb rem[0] into s0, then s3 += 1) is pinned on neither side.
  describe("sponge — every tail parity (Rust cross-check)", () => {
    const SPONGE_1_TO_8 = [
      [1820522999n, 34679397n],
      [524555141n, 137084408n],
      [1862243750n, 449482630n],
      [188265029n, 348838750n],
      [1491877616n, 716646245n],
      [1527875717n, 302206499n],
      [1714831849n, 1861755525n],
      [1315656215n, 594434174n],
    ];

    it("matches Rust sponge_t4 for n = 1..8", async () => {
      for (let n = 1; n <= 8; n++) {
        const vals = Array.from({ length: n }, (_, i) => i + 1);
        const out = await h.sponge(vals);
        expect([BigInt(out[0]), BigInt(out[1])], `length ${n}`)
          .to.deep.equal(SPONGE_1_TO_8[n - 1]);
      }
    });
  });
});
