const { expect } = require("chai");
const { ethers } = require("hardhat");

const P = 2n ** 31n - 1n;

// Reference vectors frozen in stark_stwo/src/poseidon2_t8.rs::test_reference_vectors.
const VEC_ZERO = [
  216312942n, 155820902n, 926495998n, 1144704772n,
  1934653642n, 1380128781n, 12500119n, 1030062085n,
];
const VEC_SEQ = [
  890515421n, 531626735n, 2060583819n, 1311645369n,
  1183191699n, 1798384804n, 1654039744n, 1303745775n,
];
const VEC_SPONGE_1_8 = [1440998077n, 1368105497n, 587877558n, 669993876n];
const VEC_COMPRESS = [890515421n, 531626735n, 2060583819n, 1311645369n];

describe("Poseidon2M31T8", function () {
  let h;

  before(async () => {
    const Factory = await ethers.getContractFactory("Poseidon2M31T8Harness");
    h = await Factory.deploy();
  });

  describe("permute — Rust cross-check vectors", function () {
    it("permute([0;8]) matches poseidon2_t8.rs", async () => {
      const out = await h.permute([0, 0, 0, 0, 0, 0, 0, 0]);
      expect(out.map(BigInt)).to.deep.equal(VEC_ZERO);
    });

    it("permute([1..8]) matches poseidon2_t8.rs", async () => {
      const out = await h.permute([1, 2, 3, 4, 5, 6, 7, 8]);
      expect(out.map(BigInt)).to.deep.equal(VEC_SEQ);
    });

    it("outputs are in M31 field range", async () => {
      const out = await h.permute([P - 1n, P - 1n, P - 1n, P - 1n, P - 1n, P - 1n, P - 1n, P - 1n]);
      for (const v of out.map(BigInt)) {
        expect(v).to.be.lessThan(P);
      }
    });

    it("is deterministic", async () => {
      const inp = [42, 7, 99, 3, 11, 22, 33, 44];
      const a = await h.permute(inp);
      const b = await h.permute(inp);
      expect(a.map(BigInt)).to.deep.equal(b.map(BigInt));
    });

    it("single-cell input change diffuses to every output cell", async () => {
      const a = (await h.permute([1, 2, 3, 4, 5, 6, 7, 8])).map(BigInt);
      const b = (await h.permute([1, 2, 3, 4, 5, 6, 7, 9])).map(BigInt);
      for (let i = 0; i < 8; i++) {
        expect(a[i]).to.not.equal(b[i]);
      }
    });
  });

  describe("compress — 4-word (124-bit) wide nodes", function () {
    it("compress([1..4],[5..8]) matches poseidon2_t8.rs", async () => {
      const out = await h.compress([1, 2, 3, 4], [5, 6, 7, 8]);
      expect(out.map(BigInt)).to.deep.equal(VEC_COMPRESS);
    });

    it("equals permute of the concatenated state (cells 0..3)", async () => {
      const perm = (await h.permute([1, 2, 3, 4, 5, 6, 7, 8])).map(BigInt);
      const comp = (await h.compress([1, 2, 3, 4], [5, 6, 7, 8])).map(BigInt);
      expect(comp).to.deep.equal(perm.slice(0, 4));
    });

    it("is order-sensitive", async () => {
      const lr = (await h.compress([11, 22, 33, 44], [55, 66, 77, 88])).map(BigInt);
      const rl = (await h.compress([55, 66, 77, 88], [11, 22, 33, 44])).map(BigInt);
      expect(lr).to.not.deep.equal(rl);
    });
  });

  describe("sponge — rate-4 capacity-4", function () {
    it("sponge([1..8]) node matches poseidon2_t8.rs", async () => {
      const out = await h.sponge([1, 2, 3, 4, 5, 6, 7, 8]);
      expect(out.map(BigInt)).to.deep.equal(VEC_SPONGE_1_8);
    });

    it("is deterministic and in-field", async () => {
      const a = (await h.sponge([1, 2, 3, 4, 5, 6, 7, 8])).map(BigInt);
      const b = (await h.sponge([1, 2, 3, 4, 5, 6, 7, 8])).map(BigInt);
      expect(a).to.deep.equal(b);
      for (const v of a) expect(v).to.be.lessThan(P);
    });

    it("padding distinguishes lengths ([1,2,3] ≠ [1,2,3,1] ≠ [1,2,3,0])", async () => {
      const a = (await h.sponge([1, 2, 3])).map(BigInt);
      const b = (await h.sponge([1, 2, 3, 1])).map(BigInt);
      const c = (await h.sponge([1, 2, 3, 0])).map(BigInt);
      expect(a).to.not.deep.equal(b);
      expect(a).to.not.deep.equal(c);
    });
  });
});
