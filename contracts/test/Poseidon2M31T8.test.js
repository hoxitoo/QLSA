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

    // Frozen Rust vectors for EVERY tail-length residue (n mod 4 = 0,1,2,3),
    // mirroring stark_stwo poseidon2_t8.rs::sponge_length_vectors.  The other
    // cross-checks only cover n = 8 — an exact multiple of the rate, i.e. no
    // padded tail — so without these the odd-tail branch (absorb rem[k] into
    // state[k], then s7 += 1) was pinned on neither side.
    const SPONGE_1_TO_12 = [
      [1602001037n, 1159405765n, 1921860026n, 2002639276n],
      [1555987374n, 1688093151n, 2127323245n, 361838150n],
      [112403478n, 521399817n, 1196614111n, 2120628259n],
      [1073120416n, 1930841549n, 67141568n, 840805313n],
      [1211130541n, 319063584n, 2140513727n, 749177741n],
      [467986364n, 1089613104n, 1110911080n, 1548533126n],
      [244352717n, 1116616254n, 1533576768n, 1130591728n],
      [1440998077n, 1368105497n, 587877558n, 669993876n],
      [1146550239n, 1854944943n, 689231702n, 1773328536n],
      [1823865393n, 1869725030n, 515593527n, 2051133110n],
      [1512006615n, 2120640284n, 1191961299n, 1220524832n],
      [665623931n, 104507602n, 1166029400n, 1568827346n],
    ];

    it("sponge matches Rust for every tail length (n = 1..12)", async () => {
      for (let n = 1; n <= 12; n++) {
        const vals = Array.from({ length: n }, (_, i) => i + 1);
        const out = (await h.sponge(vals)).map(BigInt);
        expect(out, `length ${n}`).to.deep.equal(SPONGE_1_TO_12[n - 1]);
      }
    });

    it("reduces non-canonical words (v and v+P absorb identically)", async () => {
      const canonical = (await h.sponge([1, 2, 3])).map(BigInt);
      const shifted = (await h.sponge([1 + Number(P), 2, 3 + Number(P)])).map(BigInt);
      expect(shifted).to.deep.equal(canonical);
    });
  });
});
