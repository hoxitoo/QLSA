/**
 * Poseidon2M31T16 — Solidity t=16 permutation, cross-checked against the FROZEN
 * Rust reference vectors in stark_stwo/src/poseidon2_t16.rs.
 *
 * t=16 carries 8-word (248-bit) Merkle nodes → node collision ~2^124 ≈ 128-bit,
 * the last rung of the ladder (t=2/t=4 → 2^31, t=8 → 2^62). Whether a t=16
 * ON-CHAIN verifier is affordable is the open question these tests measure; the
 * correctness half is settled here first.
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");

const P = 2n ** 31n - 1n;

// Full 16-cell outputs. The first four cells of each are the anchors frozen in
// poseidon2_t16.rs::test_reference_vectors; the rest come from the same
// reference construction and are pinned here so a partial regression cannot hide
// in cells 4..15.
const VEC_ZERO = [
  816977494n, 440045756n, 1261832507n, 1370560761n,
  1607159615n, 2144341134n, 569375869n, 1423413921n,
  118372238n, 779338566n, 1713932905n, 816125924n,
  1648535676n, 1576356569n, 594005927n, 1031292914n,
];
const VEC_SEQ = [
  1896676506n, 1113082531n, 1826142252n, 1263581674n,
  694653155n, 1856461508n, 173489390n, 625083048n,
  1260549710n, 678527598n, 328982191n, 294744088n,
  1954738020n, 1161645390n, 1247407946n, 924192483n,
];

describe("Poseidon2M31T16 — t=16 permutation (128-bit node width)", function () {
  let h;

  before(async function () {
    h = await (await ethers.getContractFactory("Poseidon2M31T16Harness")).deploy();
    await h.waitForDeployment();
  });

  it("permute([0;16]) matches poseidon2_t16.rs", async function () {
    const out = (await h.permute(Array(16).fill(0))).map(BigInt);
    expect(out).to.deep.equal(VEC_ZERO);
  });

  it("permute([1..16]) matches poseidon2_t16.rs", async function () {
    const input = Array.from({ length: 16 }, (_, i) => i + 1);
    const out = (await h.permute(input)).map(BigInt);
    expect(out).to.deep.equal(VEC_SEQ);
  });

  it("every output cell is in-field", async function () {
    const out = (await h.permute(Array.from({ length: 16 }, (_, i) => i * 7 + 1))).map(BigInt);
    for (const v of out) expect(v).to.be.lessThan(P);
  });

  it("accepts unreduced inputs (lazy reduction is exact)", async function () {
    // v and v+P are the same field element and must permute identically.
    const base = Array.from({ length: 16 }, (_, i) => i + 1);
    const shifted = base.map((v) => BigInt(v) + P);
    const a = (await h.permute(base)).map(BigInt);
    const b = (await h.permute(shifted)).map(BigInt);
    expect(b).to.deep.equal(a);
  });

  it("a single-cell change diffuses to every output cell", async function () {
    const a = (await h.permute(Array(16).fill(0))).map(BigInt);
    const flipped = Array(16).fill(0);
    flipped[9] = 1;
    const b = (await h.permute(flipped)).map(BigInt);
    for (let i = 0; i < 16; i++) expect(b[i]).to.not.equal(a[i], `cell ${i}`);
  });

  it("compress is the permutation's first 8 cells and is order-sensitive", async function () {
    const l = [1, 2, 3, 4, 5, 6, 7, 8];
    const r = [9, 10, 11, 12, 13, 14, 15, 16];
    const c = (await h.compress(l, r)).map(BigInt);
    expect(c).to.deep.equal(VEC_SEQ.slice(0, 8));
    const swapped = (await h.compress(r, l)).map(BigInt);
    expect(swapped).to.not.deep.equal(c);
  });

  it("[gas] measures the t=16 permutation against t=8", async function () {
    this.timeout(300_000);
    const t8 = await (await ethers.getContractFactory("Poseidon2M31T8Harness")).deploy();
    const g16 = await h.permute.estimateGas(Array.from({ length: 16 }, (_, i) => i + 1));
    const g8 = await t8.permute.estimateGas([1, 2, 3, 4, 5, 6, 7, 8]);
    console.log(`        [gas] t8.permute  = ${g8}`);
    console.log(`        [gas] t16.permute = ${g16}`);
    console.log(`        [gas] ratio       = ${(Number(g16) / Number(g8)).toFixed(2)}x`);
    expect(g16).to.be.greaterThan(0n);
  });
});
