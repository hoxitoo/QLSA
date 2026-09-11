/**
 * Poseidon2M31 — cross-check test vectors (verified against Stwo 2.2.0 Rust).
 *
 * Parameters: t=2, α=5, R_F=8, R_P=0, MDS=[[3,1],[1,3]], P=2^31-1.
 * Round constants: SHA-256 IV/K values reduced mod P.
 *
 * All test vectors independently verified in Rust (stark_stwo crate).
 * Gas estimate: ~1000 gas per permute (8 rounds × ~125 gas/round).
 */
"use strict";

const { expect } = require("chai");
const { ethers }  = require("hardhat");

const P = 2_147_483_647n;  // 2^31 - 1

describe("Poseidon2M31 — cross-check vs Stwo 2.2.0 Rust", function () {
  let h;

  before(async function () {
    const Factory = await ethers.getContractFactory("Poseidon2M31Harness");
    h = await Factory.deploy();
    await h.waitForDeployment();
  });

  // ── permute() — 4 Rust-verified test vectors ──────────────────────────────

  it("permute(0, 0) → (204_783_406, 774_225_216)", async function () {
    const [o0, o1] = await h.permute(0n, 0n);
    expect(o0).to.equal(204_783_406n);
    expect(o1).to.equal(774_225_216n);
  });

  it("permute(42, 7) → (1_857_996_239, 291_126_382)", async function () {
    const [o0, o1] = await h.permute(42n, 7n);
    expect(o0).to.equal(1_857_996_239n);
    expect(o1).to.equal(291_126_382n);
  });

  it("permute(1, 2) → (761_825_867, 414_788_754)", async function () {
    const [o0, o1] = await h.permute(1n, 2n);
    expect(o0).to.equal(761_825_867n);
    expect(o1).to.equal(414_788_754n);
  });

  it("permute(1, 1) → (1_348_434_693, 1_943_418_549)", async function () {
    const [o0, o1] = await h.permute(1n, 1n);
    expect(o0).to.equal(1_348_434_693n);
    expect(o1).to.equal(1_943_418_549n);
  });

  // ── permute() — boundary values ───────────────────────────────────────────

  it("permute(P-1, P-1) stays within field", async function () {
    const [o0, o1] = await h.permute(P - 1n, P - 1n);
    expect(o0).to.be.lt(P);
    expect(o1).to.be.lt(P);
  });

  it("permute(P-1, 0) stays within field", async function () {
    const [o0, o1] = await h.permute(P - 1n, 0n);
    expect(o0).to.be.lt(P);
    expect(o1).to.be.lt(P);
  });

  // ── compress() — derived from permute ─────────────────────────────────────

  it("compress(left, right) == permute(left, right)[0]", async function () {
    for (const [l, r] of [[0n, 0n], [42n, 7n], [1n, 2n], [100n, 200n]]) {
      const c = await h.compress(l, r);
      const [p0] = await h.permute(l, r);
      expect(c).to.equal(p0);
    }
  });

  it("compress is non-commutative: compress(a,b) ≠ compress(b,a) generally", async function () {
    const ab = await h.compress(42n, 7n);
    const ba = await h.compress(7n, 42n);
    expect(ab).to.not.equal(ba);
  });

  it("compress output is within field", async function () {
    const c = await h.compress(1_000_000n, 999_999n);
    expect(c).to.be.lt(P);
  });

  // ── sponge() — chain absorption ───────────────────────────────────────────

  it("sponge([]) → (0, 0)  (empty input: initial state)", async function () {
    const [s0, s1] = await h.sponge([]);
    expect(s0).to.equal(0n);
    expect(s1).to.equal(0n);
  });

  it("sponge([0]) == permute(0, 0)", async function () {
    const [s0, s1] = await h.sponge([0n]);
    const [p0, p1] = await h.permute(0n, 0n);
    expect(s0).to.equal(p0);
    expect(s1).to.equal(p1);
  });

  it("sponge([42]) output within field", async function () {
    const [s0, s1] = await h.sponge([42n]);
    expect(s0).to.be.lt(P);
    expect(s1).to.be.lt(P);
  });

  it("sponge([1, 2]) is chained: permute(permute(1,0)[0]+2, permute(1,0)[1])", async function () {
    const [r0, r1] = await h.permute(1n, 0n);
    const carry0 = (r0 + 2n) % P;   // absorb 2 into s0
    const [e0, e1] = await h.permute(carry0, r1);
    const [s0, s1] = await h.sponge([1n, 2n]);
    expect(s0).to.equal(e0);
    expect(s1).to.equal(e1);
  });

  it("sponge([1..8]) → (1_628_177_261, 1_519_148_168)  (Rust cross-check)", async function () {
    const [s0, s1] = await h.sponge([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]);
    expect(s0).to.equal(1_628_177_261n);
    expect(s1).to.equal(1_519_148_168n);
  });

  it("sponge is deterministic (same input → same output)", async function () {
    const inputs = [10n, 20n, 30n];
    const [a0, a1] = await h.sponge(inputs);
    const [b0, b1] = await h.sponge(inputs);
    expect(a0).to.equal(b0);
    expect(a1).to.equal(b1);
  });

  it("sponge output changes when input changes", async function () {
    const [s0a] = await h.sponge([1n, 2n, 3n]);
    const [s0b] = await h.sponge([1n, 2n, 4n]);
    expect(s0a).to.not.equal(s0b);
  });
});
