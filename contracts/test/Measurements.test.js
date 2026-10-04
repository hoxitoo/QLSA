/**
 * Re-measures every gas figure this project makes a strategic claim from.
 *
 * The project reversed three strategic conclusions because a number was wrong,
 * and in each case the correction was APPENDED beside the wrong claim rather
 * than replacing it — so a later reader met the stale claim first and re-derived
 * from it. The "skip the t=16 verifier" decision was made from a >100M figure
 * already known to be an artefact, and stood for six weeks.
 *
 * Prose cannot be kept in sync by discipline. This test can keep it in sync by
 * failing. fixtures/measurements.json is the single source of truth for these
 * numbers; every entry here is MEASURED, never asserted from the file.
 *
 * The measurement rules are in the fixture's _README, and each is a mistake this
 * project actually made:
 *   - a gasLimit above 2^24 is rejected BEFORE execution, so a rejection is not
 *     an out-of-gas;
 *   - estimateGas over-provisions nested calls ~3x, so measure gasUsed of a sent
 *     transaction (or binary-search a view call);
 *   - in a RATIO the shared 21,000 transaction base must cancel, so measure
 *     marginally.
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const path = require("path");
const fs = require("fs");

const M = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures", "measurements.json"), "utf8"));

const FX = (name) => {
  const p = path.join(__dirname, "fixtures", name);
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : null;
};

function check(key, measured) {
  const e = M.entries[key];
  const want = BigInt(e.value);
  const got = BigInt(measured);
  const drift = Math.abs(Number(got - want)) / Number(want);
  const pct = (drift * 100).toFixed(2);
  console.log(`        [${key}] recorded ${want}, measured ${got} (${pct}% drift)`);
  expect(
    drift,
    `${key} drifted ${pct}% from measurements.json (${want} -> ${got}). ` +
    `Update the fixture AND every prose copy, or investigate the regression.`
  ).to.be.lessThan(M.tolerance);
}

// Binary-search the smallest gasLimit at which a view call still returns true.
async function minGas(fn) {
  let lo = 100_000n, hi = BigInt(M.cap) - 1n;
  if (!(await fn(hi))) return null;
  while (hi - lo > 20_000n) {
    const mid = (lo + hi) / 2n;
    if (await fn(mid)) hi = mid; else lo = mid;
  }
  return hi;
}

describe("[measurements] every load-bearing gas figure, re-measured", function () {
  this.timeout(1_800_000);

  it("Poseidon2 permutation cost, t=8 and t=16 (marginal)", async function () {
    const marginal = async (h, vec) =>
      (await h.permuteN.estimateGas(vec, 2)) - (await h.permuteN.estimateGas(vec, 1));

    const h8 = await (await ethers.getContractFactory("Poseidon2M31T8Harness")).deploy();
    const h16 = await (await ethers.getContractFactory("Poseidon2M31T16Harness")).deploy();
    const p8 = await marginal(h8, [1, 2, 3, 4, 5, 6, 7, 8]);
    const p16 = await marginal(h16, Array.from({ length: 16 }, (_, i) => i + 1));

    check("permute_marginal_t8", p8);
    check("permute_marginal_t16", p16);

    // The claim these numbers back: t=16 is DEARER per bit of node capacity
    // (248-bit nodes vs 124-bit), not cheaper. An earlier revision said the
    // reverse, from a ratio in which the transaction base had not cancelled.
    const perBit8 = Number(p8) / 124;
    const perBit16 = Number(p16) / 248;
    expect(perBit16).to.be.greaterThan(
      perBit8, "t=16 must measure as dearer per bit of node capacity");
  });

  it("full-V23 dual submitBatch: t=8 and t=16, one transaction each", async function () {
    const [owner] = await ethers.getSigners();

    const run = async (verifierName, fixtureName, key) => {
      const fx = FX(fixtureName);
      if (!fx) { console.log(`        [${key}] fixture absent — skipped`); return; }
      const v = await (await ethers.getContractFactory(verifierName)).deploy();
      const reg = await (await ethers.getContractFactory("BatchRegistryV5"))
        .deploy(owner.address, await v.getAddress());
      const tx = await reg.submitBatch(
        fx.merkleRoot,
        fx.log10_commitment, fx.log10_proof, fx.log10_queryHints,
        fx.log8_commitment, fx.log8_proof, fx.log8_queryHints,
        { gasLimit: BigInt(M.cap) - 1n });
      const rc = await tx.wait();
      check(key, rc.gasUsed);
      // Both must fit ONE transaction — that is the whole claim.
      expect(rc.gasUsed).to.be.lessThan(BigInt(M.cap));
    };

    await run("QLSAVerifierVFRI11", "full_v23_vfri11_cross_bound_e2e.json",
              "v23_dual_submitBatch_t8");
    await run("QLSAVerifierVFRI12", "full_v23_vfri12_cross_bound_e2e.json",
              "v23_dual_submitBatch_t16");
  });

// The loop the project's headline describes, closed: N signatures -> an
  // aggregation tree -> two roots -> ONE transaction at 130-bit FRI soundness.
  // Re-measured here rather than quoted, like every other load-bearing figure.
  it("a BATCH of signatures finalizes from the aggregation tree's roots", async function () {
    const fx = FX("tree_recursive_bundles_e2e.json");
    if (!fx) { console.log("        [v7_tree_submitBatch] fixture absent — skipped"); return; }
    const [owner] = await ethers.getSigners();

    const vfri11 = await (await ethers.getContractFactory("QLSAVerifierVFRI11")).deploy();
    const recursive = await (await ethers.getContractFactory("QLSAVerifierRecursive"))
      .deploy(await vfri11.getAddress());
    const reg = await (await ethers.getContractFactory("BatchRegistryV7"))
      .deploy(owner.address, await recursive.getAddress());

    const bundle = (b) => ({
      inner: b.inner,
      outerProof: b.outerProof,
      outerCommitment: b.outerCommitment,
      outerHints: b.outerHints,
      lastLayerEvals: b.lastLayerEvals,
    });

    // The REAL txListRoot, not a zero: storing a nonzero value costs 20,000 gas
    // (SSTORE from zero), so a zero here under-reports by that much — and
    // production always has one. With ethers.ZeroHash this measured 14,643,678
    // against the honest 14,663,950, and the 0.14% gap is exactly that write.
    const tx = await reg.submitBatch(fx.merkleRoot, fx.txListRoot, bundle(fx.bundle10), bundle(fx.bundle8),
      { gasLimit: BigInt(M.cap) - 1n });
    const rc = await tx.wait();
    check("v7_tree_submitBatch", rc.gasUsed);
    expect(rc.gasUsed).to.be.lessThan(BigInt(M.cap));

    // The on-chain last-layer rebuild must stay small whatever the tree's depth.
    // Inheriting the leaves' fold count put 512 evaluations here and reverted.
    expect(fx.bundle10.lastLayerEvals.length).to.equal(16);
    expect(fx.bundle8.lastLayerEvals.length).to.equal(16);
  });

// Ф3's economics turn on this one figure, so it is re-measured like the rest.
  // Marginally: the difference between 10 and 25 senders, so the ~14.7M shared
  // batch cost and the 21,000 tx base cancel. Measuring one call and dividing
  // would charge the whole batch to a single sender.
  it("marginal cost of a sender in BatchRegistryV7", async function () {
    const fx = FX("tree_recursive_bundles_e2e.json");
    if (!fx) { console.log("        [v7_sender_marginal] fixture absent — skipped"); return; }
    this.timeout(1_800_000);
    const [owner] = await ethers.getSigners();

    const bundle = (b) => ({
      inner: b.inner, outerProof: b.outerProof, outerCommitment: b.outerCommitment,
      outerHints: b.outerHints, lastLayerEvals: b.lastLayerEvals,
    });

    // A fresh registry per call: finalizedBatches rejects a repeat root, and a
    // warm senderNonces slot costs less than a cold one.
    const run = async (n) => {
      const vfri11 = await (await ethers.getContractFactory("QLSAVerifierVFRI11")).deploy();
      const recursive = await (await ethers.getContractFactory("QLSAVerifierRecursive"))
        .deploy(await vfri11.getAddress());
      const reg = await (await ethers.getContractFactory("BatchRegistryV7"))
        .deploy(owner.address, await recursive.getAddress());
      const senders = Array.from({ length: n }, (_, i) =>
        ethers.zeroPadValue(ethers.toBeHex(i + 1), 32));
      const tx = await reg.submitBatchWithNonces(
        fx.merkleRoot, fx.txListRoot, bundle(fx.bundle10), bundle(fx.bundle8),
        senders, Array.from({ length: n }, () => 1n),
        { gasLimit: BigInt(M.cap) - 1n });
      return (await tx.wait()).gasUsed;
    };

    const g10 = await run(10);
    const g25 = await run(25);
    check("v7_sender_marginal", (g25 - g10) / 15n);
  });

  it("outer recursion verify: why a fully t=16 recursion does not fit", async function () {
    const fx = FX("outer_width_probe.json");
    if (!fx) { this.skip(); return; }
    const root = "0x" + "5c".repeat(32);

    const measure = async (contractName, part) => {
      const v = await (await ethers.getContractFactory(contractName)).deploy();
      return minGas(async (g) => {
        try {
          return await v.verify.staticCall(
            part.proof, part.commitment, root, part.queryHints, { gasLimit: g });
        } catch { return false; }
      });
    };

    const g8 = await measure("QLSAVerifierVFRI11", fx.vfri11);
    const g16 = await measure("QLSAVerifierVFRI12", fx.vfri12);
    check("outer_recursion_verify_t8", g8);
    check("outer_recursion_verify_t16", g16);

    // BatchRegistryV7 needs TWO of these per transaction, plus the inner channel
    // replay and last-layer check. This is the arithmetic that rules out moving
    // the recursion to t=16 — keep it as an assertion, not a paragraph.
    expect(Number(g16) * 2).to.be.greaterThan(
      M.cap, "if two t=16 outer verifies ever fit, the t=16 recursion is back on");
    expect(Number(g8) * 2).to.be.lessThan(
      M.cap, "two t=8 outer verifies must still fit — this is the shipped v8 stack");
  });
});
