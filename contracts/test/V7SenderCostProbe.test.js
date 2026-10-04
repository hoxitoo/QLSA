/**
 * [probe] what a SENDER costs in BatchRegistryV7 — the aggregating path.
 *
 * ROADMAP § 1.5 planned Ф3 on per-sender figures of ~42k (today) and ~22k
 * (after A-3). Those were measured on `BatchRegistryV5`, whose storage layout
 * and loop body differ, and — more importantly — which proves `tx[0]` only.
 * V7 is the path that actually aggregates N signatures, so its numbers are the
 * ones the economics depend on, and they had never been taken.
 *
 * Measured MARGINALLY: the difference between n and m senders, so the ~14.7M of
 * shared batch cost and the 21,000 transaction base cancel. Measuring a single
 * call and dividing would charge the whole batch to one sender — the mistake
 * docs/conclusions.md §1 records.
 *
 * `gasUsed` of a SENT transaction, never estimateGas.
 *
 * Fixture: tree_recursive_bundles_e2e.json (regenerate with
 *   cargo test write_tree_recursive_bundles_fixture -- --ignored --nocapture)
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const FIXTURE_PATH = path.join(__dirname, "fixtures", "tree_recursive_bundles_e2e.json");
const FIXTURE_EXISTS = fs.existsSync(FIXTURE_PATH);
const CAP = 16_777_216n;

function bundleTuple(b) {
  return {
    inner: b.inner,
    outerProof: b.outerProof,
    outerCommitment: b.outerCommitment,
    outerHints: b.outerHints,
    lastLayerEvals: b.lastLayerEvals,
  };
}

describe("[probe] per-sender cost in BatchRegistryV7", function () {
  let fx, b10, b8;

  before(function () {
    if (FIXTURE_EXISTS) {
      fx = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
      b10 = bundleTuple(fx.bundle10);
      b8 = bundleTuple(fx.bundle8);
    }
  });

  // A fresh registry per call: `finalizedBatches` would reject the second
  // submission of the same root, and a warm `senderNonces` slot costs less than
  // a cold one — reusing one registry would measure the wrong thing.
  async function submitWith(nSenders) {
    const [owner] = await ethers.getSigners();
    const vfri11 = await (await ethers.getContractFactory("QLSAVerifierVFRI11")).deploy();
    const recursive = await (
      await ethers.getContractFactory("QLSAVerifierRecursive")
    ).deploy(await vfri11.getAddress());
    const reg = await (
      await ethers.getContractFactory("BatchRegistryV7")
    ).deploy(owner.address, await recursive.getAddress());

    const senders = Array.from({ length: nSenders }, (_, i) =>
      ethers.zeroPadValue(ethers.toBeHex(i + 1), 32));
    const nonces = Array.from({ length: nSenders }, () => 1n);

    const tx = await reg.submitBatchWithNonces(
      fx.merkleRoot, fx.txListRoot, b10, b8, senders, nonces,
      { gasLimit: CAP - 1n });
    const rc = await tx.wait();
    return rc.gasUsed;
  }

  it("[gas] marginal cost of one sender, and the N it leaves room for", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(1_800_000);

    const g1 = await submitWith(1);
    const g10 = await submitWith(10);
    const g25 = await submitWith(25);

    const m1to10 = (g10 - g1) / 9n;
    const m10to25 = (g25 - g10) / 15n;

    console.log(`        [gas] V7 submitBatchWithNonces:  1 sender = ${g1}`);
    console.log(`        [gas]                           10 senders = ${g10}`);
    console.log(`        [gas]                           25 senders = ${g25}`);
    console.log(`        [gas] marginal per sender, 1->10  = ${m1to10}`);
    console.log(`        [gas] marginal per sender, 10->25 = ${m10to25}`);

    // The O(n²) duplicate scan means the marginal cost GROWS with n. If it did
    // not, the scan would not be quadratic and the A-3 premise would be wrong.
    expect(m10to25).to.be.greaterThan(
      m1to10, "the O(n^2) scan must make each additional sender dearer");

    const headroom = CAP - g1;
    const ceiling = headroom / m10to25;
    console.log(`        [gas] headroom above a 1-sender batch = ${headroom}`);
    console.log(`        [calc] sender ceiling at the 10->25 marginal ≈ ${ceiling}`);

    // What the economics turn on: 52,944 gas of calldata saved per signature
    // (sig alone, 3309 B at 16 gas/byte). Break-even needs
    // N × 52,944 > base + N × marginal.
    const SAVED = 52_944n;
    if (m10to25 < SAVED) {
      const breakEven = g1 / (SAVED - m10to25);
      console.log(`        [calc] break-even N ≈ ${breakEven} (ceiling ${ceiling})`);
    } else {
      console.log(`        [calc] break-even UNREACHABLE: a sender costs more than a signature saves`);
    }
  });
});
