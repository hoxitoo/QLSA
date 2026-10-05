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
  async function submitWith(nSenders, { repeatOneSender = false } = {}) {
    const [owner] = await ethers.getSigners();
    const vfri11 = await (await ethers.getContractFactory("QLSAVerifierVFRI11")).deploy();
    const recursive = await (
      await ethers.getContractFactory("QLSAVerifierRecursive")
    ).deploy(await vfri11.getAddress());
    const reg = await (
      await ethers.getContractFactory("BatchRegistryV7")
    ).deploy(owner.address, await recursive.getAddress(), ethers.ZeroHash, 0);

    // Two shapes, to separate the storage cost from everything else:
    //
    //   distinct  n different senders  -> n writes to ZERO slots (SSTORE_SET)
    //   repeat    ONE sender, n rising -> 1 write to a zero slot, then n-1
    //             nonces                  writes to the SAME warm slot
    //
    // The contract permits duplicates as long as they strictly increase, which
    // is what makes `repeat` a legal call rather than a contrived one.
    const senders = repeatOneSender
      ? Array.from({ length: nSenders }, () => ethers.zeroPadValue("0x07", 32))
      : Array.from({ length: nSenders }, (_, i) =>
          ethers.zeroPadValue(ethers.toBeHex(i + 1), 32));
    const nonces = repeatOneSender
      ? Array.from({ length: nSenders }, (_, i) => BigInt(i + 1))
      : Array.from({ length: nSenders }, () => 1n);

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

  // ── Why the figure above is not the one the economics should use ───────────
  //
  // Every measurement here deploys a FRESH registry, so each sender writes a
  // ZERO slot: SSTORE_SET (20,000) plus the cold-slot surcharge (2,100). That
  // is the FIRST-TIME cost. A sender that has transacted before writes a
  // non-zero slot — SSTORE_RESET (2,900) + 2,100 — which is what a running
  // system pays for almost every sender.
  //
  // The distinction decides different things and must not be collapsed:
  //
  //   the CEILING (how many senders fit one transaction) needs the COLD figure,
  //     because a batch of all-new senders is the worst case and a ceiling has
  //     to hold there;
  //   BREAK-EVEN (the economics) needs the STEADY-STATE figure, because that is
  //     what is paid on average over the system's life.
  //
  // ROADMAP § 1.5 and measurements.json used the cold figure for BOTH, which
  // makes the mapping look dearer than it is and so overstates the case for the
  // nonce accumulator (§ A-4).
  it("[gas] cold vs warm: what a REPEAT sender costs", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(1_800_000);

    const d10 = await submitWith(10);
    const d25 = await submitWith(25);
    const r10 = await submitWith(10, { repeatOneSender: true });
    const r25 = await submitWith(25, { repeatOneSender: true });

    const cold = (d25 - d10) / 15n;
    const warm = (r25 - r10) / 15n;

    console.log(`        [gas] distinct senders: 10 = ${d10}  25 = ${d25}`);
    console.log(`        [gas] one sender, rising nonces: 10 = ${r10}  25 = ${r25}`);
    console.log(`        [gas] marginal, COLD slot (new sender)   = ${cold}`);
    console.log(`        [gas] marginal, WARM slot (same tx)      = ${warm}`);
    console.log(`        [gas] difference attributable to storage = ${cold - warm}`);

    // Directional, not exact. `warm` here is a write to a slot already touched
    // in THIS transaction (~100 gas), so it is a LOWER bound on the
    // across-transaction warm cost (~5,000: SSTORE_RESET + a fresh cold
    // surcharge each tx). It also carries slightly MORE scan work than `cold`,
    // because with identical senders every pair of the O(n^2) scan evaluates
    // the nonce comparison instead of short-circuiting on the address — so if
    // anything this OVERSTATES warm, which is the safe direction.
    expect(warm).to.be.lessThan(
      cold, "a warm slot must cost less than a cold one, or the SSTORE_SET premise is wrong");

    // SSTORE_SET (20,000) minus SSTORE_RESET (2,900) is 17,100; the measured
    // gap should be in that neighbourhood and is certainly not a rounding
    // effect. A loose bound, because the scan asymmetry above sits inside it.
    expect(cold - warm).to.be.greaterThan(
      10_000n, "the cold/warm gap should be dominated by SSTORE_SET, ~17,100 gas");

    const SAVED = 52_944n;
    const base = await submitWith(1);
    const headroom = CAP - base;
    for (const [label, m] of [["cold", cold], ["warm (lower bound)", warm]]) {
      const ceiling = headroom / (m > 0n ? m : 1n);
      const be = m < SAVED ? base / (SAVED - m) : null;
      console.log(
        `        [calc] at the ${label} marginal: ceiling ≈ ${ceiling}` +
        (be === null ? ", break-even UNREACHABLE" : `, break-even N ≈ ${be}`));
    }
  });

  // ── The figure the economics actually need: ACROSS transactions ────────────
  //
  // A sender that appeared in an earlier BATCH writes a non-zero slot, and pays
  // a fresh cold-slot surcharge because each transaction warms its own access
  // list. That is the steady-state cost, and the real contract cannot produce it
  // — a second batch needs a second merkleRoot, finalizedBatches rejects a
  // repeat, and a different root needs different cross-bound proofs.
  //
  // So it is measured on NonceLoopHarness, which carries V7's nonce block
  // verbatim. The harness is cross-checked against the real contract on the two
  // points the real contract CAN produce before its third is believed.
  describe("[gas] steady state: a sender that has transacted before", function () {
    const deployHarness = async () =>
      (await (await ethers.getContractFactory("NonceLoopHarness")).deploy());

    const distinct = (n, from = 1) =>
      Array.from({ length: n }, (_, i) => ethers.zeroPadValue(ethers.toBeHex(from + i), 32));

    async function marginal(run) {
      const g10 = await run(10);
      const g25 = await run(25);
      return (g25 - g10) / 15n;
    }

    it("the harness reproduces the real contract's per-sender cost", async function () {
      if (!FIXTURE_EXISTS) { this.skip(); return; }
      this.timeout(1_800_000);

      // (1) cold: n brand-new senders, one call.
      const hCold = await marginal(async (n) => {
        const h = await deployHarness();
        const tx = await h.applyNonces(distinct(n), Array.from({ length: n }, () => 1n));
        return (await tx.wait()).gasUsed;
      });

      // (2) warm within one transaction: one sender, n rising nonces.
      const hWarmSameTx = await marginal(async (n) => {
        const h = await deployHarness();
        const tx = await h.applyNonces(
          Array.from({ length: n }, () => ethers.zeroPadValue("0x07", 32)),
          Array.from({ length: n }, (_, i) => BigInt(i + 1)));
        return (await tx.wait()).gasUsed;
      });

      const rCold = (await submitWith(25) - await submitWith(10)) / 15n;
      const rWarm = (await submitWith(25, { repeatOneSender: true })
                   - await submitWith(10, { repeatOneSender: true })) / 15n;

      console.log(`        [gas] cold      harness ${hCold}  vs real ${rCold}`);
      console.log(`        [gas] warm/1tx  harness ${hWarmSameTx}  vs real ${rWarm}`);

      // Within 5%: the harness omits the proofs, which are a per-CALL cost and
      // cancel marginally, but every per-SENDER operation is identical. A wider
      // divergence means the loops have drifted and the harness may not be used.
      const within = (a, b) => {
        const d = a > b ? a - b : b - a;
        return Number(d * 100n / b) <= 5;
      };
      expect(within(hCold, rCold), `cold: ${hCold} vs ${rCold}`).to.equal(true);
      expect(within(hWarmSameTx, rWarm), `warm: ${hWarmSameTx} vs ${rWarm}`).to.equal(true);
    });

    it("[gas] marginal cost of a RETURNING sender", async function () {
      this.timeout(1_800_000);

      // Two calls into ONE harness: the first warms the slots, the second is
      // what a steady-state batch costs.
      const acrossTx = await marginal(async (n) => {
        const h = await deployHarness();
        const s = distinct(n);
        await (await h.applyNonces(s, Array.from({ length: n }, () => 1n))).wait();
        const tx = await h.applyNonces(s, Array.from({ length: n }, () => 2n));
        return (await tx.wait()).gasUsed;
      });

      const coldTx = await marginal(async (n) => {
        const h = await deployHarness();
        const tx = await h.applyNonces(distinct(n), Array.from({ length: n }, () => 1n));
        return (await tx.wait()).gasUsed;
      });

      console.log(`        [gas] harness marginal, FIRST-TIME sender = ${coldTx}`);
      console.log(`        [gas] harness marginal, RETURNING sender  = ${acrossTx}`);
      console.log(`        [gas] saved by the slot already existing  = ${coldTx - acrossTx}`);

      // SSTORE_SET (20,000) vs SSTORE_RESET (2,900): the gap should be ~17,100.
      expect(acrossTx).to.be.lessThan(coldTx);
      expect(coldTx - acrossTx).to.be.greaterThan(15_000n);
      expect(coldTx - acrossTx).to.be.lessThan(19_000n);

      // What this does to the two conclusions that used ONE figure for both.
      const SAVED = 52_944n;
      const base = 14_689_887n; // measured 1-sender V7 batch
      const headroom = CAP - base;
      for (const [label, m] of [["first-time", coldTx], ["returning", acrossTx]]) {
        const ceiling = headroom / m;
        const be = m < SAVED ? base / (SAVED - m) : null;
        console.log(
          `        [calc] ${label} senders: ceiling ≈ ${ceiling}, ` +
          (be === null ? "break-even UNREACHABLE" : `break-even N ≈ ${be}`) +
          (be !== null && be <= ceiling ? "  -> INSIDE the ceiling" : "  -> outside the ceiling"));
      }
    });
  });
});
