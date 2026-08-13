/**
 * What does the on-chain channel replay cost, and what does that allow?
 *
 * The recursion deliberately keeps the inner proof's Fiat-Shamir replay ON-CHAIN
 * (R3.10): the channel is cheap relative to the circuit, so its challenges become
 * public inputs rather than in-circuit work. That split is what makes the current
 * v8 stack affordable.
 *
 * It also sets the ceiling on aggregating N signatures at a SINGLE recursion
 * level. One level means N inner statements, and the on-chain side replays one
 * channel per inner statement — so the achievable N is (transaction headroom) /
 * (cost of a replay). This measures both numbers, because "just widen the fan-in"
 * is the obvious first idea and it needs an answer before a tree is built
 * instead.
 *
 * A binary tree does not have this problem: its ROOT has fan-in 2 whatever N is,
 * so the on-chain replay count is constant. The price is that intermediate levels
 * must replay their children's channels in-circuit. See docs/TECH_DEBT.md A-2.
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const FIXTURE = path.join(__dirname, "fixtures", "v23_recursive_bundles_e2e.json");
const CAP = 16_777_216n;          // EIP-7825 per-transaction cap
const V8_USED = 13_168_471n;      // measured full v8 batch, see measurements.json
const TX_BASE = 21_000n;

describe("[probe] on-chain channel replay: cost and the fan-in it allows", function () {
  it("measures one replay and the resulting single-level ceiling", async function () {
    if (!fs.existsSync(FIXTURE)) { this.skip(); return; }
    this.timeout(300_000);

    const h = await (await ethers.getContractFactory("RecursiveChannelReplayHarness")).deploy();
    const ip = JSON.parse(fs.readFileSync(FIXTURE, "utf8")).bundle10.inner;

    const gross = await h.replay.estimateGas(
      ip.traceRoot, ip.oodsComboPos, ip.oodsComboNeg, ip.compRoot,
      ip.friLayerRoots, ip.batchRoot, ip.treeDepth, ip.nQueries);
    const net = gross - TX_BASE;

    const headroom = CAP - V8_USED;
    const fanIn = headroom / net;

    console.log(`        shape: nQueries=${ip.nQueries} treeDepth=${ip.treeDepth} friLayerRoots=${ip.friLayerRoots.length}`);
    console.log(`        [gas] one replay        = ${net} (net of the ${TX_BASE} tx base)`);
    console.log(`        [gas] v8 tx headroom    = ${headroom}`);
    console.log(`        single-level fan-in     ≈ ${fanIn} extra inner statements`);

    // The claim this probe exists to settle: widening the fan-in at one level
    // does NOT reach a useful N. If this ever becomes false — a cheaper replay,
    // a larger cap — revisit whether a tree is still required.
    expect(fanIn).to.be.lessThan(
      16n, "single-level fan-in must remain small; a tree is what scales N");
  });
});
