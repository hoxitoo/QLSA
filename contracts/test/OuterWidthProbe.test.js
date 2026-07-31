/**
 * How much does moving the RECURSION to t=16 cost?
 *
 * The v8 stack and VFRI12 each reach production on one bound and not the other:
 *
 *   recursion (t=8)  130-bit FRI soundness, but ~2^62 Merkle nodes
 *   VFRI12 direct    ~2^124 nodes, but 16-bit FRI (n_queries=1)
 *
 * Only a t=16 recursion reaches both at once. Its on-chain cost is dominated by
 * verifying the OUTER proof — the recursive circuit's own trace, 87 columns at
 * outer_log=14 no matter how large the inner statement was — so that single
 * verify decides whether the combined path is affordable at all.
 *
 * This measures exactly that: the SAME outer trace (from real V23 recursion
 * inputs at production n_queries=20) proved once with the t=8 pipeline and once
 * with t=16, verified against the deployed verifiers. The only difference
 * between the two numbers is the hash width.
 *
 * Fixture: outer_width_probe.json — regenerate with
 *   cargo test write_outer_width_probe -- --ignored --nocapture
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const path = require("path");
const fs = require("fs");

const FIXTURE_PATH = path.join(__dirname, "fixtures", "outer_width_probe.json");
const FIXTURE_EXISTS = fs.existsSync(FIXTURE_PATH);

// Binary-search the smallest gasLimit at which a view call still succeeds.
// estimateGas over-provisions nested calls by ~3x (docs/conclusions.md §1.2),
// and a view call has no gasUsed to read, so this is the honest measurement.
async function minGas(verifier, fx) {
  let lo = 100_000n;
  let hi = 16_777_215n;
  const ok = async (g) => {
    try {
      return await verifier.verify.staticCall(
        fx.proof, fx.commitment, "0x" + "5c".repeat(32), fx.queryHints, { gasLimit: g });
    } catch {
      return false;
    }
  };
  if (!(await ok(hi))) return null;           // does not fit the per-tx cap
  while (hi - lo > 20_000n) {
    const mid = (lo + hi) / 2n;
    if (await ok(mid)) hi = mid; else lo = mid;
  }
  return hi;
}

describe("[probe] outer recursion proof: t=8 vs t=16", function () {
  let v11, v12, fx;

  before(async function () {
    v11 = await (await ethers.getContractFactory("QLSAVerifierVFRI11")).deploy();
    v12 = await (await ethers.getContractFactory("QLSAVerifierVFRI12")).deploy();
    await v11.waitForDeployment();
    await v12.waitForDeployment();
    if (FIXTURE_EXISTS) fx = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  });

  it("fixture is the production outer shape", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    expect(fx.outer_log).to.equal(14);
    expect(fx.outer_folds).to.equal(9, "32-leaf outer last layer (R4.16)");
    expect(fx.n_cols).to.equal(87);
    // Identical ABI: the width change must not move the hint size.
    expect(fx.vfri12.queryHints.length).to.equal(fx.vfri11.queryHints.length);
  });

  it("both outer proofs verify under their own backend", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(300_000);
    const root = "0x" + "5c".repeat(32);
    expect(await v11.verify.staticCall(
      fx.vfri11.proof, fx.vfri11.commitment, root, fx.vfri11.queryHints,
      { gasLimit: 16_777_215n })).to.equal(true, "t=8 outer");
    expect(await v12.verify.staticCall(
      fx.vfri12.proof, fx.vfri12.commitment, root, fx.vfri12.queryHints,
      { gasLimit: 16_777_215n })).to.equal(true, "t=16 outer");
  });

  it("[gas] measures the width cost of the outer verify", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(900_000);
    const g11 = await minGas(v11, fx.vfri11);
    const g12 = await minGas(v12, fx.vfri12);
    console.log(`        [gas] outer verify, t=8  = ${g11}`);
    console.log(`        [gas] outer verify, t=16 = ${g12}`);
    console.log(`        [gas] ratio              = ${(Number(g12) / Number(g11)).toFixed(2)}x`);
    // A recursive bundle is this verify plus the inner channel replay and the
    // inner last-layer check; BatchRegistryV7 runs TWO bundles per transaction.
    // So roughly 2x this figure has to leave room for the rest under the cap.
    if (g12 !== null) console.log(`        [note] 2 x t=16 outer = ${g12 * 2n} of a 16,777,216 cap`);
    expect(g11 === null, "t=8 outer must fit one transaction").to.equal(false);
    expect(g12 === null, "t=16 outer must fit one transaction").to.equal(false);
  });
});
