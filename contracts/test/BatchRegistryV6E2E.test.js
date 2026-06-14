/**
 * BatchRegistryV6 — per-group (split) V23 finalization with QLSAVerifierVFRI10.
 *
 * BatchRegistryV5 runs BOTH t=4 group verifies in one submitBatch tx, which
 * overruns the ~16.7M per-tx gas cap.  BatchRegistryV6 verifies each group in
 * its own transaction (≤16.7M each) and finalizes once both are present and
 * cross-consistent, preserving BatchRegistryV5's cross-proof binding.
 *
 * Reuses the VFRI10 V23 cross-bound fixture (num_folds=6) where:
 *   boundRoot10 = keccak256(merkleRoot ‖ traceRoot8),  traceRoot8  = proof8[8:40]
 *   boundRoot8  = keccak256(merkleRoot ‖ traceRoot10), traceRoot10 = proof10[8:40]
 * so the cross trace root passed to each submitGroup call is the OTHER proof's
 * embedded trace root.  Skips if the fixture is absent.
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const path = require("path");
const fs = require("fs");

const FIXTURE_PATH = path.join(__dirname, "fixtures", "full_v23_vfri10_cross_bound_e2e.json");
const FIXTURE_EXISTS = fs.existsSync(FIXTURE_PATH);
const GAS = 16_700_000n;

function traceRootOf(proofHex) {
  return "0x" + Buffer.from(proofHex.slice(2), "hex").slice(8, 40).toString("hex");
}

describe("BatchRegistryV6 — per-group split V23 finalization (VFRI10)", function () {
  let verifier, signer, fixture, traceRoot10, traceRoot8;

  before(async function () {
    [signer] = await ethers.getSigners();
    verifier = await (await ethers.getContractFactory("QLSAVerifierVFRI10")).deploy();
    await verifier.waitForDeployment();
    if (FIXTURE_EXISTS) {
      fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
      traceRoot10 = traceRootOf(fixture.log10_proof);
      traceRoot8 = traceRootOf(fixture.log8_proof);
    }
  });

  async function freshRegistry() {
    const r = await (await ethers.getContractFactory("BatchRegistryV6"))
      .deploy(signer.address, await verifier.getAddress());
    await r.waitForDeployment();
    return r;
  }

  // ── Deployment / wiring (no fixture needed) ──────────────────────────────────

  it("deploys and wires the VFRI10 verifier", async function () {
    const r = await freshRegistry();
    expect(await r.verifier()).to.equal(await verifier.getAddress());
    expect(await r.MAX_SENDERS()).to.equal(3000n);
  });

  // ── Happy path: each group in its own tx, ≤16.7M gas ─────────────────────────

  it("submitGroup10 then submitGroup8 finalizes; each verify fits ≤16.7M gas", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(180_000);
    const r = await freshRegistry();

    const tx10 = await r.submitGroup10(
      fixture.merkleRoot, traceRoot8, fixture.log10_commitment,
      fixture.log10_proof, fixture.log10_queryHints, { gasLimit: GAS }
    );
    const rc10 = await tx10.wait();
    console.log(`    ↳ submitGroup10 gas: ${rc10.gasUsed}`);
    expect(rc10.gasUsed).to.be.lessThan(GAS);
    expect(await r.isBatchFinalized(fixture.merkleRoot)).to.equal(false);
    let [has10, has8, ready] = await r.pendingGroups(fixture.merkleRoot);
    expect(has10).to.equal(true);
    expect(has8).to.equal(false);
    expect(ready).to.equal(false);

    const tx8 = await r.submitGroup8(
      fixture.merkleRoot, traceRoot10, fixture.log8_commitment,
      fixture.log8_proof, fixture.log8_queryHints, { gasLimit: GAS }
    );
    const rc8 = await tx8.wait();
    console.log(`    ↳ submitGroup8 gas:  ${rc8.gasUsed}`);
    expect(rc8.gasUsed).to.be.lessThan(GAS);

    const ev = rc8.logs.find(l => {
      try { return r.interface.parseLog(l)?.name === "BatchFinalized"; } catch { return false; }
    });
    expect(ev, "BatchFinalized must be emitted on the completing call").to.not.be.undefined;
    expect(await r.isBatchFinalized(fixture.merkleRoot)).to.equal(true);
    // Pending state cleared on finalize.
    [has10, has8, ready] = await r.pendingGroups(fixture.merkleRoot);
    expect(has10).to.equal(false);
    expect(has8).to.equal(false);
  });

  it("order-independent: submitGroup8 first, then submitGroup10 finalizes", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(180_000);
    const r = await freshRegistry();
    await (await r.submitGroup8(
      fixture.merkleRoot, traceRoot10, fixture.log8_commitment,
      fixture.log8_proof, fixture.log8_queryHints, { gasLimit: GAS })).wait();
    expect(await r.isBatchFinalized(fixture.merkleRoot)).to.equal(false);
    await (await r.submitGroup10(
      fixture.merkleRoot, traceRoot8, fixture.log10_commitment,
      fixture.log10_proof, fixture.log10_queryHints, { gasLimit: GAS })).wait();
    expect(await r.isBatchFinalized(fixture.merkleRoot)).to.equal(true);
  });

  // ── Rejections ───────────────────────────────────────────────────────────────

  it("submitGroup10 with a wrong cross trace root fails verification", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(120_000);
    const r = await freshRegistry();
    await expect(
      r.submitGroup10(
        fixture.merkleRoot, "0x" + "11".repeat(32), fixture.log10_commitment,
        fixture.log10_proof, fixture.log10_queryHints, { gasLimit: GAS })
    ).to.be.revertedWithCustomError(r, "Log10ProofInvalid");
  });

  it("re-submitting a group after finalization reverts BatchAlreadyFinalized", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(180_000);
    const r = await freshRegistry();
    await (await r.submitGroup10(
      fixture.merkleRoot, traceRoot8, fixture.log10_commitment,
      fixture.log10_proof, fixture.log10_queryHints, { gasLimit: GAS })).wait();
    await (await r.submitGroup8(
      fixture.merkleRoot, traceRoot10, fixture.log8_commitment,
      fixture.log8_proof, fixture.log8_queryHints, { gasLimit: GAS })).wait();
    await expect(
      r.submitGroup10(
        fixture.merkleRoot, traceRoot8, fixture.log10_commitment,
        fixture.log10_proof, fixture.log10_queryHints, { gasLimit: GAS })
    ).to.be.revertedWithCustomError(r, "BatchAlreadyFinalized");
  });

  it("zero merkleRoot reverts InvalidMerkleRoot", async function () {
    const r = await freshRegistry();
    await expect(
      r.submitGroup10(
        "0x" + "00".repeat(32), "0x" + "00".repeat(32), "0x" + "00".repeat(16),
        "0x" + "01".repeat(40), "0x", { gasLimit: GAS })
    ).to.be.revertedWithCustomError(r, "InvalidMerkleRoot");
  });

  // ── Nonce-enforced finalization ──────────────────────────────────────────────

  it("submitGroup8WithNonces finalizes with replay protection after group10", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(180_000);
    const r = await freshRegistry();
    await (await r.submitGroup10(
      fixture.merkleRoot, traceRoot8, fixture.log10_commitment,
      fixture.log10_proof, fixture.log10_queryHints, { gasLimit: GAS })).wait();

    const sender = "0x" + "ab".repeat(32);
    const tx = await r.submitGroup8WithNonces(
      fixture.merkleRoot, traceRoot10, fixture.log8_commitment,
      fixture.log8_proof, fixture.log8_queryHints, [sender], [5], { gasLimit: GAS });
    await tx.wait();
    expect(await r.isBatchFinalized(fixture.merkleRoot)).to.equal(true);
    expect(await r.senderNonces(sender)).to.equal(5n);
  });

  it("submitGroup8WithNonces reverts NotReadyToFinalize if group10 is absent", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(120_000);
    const r = await freshRegistry();
    await expect(
      r.submitGroup8WithNonces(
        fixture.merkleRoot, traceRoot10, fixture.log8_commitment,
        fixture.log8_proof, fixture.log8_queryHints,
        ["0x" + "ab".repeat(32)], [5], { gasLimit: GAS })
    ).to.be.revertedWithCustomError(r, "NotReadyToFinalize");
  });
});
