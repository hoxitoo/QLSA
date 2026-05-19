/**
 * End-to-end test: BatchRegistryV3 + QLSAVerifierVFRI3 full on-chain flow.
 *
 * Uses the pre-computed fixture `vfri3_real_e2e.json` (real Poseidon2 trace,
 * barycentric OODS, non-constant last layer) to finalize a batch through the
 * production contract stack: BatchRegistryV3 → QLSAVerifierVFRI3 → accepted.
 */
"use strict";

const { expect } = require("chai");
const { ethers }  = require("hardhat");
const path        = require("path");
const fs          = require("fs");

describe("BatchRegistryV3 + QLSAVerifierVFRI3 — end-to-end", function () {
  let registry;
  let verifier;
  let owner;

  const fixture = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "fixtures", "vfri3_real_e2e.json"),
      "utf8"
    )
  );

  before(async function () {
    [owner] = await ethers.getSigners();

    const VFRI3Factory      = await ethers.getContractFactory("QLSAVerifierVFRI3");
    verifier = await VFRI3Factory.deploy();
    await verifier.waitForDeployment();

    const RegistryFactory   = await ethers.getContractFactory("BatchRegistryV3");
    registry = await RegistryFactory.deploy(owner.address, await verifier.getAddress());
    await registry.waitForDeployment();
  });

  it("verifier is QLSAVerifierVFRI3", async function () {
    expect(await registry.verifier()).to.equal(await verifier.getAddress());
  });

  it("submitBatch with real VFRI3 hints finalizes the batch", async function () {
    const tx = await registry.submitBatch(
      fixture.merkleRoot,
      fixture.commitment,
      fixture.proof,
      fixture.queryHints
    );
    const receipt = await tx.wait();

    // BatchFinalized event must be emitted with the correct merkle root
    const event = receipt.logs
      .map(l => { try { return registry.interface.parseLog(l); } catch { return null; } })
      .find(e => e && e.name === "BatchFinalized");
    expect(event).to.not.be.undefined;
    expect(event.args.merkleRoot).to.equal(fixture.merkleRoot);
  });

  it("batch is marked finalized after submitBatch", async function () {
    expect(await registry.finalizedBatches(fixture.merkleRoot)).to.equal(true);
  });

  it("batch commitment stored correctly", async function () {
    expect(await registry.batchCommitments(fixture.merkleRoot)).to.equal(fixture.commitment);
  });

  it("cannot submit same merkleRoot twice (duplicate rejection)", async function () {
    await expect(
      registry.submitBatch(
        fixture.merkleRoot,
        fixture.commitment,
        fixture.proof,
        fixture.queryHints
      )
    ).to.be.reverted;
  });

  it("rejects submitBatch with tampered queryHints", async function () {
    const hintsBytes = Buffer.from(fixture.queryHints.slice(2), "hex");
    hintsBytes[500] ^= 0x01;
    const badHints = "0x" + hintsBytes.toString("hex");

    await expect(
      registry.submitBatch(
        fixture.merkleRoot,
        fixture.commitment,
        fixture.proof,
        badHints
      )
    ).to.be.reverted;
  });

  it("rejects submitBatch with zero merkleRoot", async function () {
    await expect(
      registry.submitBatch(
        ethers.ZeroHash,
        fixture.commitment,
        fixture.proof,
        fixture.queryHints
      )
    ).to.be.reverted;
  });
});
