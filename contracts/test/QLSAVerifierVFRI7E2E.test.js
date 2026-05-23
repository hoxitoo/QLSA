/**
 * QLSAVerifierVFRI7 — E2E test: cross-proof binding (MVP-5 Priority 2).
 *
 * VFRI7 changes from VFRI6:
 *   Before drawQueries, the Fiat-Shamir channel receives an extra:
 *     TwoChannel.mixRoot(chan, merkleRoot)
 *   This binds FRI query indices to the external batch context.
 *
 *   BatchRegistryV4 uses cross-bound roots:
 *     boundRoot10 = keccak256(batchRoot ‖ proof8[8:40])   (traceRoot of LOG=8 group)
 *     boundRoot8  = keccak256(batchRoot ‖ proof10[8:40])  (traceRoot of LOG=10 group)
 *
 *   An adversary mixing proofs from different ML-DSA witnesses gets mismatched
 *   query indices and fails on-chain Merkle verification.
 *
 * Fixture: full_v23_vfri7_cross_bound_e2e.json
 *   Keys: merkleRoot, log10_proof, log10_commitment, log10_queryHints,
 *         log8_proof, log8_commitment, log8_queryHints,
 *         bound_root_10, bound_root_8, n_queries
 */
"use strict";

const { expect } = require("chai");
const { ethers }  = require("hardhat");
const path        = require("path");
const fs          = require("fs");

describe("QLSAVerifierVFRI7 — Cross-Proof Binding E2E (MVP-5)", function () {
  let verifier7, registry4;

  const fixture = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "fixtures", "full_v23_vfri7_cross_bound_e2e.json"),
      "utf8"
    )
  );

  before(async function () {
    const [signer] = await ethers.getSigners();

    const V7Factory = await ethers.getContractFactory("QLSAVerifierVFRI7");
    verifier7 = await V7Factory.deploy();
    await verifier7.waitForDeployment();

    const RFactory = await ethers.getContractFactory("BatchRegistryV4");
    registry4 = await RFactory.deploy(signer.address, await verifier7.getAddress());
    await registry4.waitForDeployment();
  });

  // ── Fixture structural checks ─────────────────────────────────────────────

  it("fixture has required keys", function () {
    const keys = ["merkleRoot","log10_proof","log10_commitment","log10_queryHints",
                  "log8_proof","log8_commitment","log8_queryHints",
                  "bound_root_10","bound_root_8","n_queries"];
    for (const k of keys) {
      expect(fixture, `missing key: ${k}`).to.have.property(k);
    }
    expect(fixture.n_queries).to.equal(1);
  });

  it("LOG=10 commitment binds Blake2s(proof[:32]‖bound_root_10)[:16]", function () {
    const { createHash } = require("crypto");
    const proof = Buffer.from(fixture.log10_proof.slice(2), "hex");
    const root  = Buffer.from(fixture.bound_root_10.slice(2), "hex");
    const h = createHash("blake2s256");
    h.update(proof.slice(0, 32));
    h.update(root);
    expect("0x" + h.digest().slice(0, 16).toString("hex"))
      .to.equal(fixture.log10_commitment);
  });

  it("LOG=8 commitment binds Blake2s(proof[:32]‖bound_root_8)[:16]", function () {
    const { createHash } = require("crypto");
    const proof = Buffer.from(fixture.log8_proof.slice(2), "hex");
    const root  = Buffer.from(fixture.bound_root_8.slice(2), "hex");
    const h = createHash("blake2s256");
    h.update(proof.slice(0, 32));
    h.update(root);
    expect("0x" + h.digest().slice(0, 16).toString("hex"))
      .to.equal(fixture.log8_commitment);
  });

  it("bound_root_10 = keccak256(merkleRoot ‖ proof8[8:40])", function () {
    const proof8 = Buffer.from(fixture.log8_proof.slice(2), "hex");
    const traceRoot8 = "0x" + proof8.slice(8, 40).toString("hex");
    const computed = ethers.keccak256(
      ethers.solidityPacked(["bytes32","bytes32"], [fixture.merkleRoot, traceRoot8])
    );
    expect(computed).to.equal(fixture.bound_root_10);
  });

  it("bound_root_8 = keccak256(merkleRoot ‖ proof10[8:40])", function () {
    const proof10 = Buffer.from(fixture.log10_proof.slice(2), "hex");
    const traceRoot10 = "0x" + proof10.slice(8, 40).toString("hex");
    const computed = ethers.keccak256(
      ethers.solidityPacked(["bytes32","bytes32"], [fixture.merkleRoot, traceRoot10])
    );
    expect(computed).to.equal(fixture.bound_root_8);
  });

  it("LOG=10 and LOG=8 trace roots are distinct (different domains)", function () {
    const proof10 = Buffer.from(fixture.log10_proof.slice(2), "hex");
    const proof8  = Buffer.from(fixture.log8_proof.slice(2),  "hex");
    const tr10 = proof10.slice(8, 40).toString("hex");
    const tr8  = proof8.slice(8,  40).toString("hex");
    expect(tr10).to.not.equal(tr8);
  });

  // ── VFRI7 verifier verify() ───────────────────────────────────────────────

  it("verify() returns true for LOG=10 proof with bound_root_10 (within 15M gas)", async function () {
    this.timeout(60_000);
    let result = false;
    try {
      result = await verifier7.verify.staticCall(
        fixture.log10_proof,
        fixture.log10_commitment,
        fixture.bound_root_10,
        fixture.log10_queryHints,
        { gasLimit: 15_000_000n }
      );
    } catch (e) {
      expect.fail(`verify() reverted: ${e.message}`);
    }
    expect(result).to.equal(true, "VFRI7 LOG=10 verify must return true");
    console.log("    ✓ VFRI7 LOG=10 verify() = true within 15M gas");
  });

  it("verify() returns true for LOG=8 proof with bound_root_8 (within 15M gas)", async function () {
    this.timeout(60_000);
    let result = false;
    try {
      result = await verifier7.verify.staticCall(
        fixture.log8_proof,
        fixture.log8_commitment,
        fixture.bound_root_8,
        fixture.log8_queryHints,
        { gasLimit: 15_000_000n }
      );
    } catch (e) {
      expect.fail(`verify() reverted: ${e.message}`);
    }
    expect(result).to.equal(true, "VFRI7 LOG=8 verify must return true");
    console.log("    ✓ VFRI7 LOG=8 verify() = true within 15M gas");
  });

  it("verify() returns false when wrong merkleRoot is passed (binding check)", async function () {
    this.timeout(30_000);
    const wrongRoot = "0x" + "ff".repeat(32);
    // With wrong root, the Fiat-Shamir transcript diverges → wrong query indices → Merkle proof fails
    const result = await verifier7.verify.staticCall(
      fixture.log10_proof,
      fixture.log10_commitment,
      wrongRoot,
      fixture.log10_queryHints
    );
    expect(result).to.equal(false, "Wrong merkleRoot must cause verify() to return false");
  });

  it("verify() returns false when raw merkleRoot (not bound_root_10) is used for LOG=10", async function () {
    this.timeout(30_000);
    // VFRI7 derives queries from bound_root_10; using raw batch merkleRoot gives wrong indices
    const result = await verifier7.verify.staticCall(
      fixture.log10_proof,
      fixture.log10_commitment,
      fixture.merkleRoot,   // raw batch root, NOT the cross-bound root
      fixture.log10_queryHints
    );
    expect(result).to.equal(false, "Raw merkleRoot (not bound_root) must cause verify() to return false");
  });

  it("verify() returns false when LOG=10 commitment is zero", async function () {
    const result = await verifier7.verify.staticCall(
      fixture.log10_proof,
      "0x" + "00".repeat(16),
      fixture.bound_root_10,
      fixture.log10_queryHints
    );
    expect(result).to.equal(false);
  });

  it("verify() returns false when merkleRoot is zero", async function () {
    const result = await verifier7.verify.staticCall(
      fixture.log10_proof,
      fixture.log10_commitment,
      "0x" + "00".repeat(32),
      fixture.log10_queryHints
    );
    expect(result).to.equal(false);
  });

  // ── BatchRegistryV4 integration ───────────────────────────────────────────

  it("BatchRegistryV4 finalizes with VFRI7 verifier on-chain cross-binding", async function () {
    this.timeout(120_000);
    const tx = await registry4.submitBatch(
      fixture.merkleRoot,
      fixture.log10_commitment,
      fixture.log10_proof,
      fixture.log10_queryHints,
      fixture.log8_commitment,
      fixture.log8_proof,
      fixture.log8_queryHints,
    );
    const receipt = await tx.wait();

    const event = receipt.logs.find(l => {
      try { return registry4.interface.parseLog(l)?.name === "BatchFinalized"; }
      catch { return false; }
    });
    expect(event, "BatchFinalized event must be emitted").to.not.be.undefined;
    const parsed = registry4.interface.parseLog(event);
    expect(parsed.args.merkleRoot).to.equal(fixture.merkleRoot);
    expect(parsed.args.commitmentLog10).to.equal(fixture.log10_commitment);
    expect(parsed.args.commitmentLog8).to.equal(fixture.log8_commitment);
    console.log("    ✓ BatchRegistryV4.submitBatch() finalized with VFRI7 cross-bound proofs");
  });

  it("batch is marked finalized after submitBatch", async function () {
    expect(await registry4.isBatchFinalized(fixture.merkleRoot)).to.equal(true);
  });

  it("submitBatch reverts BatchAlreadyFinalized on replay", async function () {
    await expect(
      registry4.submitBatch(
        fixture.merkleRoot,
        fixture.log10_commitment,
        fixture.log10_proof,
        fixture.log10_queryHints,
        fixture.log8_commitment,
        fixture.log8_proof,
        fixture.log8_queryHints,
      )
    ).to.be.revertedWithCustomError(registry4, "BatchAlreadyFinalized");
  });

  it("submitBatch reverts Log10ProofInvalid when LOG=10 commitment is zero", async function () {
    const newRoot = "0x" + "1a".repeat(32);
    await expect(
      registry4.submitBatch(
        newRoot,
        "0x" + "00".repeat(16),   // zero commitment → commitment check fails → verify returns false
        fixture.log10_proof,
        fixture.log10_queryHints,
        fixture.log8_commitment,
        fixture.log8_proof,
        fixture.log8_queryHints,
      )
    ).to.be.revertedWithCustomError(registry4, "Log10ProofInvalid");
  });
});
