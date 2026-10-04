/**
 * QLSAVerifierVFRI9 — E2E test: last-layer FRI check + wide Poseidon2 nodes.
 *
 * VFRI9 changes from VFRI8:
 *   1. Last-layer bounded-degree check: prover supplies all 2^(treeDepth-K)
 *      evaluations of the final FRI layer; verifier rebuilds the Merkle tree
 *      and asserts root == friLayerRoots[K].  Closes the VFRI5..8 soundness gap.
 *   2. Wide (62-bit) Poseidon2 Merkle nodes via Poseidon2MerkleVerifierW —
 *      node collision cost 2^15.5 → 2^31.
 *   3. Full-root Fiat-Shamir absorption (mixRootFull / mixRootW) — all 32
 *      bytes of the trace root and batch merkle root are bound.
 *
 *   queryHints ABI (6 head slots):
 *     abi.encode(uint128 oodsComboPos, uint128 oodsComboNeg, bytes32 compRoot,
 *                uint128[] lastLayerEvals, bytes32[] friLayerRoots, QueryHints[])
 *
 *   Cross-proof binding (identical to BatchRegistryV4/V5):
 *     boundRoot10 = keccak256(batchRoot ‖ proof8[8:40])
 *     boundRoot8  = keccak256(batchRoot ‖ proof10[8:40])
 *
 * Fixture: full_v23_vfri9_cross_bound_e2e.json (generated via
 *   stark.prover.gen_mldsa_v23_vfri9_cross_bound_hints, seed=16600,
 *   n_queries=1, num_folds=3).
 * If the fixture file is absent, fixture-dependent tests are skipped.
 */
"use strict";

const { expect } = require("chai");
const { ethers }  = require("hardhat");
const path        = require("path");
const fs          = require("fs");

const FIXTURE_PATH = path.join(__dirname, "fixtures", "full_v23_vfri9_cross_bound_e2e.json");
const FIXTURE_EXISTS = fs.existsSync(FIXTURE_PATH);

describe("QLSAVerifierVFRI9 — Last-Layer Check + Wide Poseidon2 E2E", function () {
  let verifier9, registry5;
  let fixture;

  before(async function () {
    if (!FIXTURE_EXISTS) {
      console.log("    ⚠  Fixture not found — skipping all E2E tests.");
      this.skip();
      return;
    }

    fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));

    const [signer] = await ethers.getSigners();

    const V9Factory = await ethers.getContractFactory("QLSAVerifierVFRI9");
    verifier9 = await V9Factory.deploy();
    await verifier9.waitForDeployment();

    const RFactory = await ethers.getContractFactory("BatchRegistryV5");
    registry5 = await RFactory.deploy(signer.address, await verifier9.getAddress());
    await registry5.waitForDeployment();
  });

  // ── Fixture structural checks ─────────────────────────────────────────────

  it("fixture has required keys", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const keys = ["merkleRoot","log10_proof","log10_commitment","log10_queryHints",
                  "log8_proof","log8_commitment","log8_queryHints",
                  "bound_root_10","bound_root_8","n_queries"];
    for (const k of keys) {
      expect(fixture, `missing key: ${k}`).to.have.property(k);
    }
  });

  it("proof version marker is 3 (VFRI9)", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const proof = Buffer.from(fixture.log10_proof.slice(2), "hex");
    expect(proof.readBigUInt64LE(0)).to.equal(3n);
  });

  it("hints decode with the 6-slot VFRI9 ABI (lastLayerEvals present)", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const abi = ethers.AbiCoder.defaultAbiCoder();
    const [, , , lastLayerEvals, friLayerRoots] = abi.decode(
      ["uint128", "uint128", "bytes32", "uint128[]", "bytes32[]",
       "tuple(uint256,uint256,uint128,bytes32[],uint128,bytes32[],uint128,uint256,uint256,bytes32[],tuple(uint128,bytes32[],uint128,bytes32[])[])[]"],
      fixture.log10_queryHints
    );
    // depth=10, 3 folds → 1024/8 = 128 last-layer evaluations
    expect(lastLayerEvals.length).to.equal(128);
    expect(friLayerRoots.length).to.equal(4); // L1 root + 3 fold roots
  });

  it("LOG=10 commitment binds Blake2s(proof[:32]‖bound_root_10)[:16]", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const { createHash } = require("crypto");
    const proof = Buffer.from(fixture.log10_proof.slice(2), "hex");
    const root  = Buffer.from(fixture.bound_root_10.slice(2), "hex");
    const h = createHash("blake2s256");
    h.update(proof.slice(0, 32));
    h.update(root);
    expect("0x" + h.digest().slice(0, 16).toString("hex"))
      .to.equal(fixture.log10_commitment);
  });

  it("bound roots match keccak256(merkleRoot ‖ cross trace root)", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const proof10 = Buffer.from(fixture.log10_proof.slice(2), "hex");
    const proof8  = Buffer.from(fixture.log8_proof.slice(2),  "hex");
    const tr10 = "0x" + proof10.slice(8, 40).toString("hex");
    const tr8  = "0x" + proof8.slice(8, 40).toString("hex");
    expect(ethers.keccak256(ethers.solidityPacked(
      ["bytes32","bytes32"], [fixture.merkleRoot, tr8]))).to.equal(fixture.bound_root_10);
    expect(ethers.keccak256(ethers.solidityPacked(
      ["bytes32","bytes32"], [fixture.merkleRoot, tr10]))).to.equal(fixture.bound_root_8);
  });

  // ── VFRI9 verifier verify() ───────────────────────────────────────────────

  it("verify() returns true for LOG=10 proof with bound_root_10 (within 15M gas)", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(60_000);
    let result = false;
    try {
      result = await verifier9.verify.staticCall(
        fixture.log10_proof,
        fixture.log10_commitment,
        fixture.bound_root_10,
        fixture.log10_queryHints,
        { gasLimit: 15_000_000n }
      );
    } catch (e) {
      expect.fail(`verify() reverted: ${e.message}`);
    }
    expect(result).to.equal(true, "VFRI9 LOG=10 verify must return true");
    console.log("    ✓ VFRI9 LOG=10 verify() = true within 15M gas");
  });

  it("verify() returns true for LOG=8 proof with bound_root_8 (within 15M gas)", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(60_000);
    let result = false;
    try {
      result = await verifier9.verify.staticCall(
        fixture.log8_proof,
        fixture.log8_commitment,
        fixture.bound_root_8,
        fixture.log8_queryHints,
        { gasLimit: 15_000_000n }
      );
    } catch (e) {
      expect.fail(`verify() reverted: ${e.message}`);
    }
    expect(result).to.equal(true, "VFRI9 LOG=8 verify must return true");
    console.log("    ✓ VFRI9 LOG=8 verify() = true within 15M gas");
  });

  // ── Last-layer check enforcement (the new soundness guarantee) ───────────

  it("verify() returns false when one last-layer evaluation is tampered", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(30_000);
    // lastLayerEvals starts at head(192) + length-word(32); flip one byte of eval[0].
    const hints = Buffer.from(fixture.log10_queryHints.slice(2), "hex");
    const evalsOffset = 6 * 32 + 32;
    hints[evalsOffset + 31] ^= 0x01;
    const result = await verifier9.verify.staticCall(
      fixture.log10_proof,
      fixture.log10_commitment,
      fixture.bound_root_10,
      "0x" + hints.toString("hex")
    );
    expect(result).to.equal(false, "Tampered last-layer evaluation must be rejected");
  });

  it("verify() returns false when a middle last-layer evaluation is tampered", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(30_000);
    const hints = Buffer.from(fixture.log10_queryHints.slice(2), "hex");
    const evalsOffset = 6 * 32 + 32 + 64 * 32; // eval[64] of 128
    hints[evalsOffset + 31] ^= 0x01;
    const result = await verifier9.verify.staticCall(
      fixture.log10_proof,
      fixture.log10_commitment,
      fixture.bound_root_10,
      "0x" + hints.toString("hex")
    );
    expect(result).to.equal(false, "Any tampered last-layer evaluation must be rejected");
  });

  it("verify() rejects VFRI8 hints (different ABI + transcript)", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(30_000);
    const VFRI8_FIXTURE = path.join(__dirname, "fixtures", "full_v23_vfri8_cross_bound_e2e.json");
    if (!fs.existsSync(VFRI8_FIXTURE)) { this.skip(); return; }
    const f8 = JSON.parse(fs.readFileSync(VFRI8_FIXTURE, "utf8"));
    let rejected = false;
    try {
      const result = await verifier9.verify.staticCall(
        f8.log10_proof,
        f8.log10_commitment,
        f8.bound_root_10,
        f8.log10_queryHints
      );
      rejected = (result === false);
    } catch (e) {
      rejected = true; // ABI decode revert is also a rejection
    }
    expect(rejected).to.equal(true, "VFRI9 must not accept VFRI8 hints");
  });

  // ── Binding rejections ───────────────────────────────────────────────────

  it("verify() returns false when wrong merkleRoot is passed", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(30_000);
    const result = await verifier9.verify.staticCall(
      fixture.log10_proof,
      fixture.log10_commitment,
      "0x" + "ff".repeat(32),
      fixture.log10_queryHints
    );
    expect(result).to.equal(false);
  });

  it("verify() returns false when raw merkleRoot (not bound_root_10) is used", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(30_000);
    const result = await verifier9.verify.staticCall(
      fixture.log10_proof,
      fixture.log10_commitment,
      fixture.merkleRoot,
      fixture.log10_queryHints
    );
    expect(result).to.equal(false);
  });

  it("verify() returns false when the proof's embedded trace root is tampered", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(30_000);
    // Flip a byte in proof[33] — inside embeddedRoot[8:40] but OUTSIDE the
    // Blake2s commitment binding range proof[0:32].  VFRI9's full-root
    // Fiat-Shamir absorption must still detect this (VFRI8's 4-byte mixRoot
    // would only catch changes in proof[36:40]).
    const proof = Buffer.from(fixture.log10_proof.slice(2), "hex");
    proof[33] ^= 0x01;
    const result = await verifier9.verify.staticCall(
      "0x" + proof.toString("hex"),
      fixture.log10_commitment,
      fixture.bound_root_10,
      fixture.log10_queryHints
    );
    expect(result).to.equal(false, "Tampered embedded root must change derived query indices");
  });

  it("verify() returns false when commitment is zero", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const result = await verifier9.verify.staticCall(
      fixture.log10_proof,
      "0x" + "00".repeat(16),
      fixture.bound_root_10,
      fixture.log10_queryHints
    );
    expect(result).to.equal(false);
  });

  it("verify() returns false when merkleRoot is zero", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const result = await verifier9.verify.staticCall(
      fixture.log10_proof,
      fixture.log10_commitment,
      "0x" + "00".repeat(32),
      fixture.log10_queryHints
    );
    expect(result).to.equal(false);
  });

  // ── BatchRegistryV5 integration (verifier-agnostic registry) ─────────────

  it("BatchRegistryV5 finalizes with the VFRI9 verifier", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(120_000);
    const tx = await registry5.submitBatch(
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
      try { return registry5.interface.parseLog(l)?.name === "BatchFinalized"; }
      catch { return false; }
    });
    expect(event, "BatchFinalized event must be emitted").to.not.be.undefined;
    console.log("    ✓ BatchRegistryV5.submitBatch() finalized with VFRI9 cross-bound proofs");
  });

  it("batch is marked finalized after submitBatch", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    expect(await registry5.isBatchFinalized(fixture.merkleRoot)).to.equal(true);
  });

  it("submitBatch reverts BatchAlreadyFinalized on replay", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    await expect(
      registry5.submitBatch(
        fixture.merkleRoot,
        fixture.log10_commitment,
        fixture.log10_proof,
        fixture.log10_queryHints,
        fixture.log8_commitment,
        fixture.log8_proof,
        fixture.log8_queryHints,
      )
    ).to.be.revertedWithCustomError(registry5, "BatchAlreadyFinalized");
  });

  // ── Deployment-only tests (run even without fixture) ─────────────────────

  describe("deployment checks (no fixture required)", function () {
    it("QLSAVerifierVFRI9 deploys successfully", async function () {
      const V9 = await ethers.getContractFactory("QLSAVerifierVFRI9");
      const v9 = await V9.deploy();
      await v9.waitForDeployment();
      expect(await v9.getAddress()).to.match(/^0x[0-9a-fA-F]{40}$/);
    });

    it("MAX_LAST_LAYER_SIZE constant is 65536", async function () {
      const V9 = await ethers.getContractFactory("QLSAVerifierVFRI9");
      const v9 = await V9.deploy();
      await v9.waitForDeployment();
      expect(await v9.MAX_LAST_LAYER_SIZE()).to.equal(65536n);
    });

    it("BatchRegistryV5 deploys with VFRI9 verifier", async function () {
      const [signer] = await ethers.getSigners();
      const V9 = await ethers.getContractFactory("QLSAVerifierVFRI9");
      const v9 = await V9.deploy();
      await v9.waitForDeployment();

      const R5 = await ethers.getContractFactory("BatchRegistryV5");
      const r5 = await R5.deploy(signer.address, await v9.getAddress());
      await r5.waitForDeployment();
      expect(await r5.verifier()).to.equal(await v9.getAddress());
    });
  });
});
