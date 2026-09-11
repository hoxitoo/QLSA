/**
 * QLSAVerifierVFRI8 — E2E test: cross-proof binding with Poseidon2 trace commitment.
 *
 * VFRI8 changes from VFRI7:
 *   All hash operations use Poseidon2-over-M31 instead of Blake2s:
 *   - Merkle trees: Poseidon2MerkleVerifier (hashLeaf + hashPair)
 *   - Fiat-Shamir channel: Poseidon2Channel (absorb/draw sponge)
 *   The commitment check (_checkCommitment) still uses Blake2s for the outer
 *   16-byte binding (single cheap call, not a bottleneck).
 *
 *   Cross-proof binding (identical to BatchRegistryV4/VFRI7):
 *     boundRoot10 = keccak256(batchRoot ‖ proof8[8:40])   (traceRoot of LOG=8 group)
 *     boundRoot8  = keccak256(batchRoot ‖ proof10[8:40])  (traceRoot of LOG=10 group)
 *
 *   Gas target: ≤ 15M gas per verify() call.
 *   Poseidon2 Merkle path at depth=10: 10 permutes × ~1000 gas = 10K gas per path.
 *   20 queries × 2 paths × 10K ≈ 400K gas (Merkle) + ~5M (OODS+folds) ≈ 5.4M total.
 *
 * Fixture: full_v23_vfri8_cross_bound_e2e.json
 *   Keys: merkleRoot, log10_proof, log10_commitment, log10_queryHints,
 *         log8_proof, log8_commitment, log8_queryHints,
 *         bound_root_10, bound_root_8, n_queries
 *
 * NOTE: The fixture file must be generated before running these tests:
 *   python -c "
 *     from stark.prover import gen_mldsa_v23_vfri8_cross_bound_hints
 *     import json, os
 *     # ... (see fixture generation script)
 *   "
 * If the fixture file is absent, all tests will be skipped with a clear message.
 */
"use strict";

const { expect } = require("chai");
const { ethers }  = require("hardhat");
const path        = require("path");
const fs          = require("fs");

const FIXTURE_PATH = path.join(__dirname, "fixtures", "full_v23_vfri8_cross_bound_e2e.json");
const FIXTURE_EXISTS = fs.existsSync(FIXTURE_PATH);

describe("QLSAVerifierVFRI8 — Cross-Proof Binding E2E (VFRI8 / Poseidon2)", function () {
  let verifier8, registry5;
  let fixture;

  before(async function () {
    if (!FIXTURE_EXISTS) {
      console.log("    ⚠  Fixture not found — skipping all E2E tests.");
      console.log("       Generate with: python scripts/gen_vfri8_fixture.py");
      this.skip();
      return;
    }

    fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));

    const [signer] = await ethers.getSigners();

    const V8Factory = await ethers.getContractFactory("QLSAVerifierVFRI8");
    verifier8 = await V8Factory.deploy();
    await verifier8.waitForDeployment();

    const RFactory = await ethers.getContractFactory("BatchRegistryV5");
    registry5 = await RFactory.deploy(signer.address, await verifier8.getAddress());
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

  it("LOG=8 commitment binds Blake2s(proof[:32]‖bound_root_8)[:16]", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
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
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const proof8 = Buffer.from(fixture.log8_proof.slice(2), "hex");
    const traceRoot8 = "0x" + proof8.slice(8, 40).toString("hex");
    const computed = ethers.keccak256(
      ethers.solidityPacked(["bytes32","bytes32"], [fixture.merkleRoot, traceRoot8])
    );
    expect(computed).to.equal(fixture.bound_root_10);
  });

  it("bound_root_8 = keccak256(merkleRoot ‖ proof10[8:40])", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const proof10 = Buffer.from(fixture.log10_proof.slice(2), "hex");
    const traceRoot10 = "0x" + proof10.slice(8, 40).toString("hex");
    const computed = ethers.keccak256(
      ethers.solidityPacked(["bytes32","bytes32"], [fixture.merkleRoot, traceRoot10])
    );
    expect(computed).to.equal(fixture.bound_root_8);
  });

  it("LOG=10 and LOG=8 trace roots are distinct (different domains)", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const proof10 = Buffer.from(fixture.log10_proof.slice(2), "hex");
    const proof8  = Buffer.from(fixture.log8_proof.slice(2),  "hex");
    const tr10 = proof10.slice(8, 40).toString("hex");
    const tr8  = proof8.slice(8,  40).toString("hex");
    expect(tr10).to.not.equal(tr8);
  });

  // ── VFRI8 verifier verify() ───────────────────────────────────────────────

  it("verify() returns true for LOG=10 proof with bound_root_10 (within 15M gas)", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(60_000);
    let result = false;
    try {
      result = await verifier8.verify.staticCall(
        fixture.log10_proof,
        fixture.log10_commitment,
        fixture.bound_root_10,
        fixture.log10_queryHints,
        { gasLimit: 15_000_000n }
      );
    } catch (e) {
      expect.fail(`verify() reverted: ${e.message}`);
    }
    expect(result).to.equal(true, "VFRI8 LOG=10 verify must return true");
    console.log("    ✓ VFRI8 LOG=10 verify() = true within 15M gas");
  });

  it("verify() returns true for LOG=8 proof with bound_root_8 (within 15M gas)", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(60_000);
    let result = false;
    try {
      result = await verifier8.verify.staticCall(
        fixture.log8_proof,
        fixture.log8_commitment,
        fixture.bound_root_8,
        fixture.log8_queryHints,
        { gasLimit: 15_000_000n }
      );
    } catch (e) {
      expect.fail(`verify() reverted: ${e.message}`);
    }
    expect(result).to.equal(true, "VFRI8 LOG=8 verify must return true");
    console.log("    ✓ VFRI8 LOG=8 verify() = true within 15M gas");
  });

  it("verify() returns false when wrong merkleRoot is passed (binding check)", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(30_000);
    const wrongRoot = "0x" + "ff".repeat(32);
    const result = await verifier8.verify.staticCall(
      fixture.log10_proof,
      fixture.log10_commitment,
      wrongRoot,
      fixture.log10_queryHints
    );
    expect(result).to.equal(false, "Wrong merkleRoot must cause verify() to return false");
  });

  it("verify() returns false when raw merkleRoot (not bound_root_10) is used for LOG=10", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(30_000);
    const result = await verifier8.verify.staticCall(
      fixture.log10_proof,
      fixture.log10_commitment,
      fixture.merkleRoot,
      fixture.log10_queryHints
    );
    expect(result).to.equal(false, "Raw merkleRoot (not bound_root) must cause verify() to return false");
  });

  it("verify() returns false when LOG=10 commitment is zero", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const result = await verifier8.verify.staticCall(
      fixture.log10_proof,
      "0x" + "00".repeat(16),
      fixture.bound_root_10,
      fixture.log10_queryHints
    );
    expect(result).to.equal(false);
  });

  it("verify() returns false when merkleRoot is zero", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const result = await verifier8.verify.staticCall(
      fixture.log10_proof,
      fixture.log10_commitment,
      "0x" + "00".repeat(32),
      fixture.log10_queryHints
    );
    expect(result).to.equal(false);
  });

  // ── BatchRegistryV5 integration ───────────────────────────────────────────

  it("BatchRegistryV5 finalizes with VFRI8 verifier on-chain cross-binding", async function () {
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
    const parsed = registry5.interface.parseLog(event);
    expect(parsed.args.merkleRoot).to.equal(fixture.merkleRoot);
    expect(parsed.args.commitmentLog10).to.equal(fixture.log10_commitment);
    expect(parsed.args.commitmentLog8).to.equal(fixture.log8_commitment);
    console.log("    ✓ BatchRegistryV5.submitBatch() finalized with VFRI8 cross-bound proofs");
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

  it("submitBatch reverts Log10ProofInvalid when LOG=10 commitment is zero", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const newRoot = "0x" + "1a".repeat(32);
    await expect(
      registry5.submitBatch(
        newRoot,
        "0x" + "00".repeat(16),
        fixture.log10_proof,
        fixture.log10_queryHints,
        fixture.log8_commitment,
        fixture.log8_proof,
        fixture.log8_queryHints,
      )
    ).to.be.revertedWithCustomError(registry5, "Log10ProofInvalid");
  });

  // ── Deployment-only tests (run even without fixture) ─────────────────────

  describe("deployment checks (no fixture required)", function () {
    let v8addr, r5addr;

    before(async function () {
      if (!FIXTURE_EXISTS) {
        // Deploy fresh instances since before() above skipped
        const [signer] = await ethers.getSigners();
        const V8 = await ethers.getContractFactory("QLSAVerifierVFRI8");
        const v8 = await V8.deploy();
        await v8.waitForDeployment();
        v8addr = await v8.getAddress();

        const R5 = await ethers.getContractFactory("BatchRegistryV5");
        const r5 = await R5.deploy(signer.address, v8addr);
        await r5.waitForDeployment();
        r5addr = await r5.getAddress();
      } else {
        v8addr = await verifier8.getAddress();
        r5addr = await registry5.getAddress();
      }
    });

    it("QLSAVerifierVFRI8 deploys successfully", async function () {
      const V8 = await ethers.getContractFactory("QLSAVerifierVFRI8");
      const v8 = await V8.deploy();
      await v8.waitForDeployment();
      expect(await v8.getAddress()).to.match(/^0x[0-9a-fA-F]{40}$/);
    });

    it("BatchRegistryV5 deploys with VFRI8 verifier", async function () {
      const [signer] = await ethers.getSigners();
      const V8 = await ethers.getContractFactory("QLSAVerifierVFRI8");
      const v8 = await V8.deploy();
      await v8.waitForDeployment();

      const R5 = await ethers.getContractFactory("BatchRegistryV5");
      const r5 = await R5.deploy(signer.address, await v8.getAddress());
      await r5.waitForDeployment();
      expect(await r5.verifier()).to.equal(await v8.getAddress());
    });

    it("BatchRegistryV5 reverts InvalidMerkleRoot for zero root", async function () {
      const [signer] = await ethers.getSigners();
      const V8 = await ethers.getContractFactory("QLSAVerifierVFRI8");
      const v8 = await V8.deploy();
      await v8.waitForDeployment();

      const R5 = await ethers.getContractFactory("BatchRegistryV5");
      const r5 = await R5.deploy(signer.address, await v8.getAddress());
      await r5.waitForDeployment();

      await expect(
        r5.submitBatch(
          "0x" + "00".repeat(32),
          "0x" + "00".repeat(16),
          "0x",
          "0x",
          "0x" + "00".repeat(16),
          "0x",
          "0x",
        )
      ).to.be.revertedWithCustomError(r5, "InvalidMerkleRoot");
    });

    it("BatchRegistryV5 reverts ZeroAddressVerifier in constructor", async function () {
      const [signer] = await ethers.getSigners();
      const R5 = await ethers.getContractFactory("BatchRegistryV5");
      await expect(
        R5.deploy(signer.address, ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(R5, "ZeroAddressVerifier");
    });

    it("MAX_SENDERS constant is 3000", async function () {
      const [signer] = await ethers.getSigners();
      const V8 = await ethers.getContractFactory("QLSAVerifierVFRI8");
      const v8 = await V8.deploy();
      await v8.waitForDeployment();

      const R5 = await ethers.getContractFactory("BatchRegistryV5");
      const r5 = await R5.deploy(signer.address, await v8.getAddress());
      await r5.waitForDeployment();

      expect(await r5.MAX_SENDERS()).to.equal(3000n);
    });
  });
});
