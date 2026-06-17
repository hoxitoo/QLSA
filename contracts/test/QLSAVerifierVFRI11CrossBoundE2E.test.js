/**
 * QLSAVerifierVFRI11 — full V23 cross-bound structural E2E (Poseidon2 t=8 backend).
 *
 * VFRI11 is ABI-identical to VFRI9/VFRI10; only the hash backend widens to t=8
 * (4-word/124-bit nodes), so the BatchRegistryV5 cross-binding
 * (boundRoot = keccak256(merkleRoot ‖ traceRoot)) is unchanged.
 *
 * Fixture: full_v23_vfri11_cross_bound_e2e.json — regenerate via
 *   PYTHONPATH=. python contracts/test/fixtures/gen_full_v23_vfri11_fixture.py
 *   (V23 inputs seed=16600, n_queries=1, num_folds=6).  Both LOG groups carry
 *   version marker 5.
 *
 * GAS FINDING (2026-06-16): on-chain verify() of a FULL V23 t=8 group exceeds
 * 100M gas at depth-10 (estimateGas runs out at the 100M block limit) — the t=8
 * permutation is ~3–4× t=4 per call, and the depth-10 Merkle paths + 6 fold
 * rounds compound it.  The t=8 backend's on-chain *correctness* is proven at
 * small scale by QLSAVerifierVFRI11E2E (generic depth-4 fixture, ~13.1M gas,
 * verify()==true).  Production full-V23 t=8 verification needs proof recursion
 * (constant on-chain cost) — wider permutations raise security but not the gas
 * budget.  This suite therefore asserts the structural + cross-binding
 * invariants (which are gas-cheap) and documents the wall.
 * If the fixture is absent, fixture-dependent tests skip.
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const path = require("path");
const fs = require("fs");

const FIXTURE_PATH = path.join(__dirname, "fixtures", "full_v23_vfri11_cross_bound_e2e.json");
const FIXTURE_EXISTS = fs.existsSync(FIXTURE_PATH);

const HINTS_ABI = [
  "uint128", "uint128", "bytes32", "uint128[]", "bytes32[]",
  "tuple(uint256,uint256,uint128,bytes32[],uint128,bytes32[],uint128,uint256,uint256,bytes32[],tuple(uint128,bytes32[],uint128,bytes32[])[])[]",
];

function boundRoot(merkleRoot, proofHex) {
  const proof = Buffer.from(proofHex.slice(2), "hex");
  const traceRoot = "0x" + proof.slice(8, 40).toString("hex");
  return ethers.keccak256(ethers.solidityPacked(["bytes32", "bytes32"], [merkleRoot, traceRoot]));
}

describe("QLSAVerifierVFRI11 — full V23 cross-bound structural E2E", function () {
  let verifier, registry5, signer, fixture;

  before(async function () {
    [signer] = await ethers.getSigners();

    verifier = await (await ethers.getContractFactory("QLSAVerifierVFRI11")).deploy();
    await verifier.waitForDeployment();

    // VFRI11 implements IQLSAVerifierV4, so BatchRegistryV5 accepts it directly.
    registry5 = await (await ethers.getContractFactory("BatchRegistryV5"))
      .deploy(signer.address, await verifier.getAddress());
    await registry5.waitForDeployment();

    if (FIXTURE_EXISTS) {
      fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
    }
  });

  // ── Wiring ──────────────────────────────────────────────────────────────────

  it("BatchRegistryV5 wires the VFRI11 verifier", async function () {
    expect(await registry5.verifier()).to.equal(await verifier.getAddress());
  });

  it("verifier exposes the expected constants", async function () {
    expect(await verifier.MIN_QUERIES()).to.equal(1n);
    expect(await verifier.MAX_QUERIES()).to.equal(64n);
    expect(await verifier.MAX_LAST_LAYER_SIZE()).to.equal(1n << 16n);
  });

  // ── Fixture structure ───────────────────────────────────────────────────────

  it("fixture has both LOG groups with required keys", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    for (const k of ["merkleRoot",
      "log10_proof", "log10_commitment", "log10_queryHints",
      "log8_proof", "log8_commitment", "log8_queryHints"]) {
      expect(fixture, `missing key: ${k}`).to.have.property(k);
    }
  });

  it("both proofs carry the VFRI11 version marker (5)", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const p10 = Buffer.from(fixture.log10_proof.slice(2), "hex");
    const p8 = Buffer.from(fixture.log8_proof.slice(2), "hex");
    expect(p10.readBigUInt64LE(0)).to.equal(5n);
    expect(p8.readBigUInt64LE(0)).to.equal(5n);
  });

  it("both groups decode with the 6-slot VFRI9/10/11 ABI", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const abi = ethers.AbiCoder.defaultAbiCoder();
    for (const hints of [fixture.log10_queryHints, fixture.log8_queryHints]) {
      const [, , , lastLayerEvals, friLayerRoots, hs] = abi.decode(HINTS_ABI, hints);
      expect(friLayerRoots.length).to.equal(7);      // num_folds=6 → 7 roots
      expect(lastLayerEvals.length).to.be.greaterThan(0);
      expect(hs.length).to.equal(fixture.n_queries);
    }
  });

  // ── Commitment binding (cross-bound roots) ──────────────────────────────────

  it("commitments bind Blake2s(proof[:32] ‖ boundRoot)[:16] for both groups", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const { createHash } = require("crypto");
    // BatchRegistryV5 binds each group to the OTHER group's trace root.
    const boundRoot10 = boundRoot(fixture.merkleRoot, fixture.log8_proof);
    const boundRoot8 = boundRoot(fixture.merkleRoot, fixture.log10_proof);
    for (const [proofHex, commit, br] of [
      [fixture.log10_proof, fixture.log10_commitment, boundRoot10],
      [fixture.log8_proof, fixture.log8_commitment, boundRoot8],
    ]) {
      const proof = Buffer.from(proofHex.slice(2), "hex");
      const h = createHash("blake2s256");
      h.update(proof.slice(0, 32));
      h.update(Buffer.from(br.slice(2), "hex"));
      expect("0x" + h.digest().slice(0, 16).toString("hex")).to.equal(commit);
    }
  });

  it("cross-bound roots differ from the raw merkleRoot (binding is applied)", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    expect(boundRoot(fixture.merkleRoot, fixture.log8_proof)).to.not.equal(fixture.merkleRoot);
    expect(boundRoot(fixture.merkleRoot, fixture.log10_proof)).to.not.equal(fixture.merkleRoot);
    // Each group is bound to a DIFFERENT root (the other's trace root).
    expect(boundRoot(fixture.merkleRoot, fixture.log8_proof))
      .to.not.equal(boundRoot(fixture.merkleRoot, fixture.log10_proof));
  });

  // ── Gas wall documentation ──────────────────────────────────────────────────

  it("documents that full-V23 t=8 verify() exceeds the 100M gas budget", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(120_000);
    const boundRoot10 = boundRoot(fixture.merkleRoot, fixture.log8_proof);
    let outOfGas = false;
    try {
      // estimateGas binary-searches up to the 100M block limit; for the depth-10
      // LOG=10 t=8 group it runs out, confirming the documented wall.
      await verifier.verify.estimateGas(
        fixture.log10_proof, fixture.log10_commitment, boundRoot10, fixture.log10_queryHints
      );
    } catch (e) {
      outOfGas = /gas/i.test(e.message);
    }
    expect(outOfGas, "full-V23 t=8 LOG=10 verify is expected to exceed 100M gas").to.equal(true);
  });
});
