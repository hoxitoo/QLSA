/**
 * QLSAVerifierVFRI12 — full V23 cross-bound E2E (Poseidon2 t=16 backend).
 *
 * THE question this file answers: is 128-bit Merkle-node binding reachable by
 * DIRECT on-chain verification, or only through recursion?
 *
 * VFRI12 is ABI-identical to VFRI9/VFRI10/VFRI11; only the hash backend widens
 * to t=16 (8-word/248-bit nodes → node collision ~2^124 ≈ 128-bit, versus t=8's
 * ~2^62). The BatchRegistryV5 cross-binding (boundRoot = keccak256(merkleRoot ‖
 * traceRoot)) is therefore unchanged, and the same registry accepts it.
 *
 * The fixture is generated from the SAME V23 inputs, seed, n_queries and
 * num_folds as full_v23_vfri11_cross_bound_e2e.json, so the gas figures here and
 * in QLSAVerifierVFRI11CrossBoundE2E.test.js differ ONLY by hash width and are
 * directly comparable.
 *
 * Fixture: full_v23_vfri12_cross_bound_e2e.json — regenerate via
 *   cargo test write_v23_vfri12_fixture -- --ignored --nocapture
 * If the fixture is absent, fixture-dependent tests skip.
 *
 * Measured with gasUsed of a SENT transaction, never estimateGas — the latter
 * over-provisions nested calls by ~3x (docs/conclusions.md §1.2), and a gasLimit
 * above 2^24 is rejected before execution rather than running out (§1.1).
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const path = require("path");
const fs = require("fs");

const FIXTURE_PATH = path.join(__dirname, "fixtures", "full_v23_vfri12_cross_bound_e2e.json");
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

describe("QLSAVerifierVFRI12 — full V23 cross-bound E2E (t=16, 128-bit nodes)", function () {
  let verifier, registry5, signer, fixture;

  before(async function () {
    [signer] = await ethers.getSigners();

    verifier = await (await ethers.getContractFactory("QLSAVerifierVFRI12")).deploy();
    await verifier.waitForDeployment();

    // VFRI12 implements IQLSAVerifierV4, so BatchRegistryV5 accepts it unchanged.
    registry5 = await (await ethers.getContractFactory("BatchRegistryV5"))
      .deploy(signer.address, await verifier.getAddress());
    await registry5.waitForDeployment();

    if (FIXTURE_EXISTS) fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  });

  // ── Wiring ──────────────────────────────────────────────────────────────────

  it("BatchRegistryV5 wires the VFRI12 verifier with no registry change", async function () {
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

  it("both proofs carry the VFRI12 version marker (6)", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    expect(Buffer.from(fixture.log10_proof.slice(2), "hex").readBigUInt64LE(0)).to.equal(6n);
    expect(Buffer.from(fixture.log8_proof.slice(2), "hex").readBigUInt64LE(0)).to.equal(6n);
  });

  it("both groups decode with the 6-slot VFRI9/10/11/12 ABI", function () {
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
    const boundRoot10 = boundRoot(fixture.merkleRoot, fixture.log8_proof);
    const boundRoot8 = boundRoot(fixture.merkleRoot, fixture.log10_proof);
    for (const [proofHex, commit, br] of [
      [fixture.log10_proof, fixture.log10_commitment, boundRoot10],
      [fixture.log8_proof, fixture.log8_commitment, boundRoot8],
    ]) {
      const h = createHash("blake2s256");
      h.update(Buffer.from(proofHex.slice(2), "hex").slice(0, 32));
      h.update(Buffer.from(br.slice(2), "hex"));
      expect("0x" + h.digest().slice(0, 16).toString("hex")).to.equal(commit);
    }
  });

  it("each group is bound to the OTHER group's trace root", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const b10 = boundRoot(fixture.merkleRoot, fixture.log8_proof);
    const b8 = boundRoot(fixture.merkleRoot, fixture.log10_proof);
    expect(b10).to.not.equal(fixture.merkleRoot);
    expect(b8).to.not.equal(fixture.merkleRoot);
    expect(b10).to.not.equal(b8);
  });

  // ── On-chain acceptance ─────────────────────────────────────────────────────

  it("full-V23 t=16 LOG=10 verify() accepts inside the per-tx gas cap", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(300_000);
    const ok = await verifier.verify.staticCall(
      fixture.log10_proof, fixture.log10_commitment,
      boundRoot(fixture.merkleRoot, fixture.log8_proof), fixture.log10_queryHints,
      { gasLimit: 16_777_215n }
    );
    expect(ok).to.equal(true, "LOG=10 t=16 group must verify");
  });

  it("full-V23 t=16 LOG=8 verify() accepts inside the per-tx gas cap", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(300_000);
    const ok = await verifier.verify.staticCall(
      fixture.log8_proof, fixture.log8_commitment,
      boundRoot(fixture.merkleRoot, fixture.log10_proof), fixture.log8_queryHints,
      { gasLimit: 16_777_215n }
    );
    expect(ok).to.equal(true, "LOG=8 t=16 group must verify");
  });

  it("rejects a t=16 proof under the t=8 verifier (backend mismatch)", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(300_000);
    const V11 = await (await ethers.getContractFactory("QLSAVerifierVFRI11")).deploy();
    await V11.waitForDeployment();
    const ok = await V11.verify.staticCall(
      fixture.log10_proof, fixture.log10_commitment,
      boundRoot(fixture.merkleRoot, fixture.log8_proof), fixture.log10_queryHints,
      { gasLimit: 16_777_215n }
    );
    expect(ok).to.equal(false, "t=16 hints must not verify under the t=8 backend");
  });

  // THE headline measurement. If this passes, 128-bit node binding is reachable
  // by direct verification in a single Ethereum transaction — which the project
  // had recorded as impossible, on an extrapolation rather than a measurement.
  it("BatchRegistryV5 finalizes both t=16 groups in ONE transaction", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(600_000);
    const [owner] = await ethers.getSigners();
    const reg = await (await ethers.getContractFactory("BatchRegistryV5"))
      .deploy(owner.address, await verifier.getAddress());
    await reg.waitForDeployment();

    const tx = await reg.submitBatch(
      fixture.merkleRoot,
      fixture.log10_commitment, fixture.log10_proof, fixture.log10_queryHints,
      fixture.log8_commitment, fixture.log8_proof, fixture.log8_queryHints,
      { gasLimit: 16_777_215n }
    );
    const rc = await tx.wait();
    console.log(`        [gas] dual-VFRI12 (t=16, 2^124 nodes) submitBatch = ${rc.gasUsed}`);
    expect(rc.gasUsed).to.be.lessThan(
      16_777_216n, "dual t=16 verify must fit one transaction");
    expect(await reg.isBatchFinalized(fixture.merkleRoot)).to.equal(true);
  });
});
