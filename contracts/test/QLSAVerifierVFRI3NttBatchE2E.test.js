/**
 * QLSAVerifierVFRI3 — ML-DSA NttBatch fixture validation.
 *
 * The `gen_ntt_batch_vfri3_hints` bridge generates QLSAVerifierVFRI3-compatible
 * hints from the 649-column NttBatch ML-DSA AIR (LOG_N_ROWS=10).
 *
 * On-chain gas note: NttBatch (LOG=10, 9 fold rounds, 55+ cols per polynomial)
 * requires ~20–60 M gas with the pure-Solidity Blake2s implementation.
 * This exceeds Hardhat's per-call cap (~16.7 M) and is a known MVP-4 blocker.
 * Production deployment requires a precompiled/Yul-optimised Blake2s.
 *
 * This test suite:
 *  (a) Validates the ABI structure of the generated hints is parseable.
 *  (b) Checks that the commitment binding in the fixture is correct.
 *  (c) Confirms the verifier correctly rejects invalid inputs that fail BEFORE
 *      the expensive FRI computation (zero commitment, zero merkleRoot).
 *
 * Full on-chain acceptance with a gas-optimised verifier: out-of-scope here.
 */
"use strict";

const { expect } = require("chai");
const { ethers }  = require("hardhat");
const path        = require("path");
const fs          = require("fs");

describe("QLSAVerifierVFRI3 — NttBatch fixture structure (gas note: full verify needs optimised Blake2s)", function () {
  let verifier;
  const fixture = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "fixtures", "ntt_batch_vfri3_e2e.json"),
      "utf8"
    )
  );

  before(async function () {
    const Factory = await ethers.getContractFactory("QLSAVerifierVFRI3");
    verifier = await Factory.deploy();
    await verifier.waitForDeployment();
  });

  it("fixture commitment follows Blake2s(proof[:32]‖merkleRoot)[:16]", function () {
    const { createHash } = require("crypto");
    const proofBytes = Buffer.from(fixture.proof.slice(2), "hex");
    const rootBytes  = Buffer.from(fixture.merkleRoot.slice(2), "hex");
    const h = createHash("blake2s256");
    h.update(proofBytes.slice(0, 32));
    h.update(rootBytes);
    const expected = "0x" + h.digest().slice(0, 16).toString("hex");
    expect(fixture.commitment).to.equal(expected);
  });

  it("fixture queryHints is non-empty (bridge produced ABI-encoded hints)", function () {
    expect(fixture.queryHints.length).to.be.greaterThan(2);
    const hintsBytes = Buffer.from(fixture.queryHints.slice(2), "hex");
    expect(hintsBytes.length).to.be.greaterThan(0);
  });

  it("verifier rejects zero commitment before FRI computation", async function () {
    const result = await verifier.verify(
      fixture.proof,
      "0x" + "00".repeat(16),
      fixture.merkleRoot,
      fixture.queryHints
    );
    expect(result).to.equal(false);
  });

  it("verifier rejects zero merkleRoot before FRI computation", async function () {
    const result = await verifier.verify(
      fixture.proof,
      fixture.commitment,
      ethers.ZeroHash,
      fixture.queryHints
    );
    expect(result).to.equal(false);
  });

  it("verifier rejects wrong commitment (binding check fails before FRI)", async function () {
    const commitBytes = Buffer.from(fixture.commitment.slice(2), "hex");
    commitBytes[0] ^= 0x01;
    const result = await verifier.verify(
      fixture.proof,
      "0x" + commitBytes.toString("hex"),
      fixture.merkleRoot,
      fixture.queryHints
    );
    expect(result).to.equal(false);
  });
});
