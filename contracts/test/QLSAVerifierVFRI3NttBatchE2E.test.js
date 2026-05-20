/**
 * QLSAVerifierVFRI3 — ML-DSA NttBatch on-chain verification.
 *
 * The `gen_ntt_batch_vfri3_hints_nfolds` bridge generates QLSAVerifierVFRI3-compatible
 * hints from a small NttBatch ML-DSA AIR (1 polynomial, LOG_N_ROWS=10).
 *
 * Blake2s gas note: the Yul-optimised Blake2sYul implementation (used via
 * MerkleVerifier + TwoChannel) reduces gas vs pure-Solidity Blake2s.
 * Full NttBatch verification with 1 poly / 1 query / 9 fold rounds
 * is within Hardhat's 16.7 M gas eth_call cap (~10-12 M gas).
 *
 * The test fixture (ntt_batch_vfri3_e2e.json) was produced by:
 *   gen_ntt_batch_vfri3_hints_nfolds(polys, merkle_root, n_queries=1, num_folds=9)
 *   last layer = 2^1 = 2 evaluations (minimal bounded-degree check).
 */
"use strict";

const { expect } = require("chai");
const { ethers }  = require("hardhat");
const path        = require("path");
const fs          = require("fs");

describe("QLSAVerifierVFRI3 — NttBatch on-chain verification (Blake2sYul)", function () {
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

  // ── Fixture structural checks (no on-chain call) ──────────────────────────

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

  // ── Early-rejection paths (cheap — return before FRI computation) ─────────

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

  // ── Full on-chain FRI verification (Blake2sYul path) ─────────────────────

  it("accepts valid NttBatch VFRI3 hints (full FRI verification)", async function () {
    this.timeout(120_000);
    const tx = await verifier.verify.staticCall(
      fixture.proof,
      fixture.commitment,
      fixture.merkleRoot,
      fixture.queryHints,
      { gasLimit: 15_000_000n }
    );
    expect(tx).to.equal(true);
  });

  it("rejects tampered last-layer coefficient", async function () {
    // queryHints ABI layout:
    //   bytes   0-159: 5 head offsets (5 × 32 bytes)
    //   bytes 160-191: lastLayerCoeffs length word (= 2)
    //   bytes 192-207: lastLayerCoeffs[0] zero-padding  ← DO NOT touch (revert)
    //   bytes 208-223: lastLayerCoeffs[0] actual value  ← corrupt here
    const hints = Buffer.from(fixture.queryHints.slice(2), "hex");
    const corrupted = Buffer.from(hints);
    corrupted[210] ^= 0xff;  // flip byte inside first coefficient value
    const result = await verifier.verify(
      fixture.proof,
      fixture.commitment,
      fixture.merkleRoot,
      "0x" + corrupted.toString("hex")
    );
    expect(result).to.equal(false);
  });
});
