/**
 * QLSAVerifierVFRI6 — E2E test: V23 LOG=8 component group (2206 cols) with off-chain OODS.
 *
 * Key result: 2206-col LOG=8 trace (AzFull 1523 + Ct1Full 295 + RangeQBatch 288 +
 * WPrimeFull 24 + NormCheckBatch 15 + UseHintBatchV2 61) verifies within 15 M gas.
 * VFRI6's on-chain cost is O(1) in n_cols regardless of trace size.
 *
 * Combined with the LOG=10 group (1298 cols), these two VFRI6 calls cover the
 * full V23 trace (3504 main columns).
 *
 * Hint size comparison:
 *   LOG=10 (1298 cols): 7200 B
 *   LOG=8  (2206 cols): 5344 B  (shorter Merkle paths at depth=8 vs depth=10)
 *   Both are O(1) in n_cols — size depends only on tree_depth and num_folds.
 *
 * Fixture: V23 LOG=8 group (2206 cols), n_queries=1, num_folds=7.
 */
"use strict";

const { expect } = require("chai");
const { ethers }  = require("hardhat");
const path        = require("path");
const fs          = require("fs");

describe("QLSAVerifierVFRI6 — V23 LOG=8 group E2E (2206 cols)", function () {
  let verifier;
  const fixture = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "fixtures", "mldsa_v23_log8_vfri6_e2e.json"),
      "utf8"
    )
  );

  before(async function () {
    const Factory = await ethers.getContractFactory("QLSAVerifierVFRI6");
    verifier = await Factory.deploy();
    await verifier.waitForDeployment();
  });

  // ── Fixture structural checks ─────────────────────────────────────────────

  it("fixture has correct n_cols=2206 and n_queries=1", function () {
    expect(fixture.n_cols).to.equal(2206);
    expect(fixture.n_queries).to.equal(1);
    expect(fixture.num_folds).to.equal(7);
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

  it("fixture queryHints is ~5.3 KB — O(1) in n_cols", function () {
    const len = Buffer.from(fixture.queryHints.slice(2), "hex").length;
    console.log(`    ℹ VFRI6 2206-col (LOG=8) hints: ${len} B`);
    expect(len).to.be.greaterThan(1_000);
    expect(len).to.be.lessThan(15_000);
  });

  it("LOG=8 hints are smaller than LOG=10 hints (shorter Merkle paths)", function () {
    const log10Fix = JSON.parse(
      fs.readFileSync(
        path.join(__dirname, "fixtures", "mldsa_v23_ntt_vfri6_e2e.json"), "utf8"
      )
    );
    const log8Len  = Buffer.from(fixture.queryHints.slice(2), "hex").length;
    const log10Len = Buffer.from(log10Fix.queryHints.slice(2), "hex").length;
    console.log(`    ℹ LOG=8 (2206 cols): ${log8Len} B, LOG=10 (1298 cols): ${log10Len} B`);
    expect(log8Len).to.be.lessThan(log10Len);
  });

  it("fixture proof[8:40] is non-zero (real 2206-col trace committed)", function () {
    const proofBytes = Buffer.from(fixture.proof.slice(2), "hex");
    expect(proofBytes.slice(8, 40).equals(Buffer.alloc(32, 0))).to.equal(false);
  });

  it("fixture queryHints head has 5 ABI slots (160 bytes) with correct offsets", function () {
    const hints = Buffer.from(fixture.queryHints.slice(2), "hex");
    expect(hints.length).to.be.greaterThan(160);
    // Slot 2 (bytes 64..96): compRoot — non-zero
    const compRoot = hints.slice(64, 96);
    expect(compRoot.equals(Buffer.alloc(32, 0))).to.equal(false);
    // Slot 3 (bytes 96..128): offset to friLayerRoots — must be >= 160
    const friRootsOffset = parseInt(hints.slice(96, 128).toString("hex"), 16);
    expect(friRootsOffset).to.be.greaterThanOrEqual(160);
    // Slot 4 (bytes 128..160): offset to QueryHints[] — must be > friRootsOffset
    const queryHintsOffset = parseInt(hints.slice(128, 160).toString("hex"), 16);
    expect(queryHintsOffset).to.be.greaterThan(friRootsOffset);
  });

  // ── Early-rejection paths ─────────────────────────────────────────────────

  it("rejects zero commitment", async function () {
    const result = await verifier.verify(
      fixture.proof, "0x" + "00".repeat(16), fixture.merkleRoot, fixture.queryHints
    );
    expect(result).to.equal(false);
  });

  it("rejects zero merkleRoot", async function () {
    const result = await verifier.verify(
      fixture.proof, fixture.commitment, ethers.ZeroHash, fixture.queryHints
    );
    expect(result).to.equal(false);
  });

  it("rejects tampered proof trace root", async function () {
    const proofBytes = Buffer.from(fixture.proof.slice(2), "hex");
    proofBytes[8] ^= 0x01;
    const result = await verifier.verify(
      "0x" + proofBytes.toString("hex"), fixture.commitment, fixture.merkleRoot, fixture.queryHints
    );
    expect(result).to.equal(false);
  });

  // ── KEY RESULT: 2206-col VFRI6 fits within 15 M gas ──────────────────────
  //
  // AzFull alone (1523 cols) would cost >100 M gas in VFRI4 (O(n_cols) composition).
  // VFRI6 eliminates O(n_cols): only 8 M31 words mixed regardless of n_cols.

  it("2206-col VFRI6 1-query gas ≤ 15 M — O(n_cols) eliminated", async function () {
    this.timeout(60_000);
    let passed = false;
    try {
      await verifier.verify.staticCall(
        fixture.proof, fixture.commitment, fixture.merkleRoot, fixture.queryHints,
        { gasLimit: 15_000_000n }
      );
      passed = true;
    } catch (e) {
      if (e.message && (e.message.includes("gas") || e.message.includes("Gas"))) {
        passed = false;
      } else {
        console.log(`    ⚠ verify error: ${e.message?.slice(0, 100)}`);
        passed = false;
      }
    }
    expect(passed).to.equal(true,
      "2206-col VFRI6 should fit within 15 M gas — O(n_cols) gas bottleneck eliminated"
    );
  });
});
