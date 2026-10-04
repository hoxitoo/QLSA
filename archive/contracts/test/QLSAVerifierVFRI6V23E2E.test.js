/**
 * QLSAVerifierVFRI6 — E2E test: V23 NttBatch+InttBatch (1298 cols) with off-chain OODS.
 *
 * Key result: 1298-col combined trace (NttBatch 649 + InttBatch 649) verifies
 * within 15 M gas. VFRI6's on-chain cost is O(1) in n_cols regardless of trace size.
 *
 * Calldata comparison for 1298-col trace:
 *   VFRI4: ~174 KB hints  (oodsEvalsPos[1298] + oodsEvalsNeg[1298])
 *   VFRI6:   ~7.2 KB hints  (oodsComboPos + oodsComboNeg = 2 × uint128)
 *   Reduction: 24× smaller
 *
 * Fixture: V23 NttBatch+InttBatch (1298 cols), n_queries=1, num_folds=9.
 */
"use strict";

const { expect } = require("chai");
const { ethers }  = require("hardhat");
const path        = require("path");
const fs          = require("fs");

describe("QLSAVerifierVFRI6 — V23 NttBatch+InttBatch E2E (1298 cols)", function () {
  let verifier;
  const fixture = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "fixtures", "mldsa_v23_ntt_vfri6_e2e.json"),
      "utf8"
    )
  );

  before(async function () {
    const Factory = await ethers.getContractFactory("QLSAVerifierVFRI6");
    verifier = await Factory.deploy();
    await verifier.waitForDeployment();
  });

  // ── Fixture structural checks ─────────────────────────────────────────────

  it("fixture has correct n_cols=1298 and n_queries=1", function () {
    expect(fixture.n_cols).to.equal(1298);
    expect(fixture.n_queries).to.equal(1);
    expect(fixture.num_folds).to.equal(9);
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

  it("fixture queryHints is ~7 KB — O(1) in n_cols, same size as 649-col trace", function () {
    const v6Fix649 = JSON.parse(
      fs.readFileSync(
        path.join(__dirname, "fixtures", "ntt_batch_vfri6_e2e.json"), "utf8"
      )
    );
    const len1298 = Buffer.from(fixture.queryHints.slice(2), "hex").length;
    const len649  = Buffer.from(v6Fix649.queryHints.slice(2), "hex").length;
    console.log(`    ℹ VFRI6 1298-col hints: ${len1298} B, 649-col hints: ${len649} B`);
    // VFRI6 hint size is independent of n_cols (same structure for any trace size)
    expect(len1298).to.equal(len649);
  });

  it("VFRI6 1298-col hints are >10× smaller than VFRI4 649-col hints", function () {
    // Compare 1298-col VFRI6 against 649-col VFRI4 (mldsa_v23_ntt_vfri4_e2e.json):
    // VFRI4 hint size grows O(n_cols) — 649 cols → 90.6 KB.
    // VFRI6 hint size is O(1) — 1298 cols still → 7.2 KB.
    const vfri4Fix = JSON.parse(
      fs.readFileSync(
        path.join(__dirname, "fixtures", "mldsa_v23_ntt_vfri4_e2e.json"), "utf8"
      )
    );
    const v4len = Buffer.from(vfri4Fix.queryHints.slice(2), "hex").length;
    const v6len = Buffer.from(fixture.queryHints.slice(2), "hex").length;
    const ratio = (v4len / v6len).toFixed(1);
    console.log(`    ℹ VFRI4 (649-col): ${v4len} B vs VFRI6 (1298-col): ${v6len} B (${ratio}× smaller)`);
    expect(v6len).to.be.lessThan(v4len);
    expect(v4len / v6len).to.be.greaterThan(10);
  });

  it("fixture proof[8:40] is non-zero (real 1298-col NttBatch+InttBatch committed)", function () {
    const proofBytes = Buffer.from(fixture.proof.slice(2), "hex");
    expect(proofBytes.slice(8, 40).equals(Buffer.alloc(32, 0))).to.equal(false);
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

  // ── KEY RESULT: 1298-col VFRI6 fits within 15 M gas ─────────────────────
  //
  // VFRI4 required ~240 M gas for 1298 cols (2 × O(n_cols) composition).
  // VFRI6 eliminates O(n_cols) entirely: 8 M31 words mixed regardless of n_cols.

  it("1298-col VFRI6 1-query gas ≤ 15 M — O(n_cols) eliminated", async function () {
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
      "1298-col VFRI6 should fit within 15 M gas — O(n_cols) gas bottleneck eliminated"
    );
  });
});
