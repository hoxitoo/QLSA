/**
 * BatchRegistryV7 × the AGGREGATION TREE's roots.
 *
 * This closes the loop the project's headline describes. Until now a tree
 * existed but no contract consumed it: `Batcher` proved `tx[0]`, and the tree's
 * root went nowhere. Here N signatures become two tree roots (one per V23 FRI
 * group) and ONE transaction finalizes the batch.
 *
 * Why the fixture has only two signatures: the on-chain cost is CONSTANT in N.
 * The root node's shape is a fixed point (probe_tree_root_outer_shape measured
 * the outer trace over a root to be the same 87 cols at log 14 as over a plain
 * V23 group, at 1, 4 and the production 20 queries), so the smallest honest tree
 * gives the same gas as a large one. The tree's shape at four leaves is pinned
 * by Rust tests instead.
 *
 * Fixture: tree_recursive_bundles_e2e.json — regenerate with
 *   cargo test write_tree_recursive_bundles_fixture -- --ignored --nocapture
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const FIXTURE_PATH = path.join(__dirname, "fixtures", "tree_recursive_bundles_e2e.json");
const FIXTURE_EXISTS = fs.existsSync(FIXTURE_PATH);

function bundleTuple(b) {
  return {
    inner: {
      traceRoot: b.inner.traceRoot,
      oodsComboPos: b.inner.oodsComboPos,
      oodsComboNeg: b.inner.oodsComboNeg,
      compRoot: b.inner.compRoot,
      friLayerRoots: b.inner.friLayerRoots,
      batchRoot: b.inner.batchRoot,
      treeDepth: b.inner.treeDepth,
      nQueries: b.inner.nQueries,
    },
    outerProof: b.outerProof,
    outerCommitment: b.outerCommitment,
    outerHints: b.outerHints,
    lastLayerEvals: b.lastLayerEvals,
  };
}

describe("BatchRegistryV7 × aggregation tree roots", function () {
  let registry, recursive, fx, b10, b8;

  before(async function () {
    const [owner] = await ethers.getSigners();
    const vfri11 = await (await ethers.getContractFactory("QLSAVerifierVFRI11")).deploy();
    await vfri11.waitForDeployment();
    recursive = await (
      await ethers.getContractFactory("QLSAVerifierRecursive")
    ).deploy(await vfri11.getAddress());
    await recursive.waitForDeployment();
    registry = await (
      await ethers.getContractFactory("BatchRegistryV7")
    ).deploy(owner.address, await recursive.getAddress());
    await registry.waitForDeployment();

    if (FIXTURE_EXISTS) {
      fx = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
      b10 = bundleTuple(fx.bundle10);
      b8 = bundleTuple(fx.bundle8);
    }
  });

  it("the fixture is a TREE over more than one signature", function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    expect(fx.leafCount).to.be.greaterThan(1, "a tree, not a single statement");
    expect(fx.bundle10.inner.nQueries).to.equal(20, "130-bit production security");
    expect(fx.bundle8.inner.nQueries).to.equal(20);
    // Cross-binding in both directions — bound at the root, which is the level
    // BatchRegistryV7._finalize inspects.
    expect(fx.bundle10.inner.batchRoot).to.equal(
      ethers.keccak256(ethers.concat([fx.merkleRoot, fx.bundle8.inner.traceRoot]))
    );
    expect(fx.bundle8.inner.batchRoot).to.equal(
      ethers.keccak256(ethers.concat([fx.merkleRoot, fx.bundle10.inner.traceRoot]))
    );
  });

  it("each tree root's recursive bundle verifies individually", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(900_000);
    for (const [name, b] of [["log10 root", b10], ["log8 root", b8]]) {
      const [ok] = await recursive.verifyRecursive.staticCall(
        b.inner, b.outerProof, b.outerCommitment, b.outerHints, b.lastLayerEvals,
        { gasLimit: 16_777_215n }
      );
      expect(ok, `${name} must verify`).to.equal(true);
    }
  });

  it("finalizes a BATCH of signatures from the tree roots in ONE transaction", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(900_000);
    const tx = await registry.submitBatch(fx.merkleRoot, b10, b8, {
      gasLimit: 16_777_215n,
    });
    const rc = await tx.wait();
    console.log(
      `        [gas] V7 submitBatch, ${fx.leafCount} signatures via tree roots @ q=20 = ${rc.gasUsed}`
    );
    expect(rc.gasUsed).to.be.lessThan(16_777_216n);
    expect(await registry.isBatchFinalized(fx.merkleRoot)).to.equal(true);
  });

  // Without this the suite would only show that something verifies. The
  // cross-binding is the reason two independently-proved roots cannot be mixed,
  // and it is checked at the InnerPublics level, so swapping one bundle's
  // declared batchRoot must be refused before any proof is even verified.
  it("refuses a bundle whose cross-binding does not match", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(900_000);
    const tampered = bundleTuple(fx.bundle10);
    tampered.inner.batchRoot = ethers.keccak256(
      ethers.concat([fx.merkleRoot, fx.bundle10.inner.traceRoot])  // bound to ITSELF
    );
    await expect(
      registry.submitBatch(ethers.keccak256(fx.merkleRoot), tampered, b8, {
        gasLimit: 16_777_215n,
      })
    ).to.be.revertedWithCustomError(registry, "CrossBindingMismatch");
  });
});
