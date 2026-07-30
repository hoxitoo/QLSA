/**
 * BatchRegistryV7 — finalizing a batch from RECURSIVE proofs (MVP-8).
 *
 * V7 verifies, per trace group, a STARK attesting that the inner VFRI11 proof was
 * verified — plus the cheap on-chain half the recursion deliberately leaves
 * outside the circuit (channel replay + last-layer bounded-degree check).
 *
 * A V23 batch is two groups, so two bundles are submitted and each must have been
 * produced against the OTHER's trace root:
 *
 *     bundle10.inner.batchRoot == keccak256(merkleRoot ‖ bundle8.inner.traceRoot)
 *     bundle8.inner.batchRoot  == keccak256(merkleRoot ‖ bundle10.inner.traceRoot)
 *
 * Fixture: recursive_pair_e2e.json — regenerate with
 *   cargo test write_recursive_pair_fixture -- --ignored --nocapture
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const FIXTURE_PATH = path.join(__dirname, "fixtures", "recursive_pair_e2e.json");
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

describe("BatchRegistryV7 — recursive-proof batch finalization", function () {
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

  it("wires the recursive verifier", async function () {
    expect(await registry.verifier()).to.equal(await recursive.getAddress());
  });

  it("crossBoundRoot matches keccak256(merkleRoot ‖ otherTraceRoot)", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    const expected10 = ethers.keccak256(
      ethers.concat([fx.merkleRoot, fx.bundle8.inner.traceRoot])
    );
    expect(await registry.crossBoundRoot(fx.merkleRoot, fx.bundle8.inner.traceRoot))
      .to.equal(expected10);
    // The fixture must actually be cross-bound, else the happy path proves nothing.
    expect(fx.bundle10.inner.batchRoot).to.equal(expected10);
    expect(fx.bundle8.inner.batchRoot).to.equal(
      ethers.keccak256(ethers.concat([fx.merkleRoot, fx.bundle10.inner.traceRoot]))
    );
    // Each group is bound to a DIFFERENT root.
    expect(fx.bundle10.inner.batchRoot).to.not.equal(fx.bundle8.inner.batchRoot);
    expect(fx.bundle10.inner.batchRoot).to.not.equal(fx.merkleRoot);
  });

  it("finalizes a batch from two recursive bundles in ONE transaction", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(600_000);
    const tx = await registry.submitBatch(fx.merkleRoot, b10, b8, {
      gasLimit: 16_777_215n,
    });
    const rc = await tx.wait();
    console.log(`        [gas] V7 submitBatch (2 recursive bundles) = ${rc.gasUsed}`);
    expect(rc.gasUsed).to.be.lessThan(16_777_216n, "must fit one transaction");
    expect(await registry.isBatchFinalized(fx.merkleRoot)).to.equal(true);
    expect(await registry.batchCommitmentsLog10(fx.merkleRoot))
      .to.equal(fx.bundle10.outerCommitment);
    expect(await registry.batchCommitmentsLog8(fx.merkleRoot))
      .to.equal(fx.bundle8.outerCommitment);
  });

  it("rejects a replayed batch", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(600_000);
    await expect(
      registry.submitBatch(fx.merkleRoot, b10, b8, { gasLimit: 16_777_215n })
    ).to.be.revertedWithCustomError(registry, "BatchAlreadyFinalized");
  });

  it("rejects a zero merkle root", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    await expect(
      registry.submitBatch(ethers.ZeroHash, b10, b8, { gasLimit: 16_777_215n })
    ).to.be.revertedWithCustomError(registry, "InvalidMerkleRoot");
  });

  // The binding is what stops two bundles from different witnesses being mixed.
  it("rejects the same group submitted as both bundles", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(600_000);
    const [owner] = await ethers.getSigners();
    const F = await ethers.getContractFactory("BatchRegistryV7");

    // This is the case that matters: one group cannot be passed off as both,
    // because its batchRoot commits to the OTHER group's trace root.
    for (const dup of [b10, b8]) {
      const fresh = await F.deploy(owner.address, await recursive.getAddress());
      await expect(
        fresh.submitBatch(fx.merkleRoot, dup, dup, { gasLimit: 16_777_215n })
      ).to.be.revertedWithCustomError(fresh, "CrossBindingMismatch");
    }
  });

  it("rejects bundles submitted under a different batch root", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(600_000);
    const [owner] = await ethers.getSigners();
    const fresh = await (
      await ethers.getContractFactory("BatchRegistryV7")
    ).deploy(owner.address, await recursive.getAddress());
    await expect(
      fresh.submitBatch("0x" + "5e".repeat(32), b10, b8, { gasLimit: 16_777_215n })
    ).to.be.revertedWithCustomError(fresh, "CrossBindingMismatch");
  });

  // Documented property, not an oversight: the constraint pair is SYMMETRIC under
  // exchanging the bundles, so submitting them in the other order is accepted.
  // That is not a soundness break — both are still valid recursive proofs bound to
  // this merkleRoot, and neither can be duplicated (above) — but it does mean the
  // Log10/Log8 storage slots are positional labels, not enforced group identities.
  // BatchRegistryV5's binding has the same symmetry. Pinned here so the behaviour
  // is a decision on record rather than something a reader assumes otherwise.
  it("accepts the bundles in either order (documented symmetry)", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(600_000);
    const [owner] = await ethers.getSigners();
    const fresh = await (
      await ethers.getContractFactory("BatchRegistryV7")
    ).deploy(owner.address, await recursive.getAddress());
    const tx = await fresh.submitBatch(fx.merkleRoot, b8, b10, { gasLimit: 16_777_215n });
    await tx.wait();
    expect(await fresh.isBatchFinalized(fx.merkleRoot)).to.equal(true);
    // …and the commitments land in the slots as submitted, hence "positional".
    expect(await fresh.batchCommitmentsLog10(fx.merkleRoot))
      .to.equal(fx.bundle8.outerCommitment);
  });

  it("rejects a bundle whose last layer does not match its committed root", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(600_000);
    const [owner] = await ethers.getSigners();
    const fresh = await (
      await ethers.getContractFactory("BatchRegistryV7")
    ).deploy(owner.address, await recursive.getAddress());

    const tampered = JSON.parse(JSON.stringify(fx.bundle10));
    tampered.lastLayerEvals[0] = (BigInt(tampered.lastLayerEvals[0]) ^ 1n).toString();
    await expect(
      fresh.submitBatch(fx.merkleRoot, bundleTuple(tampered), b8, { gasLimit: 16_777_215n })
    ).to.be.revertedWithCustomError(fresh, "Log10ProofInvalid");
  });

  it("finalizes with per-sender nonces and enforces monotonicity", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    this.timeout(600_000);
    const [owner] = await ethers.getSigners();
    const fresh = await (
      await ethers.getContractFactory("BatchRegistryV7")
    ).deploy(owner.address, await recursive.getAddress());

    const senders = ["0x" + "11".repeat(32), "0x" + "22".repeat(32)];
    const tx = await fresh.submitBatchWithNonces(
      fx.merkleRoot, b10, b8, senders, [1, 2], { gasLimit: 16_777_215n }
    );
    await tx.wait();
    expect(await fresh.isBatchFinalized(fx.merkleRoot)).to.equal(true);
    expect(await fresh.senderNonces(senders[0])).to.equal(1n);
    expect(await fresh.senderNonces(senders[1])).to.equal(2n);

    // Nonce 0 is unsubmittable: an unseen sender reads 0 and newNonce must exceed it.
    const other = await (
      await ethers.getContractFactory("BatchRegistryV7")
    ).deploy(owner.address, await recursive.getAddress());
    await expect(
      other.submitBatchWithNonces(fx.merkleRoot, b10, b8, [senders[0]], [0], {
        gasLimit: 16_777_215n,
      })
    ).to.be.revertedWithCustomError(other, "SenderNonceTooLow");
  });

  it("rejects mismatched sender/nonce arrays", async function () {
    if (!FIXTURE_EXISTS) { this.skip(); return; }
    await expect(
      registry.submitBatchWithNonces(fx.merkleRoot, b10, b8, ["0x" + "11".repeat(32)], [], {
        gasLimit: 16_777_215n,
      })
    ).to.be.revertedWithCustomError(registry, "NoncesLengthMismatch");
  });
});
