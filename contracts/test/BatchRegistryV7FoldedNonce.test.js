/**
 * Ф3.2, contract half — a batch AND a nonce-accumulator transition in ONE
 * transaction: `BatchRegistryV7.submitBatchWithNonceUpdates`.
 *
 * The transition is a fourth component of the log10 tree's ROOT node, and both
 * bundles are cross-bound under
 *   seedEff = keccak256("QLSA/nonce-fold/v1" ‖ merkleRoot ‖ nonceStatementBinding)
 * instead of merkleRoot — so the statement rides the two verifyRecursive calls
 * the batch already pays for. The separate-proof path (submitNonceTransition)
 * adds a third, ~6.8M, which is why it never fit next to a batch.
 *
 * What these tests pin:
 *   * Rust<->Solidity: seedEff and the (now linear) binding, against the
 *     prover's values, for 1, 25 and 150 updates;
 *   * that a folded batch finalizes and moves the root, and nothing else does:
 *     plain bundles, another statement, another root, the wrong mode, a replay;
 *   * [gas] the marginal cost per update — the figure the economics turn on.
 *
 * Fixture: tree_nonce_bundles_e2e.json (regenerate with
 *   cargo test write_tree_nonce_bundles_fixture -- --ignored --nocapture)
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");
const { bundleTuple } = require("../scripts/_testnet");

const FOLD_FX = path.join(__dirname, "fixtures", "tree_nonce_bundles_e2e.json");
const TREE_FX = path.join(__dirname, "fixtures", "tree_recursive_bundles_e2e.json");
const HAVE = fs.existsSync(FOLD_FX) && fs.existsSync(TREE_FX);
const CAP = 16_777_216n;
const GAS = { gasLimit: 16_777_215n };

const updateTuples = (st) =>
  st.updates.map((u) => ({
    index: u.index,
    oldNonce: BigInt(u.oldNonce),
    newNonce: BigInt(u.newNonce),
    postRoot: u.postRoot,
  }));

describe("[Ф3.2] BatchRegistryV7 — batch + nonce transition in one transaction", function () {
  this.timeout(1_800_000);
  let fx, tfx, recursive, owner;

  before(async function () {
    if (!HAVE) return;
    fx = JSON.parse(fs.readFileSync(FOLD_FX, "utf8"));
    tfx = JSON.parse(fs.readFileSync(TREE_FX, "utf8"));
    [owner] = await ethers.getSigners();
    const vfri11 = await (await ethers.getContractFactory("QLSAVerifierVFRI11")).deploy();
    await vfri11.waitForDeployment();
    recursive = await (await ethers.getContractFactory("QLSAVerifierRecursive"))
      .deploy(await vfri11.getAddress());
    await recursive.waitForDeployment();
  });

  const fresh = async (depth = fx.depth, root = fx.emptyRoot) => {
    const r = await (await ethers.getContractFactory("BatchRegistryV7"))
      .deploy(owner.address, await recursive.getAddress(), root, depth);
    await r.waitForDeployment();
    return r;
  };
  const args = (n, over = {}) => {
    const st = fx.statements[n];
    return [
      over.merkleRoot ?? fx.merkleRoot,
      over.txListRoot ?? fx.txListRoot,
      over.bundle10 ?? bundleTuple(st.bundle10),
      over.bundle8 ?? bundleTuple(st.bundle8),
      over.senders ?? st.senders,
      over.updates ?? updateTuples(st),
      over.newRoot ?? st.newRoot,
    ];
  };

  it("the fixture: one R for every statement, and the folded seed differs from it", function () {
    if (!HAVE) { this.skip(); return; }
    // R is the membership root — the nonce does not enter it — so the folded
    // batches share the plain fixture's R over the same signatures.
    expect(fx.merkleRoot).to.equal(tfx.merkleRoot);
    for (const n of ["1", "25", "150"]) {
      const st = fx.statements[n];
      expect(st.updates.length).to.equal(Number(n));
      expect(st.seedEff).to.not.equal(fx.merkleRoot);
      expect(st.bundle10.inner.batchRoot).to.equal(
        ethers.keccak256(ethers.concat([st.seedEff, st.bundle8.inner.traceRoot])));
      expect(st.bundle8.inner.batchRoot).to.equal(
        ethers.keccak256(ethers.concat([st.seedEff, st.bundle10.inner.traceRoot])));
    }
  });

  it("nonceStatementBinding and nonceFoldSeed match Rust (1, 25, 150 updates)", async function () {
    if (!HAVE) { this.skip(); return; }
    const reg = await fresh();
    for (const n of ["1", "25", "150"]) {
      const st = fx.statements[n];
      const binding = await reg.nonceStatementBinding(
        fx.emptyRoot, st.newRoot, fx.depth, updateTuples(st));
      expect(binding).to.equal(st.nonceBinding, `binding, ${n} updates`);
      expect(await reg.nonceFoldSeed(fx.merkleRoot, binding)).to.equal(st.seedEff, `seed, ${n}`);
    }
  });

  it("every slot in the fixture is its sender's", async function () {
    if (!HAVE) { this.skip(); return; }
    const reg = await fresh();
    const st = fx.statements["25"];
    for (let i = 0; i < st.senders.length; i++) {
      expect(await reg.nonceSlot(st.senders[i])).to.equal(BigInt(st.updates[i].index));
    }
  });

  it("finalizes the batch AND moves the nonce root, in one transaction", async function () {
    if (!HAVE) { this.skip(); return; }
    const reg = await fresh();
    const st = fx.statements["1"];
    const tx = await reg.submitBatchWithNonceUpdates(...args("1"), GAS);
    const rc = await tx.wait();
    expect(rc.gasUsed).to.be.lessThan(CAP);
    expect(await reg.isBatchFinalized(fx.merkleRoot)).to.equal(true);
    expect(await reg.nonceStateRoot()).to.equal(st.newRoot);
    expect(await reg.batchRecordMatches(fx.merkleRoot, st.bundle10.outerCommitment,
      st.bundle8.outerCommitment, fx.txListRoot)).to.equal(true);
    await expect(tx).to.emit(reg, "NonceStateAdvanced").withArgs(fx.emptyRoot, st.newRoot, 1n);
    await expect(tx).to.emit(reg, "BatchFinalized");

    // A replay of the same call: the batch is final, whatever the nonce root.
    await expect(reg.submitBatchWithNonceUpdates(...args("1"), GAS))
      .to.be.revertedWithCustomError(reg, "BatchAlreadyFinalized");
  });

  describe("refusals", function () {
    let reg;
    beforeEach(async function () {
      if (!HAVE) { this.skip(); return; }
      reg = await fresh();
    });

    it("the mapping mode refuses it", async function () {
      const mapping = await fresh(0, ethers.ZeroHash);
      await expect(mapping.submitBatchWithNonceUpdates(...args("1"), GAS))
        .to.be.revertedWithCustomError(mapping, "WrongNoncePath");
    });

    it("an empty statement is refused — that batch is submitBatch", async function () {
      await expect(reg.submitBatchWithNonceUpdates(
        ...args("1", { senders: [], updates: [], newRoot: fx.emptyRoot }), GAS))
        .to.be.revertedWithCustomError(reg, "NoNonceUpdates");
    });

    it("the PLAIN batch's bundles (bound to R alone) are refused", async function () {
      await expect(reg.submitBatchWithNonceUpdates(...args("1", {
        bundle10: bundleTuple(tfx.bundle10), bundle8: bundleTuple(tfx.bundle8) }), GAS))
        .to.be.revertedWithCustomError(reg, "CrossBindingMismatch");
    });

    it("and the folded bundles do not pass as a plain batch", async function () {
      const st = fx.statements["1"];
      await expect(reg.submitBatch(fx.merkleRoot, fx.txListRoot,
        bundleTuple(st.bundle10), bundleTuple(st.bundle8), GAS))
        .to.be.revertedWithCustomError(reg, "CrossBindingMismatch");
    });

    it("bundles generated for ANOTHER statement are refused", async function () {
      const other = fx.statements["25"];
      await expect(reg.submitBatchWithNonceUpdates(...args("1", {
        bundle10: bundleTuple(other.bundle10), bundle8: bundleTuple(other.bundle8) }), GAS))
        .to.be.revertedWithCustomError(reg, "CrossBindingMismatch");
    });

    it("a changed nonce moves the binding, and so the seed", async function () {
      const u = updateTuples(fx.statements["25"]);
      u[3].newNonce += 1n;
      await expect(reg.submitBatchWithNonceUpdates(...args("25", { updates: u }), GAS))
        .to.be.revertedWithCustomError(reg, "CrossBindingMismatch");
    });

    it("another merkleRoot is refused", async function () {
      await expect(reg.submitBatchWithNonceUpdates(
        ...args("1", { merkleRoot: "0x" + "5e".repeat(32) }), GAS))
        .to.be.revertedWithCustomError(reg, "CrossBindingMismatch");
    });

    it("a registry at another starting root refuses it", async function () {
      const moved = await fresh(fx.depth, "0x" + "ab".repeat(32));
      await expect(moved.submitBatchWithNonceUpdates(...args("1"), GAS))
        .to.be.revertedWithCustomError(moved, "CrossBindingMismatch");
    });

    it("a new root that is not where the chain ends is refused", async function () {
      await expect(reg.submitBatchWithNonceUpdates(
        ...args("1", { newRoot: "0x" + "cd".repeat(32) }), GAS))
        .to.be.revertedWithCustomError(reg, "NonceRootMismatch");
    });

    it("the absolute checks still hold: a non-increasing nonce, a foreign slot", async function () {
      const u = updateTuples(fx.statements["25"]);
      u[0].newNonce = u[0].oldNonce;
      await expect(reg.submitBatchWithNonceUpdates(...args("25", { updates: u }), GAS))
        .to.be.revertedWithCustomError(reg, "SenderNonceTooLow");
      const s = [...fx.statements["25"].senders];
      [s[0], s[1]] = [s[1], s[0]];
      await expect(reg.submitBatchWithNonceUpdates(...args("25", { senders: s }), GAS))
        .to.be.revertedWithCustomError(reg, "NonceSlotMismatch");
    });

    it("nothing was written by any refusal", async function () {
      expect(await reg.nonceStateRoot()).to.equal(fx.emptyRoot);
      expect(await reg.isBatchFinalized(fx.merkleRoot)).to.equal(false);
    });
  });

  // THE figure. Each statement starts from the empty tree, so each runs on its
  // own fresh registry; the marginal per update is a difference of two sent
  // transactions, so the batch's ~14.6M and the 21,000 base cancel.
  it("[gas] the marginal cost per update, against the mapping path", async function () {
    if (!HAVE) { this.skip(); return; }
    const g = {};
    for (const n of ["1", "25", "150"]) {
      const reg = await fresh();
      g[n] = (await (await reg.submitBatchWithNonceUpdates(...args(n), GAS)).wait()).gasUsed;
      expect(await reg.nonceStateRoot()).to.equal(fx.statements[n].newRoot);
    }
    const plainReg = await fresh(0, ethers.ZeroHash);
    const plain = (await (await plainReg.submitBatch(tfx.merkleRoot, tfx.txListRoot,
      bundleTuple(tfx.bundle10), bundleTuple(tfx.bundle8), GAS)).wait()).gasUsed;

    const m1_25 = (g["25"] - g["1"]) / 24n;
    const m25_150 = (g["150"] - g["25"]) / 125n;
    const d10 = (n) => fx.statements[n].bundle10.inner.treeDepth;
    console.log(`        [gas] plain submitBatch (same signatures)  ${plain}`);
    for (const n of ["1", "25", "150"]) {
      console.log(`        [gas] folded, ${n.padStart(3)} updates (log10 root depth ${d10(n)})  ${g[n]}`);
    }
    console.log(`        [gas] folding overhead at 1 update         ${g["1"] - plain}`);
    console.log(`        [gas] marginal per update, 1 -> 25          ${m1_25}`);
    console.log(`        [gas] marginal per update, 25 -> 150        ${m25_150}`);
    console.log(`        [gas] headroom above 1 update               ${CAP - g["1"]}`);

    expect(g["150"]).to.be.lessThan(CAP, "150 updates must fit one transaction");
    // The completion condition recorded in ROADMAP § 5: cheaper than the
    // mapping's measured 12,085 per RETURNING sender (28,777 per new one).
    expect(m1_25).to.be.lessThan(12_085n);
    expect(m25_150).to.be.lessThan(12_085n);
  });
});
