/**
 * Ф3.2 — the nonce accumulator path on BatchRegistryV7.
 *
 * `senderNonces` costs a measured 28,777 gas per first-time sender and 12,085
 * per returning one, per sender. That bounds a batch at ~71 new senders against
 * a break-even of N > 359 (measurements.json). The accumulator replaces the
 * mapping with ONE root plus a transition proof, so the on-chain cost is one
 * read and one write whatever N is.
 *
 * THE COMPLETION CONDITION FOR A-4 IS A MEASUREMENT, and it is the last test
 * here: a batch of 1 sender and a batch of 25 must cost the SAME. Anything else
 * means the ceiling was not removed.
 *
 * Two kinds of test, and they fail for different reasons:
 *   * the Rust<->Solidity cross-checks, which pin `nonceSlot` and
 *     `nonceStatementBinding` to Rust reference values rather than to
 *     Solidity's own re-derivation. A silent divergence there would mean the
 *     contract accepts a proof about a different statement than it thinks.
 *   * the absolute checks, which must hold with NO reliance on the proof.
 *
 * Fixture: nonce_accumulator_e2e.json (regenerate with
 *   cargo test write_nonce_accumulator_fixture -- --ignored --nocapture)
 */
"use strict";

const { expect } = require("chai");
const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

const NONCE_FX = path.join(__dirname, "fixtures", "nonce_accumulator_e2e.json");
const TREE_FX = path.join(__dirname, "fixtures", "tree_recursive_bundles_e2e.json");
const HAVE = fs.existsSync(NONCE_FX) && fs.existsSync(TREE_FX);
const CAP = 16_777_216n;
const DEPTH = 8;

const bundleTuple = (b) => ({
  inner: b.inner,
  outerProof: b.outerProof,
  outerCommitment: b.outerCommitment,
  outerHints: b.outerHints,
  lastLayerEvals: b.lastLayerEvals,
});

const updateTuples = (st) =>
  st.updates.map((u) => ({
    index: u.index,
    oldNonce: BigInt(u.oldNonce),
    newNonce: BigInt(u.newNonce),
    postRoot: u.postRoot,
  }));

describe("[Ф3.2] BatchRegistryV7 — the nonce accumulator", function () {
  let nfx, tfx, b10, b8;

  before(function () {
    if (!HAVE) return;
    nfx = JSON.parse(fs.readFileSync(NONCE_FX, "utf8"));
    tfx = JSON.parse(fs.readFileSync(TREE_FX, "utf8"));
    b10 = bundleTuple(tfx.bundle10);
    b8 = bundleTuple(tfx.bundle8);
  });

  async function deploy({ accumulator = true, depth = DEPTH, root = null } = {}) {
    const [owner] = await ethers.getSigners();
    const vfri11 = await (await ethers.getContractFactory("QLSAVerifierVFRI11")).deploy();
    const recursive = await (
      await ethers.getContractFactory("QLSAVerifierRecursive")
    ).deploy(await vfri11.getAddress());
    // `root` is honoured even when `accumulator` is false, so the test for
    // "a root with depth 0 is refused" can actually reach that branch. An
    // earlier version forced ZeroHash here and the assertion passed vacuously.
    const initial = root ?? (accumulator ? nfx.one.statement.oldRoot : ethers.ZeroHash);
    return (await ethers.getContractFactory("BatchRegistryV7")).deploy(
      owner.address, await recursive.getAddress(), initial, accumulator ? depth : 0);
  }

  // ── Rust is the reference; Solidity is pinned to it ────────────────────────

  it("nonceSlot matches Rust nonce_tree::slot_index", async function () {
    if (!HAVE) { this.skip(); return; }
    const reg = await deploy();

    // Every sender in the fixture, against the slot Rust assigned it. A
    // divergence here means the contract would reject honest batches, or worse,
    // accept a sender into someone else's slot.
    for (const which of ["one", "many"]) {
      const { senders, statement } = nfx[which];
      for (let i = 0; i < senders.length; i++) {
        expect(await reg.nonceSlot(senders[i])).to.equal(
          statement.updates[i].index,
          `${which}[${i}]: sender ${senders[i]}`);
      }
    }
  });

  it("nonceSlot reads the first four bytes LITTLE-endian, under the depth mask", async function () {
    if (!HAVE) { this.skip(); return; }
    const reg = await deploy({ depth: 8 });
    // 0x01 02 03 04 ... -> LE u32 = 0x04030201, masked to 8 bits = 0x01.
    // Big-endian would give 0x04. The byte order is a convention shared by the
    // Rust tree, the AIR and Poseidon2MerkleVerifierT8, so it is pinned.
    const s = "0x01020304" + "00".repeat(28);
    expect(await reg.nonceSlot(s)).to.equal(1);

    const deep = await deploy({ depth: 16 });
    expect(await deep.nonceSlot(s)).to.equal(0x0201);
  });

  it("nonceStatementBinding matches Rust vfri2_bridge::nonce_statement_binding", async function () {
    if (!HAVE) { this.skip(); return; }
    const reg = await deploy();
    for (const which of ["one", "many"]) {
      const st = nfx[which].statement;
      expect(
        await reg.nonceStatementBinding(
          st.oldRoot, st.newRoot, st.depth, updateTuples(st))
      ).to.equal(st.binding, `${which}: binding diverged from Rust`);
    }
  });

  it("the binding moves when any field moves", async function () {
    if (!HAVE) { this.skip(); return; }
    const reg = await deploy();
    const st = nfx.many.statement;
    const base = await reg.nonceStatementBinding(
      st.oldRoot, st.newRoot, st.depth, updateTuples(st));

    const other = "0x" + "9c".repeat(32);
    const seen = new Set([base]);
    seen.add(await reg.nonceStatementBinding(other, st.newRoot, st.depth, updateTuples(st)));
    seen.add(await reg.nonceStatementBinding(st.oldRoot, other, st.depth, updateTuples(st)));
    seen.add(await reg.nonceStatementBinding(st.oldRoot, st.newRoot, st.depth + 1, updateTuples(st)));

    const bumped = updateTuples(st);
    bumped[0] = { ...bumped[0], newNonce: bumped[0].newNonce + 1n };
    seen.add(await reg.nonceStatementBinding(st.oldRoot, st.newRoot, st.depth, bumped));

    const shorter = updateTuples(st).slice(0, -1);
    seen.add(await reg.nonceStatementBinding(st.oldRoot, st.newRoot, st.depth, shorter));

    expect(seen.size).to.equal(6, "two different statements share a binding");
  });

  // ── The two paths are mutually exclusive, and that is a soundness property ──

  it("accumulator mode refuses the per-sender mapping path", async function () {
    if (!HAVE) { this.skip(); return; }
    const reg = await deploy({ accumulator: true });
    expect(await reg.accumulatorMode()).to.equal(true);

    // THE replay-hole closure. With both paths live, a transaction counted in
    // the mapping is invisible to the tree and vice versa, so a replay could go
    // through whichever path had not seen it.
    await expect(
      reg.submitBatchWithNonces(
        tfx.merkleRoot, tfx.txListRoot, b10, b8,
        [ethers.zeroPadValue("0x01", 32)], [1n], { gasLimit: CAP - 1n })
    ).to.be.revertedWithCustomError(reg, "WrongNoncePath");
  });

  it("mapping mode refuses the accumulator path", async function () {
    if (!HAVE) { this.skip(); return; }
    const reg = await deploy({ accumulator: false });
    expect(await reg.accumulatorMode()).to.equal(false);
    expect(await reg.nonceTreeDepth()).to.equal(0);

    const st = nfx.one.statement;
    await expect(
      reg.submitNonceTransition(
        bundleTuple(nfx.one.bundle), nfx.one.senders, updateTuples(st), st.newRoot,
        { gasLimit: CAP - 1n })
    ).to.be.revertedWithCustomError(reg, "WrongNoncePath");
  });

  it("the constructor refuses an inconsistent mode", async function () {
    if (!HAVE) { this.skip(); return; }
    const refuses = async (opts, what) => {
      let threw = false;
      try { await deploy(opts); } catch { threw = true; }
      expect(threw, what).to.equal(true);
    };
    // A depth past what the path AIR can prove would otherwise be
    // undiscoverable until the first proof failed.
    await refuses({ depth: 29 }, "depth 29 exceeds the path AIR's MAX_DEPTH");
    // A root with no depth, or a depth with no root: an ignored argument is how
    // a deployment silently lands on the wrong path.
    await refuses(
      { accumulator: false, root: "0x" + "11".repeat(32) },
      "a root with depth 0 would be ignored");
    await refuses({ depth: 8, root: ethers.ZeroHash }, "a zero root with a depth");
  });

  // ── Checked absolutely, with no reliance on the proof ──────────────────────

  describe("the absolute checks", function () {
    let reg, st, senders;

    beforeEach(async function () {
      if (!HAVE) { this.skip(); return; }
      reg = await deploy();
      st = nfx.many.statement;
      senders = nfx.many.senders;
    });

    const submit = (overrides = {}) => {
      const o = {
        nonceBundle: bundleTuple(nfx.many.bundle),
        senders, updates: updateTuples(st), newRoot: st.newRoot,
        ...overrides,
      };
      return reg.submitNonceTransition(
        o.nonceBundle, o.senders, o.updates, o.newRoot, { gasLimit: CAP - 1n });
    };

    it("a non-increasing nonce is refused", async function () {
      const u = updateTuples(st);
      u[0] = { ...u[0], newNonce: u[0].oldNonce };
      await expect(submit({ updates: u })).to.be.revertedWithCustomError(
        reg, "SenderNonceTooLow");
    });

    it("a sender in someone else's slot is refused", async function () {
      const u = updateTuples(st);
      u[0] = { ...u[0], index: u[0].index + 1 };
      await expect(submit({ updates: u })).to.be.revertedWithCustomError(
        reg, "NonceSlotMismatch");
    });

    it("a tampered intermediate root is refused — by the BINDING, not a chain check", async function () {
      // This test began as "a broken chain is refused" and failed, reverting
      // with NonceBindingMismatch instead. That exposed a VACUOUS check: the
      // contract compared `updates[i-1].postRoot` against a variable just
      // assigned that same value, so it could never fire.
      //
      // The right conclusion was to remove the check, not repair it. The chain
      // is DEFINITIONAL — update i starts at updates[i-1].postRoot on both
      // sides — so there is no disagreement a comparison could catch. What
      // actually protects an intermediate root is that it is hashed into the
      // binding, which is what this now asserts.
      const u = updateTuples(st);
      u[0] = { ...u[0], postRoot: "0x" + "ab".repeat(32) };
      await expect(submit({ updates: u })).to.be.revertedWithCustomError(
        reg, "NonceBindingMismatch");
    });

    it("a new root that is not where the chain ends is refused", async function () {
      await expect(submit({ newRoot: "0x" + "cd".repeat(32) }))
        .to.be.revertedWithCustomError(reg, "NonceRootMismatch");
    });

    it("a proof that attests a different statement is refused", async function () {
      // The one update's bundle against the 25-update statement: a valid proof,
      // for the wrong thing.
      await expect(submit({ nonceBundle: bundleTuple(nfx.one.bundle) }))
        .to.be.revertedWithCustomError(reg, "NonceBindingMismatch");
    });

    it("a sender/update length mismatch is refused", async function () {
      await expect(submit({ senders: senders.slice(0, -1) }))
        .to.be.revertedWithCustomError(reg, "NoncesLengthMismatch");
    });
  });

  // ── What A-4 set as the completion condition, and what was measured ───────

  it("[gas] the transition's cost is nearly flat in N — but the constant is too big", async function () {
    if (!HAVE) { this.skip(); return; }
    this.timeout(1_800_000);

    const run = async (which) => {
      const st = nfx[which].statement;
      const reg = await deploy({ root: st.oldRoot });
      const tx = await reg.submitNonceTransition(
        bundleTuple(nfx[which].bundle), nfx[which].senders,
        updateTuples(st), st.newRoot, { gasLimit: CAP - 1n });
      const rc = await tx.wait();
      expect(rc.status).to.equal(1);
      // The point of the whole exercise: ONE slot holds the replay state.
      expect(await reg.nonceStateRoot()).to.equal(st.newRoot);
      return rc.gasUsed;
    };

    const g1 = await run("one");
    const g25 = await run("many");
    const perSender = (g25 - g1) / 24n;

    console.log(`        [gas] transition,  1 update  = ${g1}`);
    console.log(`        [gas] transition, 25 updates = ${g25}`);
    console.log(`        [gas] marginal per update    = ${perSender}`);
    console.log(`        [gas] mapping, for comparison: 28,777 first-time / 12,085 returning`);
    const MAPPING_WARM = 12_085n;
    console.log(`        [calc] break-even against the mapping ≈ ${g1 / MAPPING_WARM} senders`);
    console.log(`        [calc] but one transaction admits ≈ 172 senders on the mapping path`);

    // STORAGE is O(1): one slot, whatever N. That part of A-4 holds, and the
    // flat marginal is what shows it — each extra update costs its calldata and
    // one loop iteration, not a storage write.
    expect(perSender).to.be.lessThan(
      28_777n, "an update must cost less than a first-time mapping write");

    // THE NEGATIVE RESULT, asserted so it cannot quietly stop being true.
    //
    // The transition's own verifyRecursive is ~6.94M gas, CONSTANT. Against the
    // mapping's 12,085 per returning sender that only pays above ~574 senders,
    // and one transaction admits about 172. So as a SEPARATE proof the
    // accumulator does not reach break-even, and § A-4's claim that it is the
    // lever that does is wrong in this form.
    //
    // What would make it pay: folding the nonce statement into the batch proof
    // as a further path group, so it rides the two verifyRecursive calls
    // already paid for instead of adding a third.
    expect(g1).to.be.greaterThan(
      172n * MAPPING_WARM,
      "if this ever fails, the separate-proof accumulator HAS become cheaper " +
      "than the mapping within one transaction — re-derive § A-4");
  });

  it("[gas] the transition does NOT fit alongside a tree batch", async function () {
    if (!HAVE) { this.skip(); return; }
    this.timeout(1_800_000);

    // Why submitNonceTransition is its own call rather than a parameter of
    // submitBatchWithNonces. The tree batch costs a measured 14,663,950 and the
    // transition ~6.94M; together they exceed the 16,777,216 cap. Asserted here
    // because the original design DID combine them, and it reverted.
    const BATCH = 14_663_950n;
    const st = nfx.one.statement;
    const reg = await deploy({ root: st.oldRoot });
    const tx = await reg.submitNonceTransition(
      bundleTuple(nfx.one.bundle), nfx.one.senders,
      updateTuples(st), st.newRoot, { gasLimit: CAP - 1n });
    const transition = (await tx.wait()).gasUsed;

    console.log(`        [gas] tree batch              = ${BATCH}`);
    console.log(`        [gas] nonce transition        = ${transition}`);
    console.log(`        [gas] together                = ${BATCH + transition}  (cap ${CAP})`);
    expect(BATCH + transition).to.be.greaterThan(
      CAP, "they fit after all — the two could then be one transaction");
  });
});
