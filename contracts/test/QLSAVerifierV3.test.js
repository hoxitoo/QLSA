const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { P, makeCommitment, toBytes8Hex } = require("./helpers");

const VALID_M31        = 0x12345678n;
const VALID_COMMITMENT = toBytes8Hex(makeCommitment(VALID_M31)); // 0x7856341200000000

// V3 raises the floor to 700 bytes (empirical Stwo minimum)
const VALID_PROOF      = "0x" + "ab".repeat(700);
const JUST_SHORT_PROOF = "0x" + "ab".repeat(699);
const ZERO_COMMITMENT  = "0x" + "00".repeat(8);
const ALL_ZERO_PROOF   = "0x" + "00".repeat(700);

// ─────────────────────────────────────────────────────────────────────────────

describe("QLSAVerifierV3", function () {
  let verifier;

  // QLSAVerifierV3.verify() is pure — one deployment covers all tests.
  before(async function () {
    const Factory = await ethers.getContractFactory("QLSAVerifierV3");
    verifier = await Factory.deploy();
  });

  // ── Constants ─────────────────────────────────────────────────────────────

  it("MIN_PROOF_LENGTH == 700", async function () {
    expect(await verifier.MIN_PROOF_LENGTH()).to.equal(700n);
  });

  // ── Acceptance ────────────────────────────────────────────────────────────

  it("accepts valid proof and valid M31 commitment", async function () {
    expect(await verifier.verify(VALID_PROOF, VALID_COMMITMENT)).to.be.true;
  });

  it("accepts proof exactly 700 bytes", async function () {
    expect(await verifier.verify(VALID_PROOF, VALID_COMMITMENT)).to.be.true;
  });

  it("accepts proof larger than 700 bytes", async function () {
    const bigProof = "0x" + "cd".repeat(2000);
    expect(await verifier.verify(bigProof, VALID_COMMITMENT)).to.be.true;
  });

  it("accepts M31 value == 1 (smallest valid non-zero)", async function () {
    const c = toBytes8Hex(makeCommitment(1n));
    expect(await verifier.verify(VALID_PROOF, c)).to.be.true;
  });

  it("accepts M31 value == P-1 (largest valid element)", async function () {
    const c = toBytes8Hex(makeCommitment(P - 1n));
    expect(await verifier.verify(VALID_PROOF, c)).to.be.true;
  });

  // ── Proof length ──────────────────────────────────────────────────────────

  it("rejects proof shorter than 700 bytes (699)", async function () {
    expect(await verifier.verify(JUST_SHORT_PROOF, VALID_COMMITMENT)).to.be.false;
  });

  it("rejects proof shorter than V2 floor (255 bytes)", async function () {
    const short = "0x" + "ab".repeat(255);
    expect(await verifier.verify(short, VALID_COMMITMENT)).to.be.false;
  });

  it("rejects empty proof", async function () {
    expect(await verifier.verify("0x", VALID_COMMITMENT)).to.be.false;
  });

  // ── Commitment validation ─────────────────────────────────────────────────

  it("rejects all-zero commitment", async function () {
    expect(await verifier.verify(VALID_PROOF, ZERO_COMMITMENT)).to.be.false;
  });

  it("rejects commitment where M31 value == P", async function () {
    const c = toBytes8Hex(makeCommitment(P));
    expect(await verifier.verify(VALID_PROOF, c)).to.be.false;
  });

  it("rejects commitment with non-zero trailing 4 bytes", async function () {
    const bad = VALID_COMMITMENT.slice(0, 10) + "deadbeef" + VALID_COMMITMENT.slice(18);
    expect(await verifier.verify(VALID_PROOF, bad)).to.be.false;
  });

  // ── V3: trivial-proof guard ───────────────────────────────────────────────

  it("rejects all-zero proof (trivially malformed)", async function () {
    expect(await verifier.verify(ALL_ZERO_PROOF, VALID_COMMITMENT)).to.be.false;
  });

  it("accepts proof with non-zero bytes at sampled positions", async function () {
    // First and last bytes are 0x00 but middle is non-zero → accepted
    const mixed = "0x" + "00" + "ab".repeat(698) + "00";
    expect(await verifier.verify(mixed, VALID_COMMITMENT)).to.be.true;
  });
});

// ── BatchRegistry integration ─────────────────────────────────────────────────

describe("BatchRegistry with QLSAVerifierV3", function () {
  let verifier, registry, owner;

  const MERKLE_ROOT = "0x" + "03".repeat(32);

  beforeEach(async function () {
    [owner] = await ethers.getSigners();
    const V3  = await ethers.getContractFactory("QLSAVerifierV3");
    verifier = await V3.deploy();
    const Reg = await ethers.getContractFactory("BatchRegistry");
    registry  = await Reg.deploy(owner.address, await verifier.getAddress());
  });

  it("finalizes a batch with valid proof (≥700 bytes) and valid commitment", async function () {
    await expect(
      registry.submitBatch(MERKLE_ROOT, VALID_COMMITMENT, VALID_PROOF)
    ).to.emit(registry, "BatchFinalized");
    expect(await registry.isBatchFinalized(MERKLE_ROOT)).to.be.true;
  });

  it("reverts on short proof (699 bytes)", async function () {
    await expect(
      registry.submitBatch(MERKLE_ROOT, VALID_COMMITMENT, JUST_SHORT_PROOF)
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("reverts on invalid commitment (all zeros)", async function () {
    await expect(
      registry.submitBatch(MERKLE_ROOT, ZERO_COMMITMENT, VALID_PROOF)
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("owner can upgrade from V2 to V3", async function () {
    const V2  = await ethers.getContractFactory("QLSAVerifierV2");
    const v2  = await V2.deploy();
    const Reg = await ethers.getContractFactory("BatchRegistry");
    const reg = await Reg.deploy(owner.address, await v2.getAddress());

    await expect(reg.setVerifier(await verifier.getAddress()))
      .to.emit(reg, "VerifierUpdated");
    expect(await reg.verifier()).to.equal(await verifier.getAddress());
  });
});
