const { expect }      = require("chai");
const { ethers }      = require("hardhat");
const { anyValue }    = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const VALID_ROOT       = "0x" + "02".repeat(32);   // bytes32 non-zero
const VALID_COMMITMENT = "0x" + "01".repeat(8);    // bytes8  non-zero
const VALID_PROOF      = "0x" + "ab".repeat(64);   // 64 bytes ≥ MIN_PROOF_LENGTH
const SHORT_PROOF      = "0x" + "aa".repeat(32);   // 32 bytes < MIN_PROOF_LENGTH
const ZERO_COMMITMENT  = "0x" + "00".repeat(8);    // bytes8  zero

// ─────────────────────────────────────────────────────────────────────────────
// QLSAVerifier (stub)
// ─────────────────────────────────────────────────────────────────────────────

describe("QLSAVerifier", function () {
  let verifier;

  beforeEach(async function () {
    const Factory = await ethers.getContractFactory("QLSAVerifier");
    verifier = await Factory.deploy();
  });

  it("accepts a valid proof and non-zero commitment", async function () {
    expect(await verifier.verify(VALID_PROOF, VALID_COMMITMENT)).to.be.true;
  });

  it("rejects zero commitment", async function () {
    expect(await verifier.verify(VALID_PROOF, ZERO_COMMITMENT)).to.be.false;
  });

  it("rejects proof shorter than MIN_PROOF_LENGTH", async function () {
    expect(await verifier.verify(SHORT_PROOF, VALID_COMMITMENT)).to.be.false;
  });

  it("rejects empty proof", async function () {
    expect(await verifier.verify("0x", VALID_COMMITMENT)).to.be.false;
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// BatchRegistry
// ─────────────────────────────────────────────────────────────────────────────

describe("BatchRegistry", function () {
  let verifier, registry, owner, other;

  beforeEach(async function () {
    [owner, other] = await ethers.getSigners();

    const VerifierFactory  = await ethers.getContractFactory("QLSAVerifier");
    verifier = await VerifierFactory.deploy();

    const RegistryFactory = await ethers.getContractFactory("BatchRegistry");
    registry = await RegistryFactory.deploy(
      owner.address,
      await verifier.getAddress()
    );
  });

  // ── submitBatch ─────────────────────────────────────────────────────────────

  it("finalizes a valid batch and emits BatchFinalized", async function () {
    await expect(
      registry.submitBatch(VALID_ROOT, VALID_COMMITMENT, VALID_PROOF)
    )
      .to.emit(registry, "BatchFinalized")
      .withArgs(VALID_ROOT, VALID_COMMITMENT, anyValue);

    expect(await registry.isBatchFinalized(VALID_ROOT)).to.be.true;
  });

  it("records a non-zero batchTimestamp after finalization", async function () {
    await registry.submitBatch(VALID_ROOT, VALID_COMMITMENT, VALID_PROOF);
    const ts = await registry.batchTimestamps(VALID_ROOT);
    expect(ts).to.be.gt(0n);
  });

  it("reverts on zero Merkle root", async function () {
    await expect(
      registry.submitBatch(ethers.ZeroHash, VALID_COMMITMENT, VALID_PROOF)
    ).to.be.revertedWithCustomError(registry, "InvalidMerkleRoot");
  });

  it("reverts when submitting the same batch twice", async function () {
    await registry.submitBatch(VALID_ROOT, VALID_COMMITMENT, VALID_PROOF);
    await expect(
      registry.submitBatch(VALID_ROOT, VALID_COMMITMENT, VALID_PROOF)
    ).to.be.revertedWithCustomError(registry, "BatchAlreadyFinalized")
      .withArgs(VALID_ROOT);
  });

  it("reverts when proof is too short", async function () {
    await expect(
      registry.submitBatch(VALID_ROOT, VALID_COMMITMENT, SHORT_PROOF)
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("reverts when commitment is zero", async function () {
    await expect(
      registry.submitBatch(VALID_ROOT, ZERO_COMMITMENT, VALID_PROOF)
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("allows two different roots to be finalized independently", async function () {
    const ROOT_B = "0x" + "03".repeat(32);
    await registry.submitBatch(VALID_ROOT, VALID_COMMITMENT, VALID_PROOF);
    await registry.submitBatch(ROOT_B,     VALID_COMMITMENT, VALID_PROOF);
    expect(await registry.isBatchFinalized(VALID_ROOT)).to.be.true;
    expect(await registry.isBatchFinalized(ROOT_B)).to.be.true;
  });

  // ── setVerifier (admin) ──────────────────────────────────────────────────────

  it("owner can replace the verifier and emits VerifierUpdated", async function () {
    const VerifierFactory = await ethers.getContractFactory("QLSAVerifier");
    const newVerifier = await VerifierFactory.deploy();
    const newAddr     = await newVerifier.getAddress();
    const oldAddr     = await verifier.getAddress();

    await expect(registry.connect(owner).setVerifier(newAddr))
      .to.emit(registry, "VerifierUpdated")
      .withArgs(oldAddr, newAddr);

    expect(await registry.verifier()).to.equal(newAddr);
  });

  it("reverts when non-owner tries to replace the verifier", async function () {
    await expect(
      registry.connect(other).setVerifier(await verifier.getAddress())
    ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
  });

  it("reverts when owner tries to set zero-address verifier", async function () {
    await expect(
      registry.connect(owner).setVerifier(ethers.ZeroAddress)
    ).to.be.revertedWithCustomError(registry, "ZeroAddressVerifier");
  });

  // ── constructor guard ────────────────────────────────────────────────────────

  it("reverts on deployment with zero-address verifier", async function () {
    const RegistryFactory = await ethers.getContractFactory("BatchRegistry");
    await expect(
      RegistryFactory.deploy(owner.address, ethers.ZeroAddress)
    ).to.be.revertedWithCustomError(RegistryFactory, "ZeroAddressVerifier");
  });
});
