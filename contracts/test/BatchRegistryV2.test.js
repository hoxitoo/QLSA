const { expect } = require("chai");
const { ethers }  = require("hardhat");

// ─────────────────────────────────────────────────────────────────────────────
// BatchRegistryV2 — on-chain batch finalization with Merkle root binding
// ─────────────────────────────────────────────────────────────────────────────

const PROOF_LEN  = 700;
const PROOF_FILL = "ab";

const makeProof = (len, fill = PROOF_FILL) => "0x" + fill.repeat(len);
const toBytes8  = (hash32hex) => "0x" + hash32hex.slice(2, 18);

describe("BatchRegistryV2", function () {
  let registry;
  let verifier;
  let b2s;
  let owner;
  let other;

  let VALID_PROOF;
  let VALID_MERKLE;
  let VALID_COMMITMENT;

  before(async function () {
    [owner, other] = await ethers.getSigners();

    const B2sFactory = await ethers.getContractFactory("Blake2sHarness");
    b2s = await B2sFactory.deploy();

    // Deploy QLSAVerifierBound
    const VerifierFactory = await ethers.getContractFactory("QLSAVerifierBound");
    verifier = await VerifierFactory.deploy();

    // Deploy BatchRegistryV2 with owner and verifier
    const RegistryFactory = await ethers.getContractFactory("BatchRegistryV2");
    registry = await RegistryFactory.deploy(owner.address, await verifier.getAddress());

    VALID_PROOF  = makeProof(PROOF_LEN);
    VALID_MERKLE = "0x" + "cd".repeat(32);

    const proofHead = "0x" + PROOF_FILL.repeat(32);
    const input64   = proofHead + "cd".repeat(32);
    const rootHash  = await b2s.hash(input64);
    VALID_COMMITMENT = toBytes8(rootHash);
  });

  // ── Deployment ────────────────────────────────────────────────────────────

  it("stores verifier address", async function () {
    expect(await registry.verifier()).to.equal(await verifier.getAddress());
  });

  it("stores owner", async function () {
    expect(await registry.owner()).to.equal(owner.address);
  });

  it("reverts if verifier is zero address", async function () {
    const RegistryFactory = await ethers.getContractFactory("BatchRegistryV2");
    await expect(
      RegistryFactory.deploy(owner.address, ethers.ZeroAddress)
    ).to.be.revertedWithCustomError(registry, "ZeroAddressVerifier");
  });

  // ── submitBatch — successful finalization ─────────────────────────────────

  it("finalizes a valid batch and emits BatchFinalized", async function () {
    await expect(
      registry.submitBatch(VALID_MERKLE, VALID_COMMITMENT, VALID_PROOF)
    )
      .to.emit(registry, "BatchFinalized")
      .withArgs(VALID_MERKLE, VALID_COMMITMENT, await ethers.provider.getBlock("latest").then(b => b?.timestamp + 1));
  });

  it("marks batch as finalized after submitBatch", async function () {
    expect(await registry.isBatchFinalized(VALID_MERKLE)).to.be.true;
  });

  it("stores the commitment for the finalized batch", async function () {
    expect(await registry.getCommitment(VALID_MERKLE)).to.equal(VALID_COMMITMENT);
  });

  it("stores a non-zero timestamp for the finalized batch", async function () {
    expect(await registry.batchTimestamps(VALID_MERKLE)).to.be.gt(0n);
  });

  // ── submitBatch — replay protection ───────────────────────────────────────

  it("reverts on duplicate merkle root (BatchAlreadyFinalized)", async function () {
    await expect(
      registry.submitBatch(VALID_MERKLE, VALID_COMMITMENT, VALID_PROOF)
    ).to.be.revertedWithCustomError(registry, "BatchAlreadyFinalized");
  });

  // ── submitBatch — invalid inputs ──────────────────────────────────────────

  it("reverts on zero merkle root (InvalidMerkleRoot)", async function () {
    const zeroRoot = "0x" + "00".repeat(32);
    await expect(
      registry.submitBatch(zeroRoot, VALID_COMMITMENT, VALID_PROOF)
    ).to.be.revertedWithCustomError(registry, "InvalidMerkleRoot");
  });

  it("reverts when commitment does not match (wrong merkle root)", async function () {
    const otherRoot = "0x" + "ef".repeat(32);
    await expect(
      registry.submitBatch(otherRoot, VALID_COMMITMENT, VALID_PROOF)
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("reverts when commitment does not match (wrong proof)", async function () {
    const otherProof = makeProof(PROOF_LEN, "ff");
    // Fresh merkle root (not yet finalized) to avoid BatchAlreadyFinalized
    const freshRoot = "0x" + "aa".repeat(32);
    await expect(
      registry.submitBatch(freshRoot, VALID_COMMITMENT, otherProof)
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("reverts on short proof (InvalidProof via verifier)", async function () {
    const freshRoot  = "0x" + "bb".repeat(32);
    const shortProof = makeProof(100);
    await expect(
      registry.submitBatch(freshRoot, VALID_COMMITMENT, shortProof)
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  // ── Admin — setVerifier ───────────────────────────────────────────────────

  it("allows owner to update verifier", async function () {
    const NewVerifier = await ethers.getContractFactory("QLSAVerifierBound");
    const newV = await NewVerifier.deploy();
    const newAddr = await newV.getAddress();

    await expect(registry.setVerifier(newAddr))
      .to.emit(registry, "VerifierUpdated")
      .withArgs(await verifier.getAddress(), newAddr);

    expect(await registry.verifier()).to.equal(newAddr);
  });

  it("reverts setVerifier from non-owner", async function () {
    const NewVerifier = await ethers.getContractFactory("QLSAVerifierBound");
    const newV = await NewVerifier.deploy();
    await expect(
      registry.connect(other).setVerifier(await newV.getAddress())
    ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
  });

  it("reverts setVerifier(address(0))", async function () {
    await expect(
      registry.setVerifier(ethers.ZeroAddress)
    ).to.be.revertedWithCustomError(registry, "ZeroAddressVerifier");
  });

  // ── isBatchFinalized for unknown root ─────────────────────────────────────

  it("returns false for unknown Merkle root", async function () {
    const unknownRoot = "0x" + "ff".repeat(32);
    expect(await registry.isBatchFinalized(unknownRoot)).to.be.false;
  });
});
