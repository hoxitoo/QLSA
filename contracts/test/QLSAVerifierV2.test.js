const { expect } = require("chai");
const { ethers }  = require("hardhat");

// M31.P = 2^31 - 1 = 0x7FFFFFFF
const P = 2_147_483_647n;

// ── Helpers ───────────────────────────────────────────────────────────────────

// Produce a commitment bytes8 where the first 4 bytes encode `m31Val` in
// little-endian (as the Stwo prover would), and the trailing 4 bytes are zero.
function makeCommitment(m31Val) {
  const v = BigInt(m31Val);
  // LE bytes of v as uint32
  const b0 = (v >> 0n) & 0xFFn;
  const b1 = (v >> 8n) & 0xFFn;
  const b2 = (v >> 16n) & 0xFFn;
  const b3 = (v >> 24n) & 0xFFn;
  // Pack into bytes8 (big-endian memory, trailing 4 bytes = 0)
  return (b0 << 56n) | (b1 << 48n) | (b2 << 40n) | (b3 << 32n);
}

function toBytes8Hex(bigint) {
  return "0x" + bigint.toString(16).padStart(16, "0");
}

const VALID_PROOF      = "0x" + "ab".repeat(256);   // 256 bytes
const SHORT_PROOF      = "0x" + "ab".repeat(128);   // 128 bytes < 256
const ZERO_COMMITMENT  = "0x" + "00".repeat(8);

// Valid M31 element = 0x12345678 → LE bytes [0x78,0x56,0x34,0x12] → bytes8
const VALID_M31        = 0x12345678n;
const VALID_COMMITMENT = toBytes8Hex(makeCommitment(VALID_M31));

// ─────────────────────────────────────────────────────────────────────────────

describe("QLSAVerifierV2", function () {
  let verifier;

  beforeEach(async function () {
    const Factory = await ethers.getContractFactory("QLSAVerifierV2");
    verifier = await Factory.deploy();
  });

  // ── Acceptance ────────────────────────────────────────────────────────────

  it("accepts valid proof and valid M31 commitment", async function () {
    expect(await verifier.verify(VALID_PROOF, VALID_COMMITMENT)).to.be.true;
  });

  it("MIN_PROOF_LENGTH == 256", async function () {
    expect(await verifier.MIN_PROOF_LENGTH()).to.equal(256n);
  });

  // ── Proof length ─────────────────────────────────────────────────────────

  it("rejects proof shorter than MIN_PROOF_LENGTH", async function () {
    expect(await verifier.verify(SHORT_PROOF, VALID_COMMITMENT)).to.be.false;
  });

  it("rejects empty proof", async function () {
    expect(await verifier.verify("0x", VALID_COMMITMENT)).to.be.false;
  });

  it("accepts proof exactly MIN_PROOF_LENGTH bytes", async function () {
    const exactProof = "0x" + "cd".repeat(256);
    expect(await verifier.verify(exactProof, VALID_COMMITMENT)).to.be.true;
  });

  // ── Commitment validation ─────────────────────────────────────────────────

  it("rejects all-zero commitment", async function () {
    expect(await verifier.verify(VALID_PROOF, ZERO_COMMITMENT)).to.be.false;
  });

  it("rejects commitment where M31 value == P (invalid M31 element)", async function () {
    // P = 2^31 - 1 = 0x7FFFFFFF in LE = bytes [0xFF, 0xFF, 0xFF, 0x7F]
    // As bytes8: 0xFFFFFF7F00000000
    const pCommitment = toBytes8Hex(makeCommitment(P));
    expect(await verifier.verify(VALID_PROOF, pCommitment)).to.be.false;
  });

  it("rejects commitment where M31 value > P (e.g. 0x80000000)", async function () {
    const overP = 0x80000000n; // = 2^31, which is > P
    const overPCommit = toBytes8Hex(makeCommitment(overP));
    expect(await verifier.verify(VALID_PROOF, overPCommit)).to.be.false;
  });

  it("accepts commitment M31 value == 1 (smallest valid non-zero)", async function () {
    const oneCommit = toBytes8Hex(makeCommitment(1n));
    expect(await verifier.verify(VALID_PROOF, oneCommit)).to.be.true;
  });

  it("accepts commitment M31 value == P-1 (largest valid element)", async function () {
    const maxCommit = toBytes8Hex(makeCommitment(P - 1n));
    expect(await verifier.verify(VALID_PROOF, maxCommit)).to.be.true;
  });

  it("rejects commitment with non-zero trailing 4 bytes", async function () {
    // High bits set → uint32(uint64(commitment)) != 0
    const badTrail = VALID_COMMITMENT.slice(0, 10) + "deadbeef" + VALID_COMMITMENT.slice(18);
    expect(await verifier.verify(VALID_PROOF, badTrail)).to.be.false;
  });
});

// ── BatchRegistry integration with QLSAVerifierV2 ────────────────────────────

describe("BatchRegistry with QLSAVerifierV2", function () {
  let verifier, registry, owner;

  const MERKLE_ROOT = "0x" + "02".repeat(32);

  beforeEach(async function () {
    [owner] = await ethers.getSigners();
    const V2 = await ethers.getContractFactory("QLSAVerifierV2");
    verifier = await V2.deploy();
    const Reg = await ethers.getContractFactory("BatchRegistry");
    registry = await Reg.deploy(owner.address, await verifier.getAddress());
  });

  it("finalizes a batch with valid M31 commitment", async function () {
    await expect(
      registry.submitBatch(MERKLE_ROOT, VALID_COMMITMENT, VALID_PROOF)
    ).to.emit(registry, "BatchFinalized");
    expect(await registry.isBatchFinalized(MERKLE_ROOT)).to.be.true;
  });

  it("reverts on invalid commitment (all zeros)", async function () {
    await expect(
      registry.submitBatch(MERKLE_ROOT, ZERO_COMMITMENT, VALID_PROOF)
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("reverts on short proof", async function () {
    await expect(
      registry.submitBatch(MERKLE_ROOT, VALID_COMMITMENT, SHORT_PROOF)
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("owner can upgrade from stub to V2", async function () {
    // Deploy stub first
    const Stub = await ethers.getContractFactory("QLSAVerifier");
    const stub = await Stub.deploy();
    const Reg = await ethers.getContractFactory("BatchRegistry");
    const reg = await Reg.deploy(owner.address, await stub.getAddress());

    // Upgrade to V2
    await expect(reg.setVerifier(await verifier.getAddress()))
      .to.emit(reg, "VerifierUpdated");
  });
});
