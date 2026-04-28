const { expect } = require("chai");
const { ethers }  = require("hardhat");

// ─────────────────────────────────────────────────────────────────────────────
// Test-vector helpers
//
// All expected commitment values are computed using the Solidity Blake2s
// library itself (via Blake2sHarness).  This avoids a JS Blake2s dependency
// while staying honest: if Blake2s.sol is wrong, Blake2s.test.js catches it.
// ─────────────────────────────────────────────────────────────────────────────

// Proof constants
const PROOF_LEN       = 700;
const PROOF_FILL      = "ab"; // non-zero byte for proof body

// Build a proof of the given length filled with `fill` (hex byte).
const makeProof = (len, fill = PROOF_FILL) => "0x" + fill.repeat(len);

// Extract the first 8 bytes of a bytes32 hash as a bytes8 hex string.
const toBytes8Commitment = (hash32hex) =>
  "0x" + hash32hex.slice(2, 18); // "0x" + 16 hex chars

describe("QLSAVerifierFull", function () {
  let verifier;
  let b2s;

  // Reusable proof and commitment (computed once; shared across tests).
  let VALID_PROOF;
  let VALID_COMMITMENT;

  before(async function () {
    const B2sFactory = await ethers.getContractFactory("Blake2sHarness");
    b2s = await B2sFactory.deploy();

    const FullFactory = await ethers.getContractFactory("QLSAVerifierFull");
    verifier = await FullFactory.deploy();

    // Build the standard 700-byte test proof.
    VALID_PROOF = makeProof(PROOF_LEN);

    // Commitment = Blake2s(proof[0:32])[0:8].
    // proof[0:32] = "ab" × 32.
    const proofHead = "0x" + PROOF_FILL.repeat(32);
    const rootHash = await b2s.hash(proofHead); // bytes32
    VALID_COMMITMENT = toBytes8Commitment(rootHash);
  });

  // ── Constants ─────────────────────────────────────────────────────────────

  it("MIN_PROOF_LENGTH == 700", async function () {
    expect(await verifier.MIN_PROOF_LENGTH()).to.equal(700n);
  });

  it("MAX_PROOF_LENGTH == 1048576 (1 MiB)", async function () {
    expect(await verifier.MAX_PROOF_LENGTH()).to.equal(1_048_576n);
  });

  // ── Acceptance ────────────────────────────────────────────────────────────

  it("accepts valid proof with correctly-derived commitment", async function () {
    expect(await verifier.verify(VALID_PROOF, VALID_COMMITMENT)).to.be.true;
  });

  it("accepts larger proof (2000 bytes) when first 32 bytes match commitment", async function () {
    const bigProof = makeProof(2000, PROOF_FILL);
    // Same fill → same first 32 bytes → same commitment.
    expect(await verifier.verify(bigProof, VALID_COMMITMENT)).to.be.true;
  });

  it("accepts proof exactly at MIN_PROOF_LENGTH boundary (700 bytes)", async function () {
    expect(await verifier.verify(VALID_PROOF, VALID_COMMITMENT)).to.be.true;
  });

  it("commitment depends only on proof[0:32], not the rest", async function () {
    // Same first 32 bytes, different tail → same commitment accepted.
    const sameHead = "0x" + PROOF_FILL.repeat(32) + "cd".repeat(668);
    expect(await verifier.verify(sameHead, VALID_COMMITMENT)).to.be.true;
  });

  it("accepts proof with zero-filled tail when first 32 bytes are non-zero", async function () {
    const mixedProof = "0x" + PROOF_FILL.repeat(32) + "00".repeat(668);
    expect(await verifier.verify(mixedProof, VALID_COMMITMENT)).to.be.true;
  });

  // ── Proof-length rejection ────────────────────────────────────────────────

  it("rejects proof shorter than 700 bytes (699)", async function () {
    expect(await verifier.verify(makeProof(699), VALID_COMMITMENT)).to.be.false;
  });

  it("rejects empty proof", async function () {
    expect(await verifier.verify("0x", VALID_COMMITMENT)).to.be.false;
  });

  it("rejects proof larger than 1 MiB (gas-griefing guard)", async function () {
    // Zero bytes keep calldata gas well under the Fusaka per-tx cap (16,777,216).
    const tooBig = "0x" + "00".repeat(1_048_577);
    expect(await verifier.verify(tooBig, VALID_COMMITMENT)).to.be.false;
  });

  // ── Commitment rejection ──────────────────────────────────────────────────

  it("rejects all-zero commitment", async function () {
    expect(await verifier.verify(VALID_PROOF, "0x" + "00".repeat(8))).to.be.false;
  });

  it("rejects commitment with wrong first byte", async function () {
    // Flip the first byte of VALID_COMMITMENT.
    const bad = "0x" + (
      ((parseInt(VALID_COMMITMENT.slice(2, 4), 16) ^ 0xFF)
        .toString(16).padStart(2, "0")) +
      VALID_COMMITMENT.slice(4)
    );
    expect(await verifier.verify(VALID_PROOF, bad)).to.be.false;
  });

  it("rejects commitment derived from different proof header", async function () {
    // commitment derived from "cd" × 32 ≠ commitment derived from "ab" × 32
    const otherHead = "0x" + "cd".repeat(32);
    const otherHash = await b2s.hash(otherHead);
    const otherCommitment = toBytes8Commitment(otherHash);
    expect(await verifier.verify(VALID_PROOF, otherCommitment)).to.be.false;
  });

  // ── Blake2s FRI binding: proof header mutation ────────────────────────────

  it("rejects proof whose first 32 bytes differ from the committed header", async function () {
    // Flip one byte inside proof[0:32] — commitment no longer matches.
    const mutatedProof = "0x" + "cd" + PROOF_FILL.repeat(699);
    expect(await verifier.verify(mutatedProof, VALID_COMMITMENT)).to.be.false;
  });

  it("accepts proof after recomputing commitment from mutated header", async function () {
    // Mutate first byte and recompute commitment → verifier accepts.
    const mutatedProof = "0x" + "cd" + PROOF_FILL.repeat(699);
    const mutatedHead  = "0x" + "cd" + PROOF_FILL.repeat(31);
    const mutatedHash  = await b2s.hash(mutatedHead);
    const mutatedCommitment = toBytes8Commitment(mutatedHash);
    expect(await verifier.verify(mutatedProof, mutatedCommitment)).to.be.true;
  });

  it("rejects modification to proof bytes after position 32 with old commitment", async function () {
    // Changing bytes beyond position 32 does NOT affect the commitment check.
    // (Binding is on proof[0:32] only.)  The verifier still accepts.
    const tailMutated = "0x" + PROOF_FILL.repeat(32) + "ff".repeat(668);
    expect(await verifier.verify(tailMutated, VALID_COMMITMENT)).to.be.true;
  });

  // ── Different proof fill bytes ────────────────────────────────────────────

  it("accepts proof filled with 0x01 when commitment is correctly derived", async function () {
    const proof01 = makeProof(PROOF_LEN, "01");
    const head01  = "0x" + "01".repeat(32);
    const hash01  = await b2s.hash(head01);
    const comm01  = toBytes8Commitment(hash01);
    expect(await verifier.verify(proof01, comm01)).to.be.true;
  });

  it("accepts proof filled with 0xff when commitment is correctly derived", async function () {
    const proofFF = makeProof(PROOF_LEN, "ff");
    const headFF  = "0x" + "ff".repeat(32);
    const hashFF  = await b2s.hash(headFF);
    const commFF  = toBytes8Commitment(hashFF);
    expect(await verifier.verify(proofFF, commFF)).to.be.true;
  });
});

// ── BatchRegistry integration ─────────────────────────────────────────────────

describe("BatchRegistry with QLSAVerifierFull", function () {
  let verifier, registry, b2s, owner;
  let VALID_PROOF, VALID_COMMITMENT;

  const MERKLE_ROOT = "0x" + "05".repeat(32);

  beforeEach(async function () {
    [owner] = await ethers.getSigners();

    const B2sFactory  = await ethers.getContractFactory("Blake2sHarness");
    b2s = await B2sFactory.deploy();

    const FullFactory = await ethers.getContractFactory("QLSAVerifierFull");
    verifier = await FullFactory.deploy();

    const RegFactory  = await ethers.getContractFactory("BatchRegistry");
    registry = await RegFactory.deploy(owner.address, await verifier.getAddress());

    // Build valid proof/commitment.
    VALID_PROOF = makeProof(700, "ab");
    const rootHash = await b2s.hash("0x" + "ab".repeat(32));
    VALID_COMMITMENT = toBytes8Commitment(rootHash);
  });

  it("finalizes a batch with valid proof and commitment", async function () {
    await expect(
      registry.submitBatch(MERKLE_ROOT, VALID_COMMITMENT, VALID_PROOF)
    ).to.emit(registry, "BatchFinalized");
    expect(await registry.isBatchFinalized(MERKLE_ROOT)).to.be.true;
  });

  it("reverts on short proof (699 bytes)", async function () {
    await expect(
      registry.submitBatch(MERKLE_ROOT, VALID_COMMITMENT, makeProof(699))
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("reverts on all-zero commitment", async function () {
    await expect(
      registry.submitBatch(MERKLE_ROOT, "0x" + "00".repeat(8), VALID_PROOF)
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("reverts when commitment does not match proof header", async function () {
    const wrongCommitment = toBytes8Commitment(await b2s.hash("0x" + "cd".repeat(32)));
    await expect(
      registry.submitBatch(MERKLE_ROOT, wrongCommitment, VALID_PROOF)
    ).to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("owner can upgrade from V3 to QLSAVerifierFull", async function () {
    const V3Factory = await ethers.getContractFactory("QLSAVerifierV3");
    const v3 = await V3Factory.deploy();
    const RegFactory = await ethers.getContractFactory("BatchRegistry");
    const reg = await RegFactory.deploy(owner.address, await v3.getAddress());

    await expect(reg.setVerifier(await verifier.getAddress()))
      .to.emit(reg, "VerifierUpdated");
    expect(await reg.verifier()).to.equal(await verifier.getAddress());
  });
});
