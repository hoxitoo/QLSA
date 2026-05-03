const { expect } = require("chai");
const { ethers }  = require("hardhat");

// ─────────────────────────────────────────────────────────────────────────────
// QLSAVerifierBound — Merkle-root-bound commitment verifier tests
//
// Commitment scheme (128-bit):
//   commitment = Blake2s(proof[0:32] ∥ merkleRoot)[0:16]
//
// This closes the replay attack present in QLSAVerifierFull, and the
// birthday-bound collision risk of the previous 32-bit (bytes8) format.
// ─────────────────────────────────────────────────────────────────────────────

const PROOF_LEN  = 700;
const PROOF_FILL = "ab";

const makeProof = (len, fill = PROOF_FILL) => "0x" + fill.repeat(len);

// Extract the first 16 bytes of a bytes32 hash as a bytes16 hex string.
const toBytes16 = (hash32hex) => "0x" + hash32hex.slice(2, 34);

describe("QLSAVerifierBound", function () {
  let verifier;
  let b2s;

  let VALID_PROOF;
  let VALID_MERKLE;
  let VALID_COMMITMENT;

  before(async function () {
    const B2sFactory = await ethers.getContractFactory("Blake2sHarness");
    b2s = await B2sFactory.deploy();

    const Factory = await ethers.getContractFactory("QLSAVerifierBound");
    verifier = await Factory.deploy();

    VALID_PROOF  = makeProof(PROOF_LEN);
    VALID_MERKLE = "0x" + "cd".repeat(32); // non-zero 32-byte Merkle root

    // Commitment = Blake2s(proof[0:32] ∥ merkleRoot)[0:16].
    // Concatenate as 64-byte input: proof head (32 bytes) + merkle root (32 bytes).
    const proofHead = "0x" + PROOF_FILL.repeat(32);
    const input64   = proofHead + "cd".repeat(32); // 64 bytes total (no 0x on the 2nd part)
    const rootHash  = await b2s.hash(input64);
    VALID_COMMITMENT = toBytes16(rootHash);
  });

  // ── Constants ─────────────────────────────────────────────────────────────

  it("MIN_PROOF_LENGTH == 700", async function () {
    expect(await verifier.MIN_PROOF_LENGTH()).to.equal(700n);
  });

  it("MAX_PROOF_LENGTH == 1048576 (1 MiB)", async function () {
    expect(await verifier.MAX_PROOF_LENGTH()).to.equal(1_048_576n);
  });

  // ── Acceptance ────────────────────────────────────────────────────────────

  it("accepts valid (proof, commitment, merkleRoot) triple", async function () {
    expect(
      await verifier.verify(VALID_PROOF, VALID_COMMITMENT, VALID_MERKLE)
    ).to.be.true;
  });

  it("accepts larger proof when first 32 bytes and merkleRoot match", async function () {
    const bigProof = makeProof(2000, PROOF_FILL);
    expect(
      await verifier.verify(bigProof, VALID_COMMITMENT, VALID_MERKLE)
    ).to.be.true;
  });

  it("commitment depends on proof[0:32] AND merkleRoot jointly", async function () {
    const otherRoot = "0x" + "ef".repeat(32);
    expect(
      await verifier.verify(VALID_PROOF, VALID_COMMITMENT, otherRoot)
    ).to.be.false;
  });

  // ── Rejection — proof length ───────────────────────────────────────────────

  it("rejects proof shorter than MIN_PROOF_LENGTH", async function () {
    const shortProof = makeProof(699);
    expect(
      await verifier.verify(shortProof, VALID_COMMITMENT, VALID_MERKLE)
    ).to.be.false;
  });

  it("rejects empty proof", async function () {
    expect(
      await verifier.verify("0x", VALID_COMMITMENT, VALID_MERKLE)
    ).to.be.false;
  });

  it("rejects proof larger than MAX_PROOF_LENGTH", async function () {
    const hugeFill = "0x" + "00".repeat(1_048_577);
    expect(
      await verifier.verify(hugeFill, VALID_COMMITMENT, VALID_MERKLE)
    ).to.be.false;
  });

  // ── Rejection — trivial inputs ─────────────────────────────────────────────

  it("rejects zero commitment (bytes16)", async function () {
    const zeroBytes16 = "0x" + "00".repeat(16);
    expect(
      await verifier.verify(VALID_PROOF, zeroBytes16, VALID_MERKLE)
    ).to.be.false;
  });

  it("rejects zero merkleRoot", async function () {
    const zeroRoot = "0x" + "00".repeat(32);
    expect(
      await verifier.verify(VALID_PROOF, VALID_COMMITMENT, zeroRoot)
    ).to.be.false;
  });

  // ── Rejection — tampered inputs ────────────────────────────────────────────

  it("rejects tampered proof[0:32] (commitment mismatch)", async function () {
    const tamperedProof = makeProof(PROOF_LEN, "ff");
    expect(
      await verifier.verify(tamperedProof, VALID_COMMITMENT, VALID_MERKLE)
    ).to.be.false;
  });

  it("rejects wrong commitment (random bytes16)", async function () {
    const wrongCommitment = "0x" + "1234567890abcdef1234567890abcdef";
    expect(
      await verifier.verify(VALID_PROOF, wrongCommitment, VALID_MERKLE)
    ).to.be.false;
  });

  it("rejects when merkleRoot is changed to zero", async function () {
    expect(
      await verifier.verify(VALID_PROOF, VALID_COMMITMENT, "0x" + "00".repeat(32))
    ).to.be.false;
  });
});
