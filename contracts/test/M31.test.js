const { expect } = require("chai");
const { ethers }  = require("hardhat");

const P = 2_147_483_647n;  // 2^31 - 1

describe("M31 library", function () {
  let m31;

  before(async function () {
    const Factory = await ethers.getContractFactory("M31Harness");
    m31 = await Factory.deploy();
  });

  // ── Constants ──────────────────────────────────────────────────────────────

  it("P == 2^31 − 1", async function () {
    expect(await m31.P()).to.equal(P);
  });

  // ── add ────────────────────────────────────────────────────────────────────

  it("add: basic", async function () {
    expect(await m31.add(1n, 2n)).to.equal(3n);
  });

  it("add: wrap around P", async function () {
    // (P-1) + 1 = P ≡ 0 (mod P)
    expect(await m31.add(P - 1n, 1n)).to.equal(0n);
    // (P-1) + 2 = 1
    expect(await m31.add(P - 1n, 2n)).to.equal(1n);
  });

  it("add: 0 is identity", async function () {
    expect(await m31.add(12345n, 0n)).to.equal(12345n);
    expect(await m31.add(0n, 12345n)).to.equal(12345n);
  });

  // ── sub ────────────────────────────────────────────────────────────────────

  it("sub: basic", async function () {
    expect(await m31.sub(5n, 3n)).to.equal(2n);
  });

  it("sub: underflow wraps correctly", async function () {
    // 0 − 1 = P − 1
    expect(await m31.sub(0n, 1n)).to.equal(P - 1n);
    // 1 − 2 = P − 1
    expect(await m31.sub(1n, 2n)).to.equal(P - 1n);
  });

  it("sub: a − a == 0", async function () {
    expect(await m31.sub(999n, 999n)).to.equal(0n);
  });

  // ── mul ────────────────────────────────────────────────────────────────────

  it("mul: basic", async function () {
    expect(await m31.mul(3n, 4n)).to.equal(12n);
  });

  it("mul: uses mulmod (large values)", async function () {
    // (P-1) * (P-1) = P^2 - 2P + 1 ≡ 1 (mod P)
    // Because (P-1) ≡ -1, so (-1)*(-1) = 1
    expect(await m31.mul(P - 1n, P - 1n)).to.equal(1n);
  });

  it("mul: 0 absorbs", async function () {
    expect(await m31.mul(12345678n, 0n)).to.equal(0n);
    expect(await m31.mul(0n, 12345678n)).to.equal(0n);
  });

  it("mul: 1 is identity", async function () {
    expect(await m31.mul(999999n, 1n)).to.equal(999999n);
  });

  // ── pow ────────────────────────────────────────────────────────────────────

  it("pow: a^0 == 1", async function () {
    expect(await m31.mpow(123456n, 0n)).to.equal(1n);
  });

  it("pow: a^1 == a", async function () {
    expect(await m31.mpow(123456n, 1n)).to.equal(123456n);
  });

  it("pow: 2^10 == 1024", async function () {
    expect(await m31.mpow(2n, 10n)).to.equal(1024n);
  });

  it("pow: Fermat's little theorem — a^P == a (mod P)", async function () {
    // For prime P: a^P ≡ a (mod P)
    const a = 42n;
    expect(await m31.mpow(a, P)).to.equal(a);
  });

  // ── inv ────────────────────────────────────────────────────────────────────

  it("inv: a * inv(a) == 1", async function () {
    const a = 12345n;
    const a_inv = await m31.inv(a);
    expect(await m31.mul(a, a_inv)).to.equal(1n);
  });

  it("inv: inv(1) == 1", async function () {
    expect(await m31.inv(1n)).to.equal(1n);
  });

  it("inv: inv(P-1) == P-1 (since (P-1)^2 = 1 mod P)", async function () {
    expect(await m31.inv(P - 1n)).to.equal(P - 1n);
  });

  it("inv: reverts on zero", async function () {
    await expect(m31.inv(0n)).to.be.revertedWith("M31: zero has no inverse");
  });

  // ── neg ────────────────────────────────────────────────────────────────────

  it("neg: neg(0) == 0", async function () {
    expect(await m31.neg(0n)).to.equal(0n);
  });

  it("neg: a + neg(a) == 0", async function () {
    const a = 999n;
    expect(await m31.add(a, await m31.neg(a))).to.equal(0n);
  });

  it("neg: neg(1) == P-1", async function () {
    expect(await m31.neg(1n)).to.equal(P - 1n);
  });

  // ── isValid ────────────────────────────────────────────────────────────────

  it("isValid: 0 is valid", async function () {
    expect(await m31.isValid(0n)).to.be.true;
  });

  it("isValid: P-1 is valid", async function () {
    expect(await m31.isValid(P - 1n)).to.be.true;
  });

  it("isValid: P is NOT valid", async function () {
    expect(await m31.isValid(P)).to.be.false;
  });

  it("isValid: 2^32-1 is NOT valid", async function () {
    expect(await m31.isValid(4_294_967_295n)).to.be.false;
  });

  // ── fromBytes4LE / toBytes4LE ─────────────────────────────────────────────

  it("fromBytes4LE: zero bytes → 0", async function () {
    expect(await m31.fromBytes4LE("0x00000000")).to.equal(0n);
  });

  it("fromBytes4LE: LE encoding of 1 is 0x01000000", async function () {
    // uint32(1) in little-endian bytes = [0x01, 0x00, 0x00, 0x00]
    // As big-endian bytes4 in Solidity = 0x01000000
    expect(await m31.fromBytes4LE("0x01000000")).to.equal(1n);
  });

  it("fromBytes4LE: LE encoding of 0x12345678", async function () {
    // 0x12345678 in LE bytes = [0x78, 0x56, 0x34, 0x12]
    // As BE bytes4 in Solidity  = 0x78563412
    expect(await m31.fromBytes4LE("0x78563412")).to.equal(0x12345678n);
  });

  it("toBytes4LE ∘ fromBytes4LE == identity for valid M31 values", async function () {
    const val = 0x12345678n;
    const b4  = "0x78563412"; // LE bytes of val as BE bytes4
    const decoded = await m31.fromBytes4LE(b4);
    expect(decoded).to.equal(val);
    const reencoded = await m31.toBytes4LE(decoded);
    expect(reencoded.toLowerCase()).to.equal(b4.toLowerCase());
  });

  it("toBytes4LE: reverts if value >= P", async function () {
    await expect(m31.toBytes4LE(P)).to.be.revertedWith("M31: value out of range");
  });
});
