const { expect } = require("chai");
const { ethers }  = require("hardhat");

// Test vectors produced by Python: hashlib.blake2s(msg).hexdigest()
// All values confirmed against RFC 7693 and reference implementations.
const VECTORS = [
  { label: "empty",       input: "0x",                              expected: "0x69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9" },
  { label: "'abc'",       input: ethers.hexlify(ethers.toUtf8Bytes("abc")),         expected: "0x508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982" },
  { label: "fox",         input: ethers.hexlify(ethers.toUtf8Bytes("The quick brown fox jumps over the lazy dog")), expected: "0x606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812" },
  { label: "64×0x00",    input: "0x" + "00".repeat(64),            expected: "0xae09db7cd54f42b490ef09b6bc541af688e4959bb8c53f359a6f56e38ab454a3" },
  { label: "65×0x00",    input: "0x" + "00".repeat(65),            expected: "0x857328bf990b00922782d3e81c6054c25d3375d386c7424abe3e01d79041046c" },
  { label: "128×'a'",    input: ethers.hexlify(ethers.toUtf8Bytes("a".repeat(128))), expected: "0x3ac477e27353f9019b81694afe60c8049403784f91a58288428ea318bfa82809" },
];

describe("Blake2s library", function () {
  let b2s;

  before(async function () {
    const Factory = await ethers.getContractFactory("Blake2sHarness");
    b2s = await Factory.deploy();
  });

  for (const { label, input, expected } of VECTORS) {
    it(`hash(${label}) matches Python hashlib`, async function () {
      const result = await b2s.hash(input);
      expect(result.toLowerCase()).to.equal(expected.toLowerCase());
    });
  }

  // Additional structural properties
  it("empty and single-byte inputs produce different hashes", async function () {
    const h0 = await b2s.hash("0x");
    const h1 = await b2s.hash("0x00");
    expect(h0).to.not.equal(h1);
  });

  it("hash is deterministic (same input → same output)", async function () {
    const input = ethers.hexlify(ethers.toUtf8Bytes("hello world"));
    const h1 = await b2s.hash(input);
    const h2 = await b2s.hash(input);
    expect(h1).to.equal(h2);
  });

  it("one-byte difference changes the hash entirely", async function () {
    const a = await b2s.hash("0x" + "00".repeat(63) + "00");
    const b = await b2s.hash("0x" + "00".repeat(63) + "01");
    expect(a).to.not.equal(b);
  });
});
