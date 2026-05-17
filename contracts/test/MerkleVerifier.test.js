const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { blake2s } = require("@noble/hashes/blake2.js");

// ── Reference implementations ─────────────────────────────────────────────────

function hashLeafRef(colValues) {
    // Pack uint32 values as LE bytes, then Blake2s-256
    const buf = Buffer.alloc(colValues.length * 4);
    for (let i = 0; i < colValues.length; i++) {
        buf.writeUInt32LE(colValues[i], i * 4);
    }
    return "0x" + Buffer.from(blake2s(buf)).toString("hex");
}

function hashPairRef(left, right) {
    const l = Buffer.from(left.slice(2), "hex");
    const r = Buffer.from(right.slice(2), "hex");
    const buf = Buffer.concat([l, r]);
    return "0x" + Buffer.from(blake2s(buf)).toString("hex");
}

function buildMerkleTree(leaves) {
    // Returns array of levels from bottom (leaves) to root
    let level = leaves.map(l => l);
    const levels = [level];
    while (level.length > 1) {
        const next = [];
        for (let i = 0; i < level.length; i += 2) {
            next.push(hashPairRef(level[i], level[i + 1]));
        }
        level = next;
        levels.push(level);
    }
    return levels;
}

function merkleProof(levels, index) {
    const siblings = [];
    let idx = index;
    for (let d = 0; d < levels.length - 1; d++) {
        const siblingIdx = idx ^ 1;
        siblings.push(levels[d][siblingIdx]);
        idx >>= 1;
    }
    return { root: levels[levels.length - 1][0], siblings };
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe("MerkleVerifier library", function () {
    let h;

    before(async function () {
        const F = await ethers.getContractFactory("MerkleVerifierHarness");
        h = await F.deploy();
    });

    it("hashLeaf: single uint32 value 0", async function () {
        const expected = hashLeafRef([0]);
        const result   = await h.hashLeaf([0n]);
        expect(result.toLowerCase()).to.equal(expected.toLowerCase());
    });

    it("hashLeaf: single uint32 value 1", async function () {
        const expected = hashLeafRef([1]);
        const result   = await h.hashLeaf([1n]);
        expect(result.toLowerCase()).to.equal(expected.toLowerCase());
    });

    it("hashLeaf: multiple column values", async function () {
        const cols = [100, 200, 300, 400];
        const expected = hashLeafRef(cols);
        const result   = await h.hashLeaf(cols.map(BigInt));
        expect(result.toLowerCase()).to.equal(expected.toLowerCase());
    });

    it("hashPair: two 32-byte hashes", async function () {
        const l = "0x" + "ab".repeat(32);
        const r = "0x" + "cd".repeat(32);
        const expected = hashPairRef(l, r);
        const result   = await h.hashPair(l, r);
        expect(result.toLowerCase()).to.equal(expected.toLowerCase());
    });

    it("verify: 2-leaf tree, leaf 0", async function () {
        const leaves = [hashLeafRef([1]), hashLeafRef([2])];
        const levels = buildMerkleTree(leaves);
        const { root, siblings } = merkleProof(levels, 0);
        expect(await h.verify(root, leaves[0], 0n, 1n, siblings)).to.be.true;
    });

    it("verify: 2-leaf tree, leaf 1", async function () {
        const leaves = [hashLeafRef([1]), hashLeafRef([2])];
        const levels = buildMerkleTree(leaves);
        const { root, siblings } = merkleProof(levels, 1);
        expect(await h.verify(root, leaves[1], 1n, 1n, siblings)).to.be.true;
    });

    it("verify: 4-leaf tree, all leaves", async function () {
        const leaves = [1, 2, 3, 4].map(v => hashLeafRef([v]));
        const levels = buildMerkleTree(leaves);
        for (let i = 0; i < 4; i++) {
            const { root, siblings } = merkleProof(levels, i);
            expect(await h.verify(root, leaves[i], BigInt(i), 2n, siblings)).to.be.true;
        }
    });

    it("verify: 8-leaf tree, all leaves", async function () {
        const leaves = [1,2,3,4,5,6,7,8].map(v => hashLeafRef([v]));
        const levels = buildMerkleTree(leaves);
        for (let i = 0; i < 8; i++) {
            const { root, siblings } = merkleProof(levels, i);
            expect(await h.verify(root, leaves[i], BigInt(i), 3n, siblings)).to.be.true;
        }
    });

    it("verify: wrong leaf hash → false", async function () {
        const leaves = [hashLeafRef([1]), hashLeafRef([2])];
        const levels = buildMerkleTree(leaves);
        const { root, siblings } = merkleProof(levels, 0);
        const wrongLeaf = hashLeafRef([99]);
        expect(await h.verify(root, wrongLeaf, 0n, 1n, siblings)).to.be.false;
    });

    it("verify: wrong root → false", async function () {
        const leaves = [hashLeafRef([1]), hashLeafRef([2])];
        const levels = buildMerkleTree(leaves);
        const { siblings } = merkleProof(levels, 0);
        const wrongRoot = "0x" + "ff".repeat(32);
        expect(await h.verify(wrongRoot, leaves[0], 0n, 1n, siblings)).to.be.false;
    });

    it("verifyColumns: leaf 3 in 4-leaf tree with 2 columns", async function () {
        const colSets = [[1, 10], [2, 20], [3, 30], [4, 40]];
        const leaves = colSets.map(c => hashLeafRef(c));
        const levels = buildMerkleTree(leaves);
        const { root, siblings } = merkleProof(levels, 3);
        expect(
            await h.verifyColumns(root, colSets[3].map(BigInt), 3n, 2n, siblings)
        ).to.be.true;
    });
});
