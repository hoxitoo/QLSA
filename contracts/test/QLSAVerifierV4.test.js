const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { blake2s } = require("@noble/hashes/blake2.js");

const P = 2_147_483_647n;

// ── Field helpers ─────────────────────────────────────────────────────────────

function m31mul(a, b) { return (a * b) % P; }
function m31add(a, b) { return (a + b) % P; }
function m31sub(a, b) { return ((a - b) % P + P) % P; }
function m31pow(a, e) {
    let r = 1n; a = a % P;
    while (e > 0n) { if (e & 1n) r = m31mul(r, a); a = m31mul(a, a); e >>= 1n; }
    return r;
}
function m31inv(a) { return m31pow(a, P - 2n); }

// CM31 packed as uint64
function cm31pack(a, b) { return (a << 32n) | b; }
function cm31re(x) { return x >> 32n; }
function cm31im(x) { return x & 0xFFFFFFFFn; }
function cm31mul(x, y) {
    const a = cm31re(x), b = cm31im(x), c = cm31re(y), d = cm31im(y);
    return cm31pack(m31sub(m31mul(a,c), m31mul(b,d)), m31add(m31mul(a,d), m31mul(b,c)));
}

// QM31 packed as uint128
const R = cm31pack(2n, 1n);
function qm31pack(c0, c1) { return (BigInt(c0) << 64n) | BigInt(c1); }
function qm31c0(q) { return (q >> 64n) & 0xFFFFFFFFFFFFFFFFn; }
function qm31c1(q) { return q & 0xFFFFFFFFFFFFFFFFn; }

// ── Blake2s helper ─────────────────────────────────────────────────────────────

function blake2sHash(buf) {
    return "0x" + Buffer.from(blake2s(buf)).toString("hex");
}

// ── Merkle tree builder ────────────────────────────────────────────────────────

function hashLeaf(colValues) {
    const buf = Buffer.alloc(colValues.length * 4);
    for (let i = 0; i < colValues.length; i++) buf.writeUInt32LE(colValues[i], i * 4);
    return blake2sHash(buf);
}

function hashPair(l, r) {
    const buf = Buffer.concat([Buffer.from(l.slice(2), "hex"), Buffer.from(r.slice(2), "hex")]);
    return blake2sHash(buf);
}

function buildTree(leaves) {
    let level = leaves;
    const levels = [level];
    while (level.length > 1) {
        const next = [];
        for (let i = 0; i < level.length; i += 2) next.push(hashPair(level[i], level[i+1]));
        level = next;
        levels.push(level);
    }
    return levels;
}

function proofPath(levels, idx) {
    const siblings = [];
    let i = idx;
    for (let d = 0; d < levels.length - 1; d++) {
        siblings.push(levels[d][i ^ 1]);
        i >>= 1;
    }
    return { root: levels[levels.length-1][0], siblings };
}

// ── FRI fold reference ─────────────────────────────────────────────────────────

// friLinearFold for a real-valued alpha (QM31 with only c0.real non-zero)
function friLinearFoldReal(fPlus, fMinus, alphaReal) {
    const inv2 = m31inv(2n);
    const sumH  = m31mul(m31add(fPlus, fMinus), inv2);
    const diffH = m31mul(m31sub(fPlus, fMinus), inv2);
    return m31add(sumH, m31mul(alphaReal, diffH));
}

// ── Test fixture builder ───────────────────────────────────────────────────────

// Build a minimal valid proof and queryHints for QLSAVerifierV4.
// Trace tree: 4 leaves × 2 columns each.
// We pick query index 2, verify column values [300, 3000].
// friAlpha is real (c0 = alpha_m31, c1 = 0) so the fold check is integer.
function buildFixture() {
    // Trace column values for 4 rows
    const colA = [100, 200, 300, 400];   // column 0
    const colB = [1000, 2000, 3000, 4000]; // column 1
    const leaves = [0,1,2,3].map(i => hashLeaf([colA[i], colB[i]]));
    const levels = buildTree(leaves);
    const queryIdx = 2;
    const { root: traceRoot, siblings } = proofPath(levels, queryIdx);
    const treeDepth = levels.length - 1; // = 2 for 4-leaf tree

    const queryValues = [colA[queryIdx], colB[queryIdx]]; // [300, 3000]
    const fPlus   = BigInt(queryValues[0]); // f(x) at query position, first column
    const fMinus  = 1234n; // arbitrary f(-x) partner (mirror value)
    const alphaReal = 7777n; // M31 challenge value (real alpha)
    // Build a real QM31 alpha: c0 = CM31(alphaReal, 0), c1 = 0
    const friAlpha = qm31pack(cm31pack(alphaReal, 0n), 0n);

    // Expected folded value (M31)
    const foldedValue = friLinearFoldReal(fPlus, fMinus, alphaReal);

    // Build the commitment (Blake2s(proof[0:32] ‖ merkleRoot)[0:16])
    // Fake a 700-byte proof where proof[8:40] == traceRoot (bincode format)
    const proof = Buffer.alloc(700, 0x01);
    // Set proof[0:8] = u64 LE count=2 (we claim 2 commitment trees)
    proof.writeBigUInt64LE(2n, 0);
    // Set proof[8:40] = traceRoot
    const rootBuf = Buffer.from(traceRoot.slice(2), "hex");
    rootBuf.copy(proof, 8);

    const fakeMerkleRoot = Buffer.alloc(32, 0x42);
    const hInput = Buffer.concat([proof.subarray(0, 32), fakeMerkleRoot]);
    const hResult = Buffer.from(blake2s(hInput));
    const commitment = "0x" + hResult.subarray(0, 16).toString("hex");
    const merkleRootHex = "0x" + fakeMerkleRoot.toString("hex");

    // Encode queryHints
    const hints = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "uint32[]", "uint256", "uint256", "bytes32[]", "uint128", "uint256", "uint256"],
        [traceRoot, queryValues, queryIdx, treeDepth, siblings, friAlpha, foldedValue, fMinus]
    );

    return {
        proof:        "0x" + proof.toString("hex"),
        commitment:   commitment,
        merkleRoot:   merkleRootHex,
        hints,
        traceRoot,
        queryValues,
        queryIdx,
        treeDepth,
        siblings,
        friAlpha,
        foldedValue,
        fMinus,
        alphaReal,
    };
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe("QLSAVerifierV4", function () {
    let verifier;
    let fixture;

    before(async function () {
        const F = await ethers.getContractFactory("QLSAVerifierV4");
        verifier = await F.deploy();
        fixture = buildFixture();
    });

    it("MIN_PROOF_LENGTH == 700", async function () {
        expect(await verifier.MIN_PROOF_LENGTH()).to.equal(700n);
    });

    it("MAX_PROOF_LENGTH == 1 MiB", async function () {
        expect(await verifier.MAX_PROOF_LENGTH()).to.equal(1_048_576n);
    });

    it("accepts a valid proof with correct hints", async function () {
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot, fixture.hints
        )).to.be.true;
    });

    it("rejects proof shorter than MIN_PROOF_LENGTH", async function () {
        const shortProof = "0x" + "01".repeat(699);
        expect(await verifier.verify(
            shortProof, fixture.commitment, fixture.merkleRoot, fixture.hints
        )).to.be.false;
    });

    it("rejects zero commitment", async function () {
        const zeroCmt = "0x" + "00".repeat(16);
        expect(await verifier.verify(
            fixture.proof, zeroCmt, fixture.merkleRoot, fixture.hints
        )).to.be.false;
    });

    it("rejects zero merkleRoot", async function () {
        const zeroRoot = "0x" + "00".repeat(32);
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, zeroRoot, fixture.hints
        )).to.be.false;
    });

    it("rejects empty queryHints", async function () {
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot, "0x"
        )).to.be.false;
    });

    it("rejects wrong commitment (tampered proof header changes hash)", async function () {
        // Tamper proof byte 5
        const tampered = Buffer.from(fixture.proof.slice(2), "hex");
        tampered[5] ^= 0xff;
        const tamperedProof = "0x" + tampered.toString("hex");
        expect(await verifier.verify(
            tamperedProof, fixture.commitment, fixture.merkleRoot, fixture.hints
        )).to.be.false;
    });

    it("rejects wrong merkle root in hints (doesn't match proof[8:40])", async function () {
        const wrongRoot = "0x" + "aa".repeat(32);
        const badHints = ethers.AbiCoder.defaultAbiCoder().encode(
            ["bytes32", "uint32[]", "uint256", "uint256", "bytes32[]", "uint128", "uint256", "uint256"],
            [wrongRoot, fixture.queryValues, fixture.queryIdx, fixture.treeDepth,
             fixture.siblings, fixture.friAlpha, fixture.foldedValue, fixture.fMinus]
        );
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot, badHints
        )).to.be.false;
    });

    it("rejects wrong query values (Merkle path won't match)", async function () {
        const badHints = ethers.AbiCoder.defaultAbiCoder().encode(
            ["bytes32", "uint32[]", "uint256", "uint256", "bytes32[]", "uint128", "uint256", "uint256"],
            [fixture.traceRoot, [9999, 8888], fixture.queryIdx, fixture.treeDepth,
             fixture.siblings, fixture.friAlpha, fixture.foldedValue, fixture.fMinus]
        );
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot, badHints
        )).to.be.false;
    });

    it("rejects wrong query index (Merkle path for different position)", async function () {
        const badHints = ethers.AbiCoder.defaultAbiCoder().encode(
            ["bytes32", "uint32[]", "uint256", "uint256", "bytes32[]", "uint128", "uint256", "uint256"],
            [fixture.traceRoot, fixture.queryValues, 0n, fixture.treeDepth,  // wrong index (0 instead of 2)
             fixture.siblings, fixture.friAlpha, fixture.foldedValue, fixture.fMinus]
        );
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot, badHints
        )).to.be.false;
    });

    it("rejects wrong FRI fold result (when real-valued alpha)", async function () {
        const wrongFolded = (fixture.foldedValue + 1n) % P;
        const badHints = ethers.AbiCoder.defaultAbiCoder().encode(
            ["bytes32", "uint32[]", "uint256", "uint256", "bytes32[]", "uint128", "uint256", "uint256"],
            [fixture.traceRoot, fixture.queryValues, fixture.queryIdx, fixture.treeDepth,
             fixture.siblings, fixture.friAlpha, wrongFolded, fixture.fMinus]
        );
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot, badHints
        )).to.be.false;
    });
});
