const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { blake2s } = require("@noble/hashes/blake2.js");

const P = 2_147_483_647n;
const LOG_ORDER = 31n;
const GEN_X = 2n;
const GEN_Y = 1268011823n;

// ── M31 helpers ────────────────────────────────────────────────────────────────

function m31mul(a, b) { return (a * b) % P; }
function m31add(a, b) { return (a + b) % P; }
function m31sub(a, b) { return ((a - b) % P + P) % P; }
function m31pow(a, e) {
    let r = 1n; a = a % P;
    while (e > 0n) { if (e & 1n) r = m31mul(r, a); a = m31mul(a, a); e >>= 1n; }
    return r;
}
function m31inv(a) { return m31pow(a, P - 2n); }

// ── CM31 packed as uint64 ──────────────────────────────────────────────────────

function cm31pack(a, b) { return (BigInt(a) << 32n) | BigInt(b); }
function cm31re(x)      { return (BigInt(x) >> 32n) & 0xFFFFFFFFn; }
function cm31im(x)      { return BigInt(x) & 0xFFFFFFFFn; }
function cm31add(x, y)  { return cm31pack(m31add(cm31re(x), cm31re(y)), m31add(cm31im(x), cm31im(y))); }
function cm31sub(x, y)  { return cm31pack(m31sub(cm31re(x), cm31re(y)), m31sub(cm31im(x), cm31im(y))); }
function cm31mul(x, y) {
    const a = cm31re(x), b = cm31im(x), c = cm31re(y), d = cm31im(y);
    return cm31pack(m31sub(m31mul(a, c), m31mul(b, d)), m31add(m31mul(a, d), m31mul(b, c)));
}
function cm31scale(x, s) { return cm31pack(m31mul(cm31re(x), BigInt(s)), m31mul(cm31im(x), BigInt(s))); }

// ── QM31 packed as uint128 ─────────────────────────────────────────────────────

const R = cm31pack(2n, 1n); // u² = R = CM31(2,1)

function qm31pack(c0, c1)  { return (BigInt(c0) << 64n) | BigInt(c1); }
function qm31c0(q)         { return (BigInt(q) >> 64n) & 0xFFFFFFFFFFFFFFFFn; }
function qm31c1(q)         { return BigInt(q) & 0xFFFFFFFFFFFFFFFFn; }
function qm31add(x, y)     { return qm31pack(cm31add(qm31c0(x), qm31c0(y)), cm31add(qm31c1(x), qm31c1(y))); }
function qm31sub(x, y)     { return qm31pack(cm31sub(qm31c0(x), qm31c0(y)), cm31sub(qm31c1(x), qm31c1(y))); }
function qm31mul(x, y) {
    const a = qm31c0(x), b = qm31c1(x), c = qm31c0(y), d = qm31c1(y);
    // (a + bu)(c + du) = (ac + R·bd) + (ad + bc)u
    return qm31pack(cm31add(cm31mul(a, c), cm31mul(R, cm31mul(b, d))),
                    cm31add(cm31mul(a, d), cm31mul(b, c)));
}
function qm31scaleM31(x, s) {
    return qm31pack(cm31scale(qm31c0(x), s), cm31scale(qm31c1(x), s));
}
function qm31fromM31(v)          { return qm31pack(cm31pack(BigInt(v), 0n), 0n); }
function qm31fromWords(w0,w1,w2,w3) {
    return qm31pack(cm31pack(BigInt(w0), BigInt(w1)), cm31pack(BigInt(w2), BigInt(w3)));
}

// ── Circle fold ────────────────────────────────────────────────────────────────

// f_new = (f+ + f−) + α·(f+ − f−)·yInv
function circleFold(fPlus, fMinus, alpha, yInv) {
    const sum  = qm31add(fPlus, fMinus);
    const diff = qm31scaleM31(qm31sub(fPlus, fMinus), yInv);
    return qm31add(sum, qm31mul(alpha, diff));
}

// ── Circle group helpers ───────────────────────────────────────────────────────

function circleAdd(x1, y1, x2, y2) {
    return [m31sub(m31mul(x1, x2), m31mul(y1, y2)),
            m31add(m31mul(x1, y2), m31mul(x2, y1))];
}
function circleDouble(x, y) {
    const x2 = m31mul(x, x);
    return [m31sub(m31add(x2, x2), 1n), m31add(m31mul(x, y), m31mul(x, y))];
}
function genMul(scalar) {
    let rx = 1n, ry = 0n;
    let cx = GEN_X, cy = GEN_Y;
    let s = BigInt(scalar) & ((1n << LOG_ORDER) - 1n);
    while (s > 0n) {
        if (s & 1n) [rx, ry] = circleAdd(rx, ry, cx, cy);
        [cx, cy] = circleDouble(cx, cy);
        s >>= 1n;
    }
    return [rx, ry];
}
function cosetAt(logN, idx) {
    const logMask    = (1n << LOG_ORDER) - 1n;
    const initIdx    = (1n << (30n - BigInt(logN))) & logMask;
    const stepSize   = (1n << (31n - BigInt(logN))) & logMask;
    const pointIndex = (initIdx + BigInt(idx) * stepSize) & logMask;
    return genMul(pointIndex);
}

// ── Blake2s helper ─────────────────────────────────────────────────────────────

function blake2sHash(buf) { return "0x" + Buffer.from(blake2s(buf)).toString("hex"); }

// ── Merkle tree builder ────────────────────────────────────────────────────────

function hashLeaf(colValues) {
    const buf = Buffer.alloc(colValues.length * 4);
    for (let i = 0; i < colValues.length; i++) buf.writeUInt32LE(colValues[i], i * 4);
    return blake2sHash(buf);
}
function hashPair(l, r) {
    return blake2sHash(Buffer.concat([Buffer.from(l.slice(2), "hex"), Buffer.from(r.slice(2), "hex")]));
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
    for (let d = 0; d < levels.length - 1; d++) { siblings.push(levels[d][i ^ 1]); i >>= 1; }
    return { root: levels[levels.length-1][0], siblings };
}

// ── ABI types for 11-field QueryHints ─────────────────────────────────────────

const HINT_TYPES = [
    "bytes32","uint32[]","uint256","uint256","bytes32[]",
    "uint128","uint128","uint128","uint128","uint256","uint256"
];

function encodeHints(f, overrides = {}) {
    const v = { ...f, ...overrides };
    return ethers.AbiCoder.defaultAbiCoder().encode(HINT_TYPES, [
        v.traceRoot, v.queryValues, v.queryIdx, v.treeDepth, v.siblings,
        v.friAlpha, v.fPlus, v.fMinus, v.foldedValue, v.qpX, v.qpY
    ]);
}

// ── Test fixture builder ───────────────────────────────────────────────────────

function buildFixture() {
    // 4-leaf trace tree, 2 columns
    const colA = [100, 200, 300, 400];
    const colB = [1000, 2000, 3000, 4000];
    const leaves = [0,1,2,3].map(i => hashLeaf([colA[i], colB[i]]));
    const levels = buildTree(leaves);
    const queryIdx  = 2;
    const treeDepth = levels.length - 1;   // = 2 for 4-leaf tree
    const { root: traceRoot, siblings } = proofPath(levels, queryIdx);

    const queryValues = [colA[queryIdx], colB[queryIdx]]; // [300, 3000]

    // Circle domain point for (treeDepth=2, queryIdx=2)
    const [qpX, qpY] = cosetAt(treeDepth, queryIdx);
    const yInv = m31inv(qpY);

    // QM31 fold inputs
    const fPlus      = qm31fromM31(300n);
    const fMinus     = qm31fromWords(150, 0, 0, 0);
    const friAlpha   = qm31fromM31(7777n);
    const foldedValue = circleFold(fPlus, fMinus, friAlpha, yInv);

    // Build a minimal 700-byte proof
    const proof = Buffer.alloc(700, 0x01);
    proof.writeBigUInt64LE(2n, 0);
    Buffer.from(traceRoot.slice(2), "hex").copy(proof, 8);

    const fakeMerkleRoot = Buffer.alloc(32, 0x42);
    const hResult  = Buffer.from(blake2s(Buffer.concat([proof.subarray(0, 32), fakeMerkleRoot])));
    const commitment   = "0x" + hResult.subarray(0, 16).toString("hex");
    const merkleRootHex = "0x" + fakeMerkleRoot.toString("hex");

    const f = {
        proof: "0x" + proof.toString("hex"),
        commitment,
        merkleRoot: merkleRootHex,
        traceRoot,
        queryValues,
        queryIdx,
        treeDepth,
        siblings,
        friAlpha,
        fPlus,
        fMinus,
        foldedValue,
        qpX,
        qpY,
    };
    f.hints = encodeHints(f);
    return f;
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

    it("accepts a valid proof with correct circle fold hints", async function () {
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot, fixture.hints
        )).to.be.true;
    });

    it("rejects proof shorter than MIN_PROOF_LENGTH", async function () {
        expect(await verifier.verify(
            "0x" + "01".repeat(699), fixture.commitment, fixture.merkleRoot, fixture.hints
        )).to.be.false;
    });

    it("rejects zero commitment", async function () {
        expect(await verifier.verify(
            fixture.proof, "0x" + "00".repeat(16), fixture.merkleRoot, fixture.hints
        )).to.be.false;
    });

    it("rejects zero merkleRoot", async function () {
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, "0x" + "00".repeat(32), fixture.hints
        )).to.be.false;
    });

    it("rejects empty queryHints", async function () {
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot, "0x"
        )).to.be.false;
    });

    it("rejects tampered proof header (commitment mismatch)", async function () {
        const tampered = Buffer.from(fixture.proof.slice(2), "hex");
        tampered[5] ^= 0xff;
        expect(await verifier.verify(
            "0x" + tampered.toString("hex"), fixture.commitment, fixture.merkleRoot, fixture.hints
        )).to.be.false;
    });

    it("rejects wrong traceRoot in hints (doesn't match proof[8:40])", async function () {
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot,
            encodeHints(fixture, { traceRoot: "0x" + "aa".repeat(32) })
        )).to.be.false;
    });

    it("rejects wrong query values (Merkle inclusion fails)", async function () {
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot,
            encodeHints(fixture, { queryValues: [9999, 8888] })
        )).to.be.false;
    });

    it("rejects wrong query index (Merkle path for wrong position)", async function () {
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot,
            encodeHints(fixture, { queryIdx: 0 })
        )).to.be.false;
    });

    it("rejects off-circle queryPoint (x²+y²≠1 mod P)", async function () {
        // (2, 2): 4+4=8 ≠ 1 mod P
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot,
            encodeHints(fixture, { qpX: 2n, qpY: 2n })
        )).to.be.false;
    });

    it("rejects valid-circle point that is not cosetAt(treeDepth, queryIdx)", async function () {
        // GEN itself is on the circle but is not cosetAt(2, 2)
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot,
            encodeHints(fixture, { qpX: GEN_X, qpY: GEN_Y })
        )).to.be.false;
    });

    it("rejects wrong folded value", async function () {
        const wrongFolded = (BigInt(fixture.foldedValue) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            fixture.proof, fixture.commitment, fixture.merkleRoot,
            encodeHints(fixture, { foldedValue: wrongFolded })
        )).to.be.false;
    });

    it("circleFold: f+==f- gives 2*f with zero diff term", async function () {
        const val    = qm31fromM31(12345n);
        const result = circleFold(val, val, qm31fromM31(7n), m31inv(5n));
        const twice  = qm31add(val, val);
        expect(qm31c0(result)).to.equal(qm31c0(twice));
        expect(qm31c1(result)).to.equal(qm31c1(twice));
    });
});
