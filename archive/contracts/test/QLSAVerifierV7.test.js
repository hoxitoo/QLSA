const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { blake2s } = require("@noble/hashes/blake2.js");

// ─────────────────────────────────────────────────────────────────────────────
// QLSAVerifierV7 — Full Fiat-Shamir: derived friAlpha + derived query indices
//
// Fixture derivation order (must match the on-chain transcript):
//   1. Build Merkle tree → traceRoot
//   2. chan.init() → mixRoot(traceRoot) → drawSecureFelt() → friAlpha
//   3. drawQueries(treeDepth, N)                            → queryIndices
//   4. Build hints for those (alpha, index) pairs
// ─────────────────────────────────────────────────────────────────────────────

const P = 2_147_483_647n;
const LOG_ORDER = 31n;
const GEN_X = 2n;
const GEN_Y = 1268011823n;

// ── M31 ───────────────────────────────────────────────────────────────────────

function m31mul(a, b) { return (a * b) % P; }
function m31add(a, b) { return (a + b) % P; }
function m31sub(a, b) { return ((a - b) % P + P) % P; }
function m31pow(a, e) {
    let r = 1n; a = a % P;
    while (e > 0n) { if (e & 1n) r = m31mul(r, a); a = m31mul(a, a); e >>= 1n; }
    return r;
}
function m31inv(a) { return m31pow(a, P - 2n); }

// ── CM31 ──────────────────────────────────────────────────────────────────────

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

// ── QM31 ──────────────────────────────────────────────────────────────────────

const R = cm31pack(2n, 1n);
function qm31pack(c0, c1)  { return (BigInt(c0) << 64n) | BigInt(c1); }
function qm31c0(q)         { return (BigInt(q) >> 64n) & 0xFFFFFFFFFFFFFFFFn; }
function qm31c1(q)         { return BigInt(q) & 0xFFFFFFFFFFFFFFFFn; }
function qm31add(x, y)     { return qm31pack(cm31add(qm31c0(x), qm31c0(y)), cm31add(qm31c1(x), qm31c1(y))); }
function qm31sub(x, y)     { return qm31pack(cm31sub(qm31c0(x), qm31c0(y)), cm31sub(qm31c1(x), qm31c1(y))); }
function qm31mul(x, y) {
    const a = qm31c0(x), b = qm31c1(x), c = qm31c0(y), d = qm31c1(y);
    return qm31pack(cm31add(cm31mul(a, c), cm31mul(R, cm31mul(b, d))),
                    cm31add(cm31mul(a, d), cm31mul(b, c)));
}
function qm31scaleM31(x, s) {
    return qm31pack(cm31scale(qm31c0(x), s), cm31scale(qm31c1(x), s));
}
function qm31fromM31(v)     { return qm31pack(cm31pack(BigInt(v), 0n), 0n); }

// ── Circle fold ────────────────────────────────────────────────────────────────

function circleFold(fPlus, fMinus, alpha, yInv) {
    const sum  = qm31add(fPlus, fMinus);
    const diff = qm31scaleM31(qm31sub(fPlus, fMinus), yInv);
    return qm31add(sum, qm31mul(alpha, diff));
}

// ── Circle group ───────────────────────────────────────────────────────────────

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
    const logMask  = (1n << LOG_ORDER) - 1n;
    const initIdx  = (1n << (30n - BigInt(logN))) & logMask;
    const stepSize = (1n << (31n - BigInt(logN))) & logMask;
    const pointIdx = (initIdx + BigInt(idx) * stepSize) & logMask;
    return genMul(pointIdx);
}

// ── Blake2s + Merkle ───────────────────────────────────────────────────────────

function blake2sHash(buf) { return "0x" + Buffer.from(blake2s(buf)).toString("hex"); }
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
    return { root: levels[levels.length - 1][0], siblings };
}

// ── TwoChannel JS reference ────────────────────────────────────────────────────

const M31_P = 2_147_483_647;

function reduceM31(w) {
    let r = (w & 0x7FFFFFFF) + (w >>> 31);
    if (r >= M31_P) r -= M31_P;
    return r;
}
function blake2sM31(buf) {
    const h = Buffer.from(blake2s(buf));
    const out = Buffer.alloc(32);
    for (let i = 0; i < 8; i++) out.writeUInt32LE(reduceM31(h.readUInt32LE(i * 4)), i * 4);
    return out;
}
function channelInit() {
    return { digest: Buffer.alloc(32), nDraws: 0 };
}
function channelMixRoot(s, root32) {
    s.digest = blake2sM31(Buffer.concat([s.digest, root32]));
    s.nDraws = 0;
}
function channelDrawU32sRaw(s) {
    const nBuf = Buffer.alloc(4);
    nBuf.writeUInt32LE(s.nDraws, 0);
    const buf = Buffer.concat([s.digest, nBuf, Buffer.alloc(1)]);
    s.nDraws++;
    return blake2sM31(buf);
}
// Derive one QM31 secure-field element (words [w0,w1,w2,w3] → c0=(w0<<32|w1), c1=(w2<<32|w3)).
function channelDrawSecureFelt(s) {
    const raw = channelDrawU32sRaw(s);
    const w0 = BigInt(raw.readUInt32LE(0));
    const w1 = BigInt(raw.readUInt32LE(4));
    const w2 = BigInt(raw.readUInt32LE(8));
    const w3 = BigInt(raw.readUInt32LE(12));
    const c0 = (w0 << 32n) | w1;
    const c1 = (w2 << 32n) | w3;
    return (c0 << 64n) | c1;
}
function channelDrawQueries(s, logDomainSize, nQueries) {
    const mask = (1 << logDomainSize) - 1;
    const queries = [];
    while (queries.length < nQueries) {
        const raw = channelDrawU32sRaw(s);
        for (let i = 0; i < 8 && queries.length < nQueries; i++) {
            queries.push(raw.readUInt32LE(i * 4) & mask);
        }
    }
    return queries;
}

// ── QueryHints encoding ────────────────────────────────────────────────────────

const HINT_TUPLE = "tuple(bytes32,uint32[],uint256,uint256,bytes32[],uint128,uint128,uint128,uint128,uint256,uint256)";

function hintToTuple(h) {
    return [h.traceRoot, h.queryValues, h.queryIdx, h.treeDepth, h.siblings,
            h.friAlpha, h.fPlus, h.fMinus, h.foldedValue, h.qpX, h.qpY];
}
function encodeHintsArray(hints, overrides = {}) {
    const tuples = hints.map(h => hintToTuple({ ...h, ...overrides }));
    return ethers.AbiCoder.defaultAbiCoder().encode([HINT_TUPLE + "[]"], [tuples]);
}
function encodeHintsSingle(hint, overrides = {}) {
    return encodeHintsArray([hint], overrides);
}

// ── Per-query hint builder ─────────────────────────────────────────────────────

function buildQueryHint(colA, colB, levels, treeDepth, queryIdx, friAlpha) {
    const { root: traceRoot, siblings } = proofPath(levels, queryIdx);
    const queryValues = [colA[queryIdx], colB[queryIdx]];
    const [qpX, qpY]  = cosetAt(treeDepth, queryIdx);
    const yInv         = m31inv(qpY);
    const fPlus        = qm31fromM31(BigInt(colA[queryIdx]));
    const fMinus       = qm31fromM31(BigInt(Math.floor(colA[queryIdx] / 2)));
    const foldedValue  = circleFold(fPlus, fMinus, friAlpha, yInv);
    return { traceRoot, queryValues, queryIdx, treeDepth, siblings,
             friAlpha, fPlus, fMinus, foldedValue, qpX, qpY };
}

// ── V7 fixture builder ─────────────────────────────────────────────────────────
//
// CRITICAL ordering: mixRoot → drawSecureFelt (α) → drawQueries (positions).
// This matches the on-chain transcript in QLSAVerifierV7.verify().

function buildV7Fixture() {
    const colA = [100, 200, 300, 400, 500, 600, 700, 800];
    const colB = [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000];

    const leaves    = Array.from({ length: 8 }, (_, i) => hashLeaf([colA[i], colB[i]]));
    const levels    = buildTree(leaves);
    const treeDepth = levels.length - 1;   // = 3
    const traceRoot = levels[levels.length - 1][0];

    // Build proof: 700-byte blob with traceRoot embedded at bytes[8:40].
    const proof = Buffer.alloc(700, 0x01);
    proof.writeBigUInt64LE(2n, 0);
    Buffer.from(traceRoot.slice(2), "hex").copy(proof, 8);

    // Run JS channel — same order as the Solidity verifier.
    const chan = channelInit();
    channelMixRoot(chan, Buffer.from(traceRoot.slice(2), "hex"));
    const derivedAlpha   = channelDrawSecureFelt(chan);      // step 1: folding challenge
    const derivedIndices = channelDrawQueries(chan, treeDepth, 2); // step 2: query positions

    // Build hints for channel-derived (alpha, index) pairs.
    const hints = derivedIndices.map(idx =>
        buildQueryHint(colA, colB, levels, treeDepth, idx, derivedAlpha)
    );

    // Batch Merkle root (separate from trace root) + commitment binding.
    const fakeMerkleRoot = Buffer.alloc(32, 0x42);
    const hResult    = Buffer.from(blake2s(Buffer.concat([proof.subarray(0, 32), fakeMerkleRoot])));
    const commitment = "0x" + hResult.subarray(0, 16).toString("hex");
    const merkleRootHex = "0x" + fakeMerkleRoot.toString("hex");

    return {
        proof: "0x" + proof.toString("hex"),
        commitment,
        merkleRoot: merkleRootHex,
        traceRoot,
        hints,
        colA, colB, levels, treeDepth,
        derivedAlpha,
        derivedIndices,
    };
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe("QLSAVerifierV7", function () {
    let verifier;
    let f;

    before(async function () {
        const F = await ethers.getContractFactory("QLSAVerifierV7");
        verifier = await F.deploy();
        f = buildV7Fixture();
    });

    // ── Constants ─────────────────────────────────────────────────────────────

    it("MIN_PROOF_LENGTH == 700", async function () {
        expect(await verifier.MIN_PROOF_LENGTH()).to.equal(700n);
    });

    it("MAX_PROOF_LENGTH == 1 MiB", async function () {
        expect(await verifier.MAX_PROOF_LENGTH()).to.equal(1_048_576n);
    });

    it("MIN_QUERIES == 1", async function () {
        expect(await verifier.MIN_QUERIES()).to.equal(1n);
    });

    it("MAX_QUERIES == 64", async function () {
        expect(await verifier.MAX_QUERIES()).to.equal(64n);
    });

    // ── Valid paths ───────────────────────────────────────────────────────────

    it("accepts valid 2-query batch (channel-derived alpha + indices)", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsArray(f.hints)
        )).to.be.true;
    });

    it("accepts valid 1-query batch (first derived index)", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0])
        )).to.be.true;
    });

    // ── Fiat-Shamir: friAlpha enforcement ─────────────────────────────────────

    it("rejects when friAlpha is an arbitrary non-derived value", async function () {
        // Use a clearly wrong alpha (e.g. qm31fromM31(9999))
        const wrongAlpha = qm31fromM31(9999n);
        // Recompute foldedValue with the wrong alpha so the fold check would pass —
        // the verifier must catch this via friAlpha != derivedAlpha before the fold.
        const hint = f.hints[0];
        const [qpX, qpY] = cosetAt(f.treeDepth, hint.queryIdx);
        const yInv        = m31inv(qpY);
        const newFolded   = circleFold(hint.fPlus, hint.fMinus, wrongAlpha, yInv);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(hint, { friAlpha: wrongAlpha, foldedValue: newFolded })
        )).to.be.false;
    });

    it("rejects when friAlpha matches derived but foldedValue was computed with a different alpha", async function () {
        // alpha is correct, but foldedValue was computed with a different alpha.
        const wrongFolded = (BigInt(f.hints[0].foldedValue) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0], { foldedValue: wrongFolded })
        )).to.be.false;
    });

    it("rejects when second query uses a non-derived friAlpha", async function () {
        const wrongAlpha = qm31fromM31(1234n);
        const hint       = f.hints[1];
        const [qpX, qpY] = cosetAt(f.treeDepth, hint.queryIdx);
        const yInv        = m31inv(qpY);
        const newFolded   = circleFold(hint.fPlus, hint.fMinus, wrongAlpha, yInv);
        const bad = { ...hint, friAlpha: wrongAlpha, foldedValue: newFolded };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsArray([f.hints[0], bad])
        )).to.be.false;
    });

    // ── Fiat-Shamir: query index enforcement ──────────────────────────────────

    it("rejects when hint provides a non-derived queryIndex", async function () {
        const wrongIdx = (f.derivedIndices[0] + 1) % (1 << f.treeDepth);
        const bad = buildQueryHint(f.colA, f.colB, f.levels, f.treeDepth, wrongIdx, f.derivedAlpha);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(bad)
        )).to.be.false;
    });

    it("rejects when 2-query hints have indices in wrong order (if distinct)", async function () {
        const swapped = [f.hints[1], f.hints[0]];
        const result  = await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsArray(swapped)
        );
        expect(result).to.equal(f.derivedIndices[0] === f.derivedIndices[1]);
    });

    // ── Same treeDepth requirement ────────────────────────────────────────────

    it("rejects hints with mismatched treeDepths", async function () {
        const bad = { ...f.hints[1], treeDepth: f.treeDepth + 1 };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsArray([f.hints[0], bad])
        )).to.be.false;
    });

    // ── Proof-level rejections ────────────────────────────────────────────────

    it("rejects proof shorter than MIN_PROOF_LENGTH", async function () {
        expect(await verifier.verify(
            "0x" + "01".repeat(699), f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0])
        )).to.be.false;
    });

    it("rejects zero commitment", async function () {
        expect(await verifier.verify(
            f.proof, "0x" + "00".repeat(16), f.merkleRoot,
            encodeHintsSingle(f.hints[0])
        )).to.be.false;
    });

    it("rejects zero merkleRoot", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, "0x" + "00".repeat(32),
            encodeHintsSingle(f.hints[0])
        )).to.be.false;
    });

    it("rejects empty queryHints bytes", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot, "0x"
        )).to.be.false;
    });

    it("rejects an empty hints array (0 queries)", async function () {
        const encoded = ethers.AbiCoder.defaultAbiCoder().encode([HINT_TUPLE + "[]"], [[]]);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot, encoded
        )).to.be.false;
    });

    it("rejects tampered proof header (commitment mismatch)", async function () {
        const tampered = Buffer.from(f.proof.slice(2), "hex");
        tampered[5] ^= 0xff;
        expect(await verifier.verify(
            "0x" + tampered.toString("hex"), f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0])
        )).to.be.false;
    });

    // ── Per-query rejections ──────────────────────────────────────────────────

    it("rejects when hint has wrong traceRoot", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0], { traceRoot: "0x" + "aa".repeat(32) })
        )).to.be.false;
    });

    it("rejects wrong column values (Merkle inclusion fails)", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0], { queryValues: [9999, 8888] })
        )).to.be.false;
    });

    it("rejects off-circle queryPoint (x²+y²≠1 mod P)", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0], { qpX: 2n, qpY: 2n })
        )).to.be.false;
    });

    it("rejects valid-circle point not at cosetAt(treeDepth, queryIndex)", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0], { qpX: GEN_X, qpY: GEN_Y })
        )).to.be.false;
    });

    it("rejects 2-query batch when second query has wrong traceRoot", async function () {
        const bad = { ...f.hints[1], traceRoot: "0x" + "bb".repeat(32) };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsArray([f.hints[0], bad])
        )).to.be.false;
    });

    it("rejects 2-query batch when second query has wrong folded value", async function () {
        const wrongFolded = (BigInt(f.hints[1].foldedValue) + 1n) % (1n << 128n);
        const bad = { ...f.hints[1], foldedValue: wrongFolded };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsArray([f.hints[0], bad])
        )).to.be.false;
    });

    // ── Wrong embedded trace root ─────────────────────────────────────────────

    it("rejects proof with different embedded root (hints valid for original root)", async function () {
        // Build a proof with a different root at bytes[8:40]; re-derive commitment
        // so check #3 passes — but hints use original traceRoot so check fails inside.
        const altProof = Buffer.from(f.proof.slice(2), "hex");
        Buffer.from("cc".repeat(32), "hex").copy(altProof, 8);
        const fakeMR   = Buffer.from(f.merkleRoot.slice(2), "hex");
        const hResult  = Buffer.from(blake2s(Buffer.concat([altProof.subarray(0, 32), fakeMR])));
        const altCommit = "0x" + hResult.subarray(0, 16).toString("hex");
        expect(await verifier.verify(
            "0x" + altProof.toString("hex"), altCommit, f.merkleRoot,
            encodeHintsSingle(f.hints[0])
        )).to.be.false;
    });
});
