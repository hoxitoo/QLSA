const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { blake2s } = require("@noble/hashes/blake2.js");

// ─────────────────────────────────────────────────────────────────────────────
// QLSAVerifierV8 — Composition binding: fPlus/fMinus derived from committed cols
//
// Fixture derivation order (must match on-chain transcript):
//   1. Build Merkle tree → traceRoot
//   2. chan.init() → mixRoot(traceRoot) → drawSecureFelt() → compAlpha
//   3.                                  → drawSecureFelt() → friAlpha
//   4.                                  → drawQueries()    → queryIndices
//   5. For each queryIdx: antipodalIdx = (queryIdx + n/2) % n
//   6. fPlus  = Σ_j [compAlpha^j · QM31.fromM31(colJ[queryIdx])]
//   7. fMinus = Σ_j [compAlpha^j · QM31.fromM31(colJ[antipodalIdx])]
//   8. foldedValue = circleFold(fPlus, fMinus, friAlpha, yInv)
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
function cm31neg(x) { return cm31pack(cm31re(x) === 0n ? 0n : P - cm31re(x), cm31im(x) === 0n ? 0n : P - cm31im(x)); }
function cm31inv(x) {
    const a = cm31re(x), b = cm31im(x);
    const norm = m31add(m31mul(a, a), m31mul(b, b));
    const ni = m31inv(norm);
    return cm31pack(m31mul(a, ni), m31mul(P - b, ni) % P);
}

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
function qm31fromM31(v)  { return qm31pack(cm31pack(BigInt(v), 0n), 0n); }
const QM31_ONE = qm31fromM31(1n);

// ── Composition ───────────────────────────────────────────────────────────────

// Σ_j [compAlpha^j * QM31.fromM31(vals[j])]
function computeComposition(vals, compAlpha) {
    let result = 0n;
    let alphaPow = QM31_ONE;
    for (const v of vals) {
        result = qm31add(result, qm31mul(alphaPow, qm31fromM31(BigInt(v))));
        alphaPow = qm31mul(alphaPow, compAlpha);
    }
    return result;
}

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
    return genMul((initIdx + BigInt(idx) * stepSize) & logMask);
}

// Antipodal index: (idx + n/2) mod n — gives circle-group complement (-x, y).
function antipodalOf(idx, treeDepth) {
    return (idx + (1 << (treeDepth - 1))) & ((1 << treeDepth) - 1);
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
function reduceM31js(w) { let r = (w & 0x7FFFFFFF) + (w >>> 31); if (r >= M31_P) r -= M31_P; return r; }
function blake2sM31(buf) {
    const h = Buffer.from(blake2s(buf));
    const out = Buffer.alloc(32);
    for (let i = 0; i < 8; i++) out.writeUInt32LE(reduceM31js(h.readUInt32LE(i * 4)), i * 4);
    return out;
}
function channelInit()           { return { digest: Buffer.alloc(32), nDraws: 0 }; }
function channelMixRoot(s, r32)  { s.digest = blake2sM31(Buffer.concat([s.digest, r32])); s.nDraws = 0; }
function channelDrawU32sRaw(s) {
    const nBuf = Buffer.alloc(4); nBuf.writeUInt32LE(s.nDraws, 0);
    const buf = Buffer.concat([s.digest, nBuf, Buffer.alloc(1)]);
    s.nDraws++;
    return blake2sM31(buf);
}
function channelDrawSecureFelt(s) {
    const raw = channelDrawU32sRaw(s);
    const w0 = BigInt(raw.readUInt32LE(0)),  w1 = BigInt(raw.readUInt32LE(4));
    const w2 = BigInt(raw.readUInt32LE(8)),  w3 = BigInt(raw.readUInt32LE(12));
    return qm31pack(cm31pack(w0, w1), cm31pack(w2, w3));
}
function channelDrawQueries(s, logDomainSize, nQueries) {
    const mask = (1 << logDomainSize) - 1;
    const queries = [];
    while (queries.length < nQueries) {
        const raw = channelDrawU32sRaw(s);
        for (let i = 0; i < 8 && queries.length < nQueries; i++) queries.push(raw.readUInt32LE(i * 4) & mask);
    }
    return queries;
}

// ── QueryHints encoding (13-field struct) ──────────────────────────────────────
// Fields: traceRoot, queryValues, queryValuesNeg, queryIndex, treeDepth,
//         merkleSiblings, merkleSiblingsNeg, friAlpha, fPlus, fMinus, foldedValue,
//         queryPointX, queryPointY

const HINT_TUPLE = "tuple(bytes32,uint32[],uint32[],uint256,uint256,bytes32[],bytes32[],uint128,uint128,uint128,uint128,uint256,uint256)";

function hintToTuple(h) {
    return [h.traceRoot, h.queryValues, h.queryValuesNeg,
            h.queryIdx, h.treeDepth,
            h.siblings, h.siblingsNeg,
            h.friAlpha, h.fPlus, h.fMinus, h.foldedValue,
            h.qpX, h.qpY];
}
function encodeHintsArray(hints, overrides = {}) {
    const tuples = hints.map(h => hintToTuple({ ...h, ...overrides }));
    return ethers.AbiCoder.defaultAbiCoder().encode([HINT_TUPLE + "[]"], [tuples]);
}
function encodeHintsSingle(hint, overrides = {}) { return encodeHintsArray([hint], overrides); }

// ── Per-query hint builder ─────────────────────────────────────────────────────

function buildQueryHint(colA, colB, levels, treeDepth, queryIdx, compAlpha, friAlpha) {
    const antiIdx  = antipodalOf(queryIdx, treeDepth);
    const { root: traceRoot, siblings }    = proofPath(levels, queryIdx);
    const { siblings: siblingsNeg }        = proofPath(levels, antiIdx);

    const queryValues    = [colA[queryIdx],  colB[queryIdx]];
    const queryValuesNeg = [colA[antiIdx],   colB[antiIdx]];

    const [qpX, qpY] = cosetAt(treeDepth, queryIdx);
    const yInv        = m31inv(qpY);

    // Composition: fPlus/fMinus are derived from column values.
    const fPlus   = computeComposition(queryValues,    compAlpha);
    const fMinus  = computeComposition(queryValuesNeg, compAlpha);
    const foldedValue = circleFold(fPlus, fMinus, friAlpha, yInv);

    return { traceRoot, queryValues, queryValuesNeg, queryIdx, treeDepth,
             siblings, siblingsNeg, friAlpha, fPlus, fMinus, foldedValue, qpX, qpY };
}

// ── V8 fixture builder ─────────────────────────────────────────────────────────

function buildV8Fixture() {
    const colA = [100, 200, 300, 400, 500, 600, 700, 800];
    const colB = [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000];

    const leaves    = Array.from({ length: 8 }, (_, i) => hashLeaf([colA[i], colB[i]]));
    const levels    = buildTree(leaves);
    const treeDepth = levels.length - 1;  // = 3
    const traceRoot = levels[levels.length - 1][0];

    // Build proof: traceRoot embedded at bytes[8:40].
    const proof = Buffer.alloc(700, 0x01);
    proof.writeBigUInt64LE(2n, 0);
    Buffer.from(traceRoot.slice(2), "hex").copy(proof, 8);

    // Run JS channel (must match Solidity order exactly).
    const chan = channelInit();
    channelMixRoot(chan, Buffer.from(traceRoot.slice(2), "hex"));
    const compAlpha      = channelDrawSecureFelt(chan);  // step 1
    const friAlpha       = channelDrawSecureFelt(chan);  // step 2
    const derivedIndices = channelDrawQueries(chan, treeDepth, 2);  // step 3

    // Build hints.
    const hints = derivedIndices.map(idx =>
        buildQueryHint(colA, colB, levels, treeDepth, idx, compAlpha, friAlpha)
    );

    // Batch Merkle root + commitment.
    const fakeMerkleRoot = Buffer.alloc(32, 0x42);
    const hResult    = Buffer.from(blake2s(Buffer.concat([proof.subarray(0, 32), fakeMerkleRoot])));
    const commitment = "0x" + hResult.subarray(0, 16).toString("hex");

    return {
        proof: "0x" + proof.toString("hex"),
        commitment,
        merkleRoot: "0x" + fakeMerkleRoot.toString("hex"),
        traceRoot,
        hints,
        colA, colB, levels, treeDepth,
        compAlpha, friAlpha,
        derivedIndices,
    };
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe("QLSAVerifierV8", function () {
    let verifier;
    let f;

    before(async function () {
        const F = await ethers.getContractFactory("QLSAVerifierV8");
        verifier = await F.deploy();
        f = buildV8Fixture();
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

    it("accepts valid 2-query batch with composition binding", async function () {
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

    // ── Composition check — fPlus binding ────────────────────────────────────

    it("rejects when fPlus is tampered (not the column composition)", async function () {
        const wrongFPlus = (BigInt(f.hints[0].fPlus) + 1n) % (1n << 128n);
        // Also recompute foldedValue with wrong fPlus to isolate the fPlus check.
        const hint = f.hints[0];
        const [, qpY] = cosetAt(f.treeDepth, hint.queryIdx);
        const yInv = m31inv(qpY);
        const wrongFolded = circleFold(wrongFPlus, hint.fMinus, hint.friAlpha, yInv);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(hint, { fPlus: wrongFPlus, foldedValue: wrongFolded })
        )).to.be.false;
    });

    it("rejects when fMinus is tampered (not the antipodal composition)", async function () {
        const wrongFMinus = (BigInt(f.hints[0].fMinus) + 1n) % (1n << 128n);
        const hint = f.hints[0];
        const [, qpY] = cosetAt(f.treeDepth, hint.queryIdx);
        const yInv = m31inv(qpY);
        const wrongFolded = circleFold(hint.fPlus, wrongFMinus, hint.friAlpha, yInv);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(hint, { fMinus: wrongFMinus, foldedValue: wrongFolded })
        )).to.be.false;
    });

    it("rejects when queryValues are swapped (fPlus mismatch)", async function () {
        // Swap column values at position — fPlus derived from wrong columns.
        const hint = f.hints[0];
        const swappedVals = [hint.queryValues[1], hint.queryValues[0]];
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(hint, { queryValues: swappedVals })
        )).to.be.false;
    });

    it("rejects when queryValuesNeg don't match Merkle tree (antipodal Merkle fail)", async function () {
        const hint = f.hints[0];
        const badNeg = [9999, 8888];  // wrong values → Merkle fail for antipodal
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(hint, { queryValuesNeg: badNeg })
        )).to.be.false;
    });

    it("rejects when queryValuesNeg are from a different position (composition mismatch)", async function () {
        // Use valid values from a different row — Merkle might pass but composition differs.
        const hint = f.hints[0];
        const otherIdx = (hint.queryIdx + 1) & ((1 << f.treeDepth) - 1);
        const wrongNeg = [f.colA[otherIdx], f.colB[otherIdx]];
        // This will fail either at the antipodal Merkle check or the composition check.
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(hint, { queryValuesNeg: wrongNeg })
        )).to.be.false;
    });

    it("rejects when queryValues length differs from queryValuesNeg length", async function () {
        const hint = f.hints[0];
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(hint, { queryValuesNeg: [hint.queryValuesNeg[0]] }) // length 1 vs 2
        )).to.be.false;
    });

    // ── Fiat-Shamir: friAlpha enforcement (inherited from V7) ─────────────────

    it("rejects wrong friAlpha", async function () {
        const wrongAlpha = qm31fromM31(9999n);
        const hint       = f.hints[0];
        const [, qpY]    = cosetAt(f.treeDepth, hint.queryIdx);
        const yInv        = m31inv(qpY);
        const wrongFolded = circleFold(hint.fPlus, hint.fMinus, wrongAlpha, yInv);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(hint, { friAlpha: wrongAlpha, foldedValue: wrongFolded })
        )).to.be.false;
    });

    // ── Fiat-Shamir: query index enforcement (inherited from V7) ──────────────

    it("rejects non-derived queryIndex", async function () {
        const wrongIdx = (f.derivedIndices[0] + 1) % (1 << f.treeDepth);
        const bad = buildQueryHint(f.colA, f.colB, f.levels, f.treeDepth,
                                   wrongIdx, f.compAlpha, f.friAlpha);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(bad)
        )).to.be.false;
    });

    // ── treeDepth mismatch ────────────────────────────────────────────────────

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
        expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, "0x")).to.be.false;
    });

    it("rejects empty hints array (0 queries)", async function () {
        const encoded = ethers.AbiCoder.defaultAbiCoder().encode([HINT_TUPLE + "[]"], [[]]);
        expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, encoded)).to.be.false;
    });

    it("rejects tampered proof header (commitment mismatch)", async function () {
        const tampered = Buffer.from(f.proof.slice(2), "hex");
        tampered[5] ^= 0xff;
        expect(await verifier.verify(
            "0x" + tampered.toString("hex"), f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0])
        )).to.be.false;
    });

    // ── Per-query Merkle rejections ───────────────────────────────────────────

    it("rejects wrong traceRoot in hint", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0], { traceRoot: "0x" + "aa".repeat(32) })
        )).to.be.false;
    });

    it("rejects wrong column values at queryIndex (Merkle fail)", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0], { queryValues: [9999, 8888] })
        )).to.be.false;
    });

    it("rejects wrong circle fold result", async function () {
        const wrongFolded = (BigInt(f.hints[0].foldedValue) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsSingle(f.hints[0], { foldedValue: wrongFolded })
        )).to.be.false;
    });

    // ── 2-query batch rejections ──────────────────────────────────────────────

    it("rejects 2-query batch when second hint has wrong fPlus", async function () {
        const hint = f.hints[1];
        const wrongFPlus = (BigInt(hint.fPlus) + 1n) % (1n << 128n);
        const [, qpY]    = cosetAt(f.treeDepth, hint.queryIdx);
        const yInv        = m31inv(qpY);
        const wrongFolded = circleFold(wrongFPlus, hint.fMinus, hint.friAlpha, yInv);
        const bad = { ...hint, fPlus: wrongFPlus, foldedValue: wrongFolded };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsArray([f.hints[0], bad])
        )).to.be.false;
    });

    it("rejects 2-query batch when second hint has wrong antipodal Merkle siblings", async function () {
        const bad = { ...f.hints[1], siblingsNeg: f.hints[0].siblingsNeg };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHintsArray([f.hints[0], bad])
        )).to.be.false;
    });
});
