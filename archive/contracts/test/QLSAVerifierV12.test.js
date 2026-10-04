const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { blake2s } = require("@noble/hashes/blake2.js");

// ─────────────────────────────────────────────────────────────────────────────
// QLSAVerifierV12 — FRI layer 3: second line fold with doubled-x twiddle
//
// New in V12 vs V11:
//   1. After friLayer2Root is committed, channel draws friAlpha3 (second line fold α).
//   2. Prover computes lineFolded2[j] = lineFold(L2[j], L2[j+N/4], friAlpha3, doubleXInv_j)
//      for j in [0, N/4), where doubleX_j = 2·cosetAt(treeDepth, j).x² − 1.
//   3. friLayer3Root is the Merkle root of the N/4 lineFolded2 values.
//   4. Channel absorbs friLayer3Root before drawing queries.
//   5. Per-query: sibling in FRI L2, second fold, and FRI L3 are all verified.
//
// V12 transcript order:
//   mixRoot(traceRoot) → z_x → mixU32s(oodsPos) → mixU32s(oodsNeg)
//   → compAlpha → friAlpha → mixRoot(friLayer1Root) → friAlpha2
//   → mixRoot(friLayer2Root) → friAlpha3 → mixRoot(friLayer3Root) → drawQueries
// ─────────────────────────────────────────────────────────────────────────────

const P = 2_147_483_647n;
const LOG_ORDER = 31n;
const GEN_X = 2n;
const GEN_Y = 1268011823n;

// ── M31 ───────────────────────────────────────────────────────────────────────

function m31mul(a, b)  { return (a * b) % P; }
function m31add(a, b)  { return (a + b) % P; }
function m31sub(a, b)  { return ((a - b) % P + P) % P; }
function m31pow(a, e)  { let r = 1n; a %= P; while (e > 0n) { if (e & 1n) r = m31mul(r, a); a = m31mul(a, a); e >>= 1n; } return r; }
function m31inv(a)     { return m31pow(a, P - 2n); }
function m31neg(a)     { return a === 0n ? 0n : P - a; }

// ── CM31 ──────────────────────────────────────────────────────────────────────

function cm31pack(a, b) { return (BigInt(a) << 32n) | BigInt(b); }
function cm31re(x)      { return (BigInt(x) >> 32n) & 0xFFFFFFFFn; }
function cm31im(x)      { return BigInt(x) & 0xFFFFFFFFn; }
function cm31add(x, y)  { return cm31pack(m31add(cm31re(x), cm31re(y)), m31add(cm31im(x), cm31im(y))); }
function cm31sub(x, y)  { return cm31pack(m31sub(cm31re(x), cm31re(y)), m31sub(cm31im(x), cm31im(y))); }
function cm31mul(x, y) {
    const [a, b, c, d] = [cm31re(x), cm31im(x), cm31re(y), cm31im(y)];
    return cm31pack(m31sub(m31mul(a, c), m31mul(b, d)), m31add(m31mul(a, d), m31mul(b, c)));
}
function cm31neg(x)     { return cm31pack(m31neg(cm31re(x)), m31neg(cm31im(x))); }
function cm31scale(x,s) { return cm31pack(m31mul(cm31re(x), BigInt(s)), m31mul(cm31im(x), BigInt(s))); }
function cm31inv(x) {
    const [a, b] = [cm31re(x), cm31im(x)];
    const norm = m31add(m31mul(a, a), m31mul(b, b));
    const ni = m31inv(norm);
    return cm31pack(m31mul(a, ni), m31mul(m31neg(b), ni));
}

// ── QM31 ──────────────────────────────────────────────────────────────────────

const R = cm31pack(2n, 1n);
function qm31pack(c0, c1) { return (BigInt(c0) << 64n) | BigInt(c1); }
function qm31c0(q)        { return (BigInt(q) >> 64n) & 0xFFFFFFFFFFFFFFFFn; }
function qm31c1(q)        { return BigInt(q) & 0xFFFFFFFFFFFFFFFFn; }
function qm31add(x, y)    { return qm31pack(cm31add(qm31c0(x), qm31c0(y)), cm31add(qm31c1(x), qm31c1(y))); }
function qm31sub(x, y)    { return qm31pack(cm31sub(qm31c0(x), qm31c0(y)), cm31sub(qm31c1(x), qm31c1(y))); }
function qm31mul(x, y) {
    const [a, b, c, d] = [qm31c0(x), qm31c1(x), qm31c0(y), qm31c1(y)];
    return qm31pack(cm31add(cm31mul(a, c), cm31mul(R, cm31mul(b, d))),
                    cm31add(cm31mul(a, d), cm31mul(b, c)));
}
function qm31neg(x)        { return qm31pack(cm31neg(qm31c0(x)), cm31neg(qm31c1(x))); }
function qm31scaleM31(x,s) { return qm31pack(cm31scale(qm31c0(x), s), cm31scale(qm31c1(x), s)); }
function qm31fromM31(v)    { return qm31pack(cm31pack(BigInt(v), 0n), 0n); }

const QM31_ONE = qm31fromM31(1n);

function qm31inv(x) {
    const [a, b] = [qm31c0(x), qm31c1(x)];
    const norm    = cm31sub(cm31mul(a, a), cm31mul(R, cm31mul(b, b)));
    const normInv = cm31inv(norm);
    return qm31pack(cm31mul(a, normInv), cm31mul(cm31neg(b), normInv));
}
function qm31div(x, y) { return qm31mul(x, qm31inv(y)); }

function qm31ToWords(q) {
    const c0 = qm31c0(q), c1 = qm31c1(q);
    return [Number(c0 >> 32n), Number(c0 & 0xFFFFFFFFn),
            Number(c1 >> 32n), Number(c1 & 0xFFFFFFFFn)];
}

// ── Composition ───────────────────────────────────────────────────────────────

function compositionM31(vals, compAlpha) {
    let r = 0n, ap = QM31_ONE;
    for (const v of vals) { r = qm31add(r, qm31mul(ap, qm31fromM31(BigInt(v)))); ap = qm31mul(ap, compAlpha); }
    return r;
}
function compositionQM31(evals, compAlpha) {
    let r = 0n, ap = QM31_ONE;
    for (const e of evals) { r = qm31add(r, qm31mul(ap, e)); ap = qm31mul(ap, compAlpha); }
    return r;
}

// ── FRI folds ─────────────────────────────────────────────────────────────────

function circleFold(fPlus, fMinus, alpha, yInv) {
    return qm31add(qm31add(fPlus, fMinus),
                   qm31mul(alpha, qm31scaleM31(qm31sub(fPlus, fMinus), yInv)));
}
function lineFold(fPlus, fMinus, alpha, xInv) {
    return qm31add(qm31add(fPlus, fMinus),
                   qm31mul(alpha, qm31scaleM31(qm31sub(fPlus, fMinus), xInv)));
}

// ── Circle group ──────────────────────────────────────────────────────────────

function circleAdd(x1,y1,x2,y2) { return [m31sub(m31mul(x1,x2),m31mul(y1,y2)), m31add(m31mul(x1,y2),m31mul(x2,y1))]; }
function circleDouble(x,y)       { const x2=m31mul(x,x); return [m31sub(m31add(x2,x2),1n), m31add(m31mul(x,y),m31mul(x,y))]; }
function genMul(s) {
    let [rx,ry,cx,cy] = [1n,0n,GEN_X,GEN_Y];
    s = BigInt(s) & ((1n<<LOG_ORDER)-1n);
    while (s>0n) { if(s&1n) [rx,ry]=circleAdd(rx,ry,cx,cy); [cx,cy]=circleDouble(cx,cy); s>>=1n; }
    return [rx,ry];
}
function cosetAt(logN, idx) {
    const m = (1n<<LOG_ORDER)-1n;
    const ii = (1n<<(30n-BigInt(logN)))&m, st = (1n<<(31n-BigInt(logN)))&m;
    return genMul((ii + BigInt(idx)*st)&m);
}
function antipodalOf(idx, td) { return (idx + (1<<(td-1))) & ((1<<td)-1); }

// ── Blake2s + Merkle ──────────────────────────────────────────────────────────

function b2h(buf)        { return "0x"+Buffer.from(blake2s(buf)).toString("hex"); }
function hashLeaf(cols)  { const b=Buffer.alloc(cols.length*4); cols.forEach((v,i)=>b.writeUInt32LE(v,i*4)); return b2h(b); }
function hashPair(l,r)   { return b2h(Buffer.concat([Buffer.from(l.slice(2),"hex"),Buffer.from(r.slice(2),"hex")])); }
function buildTree(lv)   { const ls=[lv]; while(lv.length>1){const n=[];for(let i=0;i<lv.length;i+=2)n.push(hashPair(lv[i],lv[i+1]));lv=n;ls.push(lv);}return ls; }
function proofPath(ls,i) { const s=[]; for(let d=0;d<ls.length-1;d++){s.push(ls[d][i^1]);i>>=1;} return {root:ls[ls.length-1][0],siblings:s}; }

// ── TwoChannel JS reference ───────────────────────────────────────────────────

const M31P = 2_147_483_647;
function rm31(w) { let r=(w&0x7FFFFFFF)+(w>>>31); if(r>=M31P)r-=M31P; return r; }
function b2m31(buf) { const h=Buffer.from(blake2s(buf)),o=Buffer.alloc(32); for(let i=0;i<8;i++) o.writeUInt32LE(rm31(h.readUInt32LE(i*4)),i*4); return o; }
function chInit()          { return {digest:Buffer.alloc(32),nDraws:0}; }
function chMixRoot(s,r)    { s.digest=b2m31(Buffer.concat([s.digest,r])); s.nDraws=0; }
function chMixU32s(s,ws)   { const b=Buffer.alloc(ws.length*4); ws.forEach((w,i)=>b.writeUInt32LE(w,i*4)); s.digest=b2m31(Buffer.concat([s.digest,b])); s.nDraws=0; }
function chRaw(s)          { const nb=Buffer.alloc(4); nb.writeUInt32LE(s.nDraws,0); s.nDraws++; return b2m31(Buffer.concat([s.digest,nb,Buffer.alloc(1)])); }
function chFelt(s)         { const r=chRaw(s); const [w0,w1,w2,w3]=[r.readUInt32LE(0),r.readUInt32LE(4),r.readUInt32LE(8),r.readUInt32LE(12)]; return qm31pack(cm31pack(BigInt(w0),BigInt(w1)),cm31pack(BigInt(w2),BigInt(w3))); }
function chQueries(s,ld,n) { const mask=(1<<ld)-1,q=[]; while(q.length<n){const r=chRaw(s);for(let i=0;i<8&&q.length<n;i++)q.push(r.readUInt32LE(i*4)&mask);} return q; }

// ── V12 hint encoding (22-field struct) ───────────────────────────────────────

const HINT_TUPLE = "tuple(bytes32,uint32[],uint32[],uint256,uint256,bytes32[],bytes32[],uint128,uint128,uint128,uint128,uint256,uint256,bytes32[],uint128,bytes32[],uint128,bytes32[],uint128,bytes32[],uint128,bytes32[])";

function hintTuple(h) {
    return [h.traceRoot, h.queryValues, h.queryValuesNeg,
            h.queryIdx, h.treeDepth, h.siblings, h.siblingsNeg,
            h.friAlpha, h.fPlus, h.fMinus, h.foldedValue, h.qpX, h.qpY,
            h.friL1Siblings,
            h.friL1SiblingValue, h.friL1SiblingProof,
            h.lineFoldedValue, h.friL2Siblings,
            h.l2SiblingValue, h.l2SiblingProof,
            h.lineFoldedValue2, h.friL3Siblings];
}

function encodeHints(hints, oodsPos, oodsNeg, friL1Root, friL2Root, friL3Root, overrides = {}) {
    const tuples = hints.map(h => hintTuple({ ...h, ...overrides }));
    return ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint128[]", "uint128[]", "bytes32", "bytes32", "bytes32", HINT_TUPLE + "[]"],
        [oodsPos.map(v => v), oodsNeg.map(v => v), friL1Root, friL2Root, friL3Root, tuples]
    );
}
function encodeSingle(hint, oodsPos, oodsNeg, friL1Root, friL2Root, friL3Root, overrides = {}) {
    return encodeHints([hint], oodsPos, oodsNeg, friL1Root, friL2Root, friL3Root, overrides);
}

// ── V12 fixture builder ────────────────────────────────────────────────────────
//
// Extends V11 by:
//  7. After friLayer2Root: draw friAlpha3 (second line fold α).
//  8. Compute lineFolded2[j] for j in [0, quarter) using doubled-x twiddle.
//  9. Build FRI layer 3 tree (quarter leaves, depth treeDepth−2).
// 10. Mix friLayer3Root → drawQueries.
// 11. Per query: add l2SiblingValue + proof + lineFoldedValue2 + FRI L3 proof.

function buildV12Fixture() {
    const treeDepth = 3;
    const N         = 1 << treeDepth;   // 8
    const half      = N >> 1;           // 4
    const quarter   = N >> 2;           // 2

    const colA = [100, 200, 300, 400, 500, 600, 700, 800];
    const colB = [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000];

    // ── Trace tree ──────────────────────────────────────────────────────────
    const traceLeaves = Array.from({length: N}, (_, i) => hashLeaf([colA[i], colB[i]]));
    const traceLevels = buildTree(traceLeaves);
    const traceRoot   = traceLevels[traceLevels.length - 1][0];

    // ── Channel: trace root → z_x → OODS evals → compAlpha → friAlpha ──────
    const chan = chInit();
    chMixRoot(chan, Buffer.from(traceRoot.slice(2), "hex"));
    const z_x = chFelt(chan);

    const oodsEvalsPos = [qm31fromM31(7n),  qm31fromM31(11n)];
    const oodsEvalsNeg = [qm31fromM31(13n), qm31fromM31(17n)];
    chMixU32s(chan, oodsEvalsPos.flatMap(qm31ToWords));
    chMixU32s(chan, oodsEvalsNeg.flatMap(qm31ToWords));

    const compAlpha = chFelt(chan);
    const friAlpha  = chFelt(chan);

    const oodsComboPos = compositionQM31(oodsEvalsPos, compAlpha);
    const oodsComboNeg = compositionQM31(oodsEvalsNeg, compAlpha);

    // ── Full-domain circle fold ──────────────────────────────────────────────
    const allData = [];
    for (let idx = 0; idx < N; idx++) {
        const antiIdx = antipodalOf(idx, treeDepth);
        const qv    = [colA[idx],    colB[idx]];
        const qvNeg = [colA[antiIdx], colB[antiIdx]];
        const [qpX, qpY] = cosetAt(treeDepth, idx);
        const yInv  = m31inv(qpY);

        const rawComp    = compositionM31(qv,    compAlpha);
        const rawCompNeg = compositionM31(qvNeg, compAlpha);
        const pxQM31  = qm31fromM31(qpX);
        const denomPos = qm31sub(pxQM31, z_x);
        const denomNeg = qm31sub(qm31neg(pxQM31), z_x);

        const fPlus       = qm31div(qm31sub(rawComp,    oodsComboPos), denomPos);
        const fMinus      = qm31div(qm31sub(rawCompNeg, oodsComboNeg), denomNeg);
        const foldedValue = circleFold(fPlus, fMinus, friAlpha, yInv);

        allData.push({ fPlus, fMinus, foldedValue, qpX, qpY, qv, qvNeg });
    }

    // ── FRI layer 1 tree ────────────────────────────────────────────────────
    const friL1Leaves = allData.map(d => hashLeaf(qm31ToWords(d.foldedValue)));
    const friL1Levels = buildTree(friL1Leaves);
    const friLayer1Root = friL1Levels[friL1Levels.length - 1][0];

    // ── Channel: mixRoot(friLayer1Root) → friAlpha2 ──────────────────────────
    chMixRoot(chan, Buffer.from(friLayer1Root.slice(2), "hex"));
    const friAlpha2 = chFelt(chan);

    // ── First line fold: N/2 positions ──────────────────────────────────────
    const allLineFolded = [];
    for (let j = 0; j < half; j++) {
        const gPlus  = allData[j].foldedValue;
        const gMinus = allData[j + half].foldedValue;
        const [lineX] = cosetAt(treeDepth, j);
        const xInv = m31inv(lineX);
        allLineFolded.push(lineFold(gPlus, gMinus, friAlpha2, xInv));
    }

    // ── FRI layer 2 tree (half leaves, depth treeDepth−1) ───────────────────
    const friL2Leaves = allLineFolded.map(lf => hashLeaf(qm31ToWords(lf)));
    const friL2Levels = buildTree(friL2Leaves);
    const friLayer2Root = friL2Levels[friL2Levels.length - 1][0];

    // ── Channel: mixRoot(friLayer2Root) → friAlpha3 ── NEW ───────────────────
    chMixRoot(chan, Buffer.from(friLayer2Root.slice(2), "hex"));
    const friAlpha3 = chFelt(chan);   // second line fold challenge

    // ── Second line fold: quarter positions, doubled-x twiddle ── NEW ────────
    // doubleX(j) = 2·cosetAt(treeDepth, j).x² − 1  (correct twiddle for FRI L2→L3)
    const allLineFolded2 = [];
    for (let j = 0; j < quarter; j++) {
        const [xJ] = cosetAt(treeDepth, j);
        const xJSq   = m31mul(xJ, xJ);
        const doubleX = m31sub(m31add(xJSq, xJSq), 1n);
        const xInv2  = m31inv(doubleX);
        const gPlus2  = allLineFolded[j];
        const gMinus2 = allLineFolded[j + quarter];
        allLineFolded2.push(lineFold(gPlus2, gMinus2, friAlpha3, xInv2));
    }

    // ── FRI layer 3 tree (quarter leaves, depth treeDepth−2) ── NEW ──────────
    const friL3Leaves = allLineFolded2.map(lf => hashLeaf(qm31ToWords(lf)));
    const friL3Levels = buildTree(friL3Leaves);
    const friLayer3Root = friL3Levels[friL3Levels.length - 1][0];

    // ── Channel: mixRoot(friLayer3Root) → drawQueries ─────────────────────────
    chMixRoot(chan, Buffer.from(friLayer3Root.slice(2), "hex"));
    const derivedIndices = chQueries(chan, treeDepth, 2);

    // ── Per-query hints ───────────────────────────────────────────────────────
    const hints = derivedIndices.map(idx => {
        const lineIdx   = idx & (half - 1);
        const lineIdx2  = lineIdx & (quarter - 1);
        const siblingCircle = (idx < half)    ? idx + half       : idx - half;
        const siblingL2     = (lineIdx < quarter) ? lineIdx + quarter : lineIdx - quarter;
        const antiIdx   = antipodalOf(idx, treeDepth);

        const { root: traceRoot_, siblings }       = proofPath(traceLevels, idx);
        const { siblings: siblingsNeg }            = proofPath(traceLevels, antiIdx);
        const { siblings: friL1Siblings }          = proofPath(friL1Levels, idx);
        const { siblings: friL1SiblingProof }      = proofPath(friL1Levels, siblingCircle);
        const { siblings: friL2Siblings }          = proofPath(friL2Levels, lineIdx);
        const { siblings: l2SiblingProof }         = proofPath(friL2Levels, siblingL2);
        const { siblings: friL3Siblings }          = proofPath(friL3Levels, lineIdx2);

        const { fPlus, fMinus, foldedValue, qpX, qpY, qv, qvNeg } = allData[idx];
        const friL1SiblingValue = allData[siblingCircle].foldedValue;
        const lineFoldedValue   = allLineFolded[lineIdx];
        const l2SiblingValue    = allLineFolded[siblingL2];
        const lineFoldedValue2  = allLineFolded2[lineIdx2];

        return {
            traceRoot: traceRoot_, queryValues: qv, queryValuesNeg: qvNeg,
            queryIdx: idx, treeDepth, siblings, siblingsNeg,
            friAlpha, fPlus, fMinus, foldedValue, qpX, qpY,
            friL1Siblings,
            friL1SiblingValue, friL1SiblingProof,
            lineFoldedValue, friL2Siblings,
            l2SiblingValue, l2SiblingProof,
            lineFoldedValue2, friL3Siblings,
        };
    });

    const proof = Buffer.alloc(700, 0x01);
    proof.writeBigUInt64LE(2n, 0);
    Buffer.from(traceRoot.slice(2), "hex").copy(proof, 8);

    const fakeMerkleRoot = Buffer.alloc(32, 0x42);
    const hResult    = Buffer.from(blake2s(Buffer.concat([proof.subarray(0, 32), fakeMerkleRoot])));
    const commitment = "0x" + hResult.subarray(0, 16).toString("hex");

    return {
        proof: "0x" + proof.toString("hex"),
        commitment,
        merkleRoot: "0x" + fakeMerkleRoot.toString("hex"),
        traceRoot, treeDepth, traceLevels, colA, colB,
        oodsEvalsPos, oodsEvalsNeg,
        z_x, compAlpha, friAlpha, friAlpha2, friAlpha3,
        oodsComboPos, oodsComboNeg,
        derivedIndices, hints, allData,
        allLineFolded, allLineFolded2,
        friLayer1Root, friL1Levels,
        friLayer2Root, friL2Levels,
        friLayer3Root, friL3Levels,
    };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("QLSAVerifierV12", function () {
    let verifier;
    let f;

    before(async function () {
        const F = await ethers.getContractFactory("QLSAVerifierV12");
        verifier = await F.deploy();
        f = buildV12Fixture();
    });

    // ── Constants ─────────────────────────────────────────────────────────────

    it("MIN_PROOF_LENGTH == 700", async () => expect(await verifier.MIN_PROOF_LENGTH()).to.equal(700n));
    it("MAX_PROOF_LENGTH == 1 MiB", async () => expect(await verifier.MAX_PROOF_LENGTH()).to.equal(1_048_576n));
    it("MIN_QUERIES == 1", async () => expect(await verifier.MIN_QUERIES()).to.equal(1n));
    it("MAX_QUERIES == 64", async () => expect(await verifier.MAX_QUERIES()).to.equal(64n));

    // ── Valid paths ───────────────────────────────────────────────────────────

    it("accepts valid 2-query batch with FRI layer 3 decommitment", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg,
                        f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.true;
    });

    it("accepts valid 1-query batch (first derived index)", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.true;
    });

    // ── FRI layer 3 enforcement ───────────────────────────────────────────────

    it("rejects zero friLayer3Root", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg,
                        f.friLayer1Root, f.friLayer2Root, "0x"+"00".repeat(32))
        )).to.be.false;
    });

    it("rejects tampered lineFoldedValue2 (second fold check fails)", async function () {
        const wrong = (BigInt(f.hints[0].lineFoldedValue2) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { lineFoldedValue2: wrong })
        )).to.be.false;
    });

    it("rejects wrong friL3Siblings (FRI layer 3 Merkle fails)", async function () {
        const badSibs = f.hints[0].friL3Siblings.map(() => "0x"+"dd".repeat(32));
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { friL3Siblings: badSibs })
        )).to.be.false;
    });

    it("rejects wrong friLayer3Root (changes query indices → mismatch)", async function () {
        const altL3Root = "0x"+"cc".repeat(32);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg,
                        f.friLayer1Root, f.friLayer2Root, altL3Root)
        )).to.be.false;
    });

    // ── FRI layer 2 sibling enforcement ──────────────────────────────────────

    it("rejects tampered l2SiblingValue (second fold mismatches)", async function () {
        const wrong = (BigInt(f.hints[0].l2SiblingValue) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { l2SiblingValue: wrong })
        )).to.be.false;
    });

    it("rejects wrong l2SiblingProof (FRI L2 sibling Merkle fails)", async function () {
        const badProof = f.hints[0].l2SiblingProof.map(() => "0x"+"ee".repeat(32));
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { l2SiblingProof: badProof })
        )).to.be.false;
    });

    // ── FRI layer 2 root enforcement ─────────────────────────────────────────

    it("rejects zero friLayer2Root", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg,
                        f.friLayer1Root, "0x"+"00".repeat(32), f.friLayer3Root)
        )).to.be.false;
    });

    it("rejects wrong friLayer2Root (friAlpha3 changes → second fold fails)", async function () {
        const altL2Root = "0x"+"bb".repeat(32);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg,
                        f.friLayer1Root, altL2Root, f.friLayer3Root)
        )).to.be.false;
    });

    // ── FRI layer 1 root enforcement (inherited) ──────────────────────────────

    it("rejects zero friLayer1Root", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg,
                        "0x"+"00".repeat(32), f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });

    it("rejects wrong friLayer1Root (friAlpha2 changes → first fold fails)", async function () {
        const altL1Root = "0x"+"aa".repeat(32);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg,
                        altL1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });

    it("rejects tampered lineFoldedValue (first fold fails)", async function () {
        const wrong = (BigInt(f.hints[0].lineFoldedValue) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { lineFoldedValue: wrong })
        )).to.be.false;
    });

    // ── OODS quotient (inherited) ─────────────────────────────────────────────

    it("rejects tampered oodsEvalsPos (channel changes → OODS fails)", async function () {
        const badPos = [qm31fromM31(999n), qm31fromM31(888n)];
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, badPos, f.oodsEvalsNeg,
                        f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });

    it("rejects tampered fPlus", async function () {
        const wrong = (BigInt(f.hints[0].fPlus) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { fPlus: wrong })
        )).to.be.false;
    });

    it("rejects tampered fMinus", async function () {
        const wrong = (BigInt(f.hints[0].fMinus) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { fMinus: wrong })
        )).to.be.false;
    });

    it("rejects tampered foldedValue (FRI L1 Merkle fails + first fold fails)", async function () {
        const wrong = (BigInt(f.hints[0].foldedValue) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { foldedValue: wrong })
        )).to.be.false;
    });

    // ── FRI L1 sibling enforcement (inherited) ────────────────────────────────

    it("rejects tampered friL1SiblingValue (first fold mismatches)", async function () {
        const wrong = (BigInt(f.hints[0].friL1SiblingValue) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { friL1SiblingValue: wrong })
        )).to.be.false;
    });

    it("rejects wrong friL1SiblingProof (sibling Merkle fails)", async function () {
        const badProof = f.hints[0].friL1SiblingProof.map(() => "0x"+"ff".repeat(32));
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { friL1SiblingProof: badProof })
        )).to.be.false;
    });

    // ── Fiat-Shamir enforcement (inherited) ───────────────────────────────────

    it("rejects wrong friAlpha", async function () {
        const wrongAlpha = qm31fromM31(9999n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { friAlpha: wrongAlpha })
        )).to.be.false;
    });

    it("rejects non-derived queryIndex", async function () {
        const wrongIdx  = (f.derivedIndices[0] + 1) & ((1 << f.treeDepth) - 1);
        const half      = 1 << (f.treeDepth - 1);
        const quarter   = 1 << (f.treeDepth - 2);
        const lineIdx   = wrongIdx & (half - 1);
        const lineIdx2  = lineIdx & (quarter - 1);
        const sibCircle = (wrongIdx < half) ? wrongIdx + half : wrongIdx - half;
        const sibL2     = (lineIdx < quarter) ? lineIdx + quarter : lineIdx - quarter;
        const antiIdx   = antipodalOf(wrongIdx, f.treeDepth);

        const { root: tr, siblings }              = proofPath(f.traceLevels, wrongIdx);
        const { siblings: siblingsNeg }           = proofPath(f.traceLevels, antiIdx);
        const { siblings: friL1Siblings }         = proofPath(f.friL1Levels, wrongIdx);
        const { siblings: friL1SiblingProof }     = proofPath(f.friL1Levels, sibCircle);
        const { siblings: friL2Siblings }         = proofPath(f.friL2Levels, lineIdx);
        const { siblings: l2SiblingProof }        = proofPath(f.friL2Levels, sibL2);
        const { siblings: friL3Siblings }         = proofPath(f.friL3Levels, lineIdx2);

        const { fPlus, fMinus, foldedValue, qpX, qpY, qv, qvNeg } = f.allData[wrongIdx];
        const friL1SiblingValue = f.allData[sibCircle].foldedValue;
        const lineFoldedValue   = f.allLineFolded[lineIdx];
        const l2SiblingValue    = f.allLineFolded[sibL2];
        const lineFoldedValue2  = f.allLineFolded2[lineIdx2];

        const bad = {
            traceRoot: tr, queryValues: qv, queryValuesNeg: qvNeg,
            queryIdx: wrongIdx, treeDepth: f.treeDepth, siblings, siblingsNeg,
            friAlpha: f.friAlpha, fPlus, fMinus, foldedValue, qpX, qpY,
            friL1Siblings, friL1SiblingValue, friL1SiblingProof,
            lineFoldedValue, friL2Siblings,
            l2SiblingValue, l2SiblingProof,
            lineFoldedValue2, friL3Siblings,
        };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(bad, f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });

    it("rejects treeDepth < 3", async function () {
        const h1 = { ...f.hints[0], treeDepth: 2 };
        const h2 = { ...f.hints[1], treeDepth: 2 };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints([h1, h2], f.oodsEvalsPos, f.oodsEvalsNeg,
                        f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });

    it("rejects hints with mismatched treeDepths", async function () {
        const bad = { ...f.hints[1], treeDepth: f.treeDepth + 1 };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints([f.hints[0], bad], f.oodsEvalsPos, f.oodsEvalsNeg,
                        f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });

    // ── Proof-level rejections ────────────────────────────────────────────────

    it("rejects proof shorter than MIN_PROOF_LENGTH", async function () {
        expect(await verifier.verify(
            "0x"+"01".repeat(699), f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });

    it("rejects zero commitment", async function () {
        expect(await verifier.verify(
            f.proof, "0x"+"00".repeat(16), f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });

    it("rejects zero merkleRoot", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, "0x"+"00".repeat(32),
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });

    it("rejects empty queryHints bytes", async function () {
        expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, "0x")).to.be.false;
    });

    it("rejects empty hints array", async function () {
        const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
            ["uint128[]", "uint128[]", "bytes32", "bytes32", "bytes32", HINT_TUPLE + "[]"],
            [f.oodsEvalsPos.map(v=>v), f.oodsEvalsNeg.map(v=>v),
             f.friLayer1Root, f.friLayer2Root, f.friLayer3Root, []]
        );
        expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, encoded)).to.be.false;
    });

    it("rejects tampered proof header (commitment mismatch)", async function () {
        const t = Buffer.from(f.proof.slice(2), "hex"); t[5] ^= 0xff;
        expect(await verifier.verify(
            "0x"+t.toString("hex"), f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });

    it("rejects wrong traceRoot in hint", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg,
                         f.friLayer1Root, f.friLayer2Root, f.friLayer3Root,
                         { traceRoot: "0x"+"aa".repeat(32) })
        )).to.be.false;
    });

    it("rejects 2-query batch when second hint has wrong lineFoldedValue2", async function () {
        const wrong = (BigInt(f.hints[1].lineFoldedValue2) + 1n) % (1n << 128n);
        const bad   = { ...f.hints[1], lineFoldedValue2: wrong };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints([f.hints[0], bad], f.oodsEvalsPos, f.oodsEvalsNeg,
                        f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });

    it("rejects 2-query batch when second hint has wrong friL3Siblings", async function () {
        const badSibs = f.hints[1].friL3Siblings.map(() => "0x"+"ff".repeat(32));
        const bad     = { ...f.hints[1], friL3Siblings: badSibs };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints([f.hints[0], bad], f.oodsEvalsPos, f.oodsEvalsNeg,
                        f.friLayer1Root, f.friLayer2Root, f.friLayer3Root)
        )).to.be.false;
    });
});
