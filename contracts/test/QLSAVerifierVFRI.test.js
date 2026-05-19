const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { blake2s } = require("@noble/hashes/blake2.js");

// ─────────────────────────────────────────────────────────────────────────────
// QLSAVerifierVFRI — Parametric multi-round FRI verifier
//
// Generalises V11/V12/V13: K = friLayerRoots.length − 1 line fold rounds.
//
// queryHints encoding:
//   abi.encode(uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg,
//              bytes32[] friLayerRoots, QueryHints[])
//
// FoldHint: (siblingValue, siblingProof, foldedValue, merkleProof)
//   siblingValue/siblingProof — verified in FRI L(k+1) at depth treeDepth−k
//   foldedValue/merkleProof  — verified in FRI L(k+2) at depth treeDepth−k−1
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

// ── Chebyshev twiddle T_{2^k}(x) via k squarings of (t → 2t²−1) ──────────────

function chebyshevTwiddle(x, k) {
    let t = x;
    for (let i = 0; i < k; i++) {
        const t2 = m31mul(t, t);
        t = m31sub(m31add(t2, t2), 1n);
    }
    return t;
}

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

// ── ABI types ─────────────────────────────────────────────────────────────────

const FOLD_HINT_TYPE = "tuple(uint128,bytes32[],uint128,bytes32[])";
const HINT_TUPLE = `tuple(bytes32,uint32[],uint32[],uint256,uint256,bytes32[],bytes32[],uint128,uint128,uint128,uint128,uint256,uint256,bytes32[],${FOLD_HINT_TYPE}[])`;

function foldHintTuple(fh) {
    return [fh.siblingValue, fh.siblingProof, fh.foldedValue, fh.merkleProof];
}

function hintTuple(h) {
    return [h.traceRoot, h.queryValues, h.queryValuesNeg,
            h.queryIdx, h.treeDepth, h.siblings, h.siblingsNeg,
            h.friAlpha, h.fPlus, h.fMinus, h.foldedValue, h.qpX, h.qpY,
            h.friL1Siblings,
            h.folds.map(foldHintTuple)];
}

function encodeHints(hints, oodsPos, oodsNeg, friLayerRoots, overrides = {}) {
    const tuples = hints.map(h => hintTuple({ ...h, ...overrides }));
    return ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint128[]", "uint128[]", "bytes32[]", HINT_TUPLE + "[]"],
        [oodsPos.map(v => v), oodsNeg.map(v => v), friLayerRoots, tuples]
    );
}
function encodeSingle(hint, oodsPos, oodsNeg, friLayerRoots, overrides = {}) {
    return encodeHints([hint], oodsPos, oodsNeg, friLayerRoots, overrides);
}

// ── Parametric VFRI fixture builder ──────────────────────────────────────────
//
// treeDepth: log₂ domain size (must satisfy treeDepth ≥ numFolds + 1)
// numFolds:  number of line-fold rounds K (friLayerRoots has K+1 entries)

function buildVFRIFixture(treeDepth, numFolds) {
    const N    = 1 << treeDepth;
    const nCols = 2;

    // Simple deterministic column values
    const cols = Array.from({length: nCols}, (_, c) =>
        Array.from({length: N}, (_, i) => (i + 1) * (c + 1) * 10)
    );

    // ── Trace tree ──────────────────────────────────────────────────────────
    const traceLeaves = Array.from({length: N}, (_, i) => hashLeaf(cols.map(c => c[i])));
    const traceLevels = buildTree(traceLeaves);
    const traceRoot   = traceLevels[traceLevels.length - 1][0];

    // ── Channel: trace root → z_x → OODS evals → compAlpha → friAlpha ──────
    const chan = chInit();
    chMixRoot(chan, Buffer.from(traceRoot.slice(2), "hex"));
    const z_x = chFelt(chan);

    const oodsEvalsPos = cols.map((_, c) => qm31fromM31(BigInt(7 + c * 4)));
    const oodsEvalsNeg = cols.map((_, c) => qm31fromM31(BigInt(13 + c * 4)));
    chMixU32s(chan, oodsEvalsPos.flatMap(qm31ToWords));
    chMixU32s(chan, oodsEvalsNeg.flatMap(qm31ToWords));

    const compAlpha = chFelt(chan);
    const friAlpha  = chFelt(chan);

    const oodsComboPos = compositionQM31(oodsEvalsPos, compAlpha);
    const oodsComboNeg = compositionQM31(oodsEvalsNeg, compAlpha);

    // ── Full-domain circle fold → FRI L1 ────────────────────────────────────
    const allData = [];
    for (let idx = 0; idx < N; idx++) {
        const antiIdx = antipodalOf(idx, treeDepth);
        const qv    = cols.map(c => c[idx]);
        const qvNeg = cols.map(c => c[antiIdx]);
        const [qpX, qpY] = cosetAt(treeDepth, idx);
        const yInv  = m31inv(qpY);

        const rawComp    = compositionM31(qv,    compAlpha);
        const rawCompNeg = compositionM31(qvNeg, compAlpha);
        const pxQM31   = qm31fromM31(qpX);
        const denomPos = qm31sub(pxQM31, z_x);
        const denomNeg = qm31sub(qm31neg(pxQM31), z_x);

        const fPlus       = qm31div(qm31sub(rawComp,    oodsComboPos), denomPos);
        const fMinus      = qm31div(qm31sub(rawCompNeg, oodsComboNeg), denomNeg);
        const foldedValue = circleFold(fPlus, fMinus, friAlpha, yInv);

        allData.push({ fPlus, fMinus, foldedValue, qpX, qpY, qv, qvNeg });
    }

    const friL1Leaves = allData.map(d => hashLeaf(qm31ToWords(d.foldedValue)));
    const friL1Levels = buildTree(friL1Leaves);
    const friLayer1Root = friL1Levels[friL1Levels.length - 1][0];

    // ── K line-fold rounds, Chebyshev twiddles ───────────────────────────────
    // foldedLayers[0] = allData[*].foldedValue (N values = FRI L1)
    // foldedLayers[k+1] = lineFolded at round k (N/2^(k+1) values = FRI L(k+2))
    const foldedLayers = [allData.map(d => d.foldedValue)];  // length N
    const layerLevels  = [friL1Levels];
    const layerRoots   = [friLayer1Root];
    const friAlphas    = [];

    chMixRoot(chan, Buffer.from(friLayer1Root.slice(2), "hex"));

    for (let k = 0; k < numFolds; k++) {
        const alpha = chFelt(chan);
        friAlphas.push(alpha);

        const prevLayer = foldedLayers[k];
        const layerSize = prevLayer.length >> 1;  // N / 2^(k+1)
        const newLayer  = [];

        for (let j = 0; j < layerSize; j++) {
            const [xJ]    = cosetAt(treeDepth, j);
            const twiddle = chebyshevTwiddle(xJ, k);
            newLayer.push(lineFold(prevLayer[j], prevLayer[j + layerSize], alpha, m31inv(twiddle)));
        }

        const levels = buildTree(newLayer.map(v => hashLeaf(qm31ToWords(v))));
        const root   = levels[levels.length - 1][0];

        foldedLayers.push(newLayer);
        layerLevels.push(levels);
        layerRoots.push(root);
        chMixRoot(chan, Buffer.from(root.slice(2), "hex"));
    }

    // All FRI layer roots: [friL1Root, friL2Root, ..., friL(K+1)Root]
    const friLayerRoots = layerRoots;

    const nQueries = 2;
    const derivedIndices = chQueries(chan, treeDepth, nQueries);

    // ── Per-query hints ───────────────────────────────────────────────────────
    const hints = derivedIndices.map(idx => {
        const antiIdx = antipodalOf(idx, treeDepth);

        const { root: traceRoot_, siblings } = proofPath(traceLevels, idx);
        const { siblings: siblingsNeg }      = proofPath(traceLevels, antiIdx);
        const { siblings: friL1Siblings }    = proofPath(layerLevels[0], idx);

        const { fPlus, fMinus, foldedValue, qpX, qpY, qv, qvNeg } = allData[idx];

        // Build fold hints for each round k = 0..numFolds-1
        const folds = [];
        let curIdx = idx;
        for (let k = 0; k < numFolds; k++) {
            const layerSize = foldedLayers[k].length >> 1;  // current layer N/2^(k+1) half
            const sibIdx    = (curIdx < layerSize)
                ? curIdx + layerSize
                : curIdx - layerSize;
            const newIdx    = curIdx & (layerSize - 1);

            const { siblings: siblingProof } = proofPath(layerLevels[k], sibIdx);
            const { siblings: merkleProof }  = proofPath(layerLevels[k + 1], newIdx);

            folds.push({
                siblingValue: foldedLayers[k][sibIdx],
                siblingProof,
                foldedValue:  foldedLayers[k + 1][newIdx],
                merkleProof,
            });

            curIdx = newIdx;
        }

        return {
            traceRoot: traceRoot_,
            queryValues: qv, queryValuesNeg: qvNeg,
            queryIdx: idx, treeDepth, siblings, siblingsNeg,
            friAlpha, fPlus, fMinus, foldedValue, qpX, qpY,
            friL1Siblings,
            folds,
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
        traceRoot, treeDepth, numFolds,
        traceLevels, cols,
        oodsEvalsPos, oodsEvalsNeg,
        z_x, compAlpha, friAlpha, friAlphas,
        oodsComboPos, oodsComboNeg,
        derivedIndices, hints,
        allData, foldedLayers, layerLevels, layerRoots,
        friLayerRoots,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("QLSAVerifierVFRI", function () {
    let verifier;

    before(async function () {
        const F = await ethers.getContractFactory("QLSAVerifierVFRI");
        verifier = await F.deploy();
    });

    // ── Constants ─────────────────────────────────────────────────────────────

    it("MIN_PROOF_LENGTH == 700",   async () => expect(await verifier.MIN_PROOF_LENGTH()).to.equal(700n));
    it("MAX_PROOF_LENGTH == 1 MiB", async () => expect(await verifier.MAX_PROOF_LENGTH()).to.equal(1_048_576n));
    it("MIN_QUERIES == 1",          async () => expect(await verifier.MIN_QUERIES()).to.equal(1n));
    it("MAX_QUERIES == 64",         async () => expect(await verifier.MAX_QUERIES()).to.equal(64n));
    it("MAX_FOLD_ROUNDS == 28",     async () => expect(await verifier.MAX_FOLD_ROUNDS()).to.equal(28n));

    // ── treeDepth=2, numFolds=1 (equivalent to V11) ───────────────────────────

    describe("treeDepth=2, numFolds=1 (V11-equivalent)", function () {
        let f;
        before(() => { f = buildVFRIFixture(2, 1); });

        it("accepts valid 2-query proof", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("accepts valid 1-query proof", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects tampered foldedValue in fold[0] (fold check fails)", async function () {
            const badFolds = [{ ...f.hints[0].folds[0],
                foldedValue: (BigInt(f.hints[0].folds[0].foldedValue) + 1n) % (1n << 128n) }];
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { folds: badFolds })
            )).to.be.false;
        });

        it("rejects tampered siblingValue in fold[0] (sibling Merkle fails)", async function () {
            const badFolds = [{ ...f.hints[0].folds[0],
                siblingValue: (BigInt(f.hints[0].folds[0].siblingValue) + 1n) % (1n << 128n) }];
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { folds: badFolds })
            )).to.be.false;
        });

        it("rejects wrong sibling Merkle proof in fold[0]", async function () {
            const badFolds = [{ ...f.hints[0].folds[0],
                siblingProof: f.hints[0].folds[0].siblingProof.map(() => "0x"+"dd".repeat(32)) }];
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { folds: badFolds })
            )).to.be.false;
        });

        it("rejects wrong merkleProof in fold[0]", async function () {
            const badFolds = [{ ...f.hints[0].folds[0],
                merkleProof: f.hints[0].folds[0].merkleProof.map(() => "0x"+"ee".repeat(32)) }];
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { folds: badFolds })
            )).to.be.false;
        });
    });

    // ── treeDepth=3, numFolds=2 (equivalent to V12) ───────────────────────────

    describe("treeDepth=3, numFolds=2 (V12-equivalent)", function () {
        let f;
        before(() => { f = buildVFRIFixture(3, 2); });

        it("accepts valid 2-query proof", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("accepts valid 1-query proof", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects tampered foldedValue in fold[1] (second fold fails)", async function () {
            const bad1 = { ...f.hints[0].folds[1],
                foldedValue: (BigInt(f.hints[0].folds[1].foldedValue) + 1n) % (1n << 128n) };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { folds: [f.hints[0].folds[0], bad1] })
            )).to.be.false;
        });

        it("rejects tampered siblingValue in fold[0] (first sibling Merkle fails)", async function () {
            const bad0 = { ...f.hints[0].folds[0],
                siblingValue: (BigInt(f.hints[0].folds[0].siblingValue) + 1n) % (1n << 128n) };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { folds: [bad0, f.hints[0].folds[1]] })
            )).to.be.false;
        });

        it("rejects wrong friLayerRoots[2] (changes queries → mismatch)", async function () {
            const badRoots = [...f.friLayerRoots];
            badRoots[2] = "0x"+"cc".repeat(32);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, badRoots)
            )).to.be.false;
        });
    });

    // ── treeDepth=4, numFolds=3 (equivalent to V13) ───────────────────────────

    describe("treeDepth=4, numFolds=3 (V13-equivalent)", function () {
        let f;
        before(() => { f = buildVFRIFixture(4, 3); });

        it("accepts valid 2-query proof", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("accepts valid 1-query proof", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects tampered foldedValue in fold[2] (third fold fails)", async function () {
            const bad2 = { ...f.hints[0].folds[2],
                foldedValue: (BigInt(f.hints[0].folds[2].foldedValue) + 1n) % (1n << 128n) };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { folds: [f.hints[0].folds[0], f.hints[0].folds[1], bad2] })
            )).to.be.false;
        });

        it("rejects tampered siblingValue in fold[2] (sibling of third fold fails)", async function () {
            const bad2 = { ...f.hints[0].folds[2],
                siblingValue: (BigInt(f.hints[0].folds[2].siblingValue) + 1n) % (1n << 128n) };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { folds: [f.hints[0].folds[0], f.hints[0].folds[1], bad2] })
            )).to.be.false;
        });

        it("rejects wrong friLayerRoots[3] (fourth layer root)", async function () {
            const badRoots = [...f.friLayerRoots];
            badRoots[3] = "0x"+"bb".repeat(32);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, badRoots)
            )).to.be.false;
        });
    });

    // ── treeDepth=5, numFolds=4 (new: 4 fold rounds, V14+ territory) ──────────

    describe("treeDepth=5, numFolds=4 (4 fold rounds)", function () {
        let f;
        before(() => { f = buildVFRIFixture(5, 4); });

        it("accepts valid 2-query proof with 4 fold rounds", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects tampered foldedValue in fold[3] (fourth fold fails)", async function () {
            const bad3 = { ...f.hints[0].folds[3],
                foldedValue: (BigInt(f.hints[0].folds[3].foldedValue) + 1n) % (1n << 128n) };
            const folds = [...f.hints[0].folds];
            folds[3] = bad3;
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { folds })
            )).to.be.false;
        });
    });

    // ── Input validation ──────────────────────────────────────────────────────

    describe("input validation", function () {
        let f;
        before(() => { f = buildVFRIFixture(3, 2); });

        it("rejects proof shorter than MIN_PROOF_LENGTH", async function () {
            expect(await verifier.verify(
                "0x"+"01".repeat(699), f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects zero commitment", async function () {
            expect(await verifier.verify(
                f.proof, "0x"+"00".repeat(16), f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects zero merkleRoot", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, "0x"+"00".repeat(32),
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects empty queryHints", async function () {
            expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, "0x")).to.be.false;
        });

        it("rejects empty hints array (< MIN_QUERIES)", async function () {
            const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint128[]", "uint128[]", "bytes32[]", HINT_TUPLE + "[]"],
                [f.oodsEvalsPos.map(v=>v), f.oodsEvalsNeg.map(v=>v), f.friLayerRoots, []]
            );
            expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, encoded)).to.be.false;
        });

        it("rejects friLayerRoots with only one entry (< 2)", async function () {
            const badRoots = [f.friLayerRoots[0]];
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints.slice(0,1), f.oodsEvalsPos, f.oodsEvalsNeg, badRoots)
            )).to.be.false;
        });

        it("rejects zero root in friLayerRoots[0]", async function () {
            const badRoots = ["0x"+"00".repeat(32), ...f.friLayerRoots.slice(1)];
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, badRoots)
            )).to.be.false;
        });

        it("rejects zero root in friLayerRoots[1]", async function () {
            const badRoots = [f.friLayerRoots[0], "0x"+"00".repeat(32), ...f.friLayerRoots.slice(2)];
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, badRoots)
            )).to.be.false;
        });

        it("rejects mismatched oodsEvals lengths", async function () {
            const shortNeg = f.oodsEvalsNeg.slice(0, 1);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, shortNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects tampered proof header (commitment mismatch)", async function () {
            const t = Buffer.from(f.proof.slice(2), "hex"); t[5] ^= 0xff;
            expect(await verifier.verify(
                "0x"+t.toString("hex"), f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects wrong traceRoot in hint", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { traceRoot: "0x"+"aa".repeat(32) })
            )).to.be.false;
        });

        it("rejects hints with mismatched treeDepths", async function () {
            const bad = { ...f.hints[1], treeDepth: f.treeDepth + 1 };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints([f.hints[0], bad], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects hints with wrong folds.length", async function () {
            const bad = { ...f.hints[0], folds: f.hints[0].folds.slice(0, 1) };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints([bad, f.hints[1]], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });
    });

    // ── Fiat-Shamir enforcement ───────────────────────────────────────────────

    describe("Fiat-Shamir enforcement", function () {
        let f;
        before(() => { f = buildVFRIFixture(3, 2); });

        it("rejects wrong friAlpha in hint", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { friAlpha: qm31fromM31(9999n) })
            )).to.be.false;
        });

        it("rejects non-derived queryIndex", async function () {
            const wrongIdx = (f.derivedIndices[0] + 1) & ((1 << f.treeDepth) - 1);
            const antiIdx  = antipodalOf(wrongIdx, f.treeDepth);
            const { root: tr, siblings }          = proofPath(f.traceLevels, wrongIdx);
            const { siblings: siblingsNeg }       = proofPath(f.traceLevels, antiIdx);
            const { siblings: friL1Siblings }     = proofPath(f.layerLevels[0], wrongIdx);

            const { fPlus, fMinus, foldedValue, qpX, qpY, qv, qvNeg } = f.allData[wrongIdx];

            const folds = [];
            let curIdx = wrongIdx;
            for (let k = 0; k < f.numFolds; k++) {
                const layerSize = f.foldedLayers[k].length >> 1;
                const sibIdx    = (curIdx < layerSize) ? curIdx + layerSize : curIdx - layerSize;
                const newIdx    = curIdx & (layerSize - 1);
                const { siblings: siblingProof } = proofPath(f.layerLevels[k], sibIdx);
                const { siblings: merkleProof }  = proofPath(f.layerLevels[k + 1], newIdx);
                folds.push({
                    siblingValue: f.foldedLayers[k][sibIdx],
                    siblingProof,
                    foldedValue:  f.foldedLayers[k + 1][newIdx],
                    merkleProof,
                });
                curIdx = newIdx;
            }

            const bad = {
                traceRoot: tr, queryValues: qv, queryValuesNeg: qvNeg,
                queryIdx: wrongIdx, treeDepth: f.treeDepth, siblings, siblingsNeg,
                friAlpha: f.friAlpha, fPlus, fMinus, foldedValue, qpX, qpY,
                friL1Siblings, folds,
            };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(bad, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects tampered oodsEvalsPos", async function () {
            const badPos = f.oodsEvalsPos.map((_, i) => qm31fromM31(BigInt(999 + i)));
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, badPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects tampered fPlus", async function () {
            const wrong = (BigInt(f.hints[0].fPlus) + 1n) % (1n << 128n);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { fPlus: wrong })
            )).to.be.false;
        });

        it("rejects tampered fMinus", async function () {
            const wrong = (BigInt(f.hints[0].fMinus) + 1n) % (1n << 128n);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { fMinus: wrong })
            )).to.be.false;
        });

        it("rejects tampered foldedValue (FRI L1 Merkle fails)", async function () {
            const wrong = (BigInt(f.hints[0].foldedValue) + 1n) % (1n << 128n);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { foldedValue: wrong })
            )).to.be.false;
        });

        it("rejects second query with wrong foldedValue in fold[0]", async function () {
            const bad0 = { ...f.hints[1].folds[0],
                foldedValue: (BigInt(f.hints[1].folds[0].foldedValue) + 1n) % (1n << 128n) };
            const badHint1 = { ...f.hints[1], folds: [bad0, ...f.hints[1].folds.slice(1)] };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints([f.hints[0], badHint1], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });
    });

    // ── Trace Merkle enforcement ──────────────────────────────────────────────

    describe("trace Merkle enforcement", function () {
        let f;
        before(() => { f = buildVFRIFixture(3, 2); });

        it("rejects wrong trace Merkle siblings", async function () {
            const badSibs = f.hints[0].siblings.map(() => "0x"+"11".repeat(32));
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { siblings: badSibs })
            )).to.be.false;
        });

        it("rejects wrong antipodal siblings", async function () {
            const badSibs = f.hints[0].siblingsNeg.map(() => "0x"+"22".repeat(32));
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { siblingsNeg: badSibs })
            )).to.be.false;
        });

        it("rejects wrong FRI L1 siblings", async function () {
            const badSibs = f.hints[0].friL1Siblings.map(() => "0x"+"33".repeat(32));
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { friL1Siblings: badSibs })
            )).to.be.false;
        });
    });
});
