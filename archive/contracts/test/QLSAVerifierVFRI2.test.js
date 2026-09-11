const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { blake2s } = require("@noble/hashes/blake2.js");

// ─────────────────────────────────────────────────────────────────────────────
// QLSAVerifierVFRI2 — VFRI + last-layer constant-polynomial check
//
// New in VFRI2 vs VFRI:
//   1. `lastLayerValue` (uint128) prepended to the global queryHints encoding.
//   2. On-chain: expected last-layer Merkle root is rebuilt as a constant tree
//      of depth (treeDepth − numFolds) whose every leaf = hashLeaf(qm31Words(c)).
//      Verifier asserts: friLayerRoots[numFolds] == expectedRoot.
//   3. Because per-query Merkle proofs already bind each final fold value into
//      friLayerRoots[numFolds], and the constant-tree check proves all leaves
//      equal c, every query's final fold is cryptographically fixed to c.
//
// queryHints encoding:
//   abi.encode(uint128 lastLayerValue, uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg,
//              bytes32[] friLayerRoots, QueryHints[])
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

// Build the Merkle root of a constant tree: 2^depth leaves all equal to the same hash.
function constantTreeRoot(leafHash, depth) {
    let node = leafHash;
    for (let i = 0; i < depth; i++) node = hashPair(node, node);
    return node;
}

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

function encodeHints(hints, lastLayerValue, oodsPos, oodsNeg, friLayerRoots, overrides = {}) {
    const tuples = hints.map(h => hintTuple({ ...h, ...overrides }));
    return ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint128", "uint128[]", "uint128[]", "bytes32[]", HINT_TUPLE + "[]"],
        [lastLayerValue, oodsPos.map(v => v), oodsNeg.map(v => v), friLayerRoots, tuples]
    );
}
function encodeSingle(hint, lastLayerValue, oodsPos, oodsNeg, friLayerRoots, overrides = {}) {
    return encodeHints([hint], lastLayerValue, oodsPos, oodsNeg, friLayerRoots, overrides);
}

// ── Parametric VFRI2 fixture builder ─────────────────────────────────────────
//
// Key difference from VFRI fixture:
//   After K line-fold rounds, the fixture forces the last layer to be a
//   constant polynomial by constructing it explicitly.  The final N/2^K
//   fold values will generally NOT all be equal (they depend on the random
//   α values), so we use a specially crafted polynomial where they are.
//
// Strategy: instead of real polynomial data, we drive the fold values so that
//   after K folds the entire last-layer tree holds a single constant c.
//
// Implementation:
//   1. Pick a target constant c.
//   2. Build the last-layer tree (2^(treeDepth−K) leaves, all equal to c).
//   3. Work backwards through K fold rounds, choosing fold inputs that are
//      consistent with the fold formula and produce c at the end.
//   4. Build FRI L1 tree from circle fold values (backwards from first-fold inputs).
//   5. Construct trace column values consistent with the composition binding.
//
// For simplicity in JS tests we use a forward approach: we let the Rust-side
// fixture choose arbitrary column values, run K folds, and then inject a
// "constant override" by:
//   - Computing all fold values normally.
//   - After the K-th fold, ALL values in the last layer will generally differ.
//   - We can only produce a valid proof where the last layer IS constant if we
//     carefully choose the initial data.
//
// SIMPLER approach: use treeDepth = numFolds + 1 (minimum), so the last layer
// has exactly 2 leaves.  With only 2 leaves, we need them both equal.
// The 2-leaf last-layer tree has indices 0 and 1.
// When treeDepth = numFolds + 1, after K = numFolds line folds the remaining
// domain size is 2.  Indices 0 and 1 are each other's partners in the last fold.
// So foldedLayers[K][0] and foldedLayers[K][1] both exist but may differ.
//
// We construct column values so that after all folds the last layer is constant.
// For the last fold (k = K-1), with 4 inputs (indices 0,1 for the last layer
// of size 2, plus their fold-partners at offset 2):
//   fold(v[j], v[j+2]) = c  for j=0,1
// We choose v[0]=v[1]=A and v[2]=v[3]=B such that lineFold(A, B, αK, xInv)=c
// for the appropriate twiddles.  With A=B=c, we get lineFold(c,c,αK,xInv)=2c
// which isn't c unless c=0.  So we use a different parametric approach.
//
// CLEANEST approach for tests: use a 1-column trace with polynomial values
// chosen so the last-layer is naturally constant after all folds. This requires
// solving for the column values — feasible but complex.
//
// PRACTICAL approach: directly construct the fixture backwards:
//   Given constant c (last layer), invert each fold step to get the previous layer.
//   "Invert" of lineFold: given f(j) = ((gP+gM) + α(gP-gM)xInv), knowing
//   f(j) and that gP and gM are values at j and j+half, we set gP = gM = c
//   to produce f(j) = 2c.  But that's not c.
//
// ACTUAL PRACTICAL approach: just use the FORWARD path and accept that the
// last layer WON'T be a constant for arbitrary data. Instead, craft the test
// data so that it IS constant.  The simplest way: use 0-polynomial.
// All column values = 0, OODS evals = 0.  Then all folds = 0.  lastLayerValue = 0.
// BUT: the OODS check requires denomPos/denomNeg ≠ 0, and compAlpha divides work.
// For all-zero data, the OODS check: fPlus * (pxQM31 - z_x) = rawComp - oodsComboPos = 0 - 0 = 0
// So fPlus=0, fMinus=0.  circleFold(0,0,α,yInv) = 0.  All fold values = 0.
// lastLayerValue = 0.  This works and is clean!
//
// We use this 0-polynomial approach for the base "valid" tests, then verify
// that VFRI2 correctly rejects non-constant last layers.

function buildVFRI2Fixture(treeDepth, numFolds) {
    const N     = 1 << treeDepth;
    const nCols = 2;

    // Use 0-polynomial: all trace values = 0, OODS evals = 0.
    // This ensures all fold values = 0, making the last layer a constant (0).
    const cols = Array.from({length: nCols}, () => Array(N).fill(0));

    // ── Trace tree ──────────────────────────────────────────────────────────
    const traceLeaves = Array.from({length: N}, (_, i) => hashLeaf(cols.map(c => c[i])));
    const traceLevels = buildTree(traceLeaves);
    const traceRoot   = traceLevels[traceLevels.length - 1][0];

    // ── Channel: trace root → z_x → OODS evals → compAlpha → friAlpha ──────
    const chan = chInit();
    chMixRoot(chan, Buffer.from(traceRoot.slice(2), "hex"));
    const z_x = chFelt(chan);

    const oodsEvalsPos = cols.map(() => 0n);  // all zero
    const oodsEvalsNeg = cols.map(() => 0n);  // all zero
    chMixU32s(chan, oodsEvalsPos.flatMap(qm31ToWords));
    chMixU32s(chan, oodsEvalsNeg.flatMap(qm31ToWords));

    const compAlpha = chFelt(chan);
    const friAlpha  = chFelt(chan);

    const oodsComboPos = 0n;  // all zero
    const oodsComboNeg = 0n;  // all zero

    // ── Full-domain circle fold: all 0 → foldedValue = 0 for every position ──
    // fPlus = 0, fMinus = 0, circleFold(0,0,α,yInv) = 0
    const allData = [];
    for (let idx = 0; idx < N; idx++) {
        const antiIdx = antipodalOf(idx, treeDepth);
        const qv    = cols.map(c => c[idx]);
        const qvNeg = cols.map(c => c[antiIdx]);
        const [qpX, qpY] = cosetAt(treeDepth, idx);

        // rawComp = 0, oodsCombo = 0, so fPlus = 0/denom = 0, fMinus = 0.
        // circleFold(0, 0, friAlpha, yInv) = 0.
        allData.push({
            fPlus: 0n, fMinus: 0n,
            foldedValue: 0n,
            qpX, qpY, qv, qvNeg,
        });
    }

    // FRI L1 tree: all leaves are hashLeaf([0,0,0,0]) = same value.
    const l1Leaf = hashLeaf(qm31ToWords(0n));
    const friL1Leaves = Array(N).fill(l1Leaf);
    const friL1Levels = buildTree(friL1Leaves);
    const friLayer1Root = friL1Levels[friL1Levels.length - 1][0];

    // ── K line-fold rounds: all 0 → always 0 ─────────────────────────────────
    const foldedLayers = [Array(N).fill(0n)];  // FRI L1 values
    const layerLevels  = [friL1Levels];
    const layerRoots   = [friLayer1Root];
    const friAlphas    = [];

    chMixRoot(chan, Buffer.from(friLayer1Root.slice(2), "hex"));

    for (let k = 0; k < numFolds; k++) {
        const alpha = chFelt(chan);
        friAlphas.push(alpha);

        // All values are 0 → lineFold(0, 0, alpha, xInv) = 0
        const layerSize = foldedLayers[k].length >> 1;
        const newLayer  = Array(layerSize).fill(0n);

        // Build tree for this all-0 layer
        const lLeaf  = hashLeaf(qm31ToWords(0n));
        const leaves  = Array(layerSize).fill(lLeaf);
        const levels  = buildTree(leaves);
        const root    = levels[levels.length - 1][0];

        foldedLayers.push(newLayer);
        layerLevels.push(levels);
        layerRoots.push(root);
        chMixRoot(chan, Buffer.from(root.slice(2), "hex"));
    }

    const lastLayerValue = 0n;  // constant polynomial = 0
    const friLayerRoots  = layerRoots;

    const nQueries = 2;
    const derivedIndices = chQueries(chan, treeDepth, nQueries);

    // ── Per-query hints ───────────────────────────────────────────────────────
    const hints = derivedIndices.map(idx => {
        const antiIdx = antipodalOf(idx, treeDepth);

        const { root: traceRoot_, siblings } = proofPath(traceLevels, idx);
        const { siblings: siblingsNeg }      = proofPath(traceLevels, antiIdx);
        const { siblings: friL1Siblings }    = proofPath(layerLevels[0], idx);

        const { fPlus, fMinus, foldedValue, qpX, qpY, qv, qvNeg } = allData[idx];

        const folds = [];
        let curIdx = idx;
        for (let k = 0; k < numFolds; k++) {
            const layerSize = foldedLayers[k].length >> 1;
            const sibIdx    = (curIdx < layerSize)
                ? curIdx + layerSize
                : curIdx - layerSize;
            const newIdx    = curIdx & (layerSize - 1);

            const { siblings: siblingProof } = proofPath(layerLevels[k], sibIdx);
            const { siblings: merkleProof }  = proofPath(layerLevels[k + 1], newIdx);

            folds.push({
                siblingValue: 0n,
                siblingProof,
                foldedValue:  0n,
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
        friLayerRoots, lastLayerValue,
    };
}

// Build the JS-side constant tree root for a given lastLayerValue and depth.
function jsConstantTreeRoot(lastLayerValue, depth) {
    return constantTreeRoot(hashLeaf(qm31ToWords(lastLayerValue)), depth);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("QLSAVerifierVFRI2", function () {
    let verifier;

    before(async function () {
        const F = await ethers.getContractFactory("QLSAVerifierVFRI2");
        verifier = await F.deploy();
    });

    // ── Constants ─────────────────────────────────────────────────────────────

    it("MIN_PROOF_LENGTH == 700",   async () => expect(await verifier.MIN_PROOF_LENGTH()).to.equal(700n));
    it("MAX_PROOF_LENGTH == 1 MiB", async () => expect(await verifier.MAX_PROOF_LENGTH()).to.equal(1_048_576n));
    it("MIN_QUERIES == 1",          async () => expect(await verifier.MIN_QUERIES()).to.equal(1n));
    it("MAX_QUERIES == 64",         async () => expect(await verifier.MAX_QUERIES()).to.equal(64n));
    it("MAX_FOLD_ROUNDS == 28",     async () => expect(await verifier.MAX_FOLD_ROUNDS()).to.equal(28n));

    // ── treeDepth=2, numFolds=1 ───────────────────────────────────────────────

    describe("treeDepth=2, numFolds=1", function () {
        let f;
        before(() => { f = buildVFRI2Fixture(2, 1); });

        it("accepts valid 2-query proof with constant last layer", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("accepts valid 1-query proof", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects wrong lastLayerValue (constant tree root mismatch)", async function () {
            const wrong = qm31fromM31(42n);  // non-zero constant
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, wrong, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("verifies that JS constant tree root matches on-chain expectation", function () {
            // Sanity check: JS fixture's last layer root == constant tree root
            const lastDepth = f.treeDepth - f.numFolds;
            const expected  = jsConstantTreeRoot(f.lastLayerValue, lastDepth);
            expect(f.friLayerRoots[f.numFolds]).to.equal(expected);
        });

        it("rejects when last FRI layer root is replaced with non-constant tree root", async function () {
            // Produce a tree root from 2 DIFFERENT leaves (not a constant tree)
            const nonConstLeaf0 = hashLeaf([1, 2, 3, 4]);
            const nonConstLeaf1 = hashLeaf([5, 6, 7, 8]);
            const nonConstRoot  = hashPair(nonConstLeaf0, nonConstLeaf1);
            const badRoots = [...f.friLayerRoots];
            badRoots[f.numFolds] = nonConstRoot;
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, badRoots)
            )).to.be.false;
        });
    });

    // ── treeDepth=3, numFolds=2 ───────────────────────────────────────────────

    describe("treeDepth=3, numFolds=2", function () {
        let f;
        before(() => { f = buildVFRI2Fixture(3, 2); });

        it("accepts valid 2-query proof", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects wrong lastLayerValue", async function () {
            const wrong = qm31fromM31(99n);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, wrong, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects tampered fold[1].foldedValue (fold check fails)", async function () {
            const bad1 = { ...f.hints[0].folds[1],
                foldedValue: (BigInt(f.hints[0].folds[1].foldedValue) + 1n) % (1n << 128n) };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { folds: [f.hints[0].folds[0], bad1] })
            )).to.be.false;
        });

        it("verifies JS constant tree root matches last layer root", function () {
            const lastDepth = f.treeDepth - f.numFolds;
            expect(f.friLayerRoots[f.numFolds]).to.equal(
                jsConstantTreeRoot(f.lastLayerValue, lastDepth)
            );
        });
    });

    // ── treeDepth=4, numFolds=3 ───────────────────────────────────────────────

    describe("treeDepth=4, numFolds=3", function () {
        let f;
        before(() => { f = buildVFRI2Fixture(4, 3); });

        it("accepts valid 2-query proof with 3 fold rounds", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects wrong lastLayerValue", async function () {
            const wrong = qm31fromM31(1n);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, wrong, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("verifies JS constant tree root matches last layer root", function () {
            const lastDepth = f.treeDepth - f.numFolds;
            expect(f.friLayerRoots[f.numFolds]).to.equal(
                jsConstantTreeRoot(f.lastLayerValue, lastDepth)
            );
        });
    });

    // ── treeDepth=4, numFolds=2 (last layer has 4 leaves) ────────────────────
    // This tests a larger last-layer domain (not the minimum 2-leaf case).

    describe("treeDepth=4, numFolds=2 (last layer: 4 leaves)", function () {
        let f;
        before(() => { f = buildVFRI2Fixture(4, 2); });

        it("accepts valid 2-query proof", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("verifies constant tree has 4 leaves (lastDepth=2)", function () {
            const lastDepth = f.treeDepth - f.numFolds;  // 4-2=2 → 4 leaves
            expect(lastDepth).to.equal(2);
            expect(f.friLayerRoots[f.numFolds]).to.equal(
                jsConstantTreeRoot(f.lastLayerValue, lastDepth)
            );
        });

        it("rejects wrong lastLayerValue for 4-leaf last layer", async function () {
            const wrong = qm31fromM31(7n);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, wrong, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });
    });

    // ── Input validation ──────────────────────────────────────────────────────

    describe("input validation", function () {
        let f;
        before(() => { f = buildVFRI2Fixture(3, 2); });

        it("rejects proof shorter than MIN_PROOF_LENGTH", async function () {
            expect(await verifier.verify(
                "0x"+"01".repeat(699), f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects zero commitment", async function () {
            expect(await verifier.verify(
                f.proof, "0x"+"00".repeat(16), f.merkleRoot,
                encodeHints(f.hints, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects zero merkleRoot", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, "0x"+"00".repeat(32),
                encodeHints(f.hints, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects empty queryHints", async function () {
            expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, "0x")).to.be.false;
        });

        it("rejects empty hints array (< MIN_QUERIES)", async function () {
            const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint128", "uint128[]", "uint128[]", "bytes32[]", HINT_TUPLE + "[]"],
                [f.lastLayerValue, f.oodsEvalsPos.map(v=>v), f.oodsEvalsNeg.map(v=>v),
                 f.friLayerRoots, []]
            );
            expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, encoded)).to.be.false;
        });

        it("rejects friLayerRoots with only one entry", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints.slice(0,1), f.lastLayerValue,
                    f.oodsEvalsPos, f.oodsEvalsNeg, [f.friLayerRoots[0]])
            )).to.be.false;
        });

        it("rejects tampered proof header (commitment mismatch)", async function () {
            const t = Buffer.from(f.proof.slice(2), "hex"); t[5] ^= 0xff;
            expect(await verifier.verify(
                "0x"+t.toString("hex"), f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects wrong traceRoot in hint", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg,
                    f.friLayerRoots, { traceRoot: "0x"+"aa".repeat(32) })
            )).to.be.false;
        });

        it("rejects hints with mismatched treeDepths", async function () {
            const bad = { ...f.hints[1], treeDepth: f.treeDepth + 1 };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints([f.hints[0], bad], f.lastLayerValue,
                    f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects mismatched oodsEvals lengths", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerValue,
                    f.oodsEvalsPos, f.oodsEvalsNeg.slice(0,1), f.friLayerRoots)
            )).to.be.false;
        });
    });

    // ── Fiat-Shamir enforcement ───────────────────────────────────────────────

    describe("Fiat-Shamir enforcement", function () {
        let f;
        before(() => { f = buildVFRI2Fixture(3, 2); });

        it("rejects wrong friAlpha in hint", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg,
                    f.friLayerRoots, { friAlpha: qm31fromM31(9999n) })
            )).to.be.false;
        });

        it("rejects non-derived queryIndex", async function () {
            const wrongIdx = (f.derivedIndices[0] + 1) & ((1 << f.treeDepth) - 1);
            const antiIdx  = antipodalOf(wrongIdx, f.treeDepth);
            const { root: tr, siblings }          = proofPath(f.traceLevels, wrongIdx);
            const { siblings: siblingsNeg }       = proofPath(f.traceLevels, antiIdx);
            const { siblings: friL1Siblings }     = proofPath(f.layerLevels[0], wrongIdx);

            const folds = [];
            let curIdx = wrongIdx;
            for (let k = 0; k < f.numFolds; k++) {
                const layerSize = f.foldedLayers[k].length >> 1;
                const sibIdx    = (curIdx < layerSize) ? curIdx + layerSize : curIdx - layerSize;
                const newIdx    = curIdx & (layerSize - 1);
                const { siblings: siblingProof } = proofPath(f.layerLevels[k], sibIdx);
                const { siblings: merkleProof }  = proofPath(f.layerLevels[k + 1], newIdx);
                folds.push({ siblingValue: 0n, siblingProof, foldedValue: 0n, merkleProof });
                curIdx = newIdx;
            }

            const { fPlus, fMinus, foldedValue, qpX, qpY, qv, qvNeg } = f.allData[wrongIdx];
            const bad = {
                traceRoot: tr, queryValues: qv, queryValuesNeg: qvNeg,
                queryIdx: wrongIdx, treeDepth: f.treeDepth, siblings, siblingsNeg,
                friAlpha: f.friAlpha, fPlus, fMinus, foldedValue, qpX, qpY,
                friL1Siblings, folds,
            };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(bad, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects wrong FRI layer root (alters query indices)", async function () {
            const badRoots = [...f.friLayerRoots];
            badRoots[0] = "0x"+"cc".repeat(32);
            // Note: root[0] is also the FRI L1 root, changing it invalidates the
            // constant-tree check indirectly (wrong root ≠ expected) AND changes
            // channel transcript so derived indices don't match.
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, badRoots)
            )).to.be.false;
        });
    });

    // ── Constant polynomial check specifics ───────────────────────────────────

    describe("constant polynomial check", function () {
        let f;
        before(() => { f = buildVFRI2Fixture(3, 2); });

        it("js constantTreeRoot(0, 1) == hashPair(leafHash, leafHash)", function () {
            const lh = hashLeaf(qm31ToWords(0n));
            expect(jsConstantTreeRoot(0n, 1)).to.equal(hashPair(lh, lh));
        });

        it("js constantTreeRoot(0, 2) == 4-leaf constant tree root", function () {
            const lh = hashLeaf(qm31ToWords(0n));
            const l1 = hashPair(lh, lh);
            expect(jsConstantTreeRoot(0n, 2)).to.equal(hashPair(l1, l1));
        });

        it("rejects if last FRI root is replaced by a different constant tree", async function () {
            // Use lastLayerValue=1 but supply its constant tree as the last root.
            const lastDepth = f.treeDepth - f.numFolds;
            const wrongRoot = jsConstantTreeRoot(qm31fromM31(1n), lastDepth);
            const badRoots  = [...f.friLayerRoots];
            badRoots[f.numFolds] = wrongRoot;
            // lastLayerValue still 0, but root now matches constant=1 tree → mismatch
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg, badRoots)
            )).to.be.false;
        });

        it("rejects if both lastLayerValue and last root changed to consistent wrong value", async function () {
            // Change lastLayerValue to 1 AND change last root to matching constant-1 tree.
            // The per-query Merkle proof will then fail (the actual last-layer leaves are 0).
            const wrongLLV  = qm31fromM31(1n);
            const lastDepth = f.treeDepth - f.numFolds;
            const wrongRoot = jsConstantTreeRoot(wrongLLV, lastDepth);
            const badRoots  = [...f.friLayerRoots];
            badRoots[f.numFolds] = wrongRoot;
            // The Fiat-Shamir channel still uses the original roots for query derivation,
            // so changing the last root alone shifts friAlphas/queryIndices — but in this
            // test the hint friLayerRoots array changed, so the channel will shift, and
            // the per-query Merkle proofs (merkleProof for folds[K-1]) will fail against
            // the wrong root.
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, wrongLLV, f.oodsEvalsPos, f.oodsEvalsNeg, badRoots)
            )).to.be.false;
        });

        it("rejects wrong trace Merkle siblings", async function () {
            const badSibs = f.hints[0].siblings.map(() => "0x"+"11".repeat(32));
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg,
                    f.friLayerRoots, { siblings: badSibs })
            )).to.be.false;
        });

        it("rejects wrong FRI L1 siblings", async function () {
            const badSibs = f.hints[0].friL1Siblings.map(() => "0x"+"22".repeat(32));
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg,
                    f.friLayerRoots, { friL1Siblings: badSibs })
            )).to.be.false;
        });

        it("rejects wrong fold[0].merkleProof (last-layer inclusion proof fails)", async function () {
            const badFolds = [
                { ...f.hints[0].folds[0],
                  merkleProof: f.hints[0].folds[0].merkleProof.map(() => "0x"+"33".repeat(32)) },
                f.hints[0].folds[1],
            ];
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.lastLayerValue, f.oodsEvalsPos, f.oodsEvalsNeg,
                    f.friLayerRoots, { folds: badFolds })
            )).to.be.false;
        });

        it("rejects second query with wrong fold[1].foldedValue", async function () {
            const bad1 = { ...f.hints[1].folds[1],
                foldedValue: qm31fromM31(7n) };
            const badHint1 = { ...f.hints[1], folds: [f.hints[1].folds[0], bad1] };
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints([f.hints[0], badHint1], f.lastLayerValue,
                    f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });
    });
});
