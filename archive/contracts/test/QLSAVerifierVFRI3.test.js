const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { blake2s } = require("@noble/hashes/blake2.js");

// ─────────────────────────────────────────────────────────────────────────────
// QLSAVerifierVFRI3 — non-constant last-layer polynomial check (MVP-4)
//
// New in VFRI3 vs VFRI2:
//   1. `lastLayerCoeffs` (uint128[]) replaces `lastLayerValue` (uint128).
//   2. On-chain check:
//      - If lastLayerCoeffs.length == 1: constant-tree optimization (same as VFRI2).
//      - Otherwise: verifier builds actual Merkle tree from all evaluations and
//        asserts root == friLayerRoots[K].
//   3. Per-query Merkle proofs continue to bind fold values into friLayerRoots[K].
//      Since friLayerRoots[K] is now the Merkle root of the full last-layer polynomial,
//      each query's final fold value is bound to a specific evaluation of the polynomial.
//
// queryHints encoding:
//   abi.encode(uint128[] lastLayerCoeffs, uint128[] oodsEvalsPos, uint128[] oodsEvalsNeg,
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

function qm31ToWords(q) {
    const c0 = qm31c0(q), c1 = qm31c1(q);
    return [Number(c0 >> 32n), Number(c0 & 0xFFFFFFFFn),
            Number(c1 >> 32n), Number(c1 & 0xFFFFFFFFn)];
}

// ── Composition ───────────────────────────────────────────────────────────────

function compositionQM31(evals, compAlpha) {
    let r = 0n, ap = QM31_ONE;
    for (const e of evals) { r = qm31add(r, qm31mul(ap, e)); ap = qm31mul(ap, compAlpha); }
    return r;
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

function constantTreeRoot(leafHash, depth) {
    let node = leafHash;
    for (let i = 0; i < depth; i++) node = hashPair(node, node);
    return node;
}

// Build the Merkle root of an array of QM31 evaluations.
// Mirrors the contract's non-constant last-layer path.
function buildLastLayerRoot(coeffs) {
    const leaves = coeffs.map(c => hashLeaf(qm31ToWords(c)));
    const levels = buildTree([...leaves]);
    return levels[levels.length - 1][0];
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

// VFRI3 uses uint128[] (array) not uint128 (scalar) for lastLayerCoeffs.
function encodeHints(hints, lastLayerCoeffs, oodsPos, oodsNeg, friLayerRoots, overrides = {}) {
    const tuples = hints.map(h => hintTuple({ ...h, ...overrides }));
    return ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint128[]", "uint128[]", "uint128[]", "bytes32[]", HINT_TUPLE + "[]"],
        [lastLayerCoeffs.map(v => v), oodsPos.map(v => v), oodsNeg.map(v => v), friLayerRoots, tuples]
    );
}
function encodeSingle(hint, lastLayerCoeffs, oodsPos, oodsNeg, friLayerRoots, overrides = {}) {
    return encodeHints([hint], lastLayerCoeffs, oodsPos, oodsNeg, friLayerRoots, overrides);
}

// ── Parametric VFRI3 fixture builder ─────────────────────────────────────────
//
// Uses zero polynomial (all trace values = 0). All fold values = 0.
// Last layer: lastLayerCoeffs = Array(lastLayerSize).fill(0n).
//
// For treeDepth=T, numFolds=K: lastLayerSize = 2^(T-K).
// When lastLayerSize == 1: single-element constant path (same as VFRI2).
// When lastLayerSize > 1: non-constant path, but all values happen to be 0.
//
function buildVFRI3Fixture(treeDepth, numFolds) {
    const N     = 1 << treeDepth;
    const nCols = 2;

    const cols = Array.from({length: nCols}, () => Array(N).fill(0));

    // ── Trace tree ──────────────────────────────────────────────────────────
    const traceLeaves = Array.from({length: N}, (_, i) => hashLeaf(cols.map(c => c[i])));
    const traceLevels = buildTree(traceLeaves);
    const traceRoot   = traceLevels[traceLevels.length - 1][0];

    // ── Channel ──────────────────────────────────────────────────────────────
    const chan = chInit();
    chMixRoot(chan, Buffer.from(traceRoot.slice(2), "hex"));
    const z_x = chFelt(chan);

    const oodsEvalsPos = cols.map(() => 0n);
    const oodsEvalsNeg = cols.map(() => 0n);
    chMixU32s(chan, oodsEvalsPos.flatMap(qm31ToWords));
    chMixU32s(chan, oodsEvalsNeg.flatMap(qm31ToWords));

    const compAlpha = chFelt(chan);
    const friAlpha  = chFelt(chan);

    // ── Circle fold (all zero) ────────────────────────────────────────────────
    const allData = [];
    for (let idx = 0; idx < N; idx++) {
        const antiIdx = antipodalOf(idx, treeDepth);
        const qv    = cols.map(c => c[idx]);
        const qvNeg = cols.map(c => c[antiIdx]);
        const [qpX, qpY] = cosetAt(treeDepth, idx);
        allData.push({ fPlus: 0n, fMinus: 0n, foldedValue: 0n, qpX, qpY, qv, qvNeg });
    }

    // FRI L1 tree: all zero
    const l1Leaf    = hashLeaf(qm31ToWords(0n));
    const friL1Levels = buildTree(Array(N).fill(l1Leaf));
    const friLayer1Root = friL1Levels[friL1Levels.length - 1][0];

    // ── K line-fold rounds (all zero) ─────────────────────────────────────────
    const foldedLayers = [Array(N).fill(0n)];
    const layerLevels  = [friL1Levels];
    const layerRoots   = [friLayer1Root];
    const friAlphas    = [];

    chMixRoot(chan, Buffer.from(friLayer1Root.slice(2), "hex"));

    for (let k = 0; k < numFolds; k++) {
        const alpha     = chFelt(chan);
        friAlphas.push(alpha);
        const layerSize = foldedLayers[k].length >> 1;
        const newLayer  = Array(layerSize).fill(0n);
        const lLeaf     = hashLeaf(qm31ToWords(0n));
        const levels    = buildTree(Array(layerSize).fill(lLeaf));
        const root      = levels[levels.length - 1][0];
        foldedLayers.push(newLayer);
        layerLevels.push(levels);
        layerRoots.push(root);
        chMixRoot(chan, Buffer.from(root.slice(2), "hex"));
    }

    // ── Last layer coefficients ───────────────────────────────────────────────
    const lastLayerSize   = foldedLayers[numFolds].length; // 2^(treeDepth - numFolds)
    const lastLayerCoeffs = Array(lastLayerSize).fill(0n); // all zero for zero polynomial

    // Sanity: verify last layer root matches layerRoots[numFolds]
    const computedLastRoot = buildLastLayerRoot(lastLayerCoeffs);
    if (computedLastRoot !== layerRoots[numFolds]) {
        throw new Error("Last layer root mismatch in fixture");
    }

    const friLayerRoots  = layerRoots;
    const nQueries       = 2;
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
            const sibIdx    = (curIdx < layerSize) ? curIdx + layerSize : curIdx - layerSize;
            const newIdx    = curIdx & (layerSize - 1);
            const { siblings: siblingProof } = proofPath(layerLevels[k], sibIdx);
            const { siblings: merkleProof }  = proofPath(layerLevels[k + 1], newIdx);
            folds.push({ siblingValue: 0n, siblingProof, foldedValue: 0n, merkleProof });
            curIdx = newIdx;
        }

        return {
            traceRoot: traceRoot_,
            queryValues: qv, queryValuesNeg: qvNeg,
            queryIdx: idx, treeDepth, siblings, siblingsNeg,
            friAlpha, fPlus, fMinus, foldedValue, qpX, qpY,
            friL1Siblings, folds,
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
        traceRoot, treeDepth, numFolds, lastLayerSize,
        traceLevels, cols,
        oodsEvalsPos, oodsEvalsNeg,
        z_x, compAlpha, friAlpha, friAlphas,
        derivedIndices, hints,
        allData, foldedLayers, layerLevels, layerRoots,
        friLayerRoots, lastLayerCoeffs,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

describe("QLSAVerifierVFRI3", function () {
    let verifier;

    before(async function () {
        const F = await ethers.getContractFactory("QLSAVerifierVFRI3");
        verifier = await F.deploy();
    });

    // ── Constants ─────────────────────────────────────────────────────────────

    it("MIN_PROOF_LENGTH == 700",           async () => expect(await verifier.MIN_PROOF_LENGTH()).to.equal(700n));
    it("MAX_PROOF_LENGTH == 1 MiB",         async () => expect(await verifier.MAX_PROOF_LENGTH()).to.equal(1_048_576n));
    it("MIN_QUERIES == 1",                  async () => expect(await verifier.MIN_QUERIES()).to.equal(1n));
    it("MAX_QUERIES == 64",                 async () => expect(await verifier.MAX_QUERIES()).to.equal(64n));
    it("MAX_FOLD_ROUNDS == 28",             async () => expect(await verifier.MAX_FOLD_ROUNDS()).to.equal(28n));
    it("MAX_LAST_LAYER_SIZE == 65536",      async () => expect(await verifier.MAX_LAST_LAYER_SIZE()).to.equal(65536n));

    // ── treeDepth=2, numFolds=1, lastLayerSize=2 (non-constant path) ──────────

    describe("treeDepth=2, numFolds=1, lastLayerSize=2", function () {
        let f;
        before(() => { f = buildVFRI3Fixture(2, 1); });

        it("lastLayerSize is 2", function () {
            expect(f.lastLayerSize).to.equal(2);
            expect(f.lastLayerCoeffs.length).to.equal(2);
        });

        it("accepts valid 2-query proof with multi-element last layer", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("accepts valid 1-query proof", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeSingle(f.hints[0], f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("also accepts using constant path [0n] when last layer is all-zero", async function () {
            // Single-element constant path: [0n] is valid when all evals = 0
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, [0n], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects lastLayerCoeffs with wrong number of elements", async function () {
            // 3 elements for lastLayerSize=2 — not a power of two matching lastDepth=1
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, [0n, 0n, 0n], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects wrong lastLayerCoeffs (one non-zero element)", async function () {
            const wrong = [qm31fromM31(7n), 0n]; // first element non-zero → wrong root
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, wrong, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects both elements non-zero but equal (not matching zero polynomial)", async function () {
            const v = qm31fromM31(42n);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, [v, v], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("JS last-layer root matches friLayerRoots[K] for all-zero coeffs", function () {
            const computedRoot = buildLastLayerRoot(f.lastLayerCoeffs);
            expect(computedRoot).to.equal(f.friLayerRoots[f.numFolds]);
        });

        it("constant-tree root matches last-layer root when all coeffs are equal", function () {
            // For all-zero last layer, constant-tree and multi-leaf tree give same root
            const leafHash   = hashLeaf(qm31ToWords(0n));
            const constRoot  = constantTreeRoot(leafHash, f.treeDepth - f.numFolds);
            const multiRoot  = buildLastLayerRoot(f.lastLayerCoeffs);
            expect(constRoot).to.equal(multiRoot);
        });

        it("non-constant all-zero array is accepted under non-constant path", async function () {
            // Explicitly force non-constant code path with 2-element all-zero array
            const nonConstCoeffs = [0n, 0n];
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, nonConstCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects empty lastLayerCoeffs", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, [], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects tampered FRI layer root at index K", async function () {
            const badRoots = [...f.friLayerRoots];
            badRoots[f.numFolds] = "0x" + "ab".repeat(32);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, badRoots)
            )).to.be.false;
        });
    });

    // ── treeDepth=3, numFolds=1, lastLayerSize=4 (deeper non-constant) ────────

    describe("treeDepth=3, numFolds=1, lastLayerSize=4", function () {
        let f;
        before(() => { f = buildVFRI3Fixture(3, 1); });

        it("lastLayerSize is 4", function () {
            expect(f.lastLayerSize).to.equal(4);
            expect(f.lastLayerCoeffs.length).to.equal(4);
        });

        it("accepts valid 2-query proof with 4-element last layer", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("accepts constant-path [0n] for same fixture (optimization)", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, [0n], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects 2-element array (wrong size for lastDepth=2)", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, [0n, 0n], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects one tampered element", async function () {
            const wrong = [...f.lastLayerCoeffs];
            wrong[2] = qm31fromM31(1n);
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, wrong, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });
    });

    // ── treeDepth=3, numFolds=2, lastLayerSize=2 ──────────────────────────────

    describe("treeDepth=3, numFolds=2, lastLayerSize=2", function () {
        let f;
        before(() => { f = buildVFRI3Fixture(3, 2); });

        it("lastLayerSize is 2", function () {
            expect(f.lastLayerSize).to.equal(2);
        });

        it("accepts valid 2-query proof", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects wrong constant", async function () {
            const wrong = [qm31fromM31(99n), qm31fromM31(99n)];
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, wrong, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects mismatched Fiat-Shamir alpha", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots,
                    { friAlpha: 0xdeadn })
            )).to.be.false;
        });

        it("rejects wrong query index", async function () {
            const badHints = f.hints.map((h, i) => ({ ...h, queryIdx: (h.queryIdx + 1) & ((1 << f.treeDepth) - 1) }));
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(badHints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });
    });

    // ── treeDepth=4, numFolds=3, lastLayerSize=2 ──────────────────────────────

    describe("treeDepth=4, numFolds=3, lastLayerSize=2", function () {
        let f;
        before(() => { f = buildVFRI3Fixture(4, 3); });

        it("lastLayerSize is 2", function () {
            expect(f.lastLayerSize).to.equal(2);
        });

        it("accepts valid 2-query proof with 3 fold rounds", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.true;
        });

        it("rejects lastLayerCoeffs of size 4 when lastDepth=1", async function () {
            // lastDepth = 4-3 = 1, so size must be 2 (not 4)
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, [0n, 0n, 0n, 0n], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });
    });

    // ── Input validation ──────────────────────────────────────────────────────

    describe("input validation", function () {
        let f;
        before(() => { f = buildVFRI3Fixture(2, 1); });

        it("rejects proof too short", async function () {
            expect(await verifier.verify(
                "0x" + "aa".repeat(699), f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects zero commitment", async function () {
            expect(await verifier.verify(
                f.proof, "0x00000000000000000000000000000000", f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects zero merkleRoot", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, "0x" + "00".repeat(32),
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects tampered proof (wrong commitment)", async function () {
            const badProof = "0x" + "ff".repeat(700);
            expect(await verifier.verify(
                badProof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects wrong embedded root (proof bytes 8..40)", async function () {
            const badProof = Buffer.from(f.proof.slice(2), "hex");
            const h = Buffer.from(blake2s(Buffer.concat([badProof.subarray(0, 32), Buffer.from(f.merkleRoot.slice(2), "hex")])));
            const badCommitment = "0x" + h.subarray(0, 16).toString("hex");
            badProof.fill(0xcc, 8, 40);
            expect(await verifier.verify(
                "0x" + badProof.toString("hex"), badCommitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects friLayerRoots.length < 2", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, [f.friLayerRoots[0]])
            )).to.be.false;
        });

        it("rejects mismatched OODS eval array length", async function () {
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs,
                    [...f.oodsEvalsPos, 0n], f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });
    });

    // ── Fiat-Shamir enforcement ────────────────────────────────────────────────

    describe("Fiat-Shamir enforcement", function () {
        let f;
        before(() => { f = buildVFRI3Fixture(3, 2); });

        it("rejects wrong embedded root", async function () {
            const altRoot = "0x" + "1234".repeat(16);
            const bad = [...f.friLayerRoots];
            bad[0] = altRoot;
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, bad)
            )).to.be.false;
        });

        it("rejects swapped friLayerRoots", async function () {
            if (f.friLayerRoots.length < 3) return;
            const bad = [...f.friLayerRoots];
            [bad[1], bad[2]] = [bad[2], bad[1]];
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, bad)
            )).to.be.false;
        });

        it("rejects wrong OODS evals (breaks channel derivation)", async function () {
            const badPos = f.oodsEvalsPos.map(v => qm31fromM31(1n));
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(f.hints, f.lastLayerCoeffs, badPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });
    });

    // ── Trace Merkle enforcement ──────────────────────────────────────────────

    describe("trace Merkle enforcement", function () {
        let f;
        before(() => { f = buildVFRI3Fixture(2, 1); });

        it("rejects tampered query values", async function () {
            const badHints = f.hints.map(h => ({ ...h, queryValues: h.queryValues.map(v => (v + 1) % 100) }));
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(badHints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });

        it("rejects tampered Merkle siblings", async function () {
            const badHints = f.hints.map(h => ({
                ...h,
                siblings: h.siblings.map(s => "0x" + Buffer.from(s.slice(2), "hex").map(b => b ^ 0xff).toString("hex"))
            }));
            expect(await verifier.verify(
                f.proof, f.commitment, f.merkleRoot,
                encodeHints(badHints, f.lastLayerCoeffs, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayerRoots)
            )).to.be.false;
        });
    });
});
