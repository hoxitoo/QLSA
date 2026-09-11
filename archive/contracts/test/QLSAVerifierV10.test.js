const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { blake2s } = require("@noble/hashes/blake2.js");

// ─────────────────────────────────────────────────────────────────────────────
// QLSAVerifierV10 — FRI layer 1 decommitment
//
// New compared to V9: the prover commits all circle-fold outputs in a Merkle
// tree (friLayer1Root, N = 2^treeDepth leaves), and each query's foldedValue
// must be Merkle-provable in that tree at position queryIndex.
//
// Fixture derivation order (V10 transcript):
//   1.  Build trace tree → traceRoot
//   2.  chan.init() → mixRoot(traceRoot) → z_x = drawSecureFelt()
//   3.  Choose oodsEvalsPos / oodsEvalsNeg
//   4.  chan.mixU32s(oodsEvalsPos) → mixU32s(oodsEvalsNeg)
//   5.  compAlpha = drawSecureFelt();  friAlpha = drawSecureFelt()
//   6.  For EACH of the N circle positions: compute foldedValue (full domain)
//   7.  Build FRI layer 1 Merkle tree from all N foldedValues → friLayer1Root
//   8.  chan.mixRoot(friLayer1Root)         ← NEW vs V9
//   9.  derivedIndices = drawQueries(treeDepth, N)
//   10. For each derived idx: build hint with Merkle proof in both trace tree
//       and FRI layer 1 tree.
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

// QM31 → [c0.re, c0.im, c1.re, c1.im] as uint32 Numbers
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

// ── Circle fold ───────────────────────────────────────────────────────────────

function circleFold(fPlus, fMinus, alpha, yInv) {
    return qm31add(qm31add(fPlus, fMinus),
                   qm31mul(alpha, qm31scaleM31(qm31sub(fPlus, fMinus), yInv)));
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

// ── V10 hint encoding (14-field struct, adds friL1Siblings) ───────────────────

const HINT_TUPLE = "tuple(bytes32,uint32[],uint32[],uint256,uint256,bytes32[],bytes32[],uint128,uint128,uint128,uint128,uint256,uint256,bytes32[])";

function hintTuple(h) {
    return [h.traceRoot, h.queryValues, h.queryValuesNeg,
            h.queryIdx, h.treeDepth, h.siblings, h.siblingsNeg,
            h.friAlpha, h.fPlus, h.fMinus, h.foldedValue, h.qpX, h.qpY,
            h.friL1Siblings];
}

function encodeHints(hints, oodsPos, oodsNeg, friLayer1Root, overrides = {}) {
    const tuples = hints.map(h => hintTuple({ ...h, ...overrides }));
    return ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint128[]", "uint128[]", "bytes32", HINT_TUPLE + "[]"],
        [oodsPos.map(v => v), oodsNeg.map(v => v), friLayer1Root, tuples]
    );
}
function encodeSingle(hint, oodsPos, oodsNeg, friLayer1Root, overrides = {}) {
    return encodeHints([hint], oodsPos, oodsNeg, friLayer1Root, overrides);
}

// ── V10 fixture builder ────────────────────────────────────────────────────────
//
// Computes foldedValues for ALL N = 2^treeDepth circle positions to build the
// complete FRI layer 1 Merkle tree.  Query indices are derived only AFTER
// friLayer1Root is mixed into the channel.

function buildV10Fixture() {
    const treeDepth = 3;
    const N         = 1 << treeDepth;   // 8 circle-domain positions

    // Column values at every position.
    const colA = [100, 200, 300, 400, 500, 600, 700, 800];
    const colB = [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000];

    // ── Trace Merkle tree ──────────────────────────────────────────────────
    const traceLeaves = Array.from({length: N}, (_, i) => hashLeaf([colA[i], colB[i]]));
    const traceLevels = buildTree(traceLeaves);
    const traceRoot   = traceLevels[traceLevels.length - 1][0];

    // ── Channel: up to friAlpha (does NOT include friLayer1Root yet) ───────
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

    // ── Full-domain OODS quotient + circle fold ────────────────────────────
    // Compute foldedValue for EVERY circle position (prover evaluates the
    // entire domain so it can commit the result in a Merkle tree).
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

    // ── FRI layer 1 Merkle tree ────────────────────────────────────────────
    // Each leaf j: Blake2s(qm31Words(foldedValue[j])).
    const friL1Leaves = allData.map(d => hashLeaf(qm31ToWords(d.foldedValue)));
    const friL1Levels = buildTree(friL1Leaves);
    const friLayer1Root = friL1Levels[friL1Levels.length - 1][0];

    // ── Channel: absorb friLayer1Root, then draw queries ───────────────────
    chMixRoot(chan, Buffer.from(friLayer1Root.slice(2), "hex"));
    const derivedIndices = chQueries(chan, treeDepth, 2);

    // ── Build per-query hints ──────────────────────────────────────────────
    const hints = derivedIndices.map(idx => {
        const antiIdx = antipodalOf(idx, treeDepth);
        const { root: traceRoot_, siblings }    = proofPath(traceLevels, idx);
        const { siblings: siblingsNeg }         = proofPath(traceLevels, antiIdx);
        const { siblings: friL1Siblings }       = proofPath(friL1Levels, idx);  // ← NEW

        const { fPlus, fMinus, foldedValue, qpX, qpY, qv, qvNeg } = allData[idx];

        return {
            traceRoot: traceRoot_, queryValues: qv, queryValuesNeg: qvNeg,
            queryIdx: idx, treeDepth, siblings, siblingsNeg,
            friAlpha, fPlus, fMinus, foldedValue, qpX, qpY,
            friL1Siblings,
        };
    });

    // ── Proof + commitment ─────────────────────────────────────────────────
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
        z_x, compAlpha, friAlpha, oodsComboPos, oodsComboNeg,
        derivedIndices, hints, allData,
        friLayer1Root, friL1Levels,
    };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("QLSAVerifierV10", function () {
    let verifier;
    let f;

    before(async function () {
        const F = await ethers.getContractFactory("QLSAVerifierV10");
        verifier = await F.deploy();
        f = buildV10Fixture();
    });

    // ── Constants ─────────────────────────────────────────────────────────────

    it("MIN_PROOF_LENGTH == 700", async () => expect(await verifier.MIN_PROOF_LENGTH()).to.equal(700n));
    it("MAX_PROOF_LENGTH == 1 MiB", async () => expect(await verifier.MAX_PROOF_LENGTH()).to.equal(1_048_576n));
    it("MIN_QUERIES == 1", async () => expect(await verifier.MIN_QUERIES()).to.equal(1n));
    it("MAX_QUERIES == 64", async () => expect(await verifier.MAX_QUERIES()).to.equal(64n));

    // ── Valid paths ───────────────────────────────────────────────────────────

    it("accepts valid 2-query batch with FRI layer 1 decommitment", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root)
        )).to.be.true;
    });

    it("accepts valid 1-query batch (first derived index)", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root)
        )).to.be.true;
    });

    // ── FRI layer 1 decommitment enforcement ─────────────────────────────────

    it("rejects zero friLayer1Root", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, "0x"+"00".repeat(32))
        )).to.be.false;
    });

    it("rejects wrong friLayer1Siblings (tampered Merkle proof)", async function () {
        const badSiblings = f.hints[0].friL1Siblings.map(() => "0x"+"ab".repeat(32));
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root,
                         { friL1Siblings: badSiblings })
        )).to.be.false;
    });

    it("rejects tampered foldedValue (FRI layer 1 Merkle fails)", async function () {
        const wrong = (BigInt(f.hints[0].foldedValue) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root,
                         { foldedValue: wrong })
        )).to.be.false;
    });

    it("rejects wrong friLayer1Root (correct siblings but wrong root)", async function () {
        // Use siblings from query 0's Merkle proof but a different root — mismatch.
        const wrongRoot = "0x"+"cc".repeat(32);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, wrongRoot)
        )).to.be.false;
    });

    it("rejects wrong friLayer1Root (friLayer1Root changes query indices → wrong queryIndex)", async function () {
        // Swap in query 1's friL1Root siblings for query 0 — root is wrong AND
        // query indices change when friLayer1Root changes the channel.
        const altLeaves = [...f.friL1Levels[0]];
        altLeaves[f.derivedIndices[0]] = "0x"+"ff".repeat(32);  // tamper one leaf
        const altLevels = buildTree(altLeaves);
        const altRoot   = altLevels[altLevels.length - 1][0];
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, f.oodsEvalsPos, f.oodsEvalsNeg, altRoot)
        )).to.be.false;
    });

    // ── OODS quotient enforcement (inherited from V9) ─────────────────────────

    it("rejects when oodsEvalsPos tampered (compAlpha changes → OODS check fails)", async function () {
        const badPos = [qm31fromM31(999n), qm31fromM31(888n)];
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, badPos, f.oodsEvalsNeg, f.friLayer1Root)
        )).to.be.false;
    });

    it("rejects when oodsEvalsNeg tampered", async function () {
        const badNeg = [qm31fromM31(777n), qm31fromM31(666n)];
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints(f.hints, f.oodsEvalsPos, badNeg, f.friLayer1Root)
        )).to.be.false;
    });

    it("rejects tampered fPlus (OODS quotient check fails)", async function () {
        const wrong = (BigInt(f.hints[0].fPlus) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root,
                         { fPlus: wrong })
        )).to.be.false;
    });

    it("rejects tampered fMinus (OODS quotient check fails)", async function () {
        const wrong = (BigInt(f.hints[0].fMinus) + 1n) % (1n << 128n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root,
                         { fMinus: wrong })
        )).to.be.false;
    });

    it("rejects tampered queryValues (composition → OODS check fails)", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root,
                         { queryValues: [9999, 8888] })
        )).to.be.false;
    });

    it("rejects tampered queryValuesNeg (antipodal composition fails)", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root,
                         { queryValuesNeg: [9999, 8888] })
        )).to.be.false;
    });

    it("rejects empty oodsEvalsPos array", async function () {
        const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
            ["uint128[]", "uint128[]", "bytes32", HINT_TUPLE + "[]"],
            [[], f.oodsEvalsNeg.map(v=>v), f.friLayer1Root, [hintTuple(f.hints[0])]]
        );
        expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, encoded)).to.be.false;
    });

    it("rejects mismatched oodsEvalsPos/Neg lengths", async function () {
        const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
            ["uint128[]", "uint128[]", "bytes32", HINT_TUPLE + "[]"],
            [f.oodsEvalsPos.map(v=>v), [f.oodsEvalsNeg[0]], f.friLayer1Root, [hintTuple(f.hints[0])]]
        );
        expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, encoded)).to.be.false;
    });

    // ── Fiat-Shamir enforcement (inherited) ───────────────────────────────────

    it("rejects wrong friAlpha", async function () {
        const wrongAlpha = qm31fromM31(9999n);
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root,
                         { friAlpha: wrongAlpha })
        )).to.be.false;
    });

    it("rejects non-derived queryIndex", async function () {
        const wrongIdx = (f.derivedIndices[0] + 1) & ((1 << f.treeDepth) - 1);
        const antiIdx  = antipodalOf(wrongIdx, f.treeDepth);
        const { root: tr, siblings }    = proofPath(f.traceLevels, wrongIdx);
        const { siblings: siblingsNeg } = proofPath(f.traceLevels, antiIdx);
        const { siblings: friL1Siblings } = proofPath(f.friL1Levels, wrongIdx);
        const { fPlus, fMinus, foldedValue, qpX, qpY, qv, qvNeg } = f.allData[wrongIdx];
        const bad = { traceRoot: tr, queryValues: qv, queryValuesNeg: qvNeg,
                      queryIdx: wrongIdx, treeDepth: f.treeDepth, siblings, siblingsNeg,
                      friAlpha: f.friAlpha, fPlus, fMinus, foldedValue, qpX, qpY, friL1Siblings };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(bad, f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root)
        )).to.be.false;
    });

    it("rejects hints with mismatched treeDepths", async function () {
        const bad = { ...f.hints[1], treeDepth: f.treeDepth + 1 };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints([f.hints[0], bad], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root)
        )).to.be.false;
    });

    // ── Proof-level rejections ────────────────────────────────────────────────

    it("rejects proof shorter than MIN_PROOF_LENGTH", async function () {
        expect(await verifier.verify(
            "0x"+"01".repeat(699), f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root)
        )).to.be.false;
    });

    it("rejects zero commitment", async function () {
        expect(await verifier.verify(
            f.proof, "0x"+"00".repeat(16), f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root)
        )).to.be.false;
    });

    it("rejects zero merkleRoot", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, "0x"+"00".repeat(32),
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root)
        )).to.be.false;
    });

    it("rejects empty queryHints bytes", async function () {
        expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, "0x")).to.be.false;
    });

    it("rejects empty hints array", async function () {
        const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
            ["uint128[]", "uint128[]", "bytes32", HINT_TUPLE + "[]"],
            [f.oodsEvalsPos.map(v=>v), f.oodsEvalsNeg.map(v=>v), f.friLayer1Root, []]
        );
        expect(await verifier.verify(f.proof, f.commitment, f.merkleRoot, encoded)).to.be.false;
    });

    it("rejects tampered proof header (commitment mismatch)", async function () {
        const t = Buffer.from(f.proof.slice(2), "hex"); t[5] ^= 0xff;
        expect(await verifier.verify(
            "0x"+t.toString("hex"), f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root)
        )).to.be.false;
    });

    // ── Per-query Merkle rejections (inherited) ───────────────────────────────

    it("rejects wrong traceRoot in hint", async function () {
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root,
                         { traceRoot: "0x"+"aa".repeat(32) })
        )).to.be.false;
    });

    it("rejects wrong trace Merkle siblings (Merkle fail)", async function () {
        const badSibs = f.hints[0].siblings.map(() => "0x"+"bb".repeat(32));
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeSingle(f.hints[0], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root,
                         { siblings: badSibs })
        )).to.be.false;
    });

    it("rejects 2-query batch when second hint has wrong fPlus", async function () {
        const wrong = (BigInt(f.hints[1].fPlus) + 1n) % (1n << 128n);
        const bad   = { ...f.hints[1], fPlus: wrong };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints([f.hints[0], bad], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root)
        )).to.be.false;
    });

    it("rejects 2-query batch when second hint has wrong friL1Siblings", async function () {
        const badSibs = f.hints[1].friL1Siblings.map(() => "0x"+"ee".repeat(32));
        const bad     = { ...f.hints[1], friL1Siblings: badSibs };
        expect(await verifier.verify(
            f.proof, f.commitment, f.merkleRoot,
            encodeHints([f.hints[0], bad], f.oodsEvalsPos, f.oodsEvalsNeg, f.friLayer1Root)
        )).to.be.false;
    });
});
