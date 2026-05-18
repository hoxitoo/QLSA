const { expect } = require("chai");
const { ethers }  = require("hardhat");

// ── M31 / CM31 / QM31 arithmetic reference ────────────────────────────────────

const P = 2_147_483_647n;

function m31mul(a, b) { return (a * b) % P; }
function m31add(a, b) { const r = (a + b) % P; return r < 0n ? r + P : r; }
function m31sub(a, b) { return ((a - b) % P + P) % P; }
function m31pow(a, e) {
    let r = 1n; a = a % P;
    while (e > 0n) { if (e & 1n) r = m31mul(r, a); a = m31mul(a, a); e >>= 1n; }
    return r;
}
function m31inv(a) { return m31pow(a, P - 2n); }

// CM31 packed as BigInt uint64: (re << 32) | im
function cm31(re, im)    { return (BigInt(re) << 32n) | BigInt(im); }
function cm31re(x)       { return x >> 32n; }
function cm31im(x)       { return x & 0xFFFFFFFFn; }
function cm31add(x, y)   { return cm31(m31add(cm31re(x), cm31re(y)), m31add(cm31im(x), cm31im(y))); }
function cm31sub(x, y)   { return cm31(m31sub(cm31re(x), cm31re(y)), m31sub(cm31im(x), cm31im(y))); }
function cm31mul(x, y) {
    const a = cm31re(x), b = cm31im(x), c = cm31re(y), d = cm31im(y);
    return cm31(m31sub(m31mul(a,c), m31mul(b,d)), m31add(m31mul(a,d), m31mul(b,c)));
}
function cm31scale(x, s) { return cm31(m31mul(cm31re(x), BigInt(s)), m31mul(cm31im(x), BigInt(s))); }

// QM31 packed as BigInt uint128: (c0 << 64) | c1 where c0, c1 are CM31 (uint64)
const CM31_R = cm31(2, 1); // R = 2 + i in CM31
function qm31(c0, c1)   { return (BigInt(c0) << 64n) | BigInt(c1); }
function qm31c0(q)       { return (q >> 64n) & 0xFFFFFFFFFFFFFFFFn; }
function qm31c1(q)       { return q & 0xFFFFFFFFFFFFFFFFn; }
function qm31fromWords([a, b, c, d]) {
    return qm31(cm31(a, b), cm31(c, d));
}
function qm31toWords(q) {
    const c0 = qm31c0(q), c1 = qm31c1(q);
    return [cm31re(c0), cm31im(c0), cm31re(c1), cm31im(c1)];
}
function qm31add(x, y) { return qm31(cm31add(qm31c0(x), qm31c0(y)), cm31add(qm31c1(x), qm31c1(y))); }
function qm31sub(x, y) { return qm31(cm31sub(qm31c0(x), qm31c0(y)), cm31sub(qm31c1(x), qm31c1(y))); }
function qm31mul(x, y) {
    // (a + bu)(c + du) = ac + R*bd + (ad + bc)u  where R = 2+i
    const a = qm31c0(x), b = qm31c1(x), c = qm31c0(y), d = qm31c1(y);
    return qm31(
        cm31add(cm31mul(a, c), cm31mul(CM31_R, cm31mul(b, d))),
        cm31add(cm31mul(a, d), cm31mul(b, c))
    );
}
function qm31scaleM31(x, s) {
    const sn = BigInt(s);
    return qm31(cm31scale(qm31c0(x), sn), cm31scale(qm31c1(x), sn));
}

// ── Circle group reference ────────────────────────────────────────────────────

const GEN_X = 2n;
const GEN_Y = 1268011823n;

function circleAdd(x1, y1, x2, y2) {
    return [m31sub(m31mul(x1, x2), m31mul(y1, y2)), m31add(m31mul(x1, y2), m31mul(x2, y1))];
}
function circleDouble(x, y) {
    const x2 = m31mul(x, x);
    return [m31sub(m31add(x2, x2), 1n), m31add(m31mul(x, y), m31mul(x, y))];
}
function genMul(scalar) {
    let rx = 1n, ry = 0n;
    let cx = GEN_X, cy = GEN_Y;
    let s = BigInt(scalar) & ((1n << 31n) - 1n);
    while (s > 0n) {
        if (s & 1n) [rx, ry] = circleAdd(rx, ry, cx, cy);
        [cx, cy] = circleDouble(cx, cy);
        s >>= 1n;
    }
    return [rx, ry];
}
function cosetAt(logN, idx) {
    // CanonicCoset::new(logN).at(idx) = Coset::odds(logN).at(idx)
    // initial_index = 2^(30 - logN), step_size = 2^(31 - logN)
    const initialIndex = 1n << BigInt(30 - logN);
    const stepSize     = 1n << BigInt(31 - logN);
    const pointIndex   = (initialIndex + BigInt(idx) * stepSize) & ((1n << 31n) - 1n);
    return genMul(pointIndex);
}
function circleFoldRef(fPlus, fMinus, alpha, yInv) {
    const sum   = qm31add(fPlus, fMinus);
    const diff  = qm31sub(fPlus, fMinus);
    const dScal = qm31scaleM31(diff, yInv);
    return qm31add(sum, qm31mul(alpha, dScal));
}

// ── Rust cross-verification vectors ──────────────────────────────────────────
// From: cargo test test_circle_point -- --nocapture (Stwo 2.2.0)
const RUST = {
    genX:         2n,
    genY:         1268011823n,
    genMul2:      [7n, 777079998n],
    genMul17:     [495401635n, 1386042346n],
    genMul1000:   [2140279415n, 2123398265n],
    coset3_0:     [590768354n, 978592373n],
    coset3_1:     [1168891274n, 1556715293n],
    coset3_2:     [978592373n, 1556715293n],
    coset3_3:     [1556715293n, 978592373n],
    coset14_0:    [1543902459n, 1632329423n],
    coset14_1:    [1338697498n, 1881711368n],
    coset14_7:    [36983955n, 1951442989n],
    // circleFold test with p=coset3_0, f_p=[100,200,300,400], f_neg_p=[50,60,70,80], alpha=[7,11,13,17]
    foldPY:       978592373n,
    foldPYInv:    775648038n,
    foldResult:   [1202636475n, 645531061n, 582137855n, 532843711n],
};

// ── Tests ──────────────────────────────────────────────────────────────────────

describe("CirclePoint library", function () {
    let cp;

    before(async function () {
        const F = await ethers.getContractFactory("CirclePointHarness");
        cp = await F.deploy();
    });

    // ── isOnCircle ────────────────────────────────────────────────────────────

    it("generator G is on the circle", async function () {
        expect(await cp.isOnCircle(RUST.genX, RUST.genY)).to.be.true;
    });

    it("identity (1, 0) is on the circle", async function () {
        expect(await cp.isOnCircle(1, 0)).to.be.true;
    });

    it("(0, 1) is on the circle", async function () {
        expect(await cp.isOnCircle(0, 1)).to.be.true;
    });

    it("(0, 0) is NOT on the circle", async function () {
        expect(await cp.isOnCircle(0, 0)).to.be.false;
    });

    it("coset points are on the circle", async function () {
        for (const [x, y] of Object.values(RUST).filter(v => Array.isArray(v) && v.length === 2)) {
            expect(await cp.isOnCircle(x, y)).to.be.true;
        }
    });

    // ── pointAdd ─────────────────────────────────────────────────────────────

    it("pointAdd identity: P + (1,0) = P", async function () {
        const [rx, ry] = await cp.pointAdd(RUST.genX, RUST.genY, 1n, 0n);
        expect(rx).to.equal(RUST.genX);
        expect(ry).to.equal(RUST.genY);
    });

    it("pointAdd(G, G) == genMul(2) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.pointAdd(RUST.genX, RUST.genY, RUST.genX, RUST.genY);
        expect(rx).to.equal(RUST.genMul2[0]);
        expect(ry).to.equal(RUST.genMul2[1]);
    });

    it("pointAdd commutes", async function () {
        const [x1, y1] = RUST.coset3_0;
        const [x2, y2] = RUST.coset3_1;
        const [rx1, ry1] = await cp.pointAdd(x1, y1, x2, y2);
        const [rx2, ry2] = await cp.pointAdd(x2, y2, x1, y1);
        expect(rx1).to.equal(rx2);
        expect(ry1).to.equal(ry2);
    });

    // ── pointDouble ───────────────────────────────────────────────────────────

    it("pointDouble(G) == genMul(2) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.pointDouble(RUST.genX, RUST.genY);
        expect(rx).to.equal(RUST.genMul2[0]);
        expect(ry).to.equal(RUST.genMul2[1]);
    });

    it("pointDouble equals pointAdd(P, P)", async function () {
        const [x, y] = RUST.coset3_0;
        const [rd1x, rd1y] = await cp.pointDouble(x, y);
        const [ra1x, ra1y] = await cp.pointAdd(x, y, x, y);
        expect(rd1x).to.equal(ra1x);
        expect(rd1y).to.equal(ra1y);
    });

    // ── genMul ────────────────────────────────────────────────────────────────

    it("genMul(0) == identity (1, 0)", async function () {
        const [rx, ry] = await cp.genMul(0);
        expect(rx).to.equal(1n);
        expect(ry).to.equal(0n);
    });

    it("genMul(1) == G [Rust cross-check]", async function () {
        const [rx, ry] = await cp.genMul(1);
        expect(rx).to.equal(RUST.genX);
        expect(ry).to.equal(RUST.genY);
    });

    it("genMul(2) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.genMul(2);
        expect(rx).to.equal(RUST.genMul2[0]);
        expect(ry).to.equal(RUST.genMul2[1]);
    });

    it("genMul(17) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.genMul(17);
        expect(rx).to.equal(RUST.genMul17[0]);
        expect(ry).to.equal(RUST.genMul17[1]);
    });

    it("genMul(1000) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.genMul(1000);
        expect(rx).to.equal(RUST.genMul1000[0]);
        expect(ry).to.equal(RUST.genMul1000[1]);
    });

    it("genMul(n) is on the circle for arbitrary n", async function () {
        for (const n of [5, 100, 999999]) {
            const [rx, ry] = await cp.genMul(n);
            expect(await cp.isOnCircle(rx, ry)).to.be.true;
        }
    });

    it("genMul matches JS reference", async function () {
        for (const s of [3, 42, 12345]) {
            const [jx, jy] = genMul(s);
            const [rx, ry] = await cp.genMul(s);
            expect(rx).to.equal(jx);
            expect(ry).to.equal(jy);
        }
    });

    // ── cosetAt ───────────────────────────────────────────────────────────────

    it("cosetAt(3, 0) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.cosetAt(3, 0);
        expect(rx).to.equal(RUST.coset3_0[0]);
        expect(ry).to.equal(RUST.coset3_0[1]);
    });

    it("cosetAt(3, 1) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.cosetAt(3, 1);
        expect(rx).to.equal(RUST.coset3_1[0]);
        expect(ry).to.equal(RUST.coset3_1[1]);
    });

    it("cosetAt(3, 2) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.cosetAt(3, 2);
        expect(rx).to.equal(RUST.coset3_2[0]);
        expect(ry).to.equal(RUST.coset3_2[1]);
    });

    it("cosetAt(3, 3) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.cosetAt(3, 3);
        expect(rx).to.equal(RUST.coset3_3[0]);
        expect(ry).to.equal(RUST.coset3_3[1]);
    });

    it("cosetAt(14, 0) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.cosetAt(14, 0);
        expect(rx).to.equal(RUST.coset14_0[0]);
        expect(ry).to.equal(RUST.coset14_0[1]);
    });

    it("cosetAt(14, 1) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.cosetAt(14, 1);
        expect(rx).to.equal(RUST.coset14_1[0]);
        expect(ry).to.equal(RUST.coset14_1[1]);
    });

    it("cosetAt(14, 7) [Rust cross-check]", async function () {
        const [rx, ry] = await cp.cosetAt(14, 7);
        expect(rx).to.equal(RUST.coset14_7[0]);
        expect(ry).to.equal(RUST.coset14_7[1]);
    });

    it("cosetAt matches JS reference", async function () {
        for (const [logN, idx] of [[3, 0], [3, 2], [5, 1], [14, 5]]) {
            const [jx, jy] = cosetAt(logN, idx);
            const [rx, ry] = await cp.cosetAt(logN, idx);
            expect(rx).to.equal(jx, `cosetAt(${logN},${idx}) x`);
            expect(ry).to.equal(jy, `cosetAt(${logN},${idx}) y`);
        }
    });

    it("all coset points are on the circle", async function () {
        for (const [logN, idx] of [[3, 0], [3, 1], [14, 0], [14, 7]]) {
            const [rx, ry] = await cp.cosetAt(logN, idx);
            expect(await cp.isOnCircle(rx, ry)).to.be.true;
        }
    });

    // ── circleFold ────────────────────────────────────────────────────────────

    it("circleFold matches Rust reference (p=coset3_0)", async function () {
        const fPlus   = qm31fromWords([100n, 200n, 300n, 400n]);
        const fMinus  = qm31fromWords([50n, 60n, 70n, 80n]);
        const alpha   = qm31fromWords([7n, 11n, 13n, 17n]);
        const yInv    = RUST.foldPYInv;

        const result = await cp.circleFold(fPlus, fMinus, alpha, yInv);

        const words = qm31toWords(BigInt(result));
        expect(words[0]).to.equal(RUST.foldResult[0]);
        expect(words[1]).to.equal(RUST.foldResult[1]);
        expect(words[2]).to.equal(RUST.foldResult[2]);
        expect(words[3]).to.equal(RUST.foldResult[3]);
    });

    it("circleFold matches JS reference", async function () {
        const fPlus  = qm31fromWords([100n, 200n, 300n, 400n]);
        const fMinus = qm31fromWords([50n, 60n, 70n, 80n]);
        const alpha  = qm31fromWords([7n, 11n, 13n, 17n]);
        const yInv   = RUST.foldPYInv;

        const expected = circleFoldRef(fPlus, fMinus, alpha, yInv);
        const result   = await cp.circleFold(fPlus, fMinus, alpha, yInv);
        expect(BigInt(result)).to.equal(expected);
    });

    it("lineFold has the same formula as circleFold (same implementation)", async function () {
        const fPlus  = qm31fromWords([111n, 222n, 333n, 444n]);
        const fMinus = qm31fromWords([555n, 666n, 777n, 888n]);
        const alpha  = qm31fromWords([9n, 8n, 7n, 6n]);
        const twidInv = 123456789n; // arbitrary M31

        const circle = await cp.circleFold(fPlus, fMinus, alpha, twidInv);
        const line   = await cp.lineFold(fPlus, fMinus, alpha, twidInv);
        expect(BigInt(circle)).to.equal(BigInt(line));
    });

    it("cosetYInv matches M31.inv(coset.y)", async function () {
        const [, y] = await cp.cosetAt(3, 0);
        const yInv  = await cp.cosetYInv(3, 0);
        // Check: y * yInv == 1 (mod P)
        const prod = (BigInt(y) * BigInt(yInv)) % P;
        expect(prod).to.equal(1n);
        expect(BigInt(yInv)).to.equal(RUST.foldPYInv);
    });
});
