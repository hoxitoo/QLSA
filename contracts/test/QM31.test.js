const { expect } = require("chai");
const { ethers }  = require("hardhat");

const P = 2_147_483_647n;

// M31 helpers
function m31add(a, b) { return (a + b) % P; }
function m31sub(a, b) { return ((a - b) % P + P) % P; }
function m31mul(a, b) { return (a * b) % P; }
function m31neg(a)    { return a === 0n ? 0n : P - a; }
function m31pow(a, e) {
    let r = 1n; a = a % P;
    while (e > 0n) { if (e & 1n) r = m31mul(r, a); a = m31mul(a, a); e >>= 1n; }
    return r;
}
function m31inv(a) { return m31pow(a, P - 2n); }

// CM31 helpers
function cm31pack(a, b) { return (a << 32n) | b; }
function cm31re(x) { return x >> 32n; }
function cm31im(x) { return x & 0xFFFFFFFFn; }
function cm31add(x, y) { return cm31pack(m31add(cm31re(x), cm31re(y)), m31add(cm31im(x), cm31im(y))); }
function cm31sub(x, y) { return cm31pack(m31sub(cm31re(x), cm31re(y)), m31sub(cm31im(x), cm31im(y))); }
function cm31mul(x, y) {
    const a = cm31re(x), b = cm31im(x), c = cm31re(y), d = cm31im(y);
    return cm31pack(m31sub(m31mul(a, c), m31mul(b, d)), m31add(m31mul(a, d), m31mul(b, c)));
}
function cm31neg(x) { return cm31pack(m31neg(cm31re(x)), m31neg(cm31im(x))); }

// QM31 helpers: pack two CM31 as uint128
const R = cm31pack(2n, 1n); // 2 + i
function qm31pack(c0, c1) { return (BigInt(c0) << 64n) | BigInt(c1); }
function qm31c0(q) { return (q >> 64n) & 0xFFFFFFFFFFFFFFFFn; }
function qm31c1(q) { return q & 0xFFFFFFFFFFFFFFFFn; }
function qm31add(x, y) { return qm31pack(cm31add(qm31c0(x), qm31c0(y)), cm31add(qm31c1(x), qm31c1(y))); }
function qm31sub(x, y) { return qm31pack(cm31sub(qm31c0(x), qm31c0(y)), cm31sub(qm31c1(x), qm31c1(y))); }
function qm31mul(x, y) {
    const a = qm31c0(x), b = qm31c1(x), c = qm31c0(y), d = qm31c1(y);
    const r0 = cm31add(cm31mul(a, c), cm31mul(R, cm31mul(b, d)));
    const r1 = cm31add(cm31mul(a, d), cm31mul(b, c));
    return qm31pack(r0, r1);
}

describe("QM31 library", function () {
    let h;

    before(async function () {
        const F = await ethers.getContractFactory("QM31Harness");
        h = await F.deploy();
    });

    it("R constant == CM31(2,1)", async function () {
        expect(await h.R()).to.equal(cm31pack(2n, 1n));
    });

    it("pack/c0/c1 round-trip", async function () {
        const c0 = cm31pack(11n, 22n);
        const c1 = cm31pack(33n, 44n);
        const q  = qm31pack(c0, c1);
        expect(await h.c0(q)).to.equal(c0);
        expect(await h.c1(q)).to.equal(c1);
        expect(await h.pack(c0, c1)).to.equal(q);
    });

    it("fromM31: embeds M31 scalar", async function () {
        const a = 42n;
        const q = await h.fromM31(a);
        expect(qm31c0(q)).to.equal(cm31pack(a, 0n));
        expect(qm31c1(q)).to.equal(0n);
    });

    it("fromCM31: embeds CM31 element", async function () {
        const e = cm31pack(5n, 7n);
        const q = await h.fromCM31(e);
        expect(qm31c0(q)).to.equal(e);
        expect(qm31c1(q)).to.equal(0n);
    });

    it("add: (a+bu) + (c+du) = (a+c)+(b+d)u", async function () {
        const x = qm31pack(cm31pack(1n, 2n), cm31pack(3n, 4n));
        const y = qm31pack(cm31pack(5n, 6n), cm31pack(7n, 8n));
        expect(await h.add(x, y)).to.equal(qm31add(x, y));
    });

    it("sub: basic", async function () {
        const x = qm31pack(cm31pack(10n, 20n), cm31pack(30n, 40n));
        const y = qm31pack(cm31pack(1n, 2n),   cm31pack(3n, 4n));
        expect(await h.sub(x, y)).to.equal(qm31sub(x, y));
    });

    it("mul: 1 is identity", async function () {
        const one = qm31pack(cm31pack(1n, 0n), 0n);
        const x   = qm31pack(cm31pack(3n, 7n), cm31pack(11n, 13n));
        expect(await h.mul(x, one)).to.equal(x);
    });

    it("mul: u*u == R = 2+i (embedded in QM31)", async function () {
        // u = 0 + 1*u = pack(pack(0,0), pack(1,0))
        const u    = qm31pack(0n, cm31pack(1n, 0n));
        // u*u should equal R = 2+i in QM31 = pack(pack(2,1), pack(0,0))
        const uSq  = qm31pack(cm31pack(2n, 1n), 0n);
        expect(await h.mul(u, u)).to.equal(uSq);
    });

    it("mul is commutative", async function () {
        const x = qm31pack(cm31pack(3n, 5n), cm31pack(7n, 11n));
        const y = qm31pack(cm31pack(13n, 17n), cm31pack(19n, 23n));
        expect(await h.mul(x, y)).to.equal(await h.mul(y, x));
    });

    it("mul is associative", async function () {
        const x = qm31pack(cm31pack(2n, 3n), cm31pack(5n, 7n));
        const y = qm31pack(cm31pack(11n, 13n), cm31pack(17n, 19n));
        const z = qm31pack(cm31pack(23n, 29n), cm31pack(31n, 37n));
        const lhs = await h.mul(await h.mul(x, y), z);
        const rhs = await h.mul(x, await h.mul(y, z));
        expect(lhs).to.equal(rhs);
    });

    it("neg: x + neg(x) == 0", async function () {
        const x    = qm31pack(cm31pack(100n, 200n), cm31pack(300n, 400n));
        const zero = qm31pack(0n, 0n);
        expect(await h.add(x, await h.neg(x))).to.equal(zero);
    });

    it("inv: x * inv(x) == 1", async function () {
        const one = qm31pack(cm31pack(1n, 0n), 0n);
        const x   = qm31pack(cm31pack(3n, 7n), cm31pack(11n, 13n));
        const xi  = await h.inv(x);
        expect(await h.mul(x, xi)).to.equal(one);
    });

    it("inv: real scalar 5 + 0i + 0u + 0iu", async function () {
        const one = qm31pack(cm31pack(1n, 0n), 0n);
        const x   = qm31pack(cm31pack(5n, 0n), 0n);
        const xi  = await h.inv(x);
        expect(await h.mul(x, xi)).to.equal(one);
    });

    it("scaleM31: 3*(a+bu) = (3a)+(3b)u in M31", async function () {
        const x = qm31pack(cm31pack(4n, 5n), cm31pack(6n, 7n));
        const s = 3n;
        // Expected: each M31 component multiplied by 3
        const expected = qm31pack(
            cm31pack(m31mul(4n, s), m31mul(5n, s)),
            cm31pack(m31mul(6n, s), m31mul(7n, s))
        );
        expect(await h.scaleM31(x, s)).to.equal(expected);
    });

    it("isValid: valid element", async function () {
        const x = qm31pack(cm31pack(0n, 0n), cm31pack(0n, 0n));
        expect(await h.isValid(x)).to.be.true;
    });

    it("friLinearFold: f+ = f- = 5 → (5 + 0*alpha)", async function () {
        const alpha = qm31pack(cm31pack(100n, 200n), cm31pack(300n, 400n));
        const result = await h.friLinearFold(5n, 5n, alpha);
        // (5+5)/2 = 5, (5-5)/2 = 0, so result = 5 + alpha*0 = 5
        const expected = await h.fromM31(5n);
        expect(result).to.equal(expected);
    });

    it("friLinearFold: f+ = 10, f- = 0, alpha = 0 → 5", async function () {
        const alpha = qm31pack(0n, 0n);  // alpha = 0
        const result = await h.friLinearFold(10n, 0n, alpha);
        // (10+0)/2 = 5, (10-0)/2 = 5, result = 5 + 0*5 = 5
        const expected = await h.fromM31(5n);
        expect(result).to.equal(expected);
    });

    it("fromBytes16LE: decode 4 LE uint32 words", async function () {
        // c0 = CM31(1, 2), c1 = CM31(3, 4)
        // bytes: [01 00 00 00] [02 00 00 00] [03 00 00 00] [04 00 00 00]
        const buf = "0x" + "01000000" + "02000000" + "03000000" + "04000000";
        const q = await h.fromBytes16LE(buf, 0n);
        expect(qm31c0(q)).to.equal(cm31pack(1n, 2n));
        expect(qm31c1(q)).to.equal(cm31pack(3n, 4n));
    });
});
