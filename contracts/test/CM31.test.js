const { expect } = require("chai");
const { ethers }  = require("hardhat");

// p = 2^31 - 1
const P = 2_147_483_647n;

// Pack (a, b) → uint64 as BigInt matching CM31.pack()
function pack(a, b) { return (a << 32n) | b; }
function re(e)      { return e >> 32n; }
function im(e)      { return e & 0xFFFFFFFFn; }

// M31 helpers for test reference values
function m31add(a, b) { const r = (a + b) % P; return r < 0n ? r + P : r; }
function m31sub(a, b) { return ((a - b) % P + P) % P; }
function m31mul(a, b) { return (a * b) % P; }
function m31neg(a)    { return a === 0n ? 0n : P - a; }
function m31pow(a, e) {
    let r = 1n; a = a % P;
    while (e > 0n) { if (e & 1n) r = m31mul(r, a); a = m31mul(a, a); e >>= 1n; }
    return r;
}
function m31inv(a) { return m31pow(a, P - 2n); }

// CM31 reference arithmetic
function cm31add(x, y) { return pack(m31add(re(x), re(y)), m31add(im(x), im(y))); }
function cm31sub(x, y) { return pack(m31sub(re(x), re(y)), m31sub(im(x), im(y))); }
function cm31mul(x, y) {
    const a = re(x), b = im(x), c = re(y), d = im(y);
    return pack(m31sub(m31mul(a, c), m31mul(b, d)), m31add(m31mul(a, d), m31mul(b, c)));
}
function cm31neg(x) { return pack(m31neg(re(x)), m31neg(im(x))); }
function cm31inv(x) {
    const a = re(x), b = im(x);
    const norm = m31add(m31mul(a, a), m31mul(b, b));
    const ni = m31inv(norm);
    return pack(m31mul(a, ni), m31mul(m31neg(b), ni));
}

describe("CM31 library", function () {
    let h;

    before(async function () {
        const F = await ethers.getContractFactory("CM31Harness");
        h = await F.deploy();
    });

    it("P constant", async function () {
        expect(await h.P()).to.equal(P);
    });

    it("pack/re/im round-trip", async function () {
        const x = pack(12345n, 67890n);
        expect(await h.re(x)).to.equal(12345n);
        expect(await h.im(x)).to.equal(67890n);
        expect(await h.pack(12345n, 67890n)).to.equal(x);
    });

    it("add: basic", async function () {
        const x = pack(10n, 20n);
        const y = pack(3n, 7n);
        expect(await h.add(x, y)).to.equal(cm31add(x, y));
    });

    it("add: wraps both components", async function () {
        const x = pack(P - 1n, P - 1n);
        const y = pack(2n, 3n);
        expect(await h.add(x, y)).to.equal(cm31add(x, y));
    });

    it("sub: basic", async function () {
        const x = pack(100n, 50n);
        const y = pack(30n, 20n);
        expect(await h.sub(x, y)).to.equal(cm31sub(x, y));
    });

    it("sub: underflow wraps", async function () {
        const x = pack(0n, 1n);
        const y = pack(1n, 2n);
        expect(await h.sub(x, y)).to.equal(cm31sub(x, y));
    });

    it("mul: (2+3i)(4+5i) = (2*4-3*5) + (2*5+3*4)i = -7 + 22i", async function () {
        const x = pack(2n, 3n);
        const y = pack(4n, 5n);
        const expected = pack(m31sub(8n, 15n), m31add(10n, 12n)); // (-7, 22)
        expect(await h.mul(x, y)).to.equal(expected);
    });

    it("mul: i*i = -1 (P-1 + 0i)", async function () {
        // i = 0 + 1*i = pack(0, 1)
        const i = pack(0n, 1n);
        expect(await h.mul(i, i)).to.equal(pack(P - 1n, 0n));
    });

    it("mul: 1 is identity", async function () {
        const one = pack(1n, 0n);
        const x   = pack(12345n, 67890n);
        expect(await h.mul(x, one)).to.equal(x);
    });

    it("neg: a + neg(a) == 0", async function () {
        const x = pack(100n, 200n);
        const zero = pack(0n, 0n);
        expect(await h.add(x, await h.neg(x))).to.equal(zero);
    });

    it("inv: x * inv(x) == 1", async function () {
        const x = pack(3n, 7n);
        const one = pack(1n, 0n);
        const xi = await h.inv(x);
        expect(await h.mul(x, xi)).to.equal(one);
    });

    it("inv: real number 3 + 0i", async function () {
        const x = pack(3n, 0n);
        const one = pack(1n, 0n);
        const xi = await h.inv(x);
        expect(await h.mul(x, xi)).to.equal(one);
    });

    it("conj: a+bi → a-bi", async function () {
        const x = pack(5n, 7n);
        expect(await h.conj(x)).to.equal(pack(5n, P - 7n));
    });

    it("scale: s*(a+bi) = (s*a)+(s*b)i", async function () {
        const x = pack(3n, 4n);
        const s = 5n;
        const expected = pack(m31mul(3n, s), m31mul(4n, s));
        expect(await h.scale(x, s)).to.equal(expected);
    });

    it("fromM31: embeds as real part", async function () {
        expect(await h.fromM31(42n)).to.equal(pack(42n, 0n));
    });

    it("isValid: valid element", async function () {
        expect(await h.isValid(pack(0n, 0n))).to.be.true;
        expect(await h.isValid(pack(P - 1n, P - 1n))).to.be.true;
    });

    it("isValid: out-of-range real", async function () {
        // P fits in bits 63:32 of a uint64 but P is not < P
        expect(await h.isValid(pack(P, 0n))).to.be.false;
    });

    it("fromBytes8LE: decode two LE uint32 words", async function () {
        // a = 1 (LE: 01 00 00 00), b = 2 (LE: 02 00 00 00)
        const buf = "0x" + "01000000" + "02000000";
        expect(await h.fromBytes8LE(buf, 0n)).to.equal(pack(1n, 2n));
    });

    it("mul is commutative", async function () {
        const x = pack(123456789n, 987654321n);
        const y = pack(111111111n, 222222222n);
        expect(await h.mul(x, y)).to.equal(await h.mul(y, x));
    });

    it("mul is associative", async function () {
        const x = pack(3n, 5n);
        const y = pack(7n, 11n);
        const z = pack(13n, 17n);
        const lhs = await h.mul(await h.mul(x, y), z);
        const rhs = await h.mul(x, await h.mul(y, z));
        expect(lhs).to.equal(rhs);
    });
});
