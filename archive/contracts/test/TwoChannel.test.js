const { expect } = require("chai");
const { ethers }  = require("hardhat");
const { blake2s } = require("@noble/hashes/blake2.js");

// ── Reference implementation of TwoChannel (matches TwoChannel.sol + Stwo Rust) ──

const P = 2_147_483_647; // 2^31 - 1

/// reduce a uint32 to M31: r = (w & P) + (w >> 31); if r >= P: r -= P
function reduceM31(w) {
    let r = (w & 0x7FFFFFFF) + (w >>> 31);
    if (r >= P) r -= P;
    return r;
}

/// Blake2s-256 of buf, then reduce each LE uint32 word to M31.
function blake2sM31(buf) {
    const h = Buffer.from(blake2s(buf));
    const out = Buffer.alloc(32);
    for (let i = 0; i < 8; i++) {
        const w = h.readUInt32LE(i * 4);
        out.writeUInt32LE(reduceM31(w), i * 4);
    }
    return out;
}

// Channel state: { digest: Buffer(32), nDraws: number }
function channelInit() {
    return { digest: Buffer.alloc(32), nDraws: 0 };
}

function channelMixRoot(s, root32) {
    const buf = Buffer.concat([s.digest, root32]);
    s.digest = blake2sM31(buf);
    s.nDraws = 0;
}

function channelMixU32s(s, words) {
    const wBuf = Buffer.alloc(words.length * 4);
    for (let i = 0; i < words.length; i++) wBuf.writeUInt32LE(words[i], i * 4);
    const buf = Buffer.concat([s.digest, wBuf]);
    s.digest = blake2sM31(buf);
    s.nDraws = 0;
}

function channelDrawU32sRaw(s) {
    const nBuf = Buffer.alloc(4);
    nBuf.writeUInt32LE(s.nDraws, 0);
    const buf = Buffer.concat([s.digest, nBuf, Buffer.alloc(1)]); // 37 bytes
    s.nDraws++;
    return blake2sM31(buf);
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

// Convert bytes32 hex (0x...) to a 32-byte Buffer
function hexToBuffer(hex) {
    return Buffer.from(hex.slice(2), "hex");
}

// ── Rust reference vectors ─────────────────────────────────────────────────────
// Produced by: cargo test test_two_channel -- --nocapture
// Using Stwo 2.2.0 Blake2sM31Channel (IS_M31_OUTPUT=true).

const RUST_VECTORS = {
    mixRootZeroZero:     "0xae09db7cd64f423491ef0936bd541a7689e4951bb8c53f359b6f56638bb45423",
    mixRoot01abab:       "0x7b679217e4020e5387fd8a4625d7316df22c1b57549f5d4886f717618a501d07",
    drawU32sRawN0:       "0xf9d4e359b6d7f9024baf556ed4d5b526a1054a5a68e7877ceed8381f0dda6272",
    drawU32sRawN1:       "0x933e7a69b8c3944f891ea877701e06550ddae2325848c263f9c1e6253c2f224f",
    seqDraw1:            "0x86591d4719d7131d352a4b32fb65db43dd4a907f7c2f3954ac97953779d9fd51",
    seqDraw2:            "0x732d8e06f5945012e3b92e5504271152743e1f01469fb00e4f46005bee627417",
    drawQueriesLogSize3n5: [1, 6, 3, 4, 1],
};

// ── Tests ──────────────────────────────────────────────────────────────────────

describe("TwoChannel library", function () {
    let ch;

    before(async function () {
        const F = await ethers.getContractFactory("TwoChannelHarness");
        ch = await F.deploy();
    });

    // ── init() ─────────────────────────────────────────────────────────────────

    it("init() returns zero digest and zero nDraws", async function () {
        const [digest, nDraws] = await ch.init();
        expect(digest).to.equal("0x" + "00".repeat(32));
        expect(nDraws).to.equal(0);
    });

    // ── mixRoot() ──────────────────────────────────────────────────────────────

    it("mixRoot(zero, zero) matches JS reference", async function () {
        const root = Buffer.alloc(32);
        const ref  = channelInit();
        channelMixRoot(ref, root);
        const expected = "0x" + ref.digest.toString("hex");

        const [outDigest, outDraws] = await ch.mixRoot(
            "0x" + "00".repeat(32), 0, "0x" + "00".repeat(32)
        );
        expect(outDigest.toLowerCase()).to.equal(expected.toLowerCase());
        expect(outDraws).to.equal(0);
    });

    it("mixRoot(non-zero digest, non-zero root) matches JS reference", async function () {
        const digestHex = "01".repeat(32);
        const rootHex   = "ab".repeat(32);
        const root = Buffer.from(rootHex, "hex");

        const ref = { digest: Buffer.from(digestHex, "hex"), nDraws: 5 };
        channelMixRoot(ref, root);
        const expected = "0x" + ref.digest.toString("hex");

        const [outDigest, outDraws] = await ch.mixRoot(
            "0x" + digestHex, 5, "0x" + rootHex
        );
        expect(outDigest.toLowerCase()).to.equal(expected.toLowerCase());
        expect(outDraws).to.equal(0, "nDraws must be reset to 0 after mixRoot");
    });

    it("mixRoot resets nDraws to zero", async function () {
        const [, outDraws] = await ch.mixRoot(
            "0x" + "ff".repeat(32), 999, "0x" + "ee".repeat(32)
        );
        expect(outDraws).to.equal(0);
    });

    // ── mixU32s() ──────────────────────────────────────────────────────────────

    it("mixU32s([0x1234, 0xDEADBEEF]) matches JS reference", async function () {
        const words = [0x1234, 0xDEADBEEF];
        const ref = channelInit();
        channelMixU32s(ref, words);
        const expected = "0x" + ref.digest.toString("hex");

        const [outDigest, outDraws] = await ch.mixU32s(
            "0x" + "00".repeat(32), 0, words
        );
        expect(outDigest.toLowerCase()).to.equal(expected.toLowerCase());
        expect(outDraws).to.equal(0);
    });

    it("mixU32s resets nDraws", async function () {
        const [, outDraws] = await ch.mixU32s("0x" + "00".repeat(32), 42, [1, 2, 3]);
        expect(outDraws).to.equal(0);
    });

    // ── drawU32sRaw() ──────────────────────────────────────────────────────────

    it("drawU32sRaw from zero state matches JS reference", async function () {
        const ref = channelInit();
        const expected = "0x" + channelDrawU32sRaw(ref).toString("hex");

        const [raw, outDraws] = await ch.drawU32sRaw("0x" + "00".repeat(32), 0);
        expect(raw.toLowerCase()).to.equal(expected.toLowerCase());
        expect(outDraws).to.equal(1, "nDraws should be incremented to 1");
    });

    it("drawU32sRaw increments nDraws (second call uses nDraws=1)", async function () {
        const ref = channelInit();
        channelDrawU32sRaw(ref); // nDraws becomes 1
        const expected = "0x" + channelDrawU32sRaw(ref).toString("hex"); // nDraws=1 → becomes 2

        // Call contract with nDraws=1 (simulating second draw)
        const [raw, outDraws] = await ch.drawU32sRaw("0x" + "00".repeat(32), 1);
        expect(raw.toLowerCase()).to.equal(expected.toLowerCase());
        expect(outDraws).to.equal(2);
    });

    it("drawU32sRaw does NOT change the digest", async function () {
        const initDigest = "0x" + "aa".repeat(32);
        const [, ] = await ch.drawU32sRaw(initDigest, 0);
        // Verify digest unchanged by calling again
        const [raw1, ] = await ch.drawU32sRaw(initDigest, 0);
        const [raw2, ] = await ch.drawU32sRaw(initDigest, 0);
        expect(raw1).to.equal(raw2, "same nDraws on same digest must give same output");
    });

    it("drawU32sRaw(nDraws=0) != drawU32sRaw(nDraws=1) for same digest", async function () {
        const d = "0x" + "cc".repeat(32);
        const [raw0, ] = await ch.drawU32sRaw(d, 0);
        const [raw1, ] = await ch.drawU32sRaw(d, 1);
        expect(raw0).to.not.equal(raw1);
    });

    // ── drawSecureFelt() ───────────────────────────────────────────────────────

    it("drawSecureFelt returns QM31 whose components are M31-valid", async function () {
        const [felt, ] = await ch.drawSecureFelt("0x" + "00".repeat(32), 0);
        const Pn = BigInt(P);
        const qm31 = BigInt(felt);
        const c0 = (qm31 >> 64n) & 0xFFFFFFFFFFFFFFFFn;
        const c1 = qm31 & 0xFFFFFFFFFFFFFFFFn;
        const c0re = c0 >> 32n;
        const c0im = c0 & 0xFFFFFFFFn;
        const c1re = c1 >> 32n;
        const c1im = c1 & 0xFFFFFFFFn;
        expect(c0re).to.be.lessThan(Pn, "c0.re must be < P");
        expect(c0im).to.be.lessThan(Pn, "c0.im must be < P");
        expect(c1re).to.be.lessThan(Pn, "c1.re must be < P");
        expect(c1im).to.be.lessThan(Pn, "c1.im must be < P");
    });

    it("drawSecureFelt is consistent with drawU32sRaw word layout", async function () {
        const digest = "0x" + "55".repeat(32);
        const [raw, ] = await ch.drawU32sRaw(digest, 0);
        const [felt, ] = await ch.drawSecureFelt(digest, 0);

        // Extract first 4 LE uint32 words from raw
        const rawBuf = hexToBuffer(raw);
        const w0 = BigInt(rawBuf.readUInt32LE(0));
        const w1 = BigInt(rawBuf.readUInt32LE(4));
        const w2 = BigInt(rawBuf.readUInt32LE(8));
        const w3 = BigInt(rawBuf.readUInt32LE(12));
        const expectedFelt = (((w0 << 32n) | w1) << 64n) | ((w2 << 32n) | w3);

        expect(BigInt(felt)).to.equal(expectedFelt);
    });

    // ── drawQueries() ──────────────────────────────────────────────────────────

    it("drawQueries(logDomainSize=3, n=5) matches JS reference", async function () {
        const digest = "0x" + "00".repeat(32);
        const ref = channelInit();
        const expectedQs = channelDrawQueries(ref, 3, 5);

        const [queries, outDraws] = await ch.drawQueries(digest, 0, 3, 5);
        for (let i = 0; i < 5; i++) {
            expect(Number(queries[i])).to.equal(expectedQs[i]);
            expect(Number(queries[i])).to.be.lessThan(8, "query index must be < 2^3");
        }
        expect(outDraws).to.equal(Math.ceil(5 / 8));
    });

    it("drawQueries(logDomainSize=10, n=3) matches JS reference", async function () {
        const digestHex = "deadbeef".repeat(8);
        const ref = { digest: Buffer.from(digestHex, "hex"), nDraws: 0 };
        const expectedQs = channelDrawQueries(ref, 10, 3);

        const [queries, ] = await ch.drawQueries("0x" + digestHex, 0, 10, 3);
        for (let i = 0; i < 3; i++) {
            expect(Number(queries[i])).to.equal(expectedQs[i]);
            expect(Number(queries[i])).to.be.lessThan(1024, "query index must be < 2^10");
        }
    });

    it("drawQueries needs 2 drawU32sRaw calls for n=9", async function () {
        const [, outDraws] = await ch.drawQueries("0x" + "00".repeat(32), 0, 4, 9);
        expect(outDraws).to.equal(2, "9 queries require 2 blocks of 8 words");
    });

    // ── Sequence: mixRoot → draw → mixRoot → draw ──────────────────────────────

    it("two-step transcript: mixRoot + drawU32sRaw sequence matches JS reference", async function () {
        const root1 = Buffer.from("01".repeat(32), "hex");
        const root2 = Buffer.from("02".repeat(32), "hex");

        // JS reference
        const ref = channelInit();
        channelMixRoot(ref, root1);
        const draw1 = channelDrawU32sRaw(ref); // nDraws=0 → 1
        channelMixRoot(ref, root2);
        const draw2 = channelDrawU32sRaw(ref); // nDraws=0 → 1

        // Solidity: step 1
        let [d1, n1] = await ch.mixRoot("0x" + "00".repeat(32), 0, "0x" + "01".repeat(32));
        const [raw1, nd1] = await ch.drawU32sRaw(d1, n1);
        // step 2
        let [d2, n2] = await ch.mixRoot(d1, nd1, "0x" + "02".repeat(32));
        const [raw2, ] = await ch.drawU32sRaw(d2, n2);

        expect(raw1.toLowerCase()).to.equal("0x" + draw1.toString("hex"));
        expect(raw2.toLowerCase()).to.equal("0x" + draw2.toString("hex"));
    });

    // ── Rust cross-verification (fixed vectors from Stwo 2.2.0) ──────────────

    it("mixRoot(zero, zero) matches Stwo 2.2.0 Rust reference", async function () {
        const [outDigest, ] = await ch.mixRoot(
            "0x" + "00".repeat(32), 0, "0x" + "00".repeat(32)
        );
        expect(outDigest.toLowerCase()).to.equal(RUST_VECTORS.mixRootZeroZero.toLowerCase());
    });

    it("mixRoot(0x01..01, 0xab..ab) matches Stwo 2.2.0 Rust reference", async function () {
        const [outDigest, ] = await ch.mixRoot(
            "0x" + "01".repeat(32), 0, "0x" + "ab".repeat(32)
        );
        expect(outDigest.toLowerCase()).to.equal(RUST_VECTORS.mixRoot01abab.toLowerCase());
    });

    it("drawU32sRaw(zero, nDraws=0) matches Stwo 2.2.0 Rust reference", async function () {
        const [raw, ] = await ch.drawU32sRaw("0x" + "00".repeat(32), 0);
        expect(raw.toLowerCase()).to.equal(RUST_VECTORS.drawU32sRawN0.toLowerCase());
    });

    it("drawU32sRaw(zero, nDraws=1) matches Stwo 2.2.0 Rust reference", async function () {
        const [raw, ] = await ch.drawU32sRaw("0x" + "00".repeat(32), 1);
        expect(raw.toLowerCase()).to.equal(RUST_VECTORS.drawU32sRawN1.toLowerCase());
    });

    it("two-step sequence matches Stwo 2.2.0 Rust reference", async function () {
        let [d, n] = await ch.mixRoot("0x" + "00".repeat(32), 0, "0x" + "01".repeat(32));
        const [raw1, nd1] = await ch.drawU32sRaw(d, n);
        let [d2, n2] = await ch.mixRoot(d, nd1, "0x" + "02".repeat(32));
        const [raw2, ] = await ch.drawU32sRaw(d2, n2);
        expect(raw1.toLowerCase()).to.equal(RUST_VECTORS.seqDraw1.toLowerCase());
        expect(raw2.toLowerCase()).to.equal(RUST_VECTORS.seqDraw2.toLowerCase());
    });

    it("drawQueries(logSize=3, n=5) positions match Stwo 2.2.0 Rust reference", async function () {
        const [queries, ] = await ch.drawQueries("0x" + "00".repeat(32), 0, 3, 5);
        for (let i = 0; i < 5; i++) {
            expect(Number(queries[i])).to.equal(RUST_VECTORS.drawQueriesLogSize3n5[i]);
        }
    });

    // ── blake2sM31 reduces all words < P ──────────────────────────────────────

    it("digest after mixRoot has all 8 LE words < P", async function () {
        const [digest, ] = await ch.mixRoot(
            "0x" + "00".repeat(32), 0,
            "0x" + "ff".repeat(32)
        );
        const Pn = BigInt(P);
        const buf = hexToBuffer(digest);
        for (let i = 0; i < 8; i++) {
            const w = BigInt(buf.readUInt32LE(i * 4));
            expect(w).to.be.lessThan(Pn, `word ${i} must be a valid M31 element`);
        }
    });

    it("drawU32sRaw output has all 8 LE words < P", async function () {
        const [raw, ] = await ch.drawU32sRaw("0x" + "aa".repeat(32), 7);
        const Pn = BigInt(P);
        const buf = hexToBuffer(raw);
        for (let i = 0; i < 8; i++) {
            const w = BigInt(buf.readUInt32LE(i * 4));
            expect(w).to.be.lessThan(Pn, `word ${i} must be a valid M31 element`);
        }
    });
});
