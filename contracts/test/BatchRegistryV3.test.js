const { expect } = require("chai");
const { ethers }  = require("hardhat");

// ─────────────────────────────────────────────────────────────────────────────
// BatchRegistryV3 — on-chain batch finalization with V4 verifier interface
// (IQLSAVerifierV4 = 4-param verify including queryHints)
// ─────────────────────────────────────────────────────────────────────────────

const PROOF_LEN  = 700;
const PROOF_FILL = "ab";

const makeProof    = (len, fill = PROOF_FILL) => "0x" + fill.repeat(len);
const toBytes16    = (hash32hex) => "0x" + hash32hex.slice(2, 34);
const EMPTY_HINTS  = "0x"; // MockVerifierV4 ignores queryHints

describe("BatchRegistryV3", function () {
    let registry;
    let verifier;
    let b2s;
    let owner;
    let other;

    let VALID_PROOF;
    let VALID_MERKLE;
    let VALID_COMMITMENT;

    before(async function () {
        [owner, other] = await ethers.getSigners();

        const B2sFactory = await ethers.getContractFactory("Blake2sHarness");
        b2s = await B2sFactory.deploy();

        // MockVerifierV4: commitment-binding check, ignores queryHints
        const VerifierFactory = await ethers.getContractFactory("MockVerifierV4");
        verifier = await VerifierFactory.deploy();

        const RegistryFactory = await ethers.getContractFactory("BatchRegistryV3");
        registry = await RegistryFactory.deploy(owner.address, await verifier.getAddress());

        VALID_PROOF  = makeProof(PROOF_LEN);
        VALID_MERKLE = "0x" + "cd".repeat(32);

        const proofHead = "0x" + PROOF_FILL.repeat(32);
        const input64   = proofHead + "cd".repeat(32);
        const rootHash  = await b2s.hash(input64);
        VALID_COMMITMENT = toBytes16(rootHash);
    });

    // ── Deployment ────────────────────────────────────────────────────────────

    it("stores verifier address", async function () {
        expect(await registry.verifier()).to.equal(await verifier.getAddress());
    });

    it("stores owner", async function () {
        expect(await registry.owner()).to.equal(owner.address);
    });

    it("reverts if verifier is zero address", async function () {
        const RegistryFactory = await ethers.getContractFactory("BatchRegistryV3");
        await expect(
            RegistryFactory.deploy(owner.address, ethers.ZeroAddress)
        ).to.be.revertedWithCustomError(registry, "ZeroAddressVerifier");
    });

    // ── submitBatch — successful finalization ─────────────────────────────────

    it("finalizes a valid batch and emits BatchFinalized", async function () {
        await expect(
            registry.submitBatch(VALID_MERKLE, VALID_COMMITMENT, VALID_PROOF, EMPTY_HINTS)
        )
            .to.emit(registry, "BatchFinalized")
            .withArgs(VALID_MERKLE, VALID_COMMITMENT,
                      await ethers.provider.getBlock("latest").then(b => b?.timestamp + 1));
    });

    it("marks batch as finalized after submitBatch", async function () {
        expect(await registry.isBatchFinalized(VALID_MERKLE)).to.be.true;
    });

    it("stores the commitment for the finalized batch", async function () {
        expect(await registry.getCommitment(VALID_MERKLE)).to.equal(VALID_COMMITMENT);
    });

    it("stores a non-zero timestamp for the finalized batch", async function () {
        expect(await registry.batchTimestamps(VALID_MERKLE)).to.be.gt(0n);
    });

    // ── queryHints are forwarded to the verifier ──────────────────────────────

    it("accepts non-empty queryHints (passed through to verifier)", async function () {
        const freshMerkle = "0x" + "e1".repeat(32);
        const rootHash    = await b2s.hash("0x" + PROOF_FILL.repeat(32) + "e1".repeat(32));
        const commitment  = toBytes16(rootHash);
        const someHints   = "0x" + "deadbeef".repeat(8);  // arbitrary bytes, mock ignores them

        await expect(
            registry.submitBatch(freshMerkle, commitment, VALID_PROOF, someHints)
        ).to.emit(registry, "BatchFinalized");
    });

    // ── submitBatch — replay protection ───────────────────────────────────────

    it("reverts on duplicate merkle root (BatchAlreadyFinalized)", async function () {
        await expect(
            registry.submitBatch(VALID_MERKLE, VALID_COMMITMENT, VALID_PROOF, EMPTY_HINTS)
        ).to.be.revertedWithCustomError(registry, "BatchAlreadyFinalized");
    });

    // ── submitBatch — invalid inputs ──────────────────────────────────────────

    it("reverts on zero merkle root (InvalidMerkleRoot)", async function () {
        const zeroRoot = "0x" + "00".repeat(32);
        await expect(
            registry.submitBatch(zeroRoot, VALID_COMMITMENT, VALID_PROOF, EMPTY_HINTS)
        ).to.be.revertedWithCustomError(registry, "InvalidMerkleRoot");
    });

    it("reverts when commitment does not match (wrong merkle root)", async function () {
        const otherRoot = "0x" + "ef".repeat(32);
        await expect(
            registry.submitBatch(otherRoot, VALID_COMMITMENT, VALID_PROOF, EMPTY_HINTS)
        ).to.be.revertedWithCustomError(registry, "InvalidProof");
    });

    it("reverts when commitment does not match (wrong proof)", async function () {
        const otherProof = makeProof(PROOF_LEN, "ff");
        const freshRoot  = "0x" + "aa".repeat(32);
        await expect(
            registry.submitBatch(freshRoot, VALID_COMMITMENT, otherProof, EMPTY_HINTS)
        ).to.be.revertedWithCustomError(registry, "InvalidProof");
    });

    it("reverts on short proof (InvalidProof via verifier)", async function () {
        const freshRoot  = "0x" + "bb".repeat(32);
        const shortProof = makeProof(100);
        await expect(
            registry.submitBatch(freshRoot, VALID_COMMITMENT, shortProof, EMPTY_HINTS)
        ).to.be.revertedWithCustomError(registry, "InvalidProof");
    });

    // ── isBatchFinalized for unknown root ─────────────────────────────────────

    it("returns false for unknown Merkle root", async function () {
        const unknownRoot = "0x" + "ff".repeat(32);
        expect(await registry.isBatchFinalized(unknownRoot)).to.be.false;
    });

    // ── Admin — setVerifier ───────────────────────────────────────────────────

    it("allows owner to update verifier and emits VerifierUpdated", async function () {
        const NewVerifier = await ethers.getContractFactory("MockVerifierV4");
        const newV    = await NewVerifier.deploy();
        const newAddr = await newV.getAddress();

        await expect(registry.setVerifier(newAddr))
            .to.emit(registry, "VerifierUpdated")
            .withArgs(await verifier.getAddress(), newAddr);

        expect(await registry.verifier()).to.equal(newAddr);
    });

    it("reverts setVerifier from non-owner", async function () {
        const NewVerifier = await ethers.getContractFactory("MockVerifierV4");
        const newV = await NewVerifier.deploy();
        await expect(
            registry.connect(other).setVerifier(await newV.getAddress())
        ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });

    it("reverts setVerifier(address(0))", async function () {
        await expect(
            registry.setVerifier(ethers.ZeroAddress)
        ).to.be.revertedWithCustomError(registry, "ZeroAddressVerifier");
    });

    // ── End-to-end with real QLSAVerifierV5 + valid query hints ───────────────

    describe("end-to-end with QLSAVerifierV5", function () {
        const { blake2s } = require("@noble/hashes/blake2.js");

        const P = 2_147_483_647n;
        const LOG_ORDER = 31n;
        const GEN_X = 2n;
        const GEN_Y = 1268011823n;

        function m31mul(a, b) { return (a * b) % P; }
        function m31add(a, b) { return (a + b) % P; }
        function m31sub(a, b) { return ((a - b) % P + P) % P; }
        function m31pow(a, e) {
            let r = 1n; a = a % P;
            while (e > 0n) { if (e & 1n) r = m31mul(r, a); a = m31mul(a, a); e >>= 1n; }
            return r;
        }
        function m31inv(a) { return m31pow(a, P - 2n); }
        function cm31pack(a, b) { return (BigInt(a) << 32n) | BigInt(b); }
        function cm31re(x) { return (BigInt(x) >> 32n) & 0xFFFFFFFFn; }
        function cm31im(x) { return BigInt(x) & 0xFFFFFFFFn; }
        function cm31add(x, y) { return cm31pack(m31add(cm31re(x), cm31re(y)), m31add(cm31im(x), cm31im(y))); }
        function cm31sub(x, y) { return cm31pack(m31sub(cm31re(x), cm31re(y)), m31sub(cm31im(x), cm31im(y))); }
        function cm31mul(x, y) {
            const a = cm31re(x), b = cm31im(x), c = cm31re(y), d = cm31im(y);
            return cm31pack(m31sub(m31mul(a, c), m31mul(b, d)), m31add(m31mul(a, d), m31mul(b, c)));
        }
        function cm31scale(x, s) { return cm31pack(m31mul(cm31re(x), BigInt(s)), m31mul(cm31im(x), BigInt(s))); }
        const R = cm31pack(2n, 1n);
        function qm31pack(c0, c1) { return (BigInt(c0) << 64n) | BigInt(c1); }
        function qm31c0(q) { return (BigInt(q) >> 64n) & 0xFFFFFFFFFFFFFFFFn; }
        function qm31c1(q) { return BigInt(q) & 0xFFFFFFFFFFFFFFFFn; }
        function qm31add(x, y) { return qm31pack(cm31add(qm31c0(x), qm31c0(y)), cm31add(qm31c1(x), qm31c1(y))); }
        function qm31sub(x, y) { return qm31pack(cm31sub(qm31c0(x), qm31c0(y)), cm31sub(qm31c1(x), qm31c1(y))); }
        function qm31mul(x, y) {
            const a = qm31c0(x), b = qm31c1(x), c = qm31c0(y), d = qm31c1(y);
            return qm31pack(cm31add(cm31mul(a, c), cm31mul(R, cm31mul(b, d))),
                            cm31add(cm31mul(a, d), cm31mul(b, c)));
        }
        function qm31scaleM31(x, s) { return qm31pack(cm31scale(qm31c0(x), s), cm31scale(qm31c1(x), s)); }
        function qm31fromM31(v) { return qm31pack(cm31pack(BigInt(v), 0n), 0n); }
        function circleFold(fPlus, fMinus, alpha, yInv) {
            return qm31add(qm31add(fPlus, fMinus), qm31mul(alpha, qm31scaleM31(qm31sub(fPlus, fMinus), yInv)));
        }
        function circleAdd(x1, y1, x2, y2) {
            return [m31sub(m31mul(x1, x2), m31mul(y1, y2)), m31add(m31mul(x1, y2), m31mul(x2, y1))];
        }
        function circleDouble(x, y) {
            const x2 = m31mul(x, x);
            return [m31sub(m31add(x2, x2), 1n), m31add(m31mul(x, y), m31mul(x, y))];
        }
        function genMul(scalar) {
            let rx = 1n, ry = 0n; let cx = GEN_X, cy = GEN_Y;
            let s = BigInt(scalar) & ((1n << LOG_ORDER) - 1n);
            while (s > 0n) {
                if (s & 1n) [rx, ry] = circleAdd(rx, ry, cx, cy);
                [cx, cy] = circleDouble(cx, cy);
                s >>= 1n;
            }
            return [rx, ry];
        }
        function cosetAt(logN, idx) {
            const m = (1n << LOG_ORDER) - 1n;
            const ii = (1n << (30n - BigInt(logN))) & m;
            const ss = (1n << (31n - BigInt(logN))) & m;
            return genMul((ii + BigInt(idx) * ss) & m);
        }
        function b2sHash(buf) { return "0x" + Buffer.from(blake2s(buf)).toString("hex"); }
        function hashLeaf(vals) {
            const buf = Buffer.alloc(vals.length * 4);
            vals.forEach((v, i) => buf.writeUInt32LE(v, i * 4));
            return b2sHash(buf);
        }
        function hashPair(l, r) {
            return b2sHash(Buffer.concat([Buffer.from(l.slice(2),"hex"), Buffer.from(r.slice(2),"hex")]));
        }
        function buildTree(leaves) {
            let level = leaves; const levels = [level];
            while (level.length > 1) {
                const next = [];
                for (let i = 0; i < level.length; i += 2) next.push(hashPair(level[i], level[i+1]));
                level = next; levels.push(level);
            }
            return levels;
        }
        function proofPath(levels, idx) {
            const siblings = []; let i = idx;
            for (let d = 0; d < levels.length - 1; d++) { siblings.push(levels[d][i ^ 1]); i >>= 1; }
            return { root: levels[levels.length-1][0], siblings };
        }

        const HINT_TUPLE = "tuple(bytes32,uint32[],uint256,uint256,bytes32[],uint128,uint128,uint128,uint128,uint256,uint256)";

        let v5registry;

        before(async function () {
            const V5Factory = await ethers.getContractFactory("QLSAVerifierV5");
            const v5 = await V5Factory.deploy();
            const RegFactory = await ethers.getContractFactory("BatchRegistryV3");
            v5registry = await RegFactory.deploy(owner.address, await v5.getAddress());
        });

        it("finalizes a batch with real QLSAVerifierV5 and 2 valid queries", async function () {
            const colA = [100, 200, 300, 400];
            const colB = [1000, 2000, 3000, 4000];
            const leaves = [0,1,2,3].map(i => hashLeaf([colA[i], colB[i]]));
            const levels = buildTree(leaves);
            const depth  = levels.length - 1;
            const alpha  = qm31fromM31(7777n);

            const buildHint = (idx) => {
                const { root: traceRoot, siblings } = proofPath(levels, idx);
                const [qpX, qpY] = cosetAt(depth, idx);
                const yInv = m31inv(qpY);
                const fPlus = qm31fromM31(BigInt(colA[idx]));
                const fMinus = qm31fromM31(BigInt(Math.floor(colA[idx] / 2)));
                const foldedValue = circleFold(fPlus, fMinus, alpha, yInv);
                return [traceRoot, [colA[idx], colB[idx]], idx, depth, siblings,
                        alpha, fPlus, fMinus, foldedValue, qpX, qpY];
            };

            const traceRoot = proofPath(levels, 0).root;

            const proof = Buffer.alloc(700, 0x01);
            proof.writeBigUInt64LE(2n, 0);
            Buffer.from(traceRoot.slice(2), "hex").copy(proof, 8);
            const fakeMerkle = Buffer.alloc(32, 0x42);
            const h = Buffer.from(blake2s(Buffer.concat([proof.subarray(0,32), fakeMerkle])));
            const commitment = "0x" + h.subarray(0,16).toString("hex");
            const merkleRootHex = "0x" + fakeMerkle.toString("hex");

            const hints = ethers.AbiCoder.defaultAbiCoder().encode(
                [HINT_TUPLE + "[]"],
                [[buildHint(0), buildHint(2)]]
            );

            await expect(
                v5registry.submitBatch(merkleRootHex, commitment, "0x" + proof.toString("hex"), hints)
            ).to.emit(v5registry, "BatchFinalized");

            expect(await v5registry.isBatchFinalized(merkleRootHex)).to.be.true;
        });
    });

    // ── submitBatchWithNonces — nonce replay protection ───────────────────────

    describe("submitBatchWithNonces", function () {
        let nonceRoot;
        let nonceSender;

        before(function () {
            nonceRoot   = "0x" + "12".repeat(32);
            nonceSender = "0x" + "34".repeat(32);
        });

        async function makeCommitment(merkleHex) {
            const proofHead = "0x" + PROOF_FILL.repeat(32);
            const input64   = proofHead + merkleHex.slice(2, 66);
            const rootHash  = await b2s.hash(input64);
            return toBytes16(rootHash);
        }

        it("accepts first batch with nonce=1", async function () {
            const commitment = await makeCommitment(nonceRoot);
            await expect(
                registry.submitBatchWithNonces(
                    nonceRoot, commitment, VALID_PROOF, EMPTY_HINTS,
                    [nonceSender], [1n]
                )
            )
                .to.emit(registry, "BatchFinalized")
                .and.to.emit(registry, "NonceAdvanced")
                .withArgs(nonceSender, 1n);

            expect(await registry.senderNonces(nonceSender)).to.equal(1n);
        });

        it("rejects replay: same nonce (SenderNonceTooLow)", async function () {
            const freshRoot  = "0x" + "56".repeat(32);
            const commitment = await makeCommitment(freshRoot);
            await expect(
                registry.submitBatchWithNonces(
                    freshRoot, commitment, VALID_PROOF, EMPTY_HINTS,
                    [nonceSender], [1n]
                )
            ).to.be.revertedWithCustomError(registry, "SenderNonceTooLow");
        });

        it("accepts higher nonce in subsequent batch", async function () {
            const freshRoot  = "0x" + "78".repeat(32);
            const commitment = await makeCommitment(freshRoot);
            await expect(
                registry.submitBatchWithNonces(
                    freshRoot, commitment, VALID_PROOF, EMPTY_HINTS,
                    [nonceSender], [5n]
                )
            ).to.emit(registry, "NonceAdvanced").withArgs(nonceSender, 5n);

            expect(await registry.senderNonces(nonceSender)).to.equal(5n);
        });

        it("reverts when senders/nonces arrays length mismatch", async function () {
            const freshRoot  = "0x" + "9a".repeat(32);
            const commitment = await makeCommitment(freshRoot);
            await expect(
                registry.submitBatchWithNonces(
                    freshRoot, commitment, VALID_PROOF, EMPTY_HINTS,
                    [nonceSender], [10n, 11n]
                )
            ).to.be.revertedWithCustomError(registry, "NoncesLengthMismatch");
        });

        it("zero-nonce entry always fails (nonce must exceed stored 0)", async function () {
            const freshRoot   = "0x" + "bc".repeat(32);
            const freshSender = "0x" + "de".repeat(32);
            const commitment  = await makeCommitment(freshRoot);
            await expect(
                registry.submitBatchWithNonces(
                    freshRoot, commitment, VALID_PROOF, EMPTY_HINTS,
                    [freshSender], [0n]
                )
            ).to.be.revertedWithCustomError(registry, "SenderNonceTooLow");
        });

        it("rejects duplicate sender with non-increasing nonces in same call", async function () {
            const freshRoot   = "0x" + "f0".repeat(32);
            const freshSender = "0x" + "a1".repeat(32);
            const commitment  = await makeCommitment(freshRoot);
            // Same sender twice, second nonce not strictly greater than first
            await expect(
                registry.submitBatchWithNonces(
                    freshRoot, commitment, VALID_PROOF, EMPTY_HINTS,
                    [freshSender, freshSender], [3n, 3n]
                )
            ).to.be.revertedWithCustomError(registry, "SenderNonceTooLow");
        });
    });
});
