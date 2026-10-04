const { expect } = require("chai");
const { ethers }  = require("hardhat");

// ─────────────────────────────────────────────────────────────────────────────
// BatchRegistryV4 — dual-proof batch finalization (LOG=10 + LOG=8 VFRI6)
//
// Mock strategy (all in contracts/src/test/MockVerifierV4Dual.sol):
//
//   MockVerifierV4Dual  — pure commitment-binding verifier (same logic as
//                         MockVerifierV4).  Used as the default verifier.
//
//   SentinelVerifier    — pure commitment-binding verifier that additionally
//                         rejects commitment == SENTINEL (0xdeadbeef...).
//                         Allows the test to choose which of the two calls
//                         fails: pass a valid commitment for LOG=10 and
//                         SENTINEL as commitmentLog8 → Log8ProofInvalid.
//
//   AlwaysFalseVerifier — every verify() call returns false (both fail).
// ─────────────────────────────────────────────────────────────────────────────

const PROOF_LEN  = 700;
const PROOF_FILL = "ab";

// Build a proof of `len` bytes filled with `fill` (a 2-hex-digit string).
const makeProof = (len, fill = PROOF_FILL) => "0x" + fill.repeat(len);

// Slice the first 16 bytes out of a 32-byte hex hash (0x-prefixed).
const toBytes16 = (hash32hex) => "0x" + hash32hex.slice(2, 34);

const EMPTY_HINTS = "0x"; // MockVerifierV4Dual ignores queryHints

// ── Cross-bound root helpers ─────────────────────────────────────────────────
// BatchRegistryV4 derives cross-bound roots before calling the verifier:
//   boundRoot10 = keccak256(batchRoot ‖ proof8[8:40])
//   boundRoot8  = keccak256(batchRoot ‖ proof10[8:40])
//
// VALID_PROOF_10 uses fill "ab" → traceRoot10 = proof10[8:40] = 0xab×32
// VALID_PROOF_8  uses fill "dc" → traceRoot8  = proof8[8:40]  = 0xdc×32
const TRACE_ROOT_10 = "0x" + "ab".repeat(32);
const TRACE_ROOT_8  = "0x" + "dc".repeat(32);

function makeBoundRoots(merkleHex) {
    const boundRoot10 = ethers.keccak256(
        ethers.solidityPacked(["bytes32","bytes32"], [merkleHex, TRACE_ROOT_8])
    );
    const boundRoot8 = ethers.keccak256(
        ethers.solidityPacked(["bytes32","bytes32"], [merkleHex, TRACE_ROOT_10])
    );
    return [boundRoot10, boundRoot8];
}

// ── Fixture: compute a valid Blake2s commitment ──────────────────────────────
// MockVerifierV4Dual: commitment = Blake2s(proof[:32] ‖ merkleRoot)[:16]
// merkleRoot here is the cross-bound root that BatchRegistryV4 passes to verify().
async function makeCommitment(b2s, proofFill, merkleHex) {
    const proofHead = "0x" + proofFill.repeat(32);
    const input64   = proofHead + merkleHex.slice(2, 66);   // drop "0x" prefix
    const rootHash  = await b2s.hash(input64);
    return toBytes16(rootHash);
}

// ─────────────────────────────────────────────────────────────────────────────

describe("BatchRegistryV4", function () {
    let registry;
    let mockVerifier;   // MockVerifierV4Dual — used as the single shared verifier
    let b2s;
    let owner;
    let other;

    // Shared valid test values (set up in before()).
    let VALID_MERKLE;
    let VALID_PROOF_10;
    let VALID_PROOF_8;
    let VALID_COMMIT_10;
    let VALID_COMMIT_8;

    before(async function () {
        [owner, other] = await ethers.getSigners();

        // Blake2s harness for computing expected commitments off-chain.
        const B2sFactory = await ethers.getContractFactory("Blake2sHarness");
        b2s = await B2sFactory.deploy();

        // Deploy MockVerifierV4Dual as the single verifier for both proof calls.
        const MockFactory = await ethers.getContractFactory("MockVerifierV4Dual");
        mockVerifier = await MockFactory.deploy();

        // Deploy the registry.
        const RegFactory = await ethers.getContractFactory("BatchRegistryV4");
        registry = await RegFactory.deploy(owner.address, await mockVerifier.getAddress());

        // Set up a stable merkle root and two distinct proofs (different fill bytes).
        VALID_MERKLE   = "0x" + "cd".repeat(32);
        VALID_PROOF_10 = makeProof(PROOF_LEN, "ab");  // LOG=10 proof
        VALID_PROOF_8  = makeProof(PROOF_LEN, "dc");  // LOG=8 proof

        // BatchRegistryV4 passes cross-bound roots to the verifier, not the raw batch root.
        // MockVerifierV4Dual checks Blake2s(proof[:32] ‖ crossBoundRoot)[:16] == commitment.
        const [br10, br8] = makeBoundRoots(VALID_MERKLE);
        VALID_COMMIT_10 = await makeCommitment(b2s, "ab", br10);
        VALID_COMMIT_8  = await makeCommitment(b2s, "dc", br8);
    });

    // ── Deployment ────────────────────────────────────────────────────────────

    it("stores verifier address on deployment", async function () {
        expect(await registry.verifier()).to.equal(await mockVerifier.getAddress());
    });

    it("sets the correct owner on deployment", async function () {
        expect(await registry.owner()).to.equal(owner.address);
    });

    it("reverts construction with zero-address verifier", async function () {
        const RegFactory = await ethers.getContractFactory("BatchRegistryV4");
        await expect(
            RegFactory.deploy(owner.address, ethers.ZeroAddress)
        ).to.be.revertedWithCustomError(registry, "ZeroAddressVerifier");
    });

    // ── submitBatch — successful dual-proof finalization ──────────────────────

    it("finalizes a batch with valid LOG=10 and LOG=8 proofs, emits BatchFinalized", async function () {
        await expect(
            registry.submitBatch(
                VALID_MERKLE,
                VALID_COMMIT_10, VALID_PROOF_10, EMPTY_HINTS,
                VALID_COMMIT_8,  VALID_PROOF_8,  EMPTY_HINTS
            )
        )
            .to.emit(registry, "BatchFinalized")
            .withArgs(
                VALID_MERKLE,
                VALID_COMMIT_10,
                VALID_COMMIT_8,
                await ethers.provider.getBlock("latest").then(b => b?.timestamp + 1)
            );
    });

    it("marks batch as finalized after successful submitBatch", async function () {
        expect(await registry.isBatchFinalized(VALID_MERKLE)).to.be.true;
    });

    it("stores LOG=10 commitment for finalized batch (getCommitmentsLog10)", async function () {
        expect(await registry.getCommitmentsLog10(VALID_MERKLE)).to.equal(VALID_COMMIT_10);
    });

    it("stores LOG=8 commitment for finalized batch (getCommitmentsLog8)", async function () {
        expect(await registry.getCommitmentsLog8(VALID_MERKLE)).to.equal(VALID_COMMIT_8);
    });

    it("stores a non-zero finalization timestamp", async function () {
        expect(await registry.batchTimestamps(VALID_MERKLE)).to.be.gt(0n);
    });

    // ── submitBatch — input validation ────────────────────────────────────────

    it("reverts with InvalidMerkleRoot for zero merkle root", async function () {
        const zeroRoot = ethers.ZeroHash;
        await expect(
            registry.submitBatch(
                zeroRoot,
                VALID_COMMIT_10, VALID_PROOF_10, EMPTY_HINTS,
                VALID_COMMIT_8,  VALID_PROOF_8,  EMPTY_HINTS
            )
        ).to.be.revertedWithCustomError(registry, "InvalidMerkleRoot");
    });

    it("reverts with BatchAlreadyFinalized when merkle root reused", async function () {
        // VALID_MERKLE was finalized in the earlier test.
        await expect(
            registry.submitBatch(
                VALID_MERKLE,
                VALID_COMMIT_10, VALID_PROOF_10, EMPTY_HINTS,
                VALID_COMMIT_8,  VALID_PROOF_8,  EMPTY_HINTS
            )
        ).to.be.revertedWithCustomError(registry, "BatchAlreadyFinalized");
    });

    it("reverts with Log10ProofInvalid when LOG=10 verify() returns false", async function () {
        const freshRoot = "0x" + "a1".repeat(32);
        // all-zeros commitment is never valid (zero check fires before Blake2s)
        const wrongCommit10 = "0x" + "00".repeat(16);
        const [, br8] = makeBoundRoots(freshRoot);
        const goodCommit8   = await makeCommitment(b2s, "dc", br8);
        await expect(
            registry.submitBatch(
                freshRoot,
                wrongCommit10,  VALID_PROOF_10, EMPTY_HINTS,
                goodCommit8,    VALID_PROOF_8,  EMPTY_HINTS
            )
        ).to.be.revertedWithCustomError(registry, "Log10ProofInvalid");
    });

    it("reverts with Log8ProofInvalid when LOG=8 verify() returns false (LOG=10 passes)", async function () {
        const freshRoot = "0x" + "b2".repeat(32);
        const [br10, ] = makeBoundRoots(freshRoot);
        const goodCommit10 = await makeCommitment(b2s, "ab", br10);
        const wrongCommit8 = "0x" + "00".repeat(16);
        await expect(
            registry.submitBatch(
                freshRoot,
                goodCommit10,  VALID_PROOF_10, EMPTY_HINTS,
                wrongCommit8,  VALID_PROOF_8,  EMPTY_HINTS
            )
        ).to.be.revertedWithCustomError(registry, "Log8ProofInvalid");
    });

    it("reverts with Log10ProofInvalid when BOTH proofs fail (first check fires)", async function () {
        // Deploy an AlwaysFalse verifier and temporarily swap it in.
        const AFFactory = await ethers.getContractFactory("AlwaysFalseVerifier");
        const alwaysFalse = await AFFactory.deploy();
        await registry.setVerifier(await alwaysFalse.getAddress());

        const freshRoot = "0x" + "c3".repeat(32);
        await expect(
            registry.submitBatch(
                freshRoot,
                VALID_COMMIT_10, VALID_PROOF_10, EMPTY_HINTS,
                VALID_COMMIT_8,  VALID_PROOF_8,  EMPTY_HINTS
            )
        ).to.be.revertedWithCustomError(registry, "Log10ProofInvalid");

        // Restore the mock verifier.
        await registry.setVerifier(await mockVerifier.getAddress());
    });

    it("reverts with Log8ProofInvalid via SentinelVerifier (first call passes, second rejects SENTINEL)", async function () {
        // Deploy SentinelVerifier and swap it in; SENTINEL is 0xdeadbeefdeadbeef0000000000000000.
        const SentinelFactory = await ethers.getContractFactory("SentinelVerifier");
        const sentinelV = await SentinelFactory.deploy();
        const SENTINEL = await sentinelV.SENTINEL();   // bytes16 constant from contract

        // Temporarily use SentinelVerifier.
        const originalVerifier = await mockVerifier.getAddress();
        await registry.setVerifier(await sentinelV.getAddress());

        const freshRoot    = "0x" + "d4".repeat(32);
        const [br10, ] = makeBoundRoots(freshRoot);
        const goodCommit10 = await makeCommitment(b2s, "ab", br10);
        // Pass SENTINEL as commitmentLog8 → SentinelVerifier rejects it → Log8ProofInvalid.
        await expect(
            registry.submitBatch(
                freshRoot,
                goodCommit10, VALID_PROOF_10, EMPTY_HINTS,
                SENTINEL,     VALID_PROOF_8,  EMPTY_HINTS
            )
        ).to.be.revertedWithCustomError(registry, "Log8ProofInvalid");

        // Restore original verifier.
        await registry.setVerifier(originalVerifier);
    });

    // ── isBatchFinalized: false before, true after ────────────────────────────

    it("returns false for an unknown Merkle root", async function () {
        const unknownRoot = "0x" + "ff".repeat(32);
        expect(await registry.isBatchFinalized(unknownRoot)).to.be.false;
    });

    // ── Admin — setVerifier ───────────────────────────────────────────────────

    it("allows owner to update verifier and emits VerifierUpdated", async function () {
        const MockFactory  = await ethers.getContractFactory("MockVerifierV4Dual");
        const newVerifier  = await MockFactory.deploy();
        const newAddr      = await newVerifier.getAddress();
        const oldAddr      = await mockVerifier.getAddress();

        await expect(registry.setVerifier(newAddr))
            .to.emit(registry, "VerifierUpdated")
            .withArgs(oldAddr, newAddr);

        expect(await registry.verifier()).to.equal(newAddr);

        // Restore original verifier.
        await registry.setVerifier(oldAddr);
    });

    it("reverts setVerifier from non-owner", async function () {
        const MockFactory = await ethers.getContractFactory("MockVerifierV4Dual");
        const newV = await MockFactory.deploy();
        await expect(
            registry.connect(other).setVerifier(await newV.getAddress())
        ).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
    });

    it("reverts setVerifier(address(0)) with ZeroAddressVerifier", async function () {
        await expect(
            registry.setVerifier(ethers.ZeroAddress)
        ).to.be.revertedWithCustomError(registry, "ZeroAddressVerifier");
    });

    // ── submitBatchWithNonces — nonce replay protection ───────────────────────

    describe("submitBatchWithNonces", function () {
        let nonceMerkle;
        let nonceSender;

        before(function () {
            nonceMerkle  = "0x" + "e5".repeat(32);
            nonceSender  = "0x" + "f6".repeat(32);
        });

        async function makeNonceCommitments(merkleHex) {
            const [br10, br8] = makeBoundRoots(merkleHex);
            const c10 = await makeCommitment(b2s, "ab", br10);
            const c8  = await makeCommitment(b2s, "dc", br8);
            return { c10, c8 };
        }

        it("accepts first submitBatchWithNonces with nonce=1, emits NonceAdvanced + BatchFinalized", async function () {
            const { c10, c8 } = await makeNonceCommitments(nonceMerkle);
            await expect(
                registry.submitBatchWithNonces(
                    nonceMerkle,
                    c10, VALID_PROOF_10, EMPTY_HINTS,
                    c8,  VALID_PROOF_8,  EMPTY_HINTS,
                    [nonceSender], [1n]
                )
            )
                .to.emit(registry, "BatchFinalized")
                .and.to.emit(registry, "NonceAdvanced").withArgs(nonceSender, 1n);

            expect(await registry.senderNonces(nonceSender)).to.equal(1n);
        });

        it("reverts on replay with same nonce (SenderNonceTooLow)", async function () {
            const freshRoot = "0x" + "a7".repeat(32);
            const { c10, c8 } = await makeNonceCommitments(freshRoot);
            await expect(
                registry.submitBatchWithNonces(
                    freshRoot,
                    c10, VALID_PROOF_10, EMPTY_HINTS,
                    c8,  VALID_PROOF_8,  EMPTY_HINTS,
                    [nonceSender], [1n]  // same nonce as before
                )
            ).to.be.revertedWithCustomError(registry, "SenderNonceTooLow");
        });

        it("accepts higher nonce in subsequent submitBatchWithNonces", async function () {
            const freshRoot = "0x" + "b8".repeat(32);
            const { c10, c8 } = await makeNonceCommitments(freshRoot);
            await expect(
                registry.submitBatchWithNonces(
                    freshRoot,
                    c10, VALID_PROOF_10, EMPTY_HINTS,
                    c8,  VALID_PROOF_8,  EMPTY_HINTS,
                    [nonceSender], [5n]
                )
            ).to.emit(registry, "NonceAdvanced").withArgs(nonceSender, 5n);

            expect(await registry.senderNonces(nonceSender)).to.equal(5n);
        });

        it("reverts with NoncesLengthMismatch when arrays differ in length", async function () {
            const freshRoot = "0x" + "c9".repeat(32);
            const { c10, c8 } = await makeNonceCommitments(freshRoot);
            await expect(
                registry.submitBatchWithNonces(
                    freshRoot,
                    c10, VALID_PROOF_10, EMPTY_HINTS,
                    c8,  VALID_PROOF_8,  EMPTY_HINTS,
                    [nonceSender], [10n, 11n]  // 1 sender, 2 nonces
                )
            ).to.be.revertedWithCustomError(registry, "NoncesLengthMismatch");
        });

        it("zero-nonce entry always fails (nonce must exceed stored 0)", async function () {
            const freshRoot   = "0x" + "da".repeat(32);
            const freshSender = "0x" + "eb".repeat(32);
            const { c10, c8 } = await makeNonceCommitments(freshRoot);
            await expect(
                registry.submitBatchWithNonces(
                    freshRoot,
                    c10, VALID_PROOF_10, EMPTY_HINTS,
                    c8,  VALID_PROOF_8,  EMPTY_HINTS,
                    [freshSender], [0n]
                )
            ).to.be.revertedWithCustomError(registry, "SenderNonceTooLow");
        });

        it("reverts duplicate sender with non-increasing nonces in same call", async function () {
            const freshRoot   = "0x" + "fc".repeat(32);
            const freshSender = "0x" + "0d".repeat(32);
            const { c10, c8 } = await makeNonceCommitments(freshRoot);
            // Same sender twice with equal nonces.
            await expect(
                registry.submitBatchWithNonces(
                    freshRoot,
                    c10, VALID_PROOF_10, EMPTY_HINTS,
                    c8,  VALID_PROOF_8,  EMPTY_HINTS,
                    [freshSender, freshSender], [3n, 3n]
                )
            ).to.be.revertedWithCustomError(registry, "SenderNonceTooLow");
        });
    });
});
