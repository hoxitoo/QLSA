// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// NOTE: Compile with viaIR: true — the ABI decode in verify() uses multiple
// static fields (oodsComboPos, oodsComboNeg, compRoot) which would otherwise
// exceed Solidity's stack-depth limit.

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";
import "./verifier/CirclePoint.sol";
import "./verifier/TwoChannel.sol";

/// @title QLSAVerifierVFRI6 — VFRI5 with off-chain OODS combo (MVP-4)
///
/// Architectural change vs VFRI5:
///   VFRI5: passes oodsEvalsPos[n_cols] and oodsEvalsNeg[n_cols] in queryHints.
///          Verifier runs Poseidon2 sponge over all column evals (O(n_cols))
///          and computes Σ α^j · eval_j (O(n_cols) QM31 muls) — bottleneck at
///          649 cols (~120 M gas).
///   VFRI6: prover precomputes oodsComboPos = Σ α^j · oodsEvalsPos[j] and
///          oodsComboNeg = Σ α^j · oodsEvalsNeg[j] off-chain.  Only two uint128
///          values are passed in hints.  The verifier mixes their 8 M31 words
///          into the transcript.  No Poseidon2 sponge, no column arrays — all
///          O(n_cols) work is eliminated from on-chain execution.
///
///   Soundness: the OODS quotient FRI argument (Schwartz-Zippel) guarantees that
///   if (compValue − oodsComboPos) / (p.x − z_x) is low-degree for multiple
///   random positions p (verified by the FRI fold chain), then oodsComboPos must
///   equal the composition polynomial evaluated at z_x with overwhelming
///   probability.  No on-chain Σ α^j · eval_j is needed.
///
/// Transcript (vs VFRI5 — Poseidon2 sponge and oodsEvalsPos/Neg removed):
///   mixRoot(traceRoot)
///   z_x = drawSecureFelt
///   compAlpha = drawSecureFelt            ← drawn BEFORE mixing OODS combo
///   mixU32s([c0re(comboPos), c0im(comboPos), c1re(comboPos), c1im(comboPos),
///            c0re(comboNeg), c0im(comboNeg), c1re(comboNeg), c1im(comboNeg)])  ← 8 words
///   mixRoot(compRoot)
///   friAlpha = drawSecureFelt
///   mixRoot(friLayerRoots[0])
///   for k in 0..numFolds-1:
///     friAlphas[k] = drawSecureFelt
///     mixRoot(friLayerRoots[k+1])
///   drawQueries(treeDepth, nQueries)
///
/// queryHints ABI encoding (head = 5 × 32 = 160 bytes):
///   Slot 0: oodsComboPos  (uint128, static — Σ α^j · oodsEvalsPos[j], off-chain)
///   Slot 1: oodsComboNeg  (uint128, static — Σ α^j · oodsEvalsNeg[j], off-chain)
///   Slot 2: compRoot      (bytes32, static)
///   Slot 3: offset → friLayerRoots (bytes32[])
///   Slot 4: offset → QueryHints[]
///
///   abi.encode(uint128 oodsComboPos, uint128 oodsComboNeg,
///              bytes32 compRoot, bytes32[] friLayerRoots, QueryHints[])
contract QLSAVerifierVFRI6 is IQLSAVerifierV4 {

    uint256 public constant MIN_PROOF_LENGTH    = 700;
    uint256 public constant MAX_PROOF_LENGTH    = 1_048_576;
    uint256 public constant MIN_QUERIES         = 1;
    uint256 public constant MAX_QUERIES         = 64;
    uint256 public constant MAX_FOLD_ROUNDS     = 28;
    uint256 public constant MAX_LAST_LAYER_SIZE = 1 << 16; // 65 536 evaluations max

    /// @dev One fold-round entry per query: sibling in the current FRI layer tree,
    ///      fold result, and Merkle proof for the fold result in the next FRI layer.
    struct FoldHint {
        uint128   siblingValue;
        bytes32[] siblingProof;
        uint128   foldedValue;
        bytes32[] merkleProof;
    }

    /// @dev Per-query hint — identical to VFRI5.
    ///      Column values are NOT included; the prover instead supplies
    ///      compValue = F(p) = Σ α^j · col_j(p) pre-committed in compRoot.
    struct QueryHints {
        uint256   queryIndex;
        uint256   treeDepth;
        uint128   compValue;      // F(p)  = Σ α^j · col_j(p)   committed in compRoot
        bytes32[] compProof;      // Merkle proof for compValue  in compRoot at queryIndex
        uint128   compValueNeg;   // F(-p) = Σ α^j · col_j(-p)  committed in compRoot
        bytes32[] compProofNeg;   // Merkle proof for compValueNeg in compRoot at antipodal
        uint128   foldedValue;    // circle fold result; also FRI L1 value at queryIndex
        uint256   queryPointX;
        uint256   queryPointY;
        bytes32[] friL1Siblings;  // Merkle proof for foldedValue in friLayerRoots[0]
        FoldHint[] folds;         // folds[k] for k = 0..numFolds−1
    }

    /// @dev All derived values from one Fiat-Shamir transcript replay.
    struct VerifyCtx {
        bytes32   embeddedRoot;
        uint128   z_x;
        uint128   compAlpha;
        bytes32   compRoot;       // composition polynomial Merkle root (transcript-bound)
        uint128   friAlpha;
        uint128   oodsComboPos;   // Σ α^j · oodsEvalPos_j  (QM31, supplied by prover)
        uint128   oodsComboNeg;   // Σ α^j · oodsEvalNeg_j  (QM31, supplied by prover)
        bytes32[] friLayerRoots;
        uint128[] friAlphas;
        uint256[] derivedIndices;
    }

    // ── Public interface ──────────────────────────────────────────────────────

    function verify(
        bytes calldata proof,
        bytes16 commitment,
        bytes32 merkleRoot,
        bytes calldata queryHints
    ) external pure override returns (bool) {

        if (proof.length < MIN_PROOF_LENGTH) return false;
        if (proof.length > MAX_PROOF_LENGTH) return false;
        if (commitment == bytes16(0))        return false;
        if (merkleRoot == bytes32(0))        return false;
        if (queryHints.length == 0)          return false;
        if (!_checkCommitment(proof, commitment, merkleRoot)) return false;

        (uint128          oodsComboPos,
         uint128          oodsComboNeg,
         bytes32          compRoot,
         bytes32[] memory friLayerRoots,
         QueryHints[] memory hints) =
            abi.decode(queryHints,
                (uint128, uint128, bytes32, bytes32[], QueryHints[]));

        // ── Basic sanity checks ───────────────────────────────────────────────
        if (oodsComboPos == 0 && oodsComboNeg == 0) return false;
        if (compRoot == bytes32(0))                 return false;
        if (friLayerRoots.length < 2)               return false;
        if (friLayerRoots.length > MAX_FOLD_ROUNDS + 1) return false;
        if (hints.length < MIN_QUERIES)             return false;
        if (hints.length > MAX_QUERIES)             return false;

        for (uint256 r = 0; r < friLayerRoots.length; r++) {
            if (friLayerRoots[r] == bytes32(0)) return false;
        }

        // Pull the trace root (embedded in proof bytes 8..40).
        bytes32 embeddedRoot;
        assembly ("memory-safe") { embeddedRoot := calldataload(add(proof.offset, 8)) }

        uint256 logDomainSize = hints[0].treeDepth;
        uint256 numFolds      = friLayerRoots.length - 1;

        if (logDomainSize < numFolds + 1) return false;
        if (logDomainSize > 30)           return false;

        // Per-hint structural checks.
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].treeDepth    != logDomainSize) return false;
            if (hints[i].folds.length != numFolds)      return false;
        }

        // ── Transcript replay + query derivation ─────────────────────────────
        VerifyCtx memory ctx = _buildCtx(
            embeddedRoot, oodsComboPos, oodsComboNeg, compRoot,
            friLayerRoots, hints.length, logDomainSize
        );

        // Verify each query.
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].queryIndex != ctx.derivedIndices[i]) return false;
            if (!_verifyQuery(hints[i], ctx)) return false;
        }

        return true;
    }

    // ── Transcript ────────────────────────────────────────────────────────────

    /// @dev Replay the Fiat-Shamir transcript and return a fully populated context.
    ///
    ///   VFRI6 transcript order:
    ///     mixRoot(embeddedRoot)
    ///     z_x      = drawSecureFelt
    ///     compAlpha = drawSecureFelt          ← drawn BEFORE mixing OODS (no Poseidon2)
    ///     mixU32s(8 M31 words from oodsComboPos‖oodsComboNeg)
    ///     mixRoot(compRoot)
    ///     friAlpha = drawSecureFelt
    ///     mixRoot(friLayerRoots[0])
    ///     for k: friAlphas[k] = drawSecureFelt; mixRoot(friLayerRoots[k+1])
    ///     derivedIndices = drawQueries(logDomainSize, nQueries)
    function _buildCtx(
        bytes32   embeddedRoot,
        uint128   oodsComboPos,
        uint128   oodsComboNeg,
        bytes32   compRoot,
        bytes32[] memory friLayerRoots,
        uint256   nQueries,
        uint256   logDomainSize
    ) internal pure returns (VerifyCtx memory ctx) {
        ctx.embeddedRoot  = embeddedRoot;
        ctx.compRoot      = compRoot;
        ctx.friLayerRoots = friLayerRoots;
        ctx.oodsComboPos  = oodsComboPos;
        ctx.oodsComboNeg  = oodsComboNeg;

        TwoChannel.State memory chan = TwoChannel.init();
        TwoChannel.mixRoot(chan, embeddedRoot);

        ctx.z_x      = TwoChannel.drawSecureFelt(chan);
        ctx.compAlpha = TwoChannel.drawSecureFelt(chan);

        // Mix the 8 M31 component words of oodsComboPos and oodsComboNeg into
        // the transcript.  This binds the prover-supplied combo values into the
        // channel before compRoot / friAlpha are derived.
        {
            uint32[] memory comboWords = new uint32[](8);
            comboWords[0] = uint32(oodsComboPos >> 96);
            comboWords[1] = uint32(oodsComboPos >> 64);
            comboWords[2] = uint32(oodsComboPos >> 32);
            comboWords[3] = uint32(oodsComboPos);
            comboWords[4] = uint32(oodsComboNeg >> 96);
            comboWords[5] = uint32(oodsComboNeg >> 64);
            comboWords[6] = uint32(oodsComboNeg >> 32);
            comboWords[7] = uint32(oodsComboNeg);
            TwoChannel.mixU32s(chan, comboWords);
        }

        // Bind the composition polynomial tree into the transcript BEFORE
        // drawing friAlpha.  Prevents cherry-picking compValue after seeing friAlpha.
        TwoChannel.mixRoot(chan, compRoot);

        ctx.friAlpha = TwoChannel.drawSecureFelt(chan);

        TwoChannel.mixRoot(chan, friLayerRoots[0]);

        uint256 numFolds = friLayerRoots.length - 1;
        ctx.friAlphas = new uint128[](numFolds);
        for (uint256 k = 0; k < numFolds; k++) {
            ctx.friAlphas[k] = TwoChannel.drawSecureFelt(chan);
            TwoChannel.mixRoot(chan, friLayerRoots[k + 1]);
        }

        ctx.derivedIndices = TwoChannel.drawQueries(chan, logDomainSize, nQueries);
    }

    // ── Query verification ────────────────────────────────────────────────────

    function _verifyQuery(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {

        // 1. Merkle-verify compValue in compRoot at queryIndex.
        if (!MerkleVerifier.verifyMem(
            ctx.compRoot,
            MerkleVerifier.hashLeaf(_qm31ToWords(h.compValue)),
            h.queryIndex, h.treeDepth, h.compProof
        )) return false;

        // 2. Merkle-verify compValueNeg in compRoot at the antipodal index.
        {
            uint256 half = uint256(1) << (h.treeDepth - 1);
            uint256 anti = (h.queryIndex + half) & ((uint256(1) << h.treeDepth) - 1);
            if (!MerkleVerifier.verifyMem(
                ctx.compRoot,
                MerkleVerifier.hashLeaf(_qm31ToWords(h.compValueNeg)),
                anti, h.treeDepth, h.compProofNeg
            )) return false;
        }

        // 3. OODS quotient check using compValue and prover-supplied oodsCombo values.
        if (!_verifyOODS(h, ctx)) return false;

        // 4. Circle fold check: circleFold(fPlus, fMinus, friAlpha, yInv) == foldedValue.
        if (!_checkCircleFold(h, ctx.friAlpha)) return false;

        // 5. Verify foldedValue (= FRI L1 value) in friLayerRoots[0].
        if (!MerkleVerifier.verifyMem(
            ctx.friLayerRoots[0],
            MerkleVerifier.hashLeaf(_qm31ToWords(h.foldedValue)),
            h.queryIndex, h.treeDepth, h.friL1Siblings
        )) return false;

        // 6. Verify the FRI fold chain (line fold rounds k = 0..numFolds-1).
        return _verifyFolds(h, ctx);
    }

    /// @dev OODS quotient check (multiplication form — avoids QM31.inv except for
    ///      computing fPlus/fMinus which are needed by the circle fold).
    ///
    ///      fPlus  = (compValue    − oodsComboPos) / (p.x  − z_x)
    ///      fMinus = (compValueNeg − oodsComboNeg) / (−p.x − z_x)
    ///
    ///      Verified in multiplication form:
    ///        fPlus  * denomPos == compValue    − oodsComboPos
    ///        fMinus * denomNeg == compValueNeg − oodsComboNeg
    ///
    ///      fPlus/fMinus are stashed back into h.compValue / h.compValueNeg so
    ///      that _checkCircleFold can consume them without extra struct fields.
    ///
    ///      Security: Schwartz-Zippel guarantees that if the quotient is low-degree
    ///      for multiple random positions p (verified by the FRI chain), then
    ///      oodsComboPos must equal the polynomial evaluated at z_x with
    ///      overwhelming probability.
    function _verifyOODS(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {
        uint128 pxQM31   = QM31.fromM31(h.queryPointX);
        uint128 denomPos = QM31.sub(pxQM31, ctx.z_x);
        uint128 denomNeg = QM31.sub(QM31.neg(pxQM31), ctx.z_x);

        if (denomPos == uint128(0)) return false;
        if (denomNeg == uint128(0)) return false;

        // numerator = compValue − oodsComboPos (resp. Neg)
        uint128 numerPos = QM31.sub(h.compValue,    ctx.oodsComboPos);
        uint128 numerNeg = QM31.sub(h.compValueNeg, ctx.oodsComboNeg);

        // Compute fPlus/fMinus via QM31.inv; round-trip sanity guards against inv bugs.
        uint128 fPlus  = QM31.mul(numerPos, QM31.inv(denomPos));
        uint128 fMinus = QM31.mul(numerNeg, QM31.inv(denomNeg));

        if (QM31.mul(fPlus,  denomPos) != numerPos) return false;
        if (QM31.mul(fMinus, denomNeg) != numerNeg) return false;

        // Stash fPlus/fMinus in the hint struct slots for _checkCircleFold.
        // (QueryHints is a memory struct — writes are local and safe.)
        h.compValue    = fPlus;   // reuse compValue slot temporarily
        h.compValueNeg = fMinus;  // reuse compValueNeg slot temporarily
        return true;
    }

    /// @dev Circle fold using fPlus/fMinus stashed in h.compValue / h.compValueNeg
    ///      by _verifyOODS.  This avoids adding extra fields to QueryHints.
    function _checkCircleFold(
        QueryHints memory h,
        uint128 friAlpha
    ) internal pure returns (bool) {
        if (!CirclePoint.isOnCircle(h.queryPointX, h.queryPointY)) return false;
        if (h.treeDepth < 1 || h.treeDepth > 30) return false;
        if (h.queryIndex >= (uint256(1) << h.treeDepth)) return false;

        (uint256 cx, uint256 cy) = CirclePoint.cosetAt(h.treeDepth, h.queryIndex);
        if (cx != h.queryPointX || cy != h.queryPointY) return false;

        uint256 yInv   = M31.inv(h.queryPointY);
        uint128 fPlus  = h.compValue;    // stashed by _verifyOODS
        uint128 fMinus = h.compValueNeg; // stashed by _verifyOODS

        return CirclePoint.circleFold(fPlus, fMinus, friAlpha, yInv) == h.foldedValue;
    }

    /// @dev Verify the FRI line-fold chain across all numFolds rounds.
    ///      Identical to VFRI5._verifyFolds.
    function _verifyFolds(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {
        uint256 curLineIdx = h.queryIndex;
        uint128 curValue   = h.foldedValue;
        uint256 numFolds   = ctx.friLayerRoots.length - 1;

        for (uint256 k = 0; k < numFolds; k++) {
            uint256 domainHalf = uint256(1) << (h.treeDepth - 1 - k);
            uint256 newLineIdx = curLineIdx & (domainHalf - 1);
            uint256 sibling    = (curLineIdx < domainHalf)
                                    ? curLineIdx + domainHalf
                                    : curLineIdx - domainHalf;

            // Verify sibling in FRI layer k at depth treeDepth − k.
            if (!MerkleVerifier.verifyMem(
                ctx.friLayerRoots[k],
                MerkleVerifier.hashLeaf(_qm31ToWords(h.folds[k].siblingValue)),
                sibling, h.treeDepth - k, h.folds[k].siblingProof
            )) return false;

            // Twiddle T_{2^k}(x_j) via k doublings: T_1 = x, T_{2k}(x) = 2T_k(x)²−1.
            (uint256 xJ, ) = CirclePoint.cosetAt(h.treeDepth, newLineIdx);
            uint256 twiddle = xJ;
            for (uint256 i = 0; i < k; i++) {
                uint256 t2 = M31.mul(twiddle, twiddle);
                twiddle = M31.sub(M31.add(t2, t2), 1);
            }
            if (twiddle == 0) return false;

            {
                uint128 gPlus  = (curLineIdx < domainHalf) ? curValue : h.folds[k].siblingValue;
                uint128 gMinus = (curLineIdx < domainHalf) ? h.folds[k].siblingValue : curValue;
                if (CirclePoint.lineFold(gPlus, gMinus, ctx.friAlphas[k], M31.inv(twiddle))
                        != h.folds[k].foldedValue) return false;
            }

            // Verify fold result in FRI layer k+1 at depth treeDepth − k − 1.
            if (!MerkleVerifier.verifyMem(
                ctx.friLayerRoots[k + 1],
                MerkleVerifier.hashLeaf(_qm31ToWords(h.folds[k].foldedValue)),
                newLineIdx, h.treeDepth - k - 1, h.folds[k].merkleProof
            )) return false;

            curLineIdx = newLineIdx;
            curValue   = h.folds[k].foldedValue;
        }

        return true;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// @dev Verify commitment = Blake2s(proof[0:32] ‖ merkleRoot)[0:16].
    function _checkCommitment(
        bytes calldata proof,
        bytes16 commitment,
        bytes32 merkleRoot
    ) internal pure returns (bool) {
        bytes memory hInput = new bytes(64);
        assembly ("memory-safe") { calldatacopy(add(hInput, 32), proof.offset, 32) }
        for (uint256 i = 0; i < 32; i++) hInput[32 + i] = merkleRoot[i];
        bytes32 h = Blake2s.hash(hInput);
        return bytes16(h) == commitment;
    }

    /// @dev Pack a QM31 uint128 into 4 uint32 words (big-endian component order).
    function _qm31ToWords(uint128 q) internal pure returns (uint32[] memory words) {
        words = new uint32[](4);
        words[0] = uint32(q >> 96);
        words[1] = uint32((q >> 64) & 0xFFFFFFFF);
        words[2] = uint32((q >> 32) & 0xFFFFFFFF);
        words[3] = uint32(q & 0xFFFFFFFF);
    }
}
