// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// NOTE: Compile with viaIR: true — the ABI decode in verify() uses a bytes32
// field (compRoot) which would otherwise exceed Solidity's stack-depth limit.

import "./IQLSAVerifierV4.sol";
import "./verifier/Blake2s.sol";
import "./verifier/M31.sol";
import "./verifier/QM31.sol";
import "./verifier/MerkleVerifier.sol";
import "./verifier/CirclePoint.sol";
import "./verifier/TwoChannel.sol";
import "./verifier/Poseidon2M31.sol";

/// @title QLSAVerifierVFRI5 — VFRI4 with composition polynomial tree (MVP-4)
///
/// Architectural change vs VFRI4:
///   VFRI4: per-query hints carry queryValues[n_cols] + Merkle proof in trace
///          tree. Verifier computes Σ α^j · col_j(p) on-chain — O(n_cols) per
///          query.
///   VFRI5: prover commits F(x) = Σ α^j · col_j(x) for all domain positions in
///          a dedicated composition Merkle tree (compRoot). Per-query hints only
///          supply compValue = F(p) with a Merkle proof in compRoot — O(treeDepth)
///          per query, independent of the number of columns.
///          Σ α^j · oodsEval_j is still computed once inside _buildCtx for OODS.
///
/// Transcript (vs VFRI4):
///   mixRoot(traceRoot)
///   z_x = drawSecureFelt
///   Poseidon2Sponge(oodsPos_m31s) → mixU32s([ps0,ps1,ns0,ns1])   // same as VFRI4
///   compAlpha = drawSecureFelt
///   mixRoot(compRoot)              ← NEW: binds composition polynomial tree
///   friAlpha = drawSecureFelt
///   mixRoot(friLayerRoots[0])
///   for k in 0..numFolds-1:
///     friAlphas[k] = drawSecureFelt
///     mixRoot(friLayerRoots[k+1])
///   drawQueries(treeDepth, nQueries)
///
/// queryHints ABI encoding:
///   abi.encode(uint128[]  lastLayerCoeffs,
///              uint128[]  oodsEvalsPos,
///              uint128[]  oodsEvalsNeg,
///              bytes32    compRoot,
///              bytes32[]  friLayerRoots,
///              QueryHints[])
contract QLSAVerifierVFRI5 is IQLSAVerifierV4 {

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

    /// @dev Per-query hint.  Column values are NOT included; the prover instead
    ///      supplies compValue = F(p) = Σ α^j · col_j(p) pre-committed in compRoot.
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
        uint128   oodsComboPos;   // Σ α^j · oodsEvalPos_j  (QM31)
        uint128   oodsComboNeg;   // Σ α^j · oodsEvalNeg_j  (QM31)
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

        (uint128[] memory lastLayerCoeffs,
         uint128[] memory oodsEvalsPos,
         uint128[] memory oodsEvalsNeg,
         bytes32          compRoot,
         bytes32[] memory friLayerRoots,
         QueryHints[] memory hints) =
            abi.decode(queryHints,
                (uint128[], uint128[], uint128[], bytes32, bytes32[], QueryHints[]));

        // ── Basic sanity checks ───────────────────────────────────────────────
        if (compRoot == bytes32(0))                         return false;
        if (friLayerRoots.length < 2)                       return false;
        if (friLayerRoots.length > MAX_FOLD_ROUNDS + 1)     return false;
        if (hints.length < MIN_QUERIES)                     return false;
        if (hints.length > MAX_QUERIES)                     return false;
        if (oodsEvalsPos.length == 0)                       return false;
        if (oodsEvalsNeg.length != oodsEvalsPos.length)     return false;
        if (lastLayerCoeffs.length == 0)                    return false;

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

        // Per-hint structural checks (no column-value arrays — only folds count).
        for (uint256 i = 0; i < hints.length; i++) {
            if (hints[i].treeDepth   != logDomainSize) return false;
            if (hints[i].folds.length != numFolds)     return false;
        }

        // ── Last-layer polynomial check ───────────────────────────────────────
        // Verify that friLayerRoots[K] commits to the last-layer evaluations.
        {
            uint256 lastDepth     = logDomainSize - numFolds;
            uint256 lastLayerSize = uint256(1) << lastDepth;

            if (lastLayerCoeffs.length == 1) {
                // Constant polynomial optimisation: every leaf is the same value.
                bytes32 node = MerkleVerifier.hashLeaf(_qm31ToWords(lastLayerCoeffs[0]));
                for (uint256 i = 0; i < lastDepth; i++) {
                    node = MerkleVerifier.hashPair(node, node);
                }
                if (node != friLayerRoots[numFolds]) return false;
            } else {
                // Non-constant polynomial: build the full Merkle tree bottom-up.
                if (lastLayerCoeffs.length != lastLayerSize) return false;
                if (lastLayerSize > MAX_LAST_LAYER_SIZE)     return false;

                bytes32[] memory nodes = new bytes32[](lastLayerSize);
                for (uint256 i = 0; i < lastLayerSize; i++) {
                    nodes[i] = MerkleVerifier.hashLeaf(_qm31ToWords(lastLayerCoeffs[i]));
                }
                uint256 sz = lastLayerSize;
                while (sz > 1) {
                    sz >>= 1;
                    for (uint256 i = 0; i < sz; i++) {
                        nodes[i] = MerkleVerifier.hashPair(nodes[2 * i], nodes[2 * i + 1]);
                    }
                }
                if (nodes[0] != friLayerRoots[numFolds]) return false;
            }
        }

        // ── Transcript replay + query derivation ─────────────────────────────
        VerifyCtx memory ctx = _buildCtx(
            embeddedRoot, compRoot, oodsEvalsPos, oodsEvalsNeg,
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
    ///      VFRI5 transcript order:
    ///        mixRoot(embeddedRoot)
    ///        z_x = drawSecureFelt
    ///        Poseidon2(oodsPos) + Poseidon2(oodsNeg) → mixU32s(4 words)
    ///        compAlpha = drawSecureFelt
    ///        mixRoot(compRoot)                ← NEW
    ///        friAlpha = drawSecureFelt
    ///        mixRoot(friLayerRoots[0])
    ///        for k: friAlphas[k] = drawSecureFelt; mixRoot(friLayerRoots[k+1])
    ///        derivedIndices = drawQueries(logDomainSize, nQueries)
    function _buildCtx(
        bytes32 embeddedRoot,
        bytes32 compRoot,
        uint128[] memory oodsEvalsPos,
        uint128[] memory oodsEvalsNeg,
        bytes32[] memory friLayerRoots,
        uint256 nQueries,
        uint256 logDomainSize
    ) internal pure returns (VerifyCtx memory ctx) {
        ctx.embeddedRoot  = embeddedRoot;
        ctx.compRoot      = compRoot;
        ctx.friLayerRoots = friLayerRoots;

        TwoChannel.State memory chan = TwoChannel.init();
        TwoChannel.mixRoot(chan, embeddedRoot);

        ctx.z_x = TwoChannel.drawSecureFelt(chan);

        // Poseidon2 OODS sponge: same as VFRI4 — O(1) channel mixing.
        {
            uint256[] memory posM31s = _qm31ArrayToM31s(oodsEvalsPos);
            uint256[] memory negM31s = _qm31ArrayToM31s(oodsEvalsNeg);
            (uint256 ps0, uint256 ps1) = Poseidon2M31.sponge(posM31s);
            (uint256 ns0, uint256 ns1) = Poseidon2M31.sponge(negM31s);
            uint32[] memory oodsHash = new uint32[](4);
            oodsHash[0] = uint32(ps0); oodsHash[1] = uint32(ps1);
            oodsHash[2] = uint32(ns0); oodsHash[3] = uint32(ns1);
            TwoChannel.mixU32s(chan, oodsHash);
        }

        ctx.compAlpha = TwoChannel.drawSecureFelt(chan);

        // Bind the composition polynomial tree into the transcript BEFORE
        // drawing friAlpha.  This prevents the prover from cherry-picking
        // compValue after seeing friAlpha.
        TwoChannel.mixRoot(chan, compRoot);

        ctx.friAlpha = TwoChannel.drawSecureFelt(chan);

        // Pre-compute OODS linear combinations (done once, shared across queries).
        ctx.oodsComboPos = _compositionQM31(oodsEvalsPos, ctx.compAlpha);
        ctx.oodsComboNeg = _compositionQM31(oodsEvalsNeg, ctx.compAlpha);

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

        // 3. OODS quotient check using compValue directly (multiplication form).
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

    /// @dev OODS quotient check (multiplication form — avoids QM31.inv).
    ///      compValue replaces the raw column-value composition from VFRI4.
    ///
    ///      fPlus  · (p.x − z_x)   == compValue    − oodsComboPos
    ///      fMinus · (−p.x − z_x)  == compValueNeg − oodsComboNeg
    ///
    ///      fPlus and fMinus are derived here (not supplied in hints) using
    ///      QM31.inv when the denominators are non-zero, so we can feed them
    ///      into the circle fold.  We store them in the QueryHints fields
    ///      foldedValue/queryPointX just for the fold — but actually we need
    ///      to pass fPlus/fMinus to _checkCircleFold.  Therefore we compute
    ///      them here and call _checkCircleFoldValues directly.
    function _verifyOODS(
        QueryHints memory h,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {
        uint128 pxQM31   = QM31.fromM31(h.queryPointX);
        uint128 denomPos = QM31.sub(pxQM31, ctx.z_x);
        uint128 denomNeg = QM31.sub(QM31.neg(pxQM31), ctx.z_x);

        if (denomPos == uint128(0)) return false;
        if (denomNeg == uint128(0)) return false;

        // fPlus  = (compValue    - oodsComboPos) / denomPos
        // fMinus = (compValueNeg - oodsComboNeg) / denomNeg
        uint128 numerPos = QM31.sub(h.compValue,    ctx.oodsComboPos);
        uint128 numerNeg = QM31.sub(h.compValueNeg, ctx.oodsComboNeg);

        // Verify in multiplication form to avoid inversion:
        //   fPlus  * denomPos == numerPos
        //   fMinus * denomNeg == numerNeg
        //
        // We also need fPlus/fMinus for the circle fold.  Compute them via
        // QM31.inv (cheaper than a second multiplication check path) and
        // stash them in memory locals — they are NOT taken from hint fields.
        uint128 fPlus  = QM31.mul(numerPos, QM31.inv(denomPos));
        uint128 fMinus = QM31.mul(numerNeg, QM31.inv(denomNeg));

        // Sanity: round-trip check (guards against inv bugs).
        if (QM31.mul(fPlus,  denomPos) != numerPos) return false;
        if (QM31.mul(fMinus, denomNeg) != numerNeg) return false;

        // Store fPlus/fMinus back into the hint so _checkCircleFold can use them.
        // (QueryHints is a memory struct — writes are safe.)
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
        if (h.queryPointY == 0) return false;
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
    ///      Identical to VFRI4._verifyFolds — the fold chain is independent
    ///      of how fPlus/fMinus were obtained.
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

            // Verify sibling in FRI L(k+1) at depth treeDepth − k.
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

            // Verify fold result in FRI L(k+2) at depth treeDepth − k − 1.
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

    /// @dev Compute Σ_{j} α^j · evals[j] over QM31 (OODS linear combination).
    function _compositionQM31(uint128[] memory evals, uint128 alpha)
        internal pure returns (uint128 r)
    {
        uint128 ap = QM31.fromM31(1);
        for (uint256 j = 0; j < evals.length; j++) {
            r  = QM31.add(r, QM31.mul(ap, evals[j]));
            ap = QM31.mul(ap, alpha);
        }
    }

    /// @dev Pack a QM31 uint128 into 4 uint32 words (big-endian component order).
    function _qm31ToWords(uint128 q) internal pure returns (uint32[] memory words) {
        words = new uint32[](4);
        words[0] = uint32(q >> 96);
        words[1] = uint32((q >> 64) & 0xFFFFFFFF);
        words[2] = uint32((q >> 32) & 0xFFFFFFFF);
        words[3] = uint32(q & 0xFFFFFFFF);
    }

    /// @dev Unpack uint128[] QM31 values into uint256[] M31 components
    ///      (4 M31 words per QM31: c0.re, c0.im, c1.re, c1.im).
    ///      Used for the Poseidon2 sponge input.
    function _qm31ArrayToM31s(uint128[] memory evals)
        internal pure returns (uint256[] memory m31s)
    {
        m31s = new uint256[](evals.length * 4);
        for (uint256 i = 0; i < evals.length; i++) {
            uint128 q = evals[i];
            m31s[i * 4 + 0] = uint32(q >> 96);
            m31s[i * 4 + 1] = uint32(q >> 64);
            m31s[i * 4 + 2] = uint32(q >> 32);
            m31s[i * 4 + 3] = uint32(q);
        }
    }
}
