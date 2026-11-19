// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import "./QLSAVerifierRecursive.sol";

/// @title BatchRegistryV7 — recursive-proof batch registry (MVP-8)
///
/// Finalizes a V23 batch from RECURSIVE proofs: instead of verifying each trace
/// group's VFRI11 proof directly (BatchRegistryV5), it verifies, per group, a
/// STARK attesting that the inner VFRI11 proof was verified — plus the cheap
/// on-chain half the recursion deliberately leaves outside the circuit.
///
/// # What actually gets checked
///
/// `QLSAVerifierRecursive.verifyRecursive` covers, for one group:
///
///   on-chain   channel replay        -> the FRI challenges and query indices are
///                                       Fiat-Shamir-derived, not prover-chosen
///   on-chain   last-layer check      -> friLayerRoots[K] commits a bounded-degree
///                                       final layer (cheap + constant, so it stays
///                                       out of the circuit — see R4.13)
///   in-circuit compRoot -> compValue -> f_p -> fold chain -> finalFold -> hashLeaf
///              -> path -> friLayerRoots[K]   (R4.10 / R4.12 / C1)
///
/// # Cross-proof binding
///
/// A V23 batch is two trace groups, so two recursive bundles are submitted and
/// each is bound to the OTHER's trace root, exactly as BatchRegistryV5 does:
///
///     bundle10.inner.batchRoot == keccak256(merkleRoot | bundle8.inner.traceRoot)
///     bundle8.inner.batchRoot  == keccak256(merkleRoot | bundle10.inner.traceRoot)
///
/// `batchRoot` is mixed into the inner channel before its queries are drawn, so a
/// bundle assembled from a different witness draws different query indices and
/// fails. The binding is tighter here than in V5: there the registry read the
/// trace root out of raw proof bytes, whereas `traceRoot` is an explicit public
/// field that `outerBindingRoot` already commits to — an outer proof cannot be
/// replayed against a different trace root.
///
/// This rejects the case that matters — one group submitted as BOTH bundles,
/// since its `batchRoot` commits to the other group's trace root. Note the
/// constraint pair is SYMMETRIC under exchanging the bundles, so submitting them
/// in the opposite order is accepted: both remain valid proofs bound to this
/// `merkleRoot`, and neither can be duplicated, so it is not a soundness break —
/// but it does mean `batchCommitmentsLog10` / `batchCommitmentsLog8` are
/// POSITIONAL labels rather than enforced group identities. BatchRegistryV5's
/// binding has the same property. Enforcing the label would need a group tag in
/// the bound root (`keccak(merkleRoot | otherTraceRoot | groupId)`), which would
/// diverge from the V5 scheme and require regenerating every cross-bound fixture.
contract BatchRegistryV7 is Ownable, ReentrancyGuard {
    /// @notice One group's recursive bundle.
    struct RecursiveBundle {
        QLSAVerifierRecursive.InnerPublics inner;
        bytes outerProof;
        bytes16 outerCommitment;
        bytes outerHints;
        uint128[] lastLayerEvals;
    }

    /// @notice The recursive verifier used for BOTH groups.
    QLSAVerifierRecursive public verifier;

    /// @notice Hard backstop on senders per call — NOT a reachable capability: the
    ///         O(n²) duplicate scan bounds a call at n ~ 212 (measured; see
    ///         BatchRegistryV5 for the full gas table). Exceeding that is OUT OF
    ///         GAS, not a clean revert. Keep batches under ~150 senders.
    uint256 public constant MAX_SENDERS = 3000;

    /// @notice One storage slot per finalized batch.
    ///
    /// This used to be FIVE mappings — `finalizedBatches`, `batchTimestamps`,
    /// `batchCommitmentsLog10`, `batchCommitmentsLog8`, `batchTxListRoots` —
    /// i.e. five NEW slots per batch. Measured on Sepolia (2026-11-18), a new
    /// slot costs 80,820 gas more there than locally, and those five came to
    /// 404,100 of the batch's 434,700 gap. Only ONE value has to live in
    /// storage for the contract's own job — "has this root been finalized?" —
    /// so the record is one slot: the timestamp, which is non-zero for every
    /// finalized batch, and a 192-bit digest of the rest. The values themselves
    /// are in the `BatchFinalized` event (unchanged), and `batchRecordMatches`
    /// lets anyone holding them check them against storage.
    ///
    /// `finalizedBatches` and `batchTimestamps` keep their getters' signatures,
    /// as view functions below; the three commitment getters are gone — read
    /// the event, or check it with `batchRecordMatches`.
    struct BatchRecord {
        uint64 timestamp;
        bytes24 digest;
    }

    mapping(bytes32 => BatchRecord) public batchRecords;

    // ── txListRoot: the transaction-list commitment (in the record digest and
    //    the BatchFinalized event) ─────────────────────────────────────────────
    // Per batch, the submitter's commitment to the TRANSACTION LIST.
    //
    // **Attested, not proved.** This contract cannot check it — it has no
    // transactions — and proving `txListRoot == SHA3(tx hashes)` in-circuit
    // needs Keccak-f[1600] arithmetized, which is not done. Its value is that a
    // third party HOLDING the transaction list can recompute it; it carries no
    // soundness of its own.
    //
    // What IS proved lives in `merkleRoot`: the aggregation tree's membership
    // root, whose every leaf binds a member's `tx_id` (the first 124 bits of its
    // transaction hash) to the trace roots of the proofs verifying its
    // signature. So the transaction binding is proved at 124 bits per member;
    // `txListRoot` adds recomputability, not a new guarantee.
    //
    // It exists because `merkleRoot` depends on the prover's AIR layout — the
    // same transactions yield a different root after a pipeline change, and it
    // cannot be recomputed without running the prover. `txListRoot` has neither
    // property.
    //
    // **Zero means "not provided."** Unlike `merkleRoot`, a zero here is
    // accepted: the field is attested rather than verified, so rejecting zero
    // would only force a submitter with no transaction list — a test fixture,
    // a synthetic batch — to invent a value, which is worse than an honest
    // absence. A reader seeing zero should treat the batch as carrying no
    // transaction-list commitment, not as committing to an empty list.

    mapping(bytes32 => uint64) public senderNonces;

    // ── The nonce accumulator (A-4), an ALTERNATIVE to the mapping above ──────
    //
    // `senderNonces` costs a MEASURED 28,777 gas for a first-time sender and
    // 12,085 for a returning one (measurements.json), and the cost is per
    // sender. Against the 2^24 per-transaction cap that bounds a batch at ~71
    // new senders, while break-even needs N > 359. The accumulator replaces the
    // whole mapping with ONE root plus a proof that the transition was legal, so
    // the on-chain cost is one read and one write whatever N is.
    //
    // WHAT IT COSTS, stated here because the interface should not read stronger
    // than the guarantee. Today `newNonce > stored` is checked ABSOLUTELY, in
    // Solidity, with no proof involved. On the accumulator path the contract
    // still checks absolutely: the strict increase, the chain linkage, the slot
    // index, and that the chain starts at the stored root. What it CANNOT check
    // is that a claimed `oldNonce` is the slot's true value — that rests on the
    // transition proof, and `QLSAVerifierRecursive` is VFRI-partial (its own
    // NatSpec): constraint satisfaction and C1/C2 pinning are enforced
    // off-chain. So replay protection moves from an absolute check to a proved
    // one, under the same limitation the ML-DSA arithmetic already lives under.
    //
    // WHICH PATH IS LIVE IS FIXED AT CONSTRUCTION and cannot be changed. Two
    // live paths would be unsound: a transaction counted in the mapping is
    // invisible to the tree and vice versa, so a replay could go through
    // whichever path had not seen it. `accumulatorMode` therefore disables the
    // other path outright rather than leaving an owner switch and a window.
    //
    // Migration note: a Solidity mapping cannot be enumerated, so an existing
    // deployment's sender set is not recoverable on-chain. Moving to the
    // accumulator means deploying afresh with an initial root computed off-chain
    // from the known senders.
    bool public immutable accumulatorMode;

    /// @notice The nonce accumulator's state root — the whole replay-protection
    ///         state, in one slot. Meaningful only when `accumulatorMode`.
    bytes32 public nonceStateRoot;

    /// @notice Tree depth the state root is built at; fixes the slot count at
    ///         `2^nonceTreeDepth`. Capped at 28 by the AIR that proves the paths
    ///         (`merkle_path_t8_air::MAX_DEPTH`); 28 gives 268 million slots and
    ///         was measured to cost the same as 24.
    uint8 public immutable nonceTreeDepth;

    event BatchFinalized(
        bytes32 indexed merkleRoot,
        bytes16 indexed commitmentLog10,
        bytes16 commitmentLog8,
        bytes32 txListRoot,
        uint256 timestamp
    );
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event NonceAdvanced(bytes32 indexed sender, uint64 newNonce);
    /// @notice The accumulator moved. ONE event per batch, not one per sender.
    event NonceStateAdvanced(bytes32 indexed oldRoot, bytes32 indexed newRoot, uint256 updates);

    error InvalidMerkleRoot();
    error BatchAlreadyFinalized(bytes32 merkleRoot);
    error Log10ProofInvalid();
    error Log8ProofInvalid();
    error ZeroAddressVerifier();
    error SenderNonceTooLow(bytes32 sender, uint64 provided, uint64 expected);
    error NoncesLengthMismatch();
    error SenderCountExceedsLimit();
    /// @notice A bundle's `inner.batchRoot` is not the cross-bound root for this batch.
    error CrossBindingMismatch();

    // ── Accumulator errors ────────────────────────────────────────────────────
    /// @notice This deployment runs the other nonce path; the mode is immutable.
    error WrongNoncePath();
    /// @notice `oldRoot` is not the root this contract has stored.
    error NonceRootMismatch(bytes32 provided, bytes32 stored);
    /// @notice The transition proof does not attest THIS statement.
    error NonceBindingMismatch();
    /// @notice The transition proof failed verification.
    error NonceProofInvalid();
    /// @notice A slot index exceeds `2^nonceTreeDepth`.
    error NonceIndexOutOfRange(uint256 index);
    /// @notice A sender's slot is not the one its hash determines.
    error NonceSlotMismatch(uint256 index, uint32 provided, uint32 expected);
    /// @notice Depth outside [1, 28] — 28 is what the path AIR can prove.
    error NonceDepthOutOfRange();
    /// @notice A folded batch must move the accumulator; with no updates, use `submitBatch`.
    error NoNonceUpdates();

    /// @notice Deploy, choosing the nonce path ONCE and for good.
    ///
    /// `nonceDepth == 0` selects the MAPPING path (per-sender `senderNonces`),
    /// which is what every existing deployment runs; `initialRoot` must then be
    /// zero. A non-zero depth selects the ACCUMULATOR path.
    ///
    /// Solidity has no constructor overloading, so this is one constructor with
    /// a mode argument rather than two — which is also the honest shape, because
    /// the choice must be visible at the deployment site. Read the
    /// `accumulatorMode` comment above before passing a non-zero depth: it moves
    /// replay protection from an absolute check to a proved one.
    ///
    /// `initialRoot` is the starting state's root and must be computed
    /// off-chain — the empty tree's root for a fresh deployment, or a root over
    /// the known sender set when migrating. The contract cannot derive it: a
    /// mapping is not enumerable, so a migration's starting state is not
    /// on-chain data at all.
    constructor(
        address initialOwner,
        address _verifier,
        bytes32 initialRoot,
        uint8 nonceDepth
    ) Ownable(initialOwner) {
        if (_verifier == address(0)) revert ZeroAddressVerifier();
        verifier = QLSAVerifierRecursive(_verifier);

        if (nonceDepth == 0) {
            // Mapping path. A root here would be ignored, and an ignored
            // argument is how a deployment silently ends up on the wrong path.
            if (initialRoot != bytes32(0)) revert NonceRootMismatch(initialRoot, bytes32(0));
            accumulatorMode = false;
            nonceTreeDepth = 0;
        } else {
            // 28 is what the path AIR can prove (merkle_path_t8_air::MAX_DEPTH);
            // a deeper tree would be unprovable, so it is refused here rather
            // than discovered when the first proof fails.
            if (nonceDepth > 28) revert NonceDepthOutOfRange();
            if (initialRoot == bytes32(0)) revert NonceRootMismatch(initialRoot, bytes32(0));
            accumulatorMode = true;
            nonceTreeDepth = nonceDepth;
            nonceStateRoot = initialRoot;
        }
    }

    /// @notice The slot a sender owns: the low `nonceTreeDepth` bits of the
    ///         first four bytes of its hash, little-endian.
    ///
    /// No hashing happens here, and that is the point. `senders[i]` is ALREADY a
    /// hash — `core/transaction.py` sets `tx.sender` to SHA3-256 of the public
    /// key — so the slot is a bit extraction, costing a few gas rather than a
    /// Keccak. Proving `index == prefix(H(sender))` inside the circuit would
    /// need Keccak arithmetized, which is limitation 0 and not started; doing it
    /// here instead is what avoids that, and it is why the indices can be
    /// trusted as public inputs to the proof.
    ///
    /// Matches Rust `nonce_tree::slot_index` exactly, including the byte order.
    function nonceSlot(bytes32 sender) public view returns (uint32) {
        uint32 le = uint32(uint8(sender[0]))
            | (uint32(uint8(sender[1])) << 8)
            | (uint32(uint8(sender[2])) << 16)
            | (uint32(uint8(sender[3])) << 24);
        return le & uint32((uint256(1) << nonceTreeDepth) - 1);
    }

    function setVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddressVerifier();
        address old = address(verifier);
        verifier = QLSAVerifierRecursive(newVerifier);
        emit VerifierUpdated(old, newVerifier);
    }

    /// @notice The root a group's bundle must carry, given the OTHER group's trace root.
    function crossBoundRoot(bytes32 merkleRoot, bytes32 otherTraceRoot)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(merkleRoot, otherTraceRoot));
    }

    /// @notice One nonce update, as the contract sees it. All public.
    struct NonceUpdate {
        uint32 index;
        uint64 oldNonce;
        uint64 newNonce;
        /// @dev The state root after this update. The last must equal the new root.
        bytes32 postRoot;
    }

    /// @notice The binding the transition proof must carry as `inner.batchRoot`.
    ///
    /// Mirrors Rust `vfri2_bridge::nonce_statement_binding` byte-for-byte:
    ///
    ///   nUpdates(4) ‖ depth(4) ‖ oldRoot(32) ‖ newRoot(32)
    ///   ‖ per update: index(4) ‖ oldNonce(8) ‖ newNonce(8) ‖ postRoot(32)
    ///
    /// Count FIRST, so a statement cannot be reinterpreted at a different
    /// length, and EVERY field hashed — the R4.7 lesson, where
    /// `outerBindingRoot` bound 2 of 8 public fields and left six swappable
    /// while still returning ok=true.
    function nonceStatementBinding(
        bytes32 oldRoot,
        bytes32 newRoot,
        uint32 depth,
        NonceUpdate[] calldata updates
    ) public pure returns (bytes32) {
        // Written into ONE preallocated buffer. The first version grew it with
        // `buf = abi.encodePacked(buf, …)`, which copies the whole buffer on
        // every update — O(n²) in memory copying and expansion, in the call
        // whose point is a per-update cost that stays small.
        //
        // Each field goes in with an `mstore` of its value shifted to the top
        // of a word. A word write spills past the field, but the next field
        // overwrites the spill, and the LAST write of each record — `postRoot`,
        // a full 32 bytes — ends exactly at the record's end; so nothing is
        // written past the buffer. Values are read through Solidity's calldata
        // accessors first, so they are type-checked as before.
        uint256 n = updates.length;
        bytes memory buf = new bytes(72 + 52 * n);
        assembly {
            let p := add(buf, 32)
            mstore(p, shl(224, n))
            mstore(add(p, 4), shl(224, depth))
            mstore(add(p, 8), oldRoot)
            mstore(add(p, 40), newRoot)
        }
        for (uint256 i = 0; i < n; ++i) {
            NonceUpdate calldata u = updates[i];
            uint32 index = u.index;
            uint64 oldNonce = u.oldNonce;
            uint64 newNonce = u.newNonce;
            bytes32 postRoot = u.postRoot;
            assembly {
                let q := add(add(buf, 104), mul(i, 52))
                mstore(q, shl(224, index))
                mstore(add(q, 4), shl(192, oldNonce))
                mstore(add(q, 12), shl(192, newNonce))
                mstore(add(q, 20), postRoot)
            }
        }
        return keccak256(buf);
    }

    /// @notice The seed a FOLDED batch's two bundles are cross-bound under, in
    ///         place of `merkleRoot`.
    ///
    /// Mirrors Rust `vfri2_bridge::nonce_fold_seed`:
    /// `keccak256("QLSA/nonce-fold/v1" ‖ merkleRoot ‖ nonceBinding)`. The tag
    /// keeps it from ever equalling any other keccak of two roots here.
    function nonceFoldSeed(bytes32 merkleRoot, bytes32 nonceBinding)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked("QLSA/nonce-fold/v1", merkleRoot, nonceBinding));
    }

    /// @notice Advance the nonce STATE ROOT — O(1) storage, whatever N is.
    ///
    /// # Why this is its own transaction, and what that costs
    ///
    /// It was written to take the batch bundles too, so one call would finalize
    /// a batch AND advance the nonces. MEASURED, that does not fit: the
    /// transition proof's own `verifyRecursive` costs **6,940,263 gas** (1
    /// update) to **7,331,135** (25), and the tree batch already costs
    /// 14,663,950 — 21.6M against a 16,777,216 cap. The call reverted, which is
    /// how the figure came to be measured rather than assumed.
    ///
    /// So the transition is separate. That has a consequence worth stating
    /// plainly rather than burying: at ~6.94M constant against the mapping's
    /// measured 12,085 gas per RETURNING sender, this path only becomes cheaper
    /// above roughly **574 senders** — and one transaction admits about 172. So
    /// **as a separate proof the accumulator does not reach break-even**, and
    /// § A-4's claim that it is the lever that does is wrong in this form.
    ///
    /// What would make it pay is folding the nonce statement into the batch
    /// proof as a further path group, so it rides the two `verifyRecursive`
    /// calls already being paid for instead of adding a third. I had recorded
    /// the separate proof as "simpler and cheaper"; the first half was right.
    /// The fold is `submitBatchWithNonceUpdates` (2026-11-19); this entry point
    /// stays for a transition with no batch to ride on.
    ///
    /// # What is checked ABSOLUTELY here, with no reliance on the proof
    ///
    ///   * the chain starts at the root this contract has stored;
    ///   * every nonce strictly increases;
    ///   * every slot index is the one its sender's hash determines;
    ///   * the chain ends at the root being written.
    ///
    /// What rests on the proof: that each claimed `oldNonce` really is its
    /// slot's value in the preceding root. See the `accumulatorMode` comment.
    function submitNonceTransition(
        RecursiveBundle calldata nonceBundle,
        bytes32[] calldata senders,
        NonceUpdate[] calldata updates,
        bytes32 newNonceRoot
    ) external nonReentrant {
        if (!accumulatorMode) revert WrongNoncePath();
        bytes32 oldRoot = nonceStateRoot;
        _checkNonceUpdates(senders, updates);

        if (updates.length == 0) {
            // An empty transition must not move the root, or it would assert any
            // pair of roots with nothing to verify.
            if (newNonceRoot != oldRoot) revert NonceRootMismatch(newNonceRoot, oldRoot);
        } else {
            // The proof must attest THIS statement, not merely be a valid proof.
            bytes32 bound = _nonceBinding(oldRoot, updates, newNonceRoot);
            if (nonceBundle.inner.batchRoot != bound) revert NonceBindingMismatch();

            (bool okNonce, ) = verifier.verifyRecursive(
                nonceBundle.inner,
                nonceBundle.outerProof,
                nonceBundle.outerCommitment,
                nonceBundle.outerHints,
                nonceBundle.lastLayerEvals
            );
            if (!okNonce) revert NonceProofInvalid();
        }

        // ONE write, whatever N was.
        nonceStateRoot = newNonceRoot;
        emit NonceStateAdvanced(oldRoot, newNonceRoot, updates.length);
    }

    /// @notice Finalize a batch AND advance the nonce accumulator, in ONE
    ///         transaction and with no third proof (Ф3.2, folded).
    ///
    /// The transition is proved as a further component of the log10 tree's
    /// ROOT node (`nonce_update_t8_air`), so it rides the two `verifyRecursive`
    /// calls the batch already pays for. `submitNonceTransition` proves the
    /// same statement as a separate proof, and that third verify (~6.8M) is
    /// what kept it from fitting next to a batch.
    ///
    /// # How the statement reaches the proofs
    ///
    /// Both bundles are cross-bound under
    ///
    ///     seedEff = nonceFoldSeed(merkleRoot, nonceStatementBinding(…))
    ///
    /// in place of `merkleRoot` (`_finalize`). The binding hashes every public
    /// field of the transition, and `seedEff` enters each inner channel before
    /// its queries are drawn; bundles generated for another statement, another
    /// batch, or for a plain `submitBatch` draw other queries and fail.
    ///
    /// # What this binds, and what it does not
    ///
    /// The same as `submitNonceTransition`, and the same as batch membership:
    /// on-chain verification is VFRI-partial, so the binding establishes that
    /// THESE bundles were generated for THIS statement. That the transition is
    /// valid — one shared sibling path per update, pinned leaves and roots — is
    /// established by the Rust verifier (`verify_tree_node_with_nonce`). The
    /// fold makes the accumulator cheaper, not stronger. Checked absolutely
    /// here, as there: the chain starts at the stored root and ends at the one
    /// written, every slot is its sender's, every nonce strictly increases.
    ///
    /// The batch is recorded under `merkleRoot` (R), exactly as `submitBatch`
    /// records it: R is the batch's identity, `seedEff` only what its proofs
    /// are bound to.
    function submitBatchWithNonceUpdates(
        bytes32 merkleRoot,
        bytes32 txListRoot,
        RecursiveBundle calldata bundle10,
        RecursiveBundle calldata bundle8,
        bytes32[] calldata senders,
        NonceUpdate[] calldata updates,
        bytes32 newNonceRoot
    ) external nonReentrant {
        if (!accumulatorMode) revert WrongNoncePath();
        // An empty statement would bind the bundles to a seed that commits to
        // no transition; a batch without nonce updates is `submitBatch`.
        if (updates.length == 0) revert NoNonceUpdates();
        bytes32 oldRoot = nonceStateRoot;
        _checkNonceUpdates(senders, updates);

        bytes32 seed = nonceFoldSeed(merkleRoot, _nonceBinding(oldRoot, updates, newNonceRoot));
        _finalize(merkleRoot, seed, txListRoot, bundle10, bundle8);

        nonceStateRoot = newNonceRoot;
        emit NonceStateAdvanced(oldRoot, newNonceRoot, updates.length);
    }

    /// @notice Finalize a batch from two recursive bundles.
    function submitBatch(
        bytes32 merkleRoot,
        bytes32 txListRoot,
        RecursiveBundle calldata bundle10,
        RecursiveBundle calldata bundle8
    ) external nonReentrant {
        _finalize(merkleRoot, merkleRoot, txListRoot, bundle10, bundle8);
    }

    /// @notice Finalize a batch and advance per-sender nonces (replay protection).
    /// @dev Nonces are 1-based on-chain: an unseen sender reads 0 and `newNonce`
    ///      must exceed it, so the smallest submittable value is 1.
    function submitBatchWithNonces(
        bytes32 merkleRoot,
        bytes32 txListRoot,
        RecursiveBundle calldata bundle10,
        RecursiveBundle calldata bundle8,
        bytes32[] calldata senders,
        uint64[] calldata newNonces
    ) external nonReentrant {
        // Two live nonce paths would be a replay hole: a transaction counted in
        // the mapping is invisible to the accumulator's tree and vice versa, so
        // a replay could go through whichever had not seen it. The mode is
        // immutable, so this closes the other path outright rather than leaving
        // a window.
        if (accumulatorMode) revert WrongNoncePath();
        if (senders.length != newNonces.length) revert NoncesLengthMismatch();
        if (senders.length > MAX_SENDERS) revert SenderCountExceedsLimit();

        // Validate every nonce before touching state.
        for (uint256 i = 0; i < senders.length; ++i) {
            uint64 current = senderNonces[senders[i]];
            if (newNonces[i] <= current) {
                revert SenderNonceTooLow(senders[i], newNonces[i], current + 1);
            }
            // Duplicate senders within the call must be strictly increasing.
            for (uint256 j = i + 1; j < senders.length; ++j) {
                if (senders[i] == senders[j] && newNonces[j] <= newNonces[i]) {
                    revert SenderNonceTooLow(senders[j], newNonces[j], newNonces[i] + 1);
                }
            }
        }

        _finalize(merkleRoot, merkleRoot, txListRoot, bundle10, bundle8);

        for (uint256 i = 0; i < senders.length; ++i) {
            senderNonces[senders[i]] = newNonces[i];
            emit NonceAdvanced(senders[i], newNonces[i]);
        }
    }

    function isBatchFinalized(bytes32 merkleRoot) external view returns (bool) {
        return batchRecords[merkleRoot].timestamp != 0;
    }

    /// @notice Kept with its old getter's signature (it was a public mapping).
    function finalizedBatches(bytes32 merkleRoot) external view returns (bool) {
        return batchRecords[merkleRoot].timestamp != 0;
    }

    /// @notice Kept with its old getter's signature (it was a public mapping).
    function batchTimestamps(bytes32 merkleRoot) external view returns (uint256) {
        return batchRecords[merkleRoot].timestamp;
    }

    /// @notice The digest a batch record holds: `bytes24(keccak256(c10 ‖ c8 ‖ txListRoot))`.
    function batchRecordDigest(bytes16 commitmentLog10, bytes16 commitmentLog8, bytes32 txListRoot)
        public
        pure
        returns (bytes24)
    {
        return bytes24(keccak256(abi.encodePacked(commitmentLog10, commitmentLog8, txListRoot)));
    }

    /// @notice Do these values — read off the `BatchFinalized` event — match
    ///         what was stored? False for an unfinalized root.
    function batchRecordMatches(
        bytes32 merkleRoot,
        bytes16 commitmentLog10,
        bytes16 commitmentLog8,
        bytes32 txListRoot
    ) external view returns (bool) {
        BatchRecord memory r = batchRecords[merkleRoot];
        return r.timestamp != 0
            && r.digest == batchRecordDigest(commitmentLog10, commitmentLog8, txListRoot);
    }

    // ──────────────────────────────────────────────────────────────────────────

    /// @dev The absolute checks on a transition, shared by both accumulator
    ///      entry points. They hold with NO reliance on the proof.
    function _checkNonceUpdates(bytes32[] calldata senders, NonceUpdate[] calldata updates)
        private
        view
    {
        if (senders.length != updates.length) revert NoncesLengthMismatch();
        if (senders.length > MAX_SENDERS) revert SenderCountExceedsLimit();
        uint256 slots = uint256(1) << nonceTreeDepth;

        for (uint256 i = 0; i < updates.length; ++i) {
            NonceUpdate calldata u = updates[i];

            // The slot must be the one this sender owns — otherwise a prover
            // could advance someone else's counter, or park a transaction in an
            // unused slot and replay it against the real one.
            uint32 expected = nonceSlot(senders[i]);
            if (u.index != expected) {
                revert NonceSlotMismatch(i, u.index, expected);
            }
            if (uint256(u.index) >= slots) revert NonceIndexOutOfRange(i);

            // The replay guarantee, still enforced absolutely.
            if (u.newNonce <= u.oldNonce) {
                revert SenderNonceTooLow(senders[i], u.newNonce, u.oldNonce + 1);
            }
        }
    }

    /// @dev The binding of a NON-EMPTY transition from `oldRoot`, after checking
    ///      it ends at `newNonceRoot`.
    ///
    /// There is deliberately no "chain is linked" check. An earlier version had
    /// one and it was VACUOUS — it compared `updates[i-1].postRoot` against a
    /// variable just assigned that same value, so it could never fire. A test
    /// asserting a broken chain was rejected caught it. The chain is
    /// DEFINITIONAL, not asserted: update i starts at `updates[i-1].postRoot`
    /// by construction on both sides (Rust's `NonceStatement::pre_roots`). What
    /// must be pinned are the two ENDPOINTS: `oldRoot` comes from storage and
    /// enters the binding, and the last `postRoot` must equal what is written.
    function _nonceBinding(bytes32 oldRoot, NonceUpdate[] calldata updates, bytes32 newNonceRoot)
        private
        view
        returns (bytes32)
    {
        bytes32 last = updates[updates.length - 1].postRoot;
        if (last != newNonceRoot) revert NonceRootMismatch(newNonceRoot, last);
        return nonceStatementBinding(oldRoot, newNonceRoot, uint32(nonceTreeDepth), updates);
    }

    /// @dev Verify both bundles, cross-bound under `bindSeed`, and record the
    ///      batch under `merkleRoot`. `bindSeed` is `merkleRoot` itself unless the
    ///      batch folds a nonce transition (`submitBatchWithNonceUpdates`).
    function _finalize(
        bytes32 merkleRoot,
        bytes32 bindSeed,
        bytes32 txListRoot,
        RecursiveBundle calldata bundle10,
        RecursiveBundle calldata bundle8
    ) private {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (batchRecords[merkleRoot].timestamp != 0) revert BatchAlreadyFinalized(merkleRoot);

        // Cross-proof binding: each bundle must have been produced against the
        // OTHER group's trace root, so the two cannot come from different witnesses.
        if (bundle10.inner.batchRoot != crossBoundRoot(bindSeed, bundle8.inner.traceRoot)) {
            revert CrossBindingMismatch();
        }
        if (bundle8.inner.batchRoot != crossBoundRoot(bindSeed, bundle10.inner.traceRoot)) {
            revert CrossBindingMismatch();
        }

        (bool ok10, ) = verifier.verifyRecursive(
            bundle10.inner,
            bundle10.outerProof,
            bundle10.outerCommitment,
            bundle10.outerHints,
            bundle10.lastLayerEvals
        );
        if (!ok10) revert Log10ProofInvalid();

        (bool ok8, ) = verifier.verifyRecursive(
            bundle8.inner,
            bundle8.outerProof,
            bundle8.outerCommitment,
            bundle8.outerHints,
            bundle8.lastLayerEvals
        );
        if (!ok8) revert Log8ProofInvalid();

        // ONE new slot per batch (see `BatchRecord`).
        batchRecords[merkleRoot] = BatchRecord({
            timestamp: uint64(block.timestamp),
            digest: batchRecordDigest(bundle10.outerCommitment, bundle8.outerCommitment, txListRoot)
        });

        emit BatchFinalized(
            merkleRoot,
            bundle10.outerCommitment,
            bundle8.outerCommitment,
            txListRoot,
            block.timestamp
        );
    }
}
