// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Test helper — NOT for deployment.

/// @dev `BatchRegistryV7`'s per-sender nonce block, isolated so the cost of a
///      REPEAT sender can be measured.
///
/// # Why this exists
///
/// The economics of Ф3 (ROADMAP § 1.5, docs/TECH_DEBT.md § A-4) turn on what one
/// sender costs. That figure was measured at **28,777 gas** — but every
/// measurement deploys a fresh registry, so every sender writes a ZERO slot:
/// `SSTORE_SET` (20,000) plus the cold-slot surcharge (2,100). It is the
/// FIRST-TIME cost, and a running system pays it once per sender ever.
///
/// The repeat cost cannot be measured on the real contract: a second batch into
/// the same registry needs a second `merkleRoot`, `finalizedBatches` rejects a
/// repeat, and a different root needs different (cross-bound) proofs. So the
/// loop is isolated here instead.
///
/// # What keeps this honest
///
/// A harness that is only measured against itself measures nothing. The loop
/// below is copied VERBATIM from `BatchRegistryV7.submitBatchWithNonces`
/// (validation scan, then the write-and-emit loop, same order, same event), and
/// `V7SenderCostProbe.test.js` cross-checks it on TWO points the real contract
/// can produce — the cold marginal and the warm-within-one-transaction
/// marginal. Only then is its third figure, the across-transaction warm
/// marginal, used for anything.
///
/// If `BatchRegistryV7`'s loop changes and this one does not, the cross-check
/// fails. That is the intended failure mode.
contract NonceLoopHarness {
    uint256 public constant MAX_SENDERS = 3000;

    mapping(bytes32 => uint64) public senderNonces;

    event NonceAdvanced(bytes32 indexed sender, uint64 newNonce);

    error SenderNonceTooLow(bytes32 sender, uint64 provided, uint64 expected);
    error NoncesLengthMismatch();
    error SenderCountExceedsLimit();

    /// @notice The nonce block of `submitBatchWithNonces`, without the proofs.
    ///
    /// Everything `submitBatchWithNonces` does around it — the two
    /// `verifyRecursive` calls, the cross-binding check, the batch bookkeeping —
    /// is a per-CALL cost that cancels in a marginal measurement, so leaving it
    /// out does not change the per-sender figure. What must match, and does, is
    /// the per-sender work: the O(n²) duplicate scan, the storage write and the
    /// event.
    function applyNonces(
        bytes32[] calldata senders,
        uint64[] calldata newNonces
    ) external {
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

        for (uint256 i = 0; i < senders.length; ++i) {
            senderNonces[senders[i]] = newNonces[i];
            emit NonceAdvanced(senders[i], newNonces[i]);
        }
    }
}
