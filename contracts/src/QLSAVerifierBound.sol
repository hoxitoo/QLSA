// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./IQLSAVerifierV2.sol";
import "./verifier/Blake2s.sol";

/// @title QLSAVerifierBound — Merkle-root-bound FRI commitment verifier (128-bit)
///
/// Implements IQLSAVerifierV2: binds the STARK proof to a specific batch
/// Merkle root and uses a 128-bit (bytes16) commitment for collision resistance.
///
/// Commitment scheme (matches stark/prover.py):
///   onchain_commitment = Blake2s(proof[0:32] ∥ merkleRoot)[0:16]
///
/// Security properties:
///   + 128-bit commitment — birthday-bound collisions require ~2^64 batches.
///   + Proof cannot be replayed against a different Merkle root.
///   + Commitment cannot be forged without inverting Blake2s.
///   - Still not a full FRI verifier: polynomial queries and OODS are not checked.
///     Replace with the full Circle STARK verifier before mainnet deployment.
///
/// Off-chain counterpart:
///   Python: hashlib.blake2s(proof[:32] + merkle_root[:32]).digest()[:16].hex()
contract QLSAVerifierBound is IQLSAVerifierV2 {

    // ── Constants ─────────────────────────────────────────────────────────────

    /// @notice Minimum proof length (bytes). Shorter proofs are structurally invalid.
    uint256 public constant MIN_PROOF_LENGTH = 700;

    /// @notice Maximum proof length (bytes). Prevents gas-griefing.
    uint256 public constant MAX_PROOF_LENGTH = 1_048_576; // 1 MiB

    // ── IQLSAVerifierV2 ───────────────────────────────────────────────────────

    /// @inheritdoc IQLSAVerifierV2
    function verify(
        bytes calldata proof,
        bytes16        commitment,
        bytes32        merkleRoot
    ) external pure override returns (bool) {

        // 1. Proof length bounds.
        if (proof.length < MIN_PROOF_LENGTH) return false;
        if (proof.length > MAX_PROOF_LENGTH) return false;

        // 2. Non-trivial inputs.
        if (commitment == bytes16(0)) return false;
        if (merkleRoot == bytes32(0)) return false;

        // 3. Merkle-root-bound commitment check.
        //    Hash the first 32 bytes of the proof concatenated with the Merkle root.
        //    commitment must equal the first 16 bytes of that Blake2s hash (128-bit).
        //    proof.length >= 700 so proof[0:32] is always in bounds.
        bytes memory input = new bytes(64);
        assembly {
            // Copy proof[0:32] into input[0:32].
            calldatacopy(add(input, 32), proof.offset, 32)
            // Copy merkleRoot (bytes32, right-aligned) into input[32:64].
            mstore(add(input, 64), merkleRoot)
        }
        bytes32 h = Blake2s.hash(input);
        if (bytes16(h) != commitment) return false;

        return true;
    }
}
