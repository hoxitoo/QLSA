//! Recursive STARK verifier — AIR gadgets (R3.2, 2026-06-17).
//!
//! Production gas target: a STARK that proves "I verified a VFRI11 STARK".  The
//! outer proof is constant-size (~5M gas on-chain) and the inner verifier
//! circuit may use any-width hash (t=16/RPO256) for free.  See
//! `docs/roadmap/recursion.md` for the full plan and the (2026-06-17) decision
//! to skip the standalone t=16 verifier in favour of recursion.
//!
//! This module collects the foundational AIR gadgets from which the recursive
//! VFRI11 verifier is assembled.  Each gadget is self-contained, cross-checked
//! against the `u128` QM31 reference in `vfri2_bridge.rs`, and carries a full
//! Stwo prove/verify roundtrip test.
//!
//! | Gadget | File | Proves |
//! |--------|------|--------|
//! | QM31 batch multiply | `qm31_mul_air` | `z = x · y` in QM31 = CM31[u]/(u²−R), R = 2+i |
//! | FRI circle/line fold | `fold_air` | `folded = (f₊+f₋) + α·(f₊−f₋)·inv` (one FRI fold step) |
//! | OODS quotient | `oods_air` | `fₚ·(px − z_x) = compValue − oodsCombo` (multiplicative form) |
//! | Merkle auth-path | `merkle_path_air` | `leaf @ index + siblings → root` (Poseidon2 t=2 compression) |
//! | Fiat-Shamir absorb | `channel_air` | Poseidon2 t=2 sponge absorb (`mixU32s` core) → digest |
//! | **Fiat-Shamir draw** | `transcript_draw_air` | **Poseidon2 t=2 sponge squeeze (`drawSecureFelt`/`drawQueries` core): digest → drawn pairs (R3.6)** |
//! | Per-query FRI step | `query_step_air` | OODS± + circle fold chained via shared fPlus/fMinus (R3.1) |
//! | FRI fold chain | `fri_fold_chain_air` | K line-fold rounds chained: output[k]=lineFold(output[k−1], …) (R3.2) |
//! | Per-query recursive verifier | `recursive_verifier` | OODS± + circle fold + K line folds in ONE AIR; full per-query FRI chain, cross-row bound (R3.3) |
//! | Per-query integration | `integration` | recursive_verifier → `qm31_leaf_hash` → `merkle_path_air`: full per-query FRI verification, value-bound across 3 sub-proofs (R3.4) |
//! | Multi-query aggregation | `recursive_verifier` | N queries in ONE STARK (`prove_recursive_queries`): N blocks of (1+K) rows, same AIR, all finalFolds bound (R3.5) |
//!
//! **The full recursion gadget set is complete (R3.6):** QM31 arithmetic, FRI
//! fold/OODS, inner-hash Merkle path, Fiat-Shamir absorb + draw, per-query
//! composition (single + N-query), and the leaf-hash integration.  Next (roadmap
//! R3.7 → R4): a top-level assembly wiring the channel (absorb→draw) to derive the
//! channel-bound query indices + fold challenges and feed them into the multi-query
//! verifier, then on-chain `QLSAVerifierRecursive.sol` (~5M gas constant).
//!
//! # ⚠ Soundness status (audit 2026-06-17) — NOT YET COMPLETE
//!
//! These gadgets are **correct arithmetic *relation* provers** (each pins its
//! output columns to its input columns; verified by the rejection tests and the
//! cross-checks against `vfri2_bridge.rs`).  They are **not yet a sound
//! *composition*** against a malicious prover.  Two confirmed gaps must be closed
//! before any `QLSAVerifierRecursive` is wired to real proofs (both blockers for
//! R3.7):
//!
//! - **[C1] Public outputs are bound only via Fiat-Shamir, not by an in-circuit
//!   constraint.**  `mix_public` / `mix_digest` make a proof *specific to* a
//!   mixed value but do NOT prove the trace *computed* it.  A malicious prover can
//!   present a proof whose claimed public output (`root` / `finalFold` / `digest`)
//!   differs from its trace's real output.  Fix: add an `is_output`-gated
//!   `(out_col − public) = 0` constraint tying the trace output row to a
//!   verifier-fixed public input.
//! - **[C2] Preprocessed columns (selectors AND round constants) are prover-
//!   supplied in Tree 0 and never pinned to a canonical spec.**  The verifier
//!   commits `proof.commitments[0]` as given, so a prover can forge selectors
//!   (e.g. `is_step ≡ 0`) to gate constraints off (confirmed: a forged `is_step`
//!   with a corrupted `compPos` verifies `true`).  Fix: the verifier must
//!   regenerate the canonical preprocessed columns and pin their root (reject a
//!   mismatch) instead of trusting the prover's tree.
//!
//! NOTE: the same unpinned-preprocessed pattern (`commit(proof.commitments[0], …)`)
//! is used by the mature `stark_stwo/src/lib.rs` verifiers; whether each is
//! independently exploitable needs a per-circuit follow-up — treat C2 as a
//! codebase-wide review item, not recursion-only.

pub mod channel_air;
pub mod fold_air;
pub mod fri_fold_chain_air;
pub mod integration;
pub mod merkle_path_air;
pub mod oods_air;
pub mod qm31_mul_air;
pub mod query_step_air;
pub mod recursive_verifier;
pub mod transcript_draw_air;
