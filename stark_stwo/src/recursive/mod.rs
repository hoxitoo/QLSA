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
//! # Soundness status (audit 2026-06-17) — C1/C2 CLOSED for `recursive_verifier`
//!
//! These gadgets are correct arithmetic *relation* provers (each pins its output
//! columns to its input columns; verified by the rejection tests and the
//! cross-checks against `vfri2_bridge.rs`).  The audit found two composition-level
//! gaps against a malicious prover; both are now **closed for the flagship
//! composition gadget `recursive_verifier`** (single + N-query):
//!
//! - **[C1 — FIXED] Output binding.**  The verifier-fixed claimed final value is
//!   carried in pinned `fin0..fin3` preprocessed columns, and an `is_output`-gated
//!   in-circuit constraint forces the trace's real output row to equal it.  A
//!   prover whose trace computes X cannot claim Y ≠ X (regression test
//!   `test_forged_output_cannot_prove`).
//! - **[C2 — FIXED] Preprocessed pinning.**  Selectors + claimed-output columns
//!   are produced by the single canonical source `build_preproc`; the verifier
//!   recomputes their commitment root (`canonical_preproc_root`) and rejects any
//!   proof whose `commitments[0]` differs — a forged `is_step ≡ 0` no longer
//!   verifies (regression test `test_forged_selector_rejected`; previously it
//!   verified `true`).
//!
//! **Remaining (R3.7 follow-up):** the same pinning + output-binding mechanism
//! still needs porting to the standalone sub-gadgets (`merkle_path_air`,
//! `channel_air`, `transcript_draw_air`, `fri_fold_chain_air`) — they retain the
//! documented Fiat-Shamir-only binding — and to the mature `stark_stwo/src/lib.rs`
//! V23/VFRI verifiers, which use the same unpinned `commit(proof.commitments[0], …)`
//! pattern (per-circuit codebase-wide review item). The `recursive_verifier`
//! pattern is the reference implementation to follow.

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
