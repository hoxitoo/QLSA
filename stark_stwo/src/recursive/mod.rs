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
//! | Fiat-Shamir transcript | `channel_air` | Poseidon2 t=2 sponge absorb (`mixU32s` core) → digest |
//! | Per-query FRI step | `query_step_air` | OODS± + circle fold chained via shared fPlus/fMinus (R3.1) |
//! | **FRI fold chain** | `fri_fold_chain_air` | **K line-fold rounds chained: output[k]=lineFold(output[k−1], …) (R3.2)** |
//!
//! Next (see roadmap R3): full recursive verifier composition (channel + query_step +
//! fri_fold_chain + merkle_path in one multi-component Stwo proof).

pub mod channel_air;
pub mod fold_air;
pub mod fri_fold_chain_air;
pub mod merkle_path_air;
pub mod oods_air;
pub mod query_step_air;
pub mod qm31_mul_air;
