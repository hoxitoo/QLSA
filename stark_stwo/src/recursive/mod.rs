//! Recursive STARK verifier — AIR gadgets (R0 groundwork, 2026-06-17).
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
//!
//! Next (see roadmap R2+): widen the inner hash to t=16, recursive verifier
//! composition (R3).

pub mod channel_air;
pub mod fold_air;
pub mod merkle_path_air;
pub mod oods_air;
pub mod qm31_mul_air;
