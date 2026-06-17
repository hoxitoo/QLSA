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
//!
//! Next (see roadmap R1+): QM31 linear combination, circle/line fold, OODS
//! quotient, Poseidon2-t16 Merkle path, Fiat-Shamir transcript replay.

pub mod qm31_mul_air;
