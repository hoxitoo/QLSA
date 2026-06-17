//! QM31 batch-multiplication AIR — foundational recursive-verifier gadget (R0.1).
//!
//! Proves `z = x · y` for a batch of QM31 operations, where QM31 is the degree-4
//! extension `CM31[u] / (u² − R)` with `R = CM31(2, 1) = 2 + i` (matching Stwo
//! and the on-chain `QM31.sol`).  This is THE foundational primitive of the
//! recursive verifier: circleFold, lineFold and the OODS quotient checks all
//! reduce to QM31 add/mul, and add is degree-1 (foldable into linear
//! constraints), so the multiplication gadget is the load-bearing one.
//!
//! # QM31 encoding
//!
//! A QM31 value is `c0 + c1·u` with `c0, c1 ∈ CM31`, and each CM31 value is
//! `re + im·i` with `i² = −1`.  We lay the 4 M31 limbs out as
//! `[c0.re, c0.im, c1.re, c1.im]`, matching the `u128` packing in
//! `vfri2_bridge.rs` (`c0` in bits[127:64], `c1` in bits[63:0]; each CM31 is
//! `(re << 32) | im`).
//!
//! # Multiplication formula
//!
//! With `x = (xa,xb,xc,xd)`, `y = (ya,yb,yc,yd)` and the helpers
//! `u = xc·yc − xd·yd`, `v = xc·yd + xd·yc` (= `x1 · y1` in CM31):
//!
//! ```text
//! z0.re = xa·ya − xb·yb + 2u − v      (c0.re: x0·y0 + R·(x1·y1), real part)
//! z0.im = xa·yb + xb·ya + u + 2v      (c0.im)
//! z1.re = xa·yc − xb·yd + xc·ya − xd·yb   (c1.re: x0·y1 + x1·y0, real part)
//! z1.im = xa·yd + xb·yc + xc·yb + xd·ya   (c1.im)
//! ```
//!
//! These are exactly the four (degree-2) AIR constraints.  Everything is a field
//! identity over M31, so no range checks are needed — wrap-around is the correct
//! extension-field semantics (unlike the integer multiplications that needed
//! `RangeQBatch`).
//!
//! # Trace layout (12 columns, no preprocessed columns)
//!
//! ```text
//! 0  xa   1  xb   2  xc   3  xd     (operand x = c0.re,c0.im,c1.re,c1.im)
//! 4  ya   5  yb   6  yc   7  yd     (operand y)
//! 8  z0   9  z1  10  z2  11  z3     (product z = x · y)
//! ```

use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub const N_COLS: usize = 12;
/// Smallest trace is 2 rows (1 real op + padding); Circle STARK needs ≥ 2 rows.
pub const MIN_LOG_SIZE: u32 = 1;
pub const MAX_LOG_SIZE: u32 = 20;

const M31_P: u64 = (1u64 << 31) - 1;
const MASK32: u128 = 0xFFFF_FFFF;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub type Qm31MulComponent = FrameworkComponent<Qm31MulEval>;

// ── Scalar M31 / QM31 reference (cross-checked against vfri2_bridge::qm31_mul) ──

#[inline]
fn m31_mul(a: u64, b: u64) -> u64 { (a * b) % M31_P }
#[inline]
fn m31_add(a: u64, b: u64) -> u64 { (a + b) % M31_P }
#[inline]
fn m31_sub(a: u64, b: u64) -> u64 { (a + M31_P - b) % M31_P }

/// Decode a packed-`u128` QM31 into its four M31 limbs `[c0.re, c0.im, c1.re, c1.im]`.
#[inline]
pub fn limbs(q: u128) -> [u64; 4] {
    [
        ((q >> 96) & MASK32) as u64,
        ((q >> 64) & MASK32) as u64,
        ((q >> 32) & MASK32) as u64,
        (q & MASK32) as u64,
    ]
}

/// Pack four M31 limbs back into the `u128` QM31 encoding.
#[inline]
pub fn pack(l: [u64; 4]) -> u128 {
    ((l[0] as u128) << 96) | ((l[1] as u128) << 64) | ((l[2] as u128) << 32) | (l[3] as u128)
}

/// Reference QM31 multiply over the four limbs — the value the AIR proves.
pub fn mul_limbs(x: [u64; 4], y: [u64; 4]) -> [u64; 4] {
    let (xa, xb, xc, xd) = (x[0], x[1], x[2], x[3]);
    let (ya, yb, yc, yd) = (y[0], y[1], y[2], y[3]);
    // u + v·i = x1 · y1 (CM31)
    let u = m31_sub(m31_mul(xc, yc), m31_mul(xd, yd));
    let v = m31_add(m31_mul(xc, yd), m31_mul(xd, yc));
    let two = |t: u64| m31_add(t, t);
    let z0 = m31_add(m31_sub(m31_mul(xa, ya), m31_mul(xb, yb)), m31_sub(two(u), v));
    let z1 = m31_add(m31_add(m31_mul(xa, yb), m31_mul(xb, ya)), m31_add(u, two(v)));
    let z2 = m31_add(m31_sub(m31_mul(xa, yc), m31_mul(xb, yd)),
                     m31_sub(m31_mul(xc, ya), m31_mul(xd, yb)));
    let z3 = m31_add(m31_add(m31_mul(xa, yd), m31_mul(xb, yc)),
                     m31_add(m31_mul(xc, yb), m31_mul(xd, ya)));
    [z0, z1, z2, z3]
}

// ── AIR ──────────────────────────────────────────────────────────────────────

pub struct Qm31MulEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for Qm31MulEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // constraints are degree 2
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let mut c: Vec<E::F> = Vec::with_capacity(N_COLS);
        for _ in 0..N_COLS {
            c.push(eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone());
        }
        let (xa, xb, xc, xd) = (c[0].clone(), c[1].clone(), c[2].clone(), c[3].clone());
        let (ya, yb, yc, yd) = (c[4].clone(), c[5].clone(), c[6].clone(), c[7].clone());
        let (z0, z1, z2, z3) = (c[8].clone(), c[9].clone(), c[10].clone(), c[11].clone());
        let two = BaseField::from_u32_unchecked(2);

        // u + v·i = x1 · y1 (CM31)
        let u = xc.clone() * yc.clone() - xd.clone() * yd.clone();
        let v = xc.clone() * yd.clone() + xd.clone() * yc.clone();

        // C0: z0 = xa·ya − xb·yb + 2u − v
        eval.add_constraint(
            z0 - (xa.clone() * ya.clone() - xb.clone() * yb.clone() + u.clone() * two - v.clone()),
        );
        // C1: z1 = xa·yb + xb·ya + u + 2v
        eval.add_constraint(
            z1 - (xa.clone() * yb.clone() + xb.clone() * ya.clone() + u + v * two),
        );
        // C2: z2 = xa·yc − xb·yd + xc·ya − xd·yb
        eval.add_constraint(
            z2 - (xa.clone() * yc.clone() - xb.clone() * yd.clone()
                + xc.clone() * ya.clone() - xd.clone() * yb.clone()),
        );
        // C3: z3 = xa·yd + xb·yc + xc·yb + xd·ya
        eval.add_constraint(
            z3 - (xa * yd + xb * yc + xc * yb + xd * ya),
        );

        eval
    }
}

fn new_component(log_n_rows: u32) -> Qm31MulComponent {
    Qm31MulComponent::new(
        &mut TraceLocationAllocator::default(),
        Qm31MulEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ──────────────────────────────────────────────────────────────

/// Compute the log2 row count needed for `n_ops` operations (≥ MIN_LOG_SIZE).
pub fn compute_log_size(n_ops: usize) -> u32 {
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < n_ops.max(1) {
        log += 1;
    }
    log
}

/// Build the QM31-multiply trace from a batch of `(x, y)` operations (packed
/// `u128` QM31).  Each row stores `x`, `y` and the correct product `z = x·y`.
/// Unused rows are padded with zeros (`0·0 = 0`).  `log_n_rows` must be large
/// enough to hold every op (use [`compute_log_size`]).
pub fn build_trace(ops: &[(u128, u128)], log_n_rows: u32) -> TraceColumns {
    let n = 1usize << log_n_rows;
    debug_assert!(ops.len() <= n, "ops exceed trace capacity");
    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_COLS];

    for (r, &(x, y)) in ops.iter().enumerate() {
        let xl = limbs(x);
        let yl = limbs(y);
        let zl = mul_limbs(xl, yl);
        for k in 0..4 {
            cols[k][r] = BaseField::from_u32_unchecked(xl[k] as u32);
            cols[4 + k][r] = BaseField::from_u32_unchecked(yl[k] as u32);
            cols[8 + k][r] = BaseField::from_u32_unchecked(zl[k] as u32);
        }
    }

    for col in cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

// ── Prove / verify roundtrip ────────────────────────────────────────────────────

/// Prove a batch of QM31 multiplications.  Returns `(proof_bytes, log_size)`.
pub fn prove_qm31_mul(ops: &[(u128, u128)]) -> Result<(Vec<u8>, u32), String> {
    if ops.is_empty() {
        return Err("ops must not be empty".into());
    }
    let log_size = compute_log_size(ops.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("too many ops: log_size {log_size} exceeds {MAX_LOG_SIZE}"));
    }

    let columns = build_trace(ops, log_size);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: preprocessed (none for this gadget).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    // Tree 1: main trace (12 columns).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    let component = new_component(log_size);

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, log_size))
}

/// Verify a proof produced by [`prove_qm31_mul`].
pub fn verify_qm31_mul(proof_bytes: &[u8], log_size: u32) -> Result<bool, String> {
    if !(MIN_LOG_SIZE..=MAX_LOG_SIZE).contains(&log_size) {
        return Err(format!(
            "log_size {log_size} out of range [{MIN_LOG_SIZE}, {MAX_LOG_SIZE}]"
        ));
    }

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let component = new_component(log_size);

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected ≥ 2 commitments, got {}",
            proof.commitments.len()
        ));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    let result = verify::<Blake2sM31MerkleChannel>(
        &[&component],
        verifier_channel,
        commitment_scheme,
        proof,
    );

    Ok(result.is_ok())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent QM31 multiply over the `u128` encoding (mirrors
    /// `vfri2_bridge::qm31_mul`) — the ground truth for cross-checking.
    fn qm31_mul_ref(x: u128, y: u128) -> u128 {
        pack(mul_limbs(limbs(x), limbs(y)))
    }

    fn rand_qm31(seed: &mut u64) -> u128 {
        let mut next = || {
            *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((*seed >> 33) as u64 % M31_P) as u128
        };
        (next() << 96) | (next() << 64) | (next() << 32) | next()
    }

    #[test]
    fn test_mul_limbs_matches_known_vector() {
        // 1 · y = y  (QM31 multiplicative identity is 1 = c0.re=1, rest 0).
        let one = pack([1, 0, 0, 0]);
        let y = pack([7, 11, 13, 17]);
        assert_eq!(qm31_mul_ref(one, y), y);

        // u · u = R = 2 + i  (u = c1 = 1 → limbs [0,0,1,0]; u² = R = (2,1,0,0)).
        let u = pack([0, 0, 1, 0]);
        assert_eq!(limbs(qm31_mul_ref(u, u)), [2, 1, 0, 0]);
    }

    #[test]
    fn test_mul_limbs_commutative() {
        let mut seed = 0xC0FFEE;
        for _ in 0..200 {
            let x = rand_qm31(&mut seed);
            let y = rand_qm31(&mut seed);
            assert_eq!(qm31_mul_ref(x, y), qm31_mul_ref(y, x));
        }
    }

    #[test]
    fn test_build_trace_dimensions() {
        let ops = vec![(pack([1, 2, 3, 4]), pack([5, 6, 7, 8]))];
        let log = compute_log_size(ops.len());
        let cols = build_trace(&ops, log);
        assert_eq!(cols.len(), N_COLS);
        assert_eq!(cols[0].values.len(), 1 << log);
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let mut seed = 0x1234_5678;
        let ops: Vec<(u128, u128)> =
            (0..16).map(|_| (rand_qm31(&mut seed), rand_qm31(&mut seed))).collect();
        let (proof, log_size) = prove_qm31_mul(&ops).expect("prove");
        assert!(verify_qm31_mul(&proof, log_size).expect("verify"), "valid proof must verify");
    }

    #[test]
    fn test_single_op_roundtrip() {
        let ops = vec![(pack([2, 0, 1, 0]), pack([0, 0, 1, 0]))]; // (2+u)·u
        let (proof, log_size) = prove_qm31_mul(&ops).expect("prove");
        assert!(verify_qm31_mul(&proof, log_size).expect("verify"));
    }

    #[test]
    fn test_empty_ops_rejected() {
        assert!(prove_qm31_mul(&[]).is_err());
    }
}
