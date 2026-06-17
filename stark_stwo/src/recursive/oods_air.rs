//! OODS quotient AIR — recursive-verifier gadget (R1).
//!
//! Proves the out-of-domain-sampling (OODS) quotient relation that links each
//! query's committed composition value to the FRI layer-1 input, in the
//! **multiplicative form** the on-chain verifier uses (no QM31 inverse):
//!
//! ```text
//! fₚ · (px − z_x) = compValue − oodsCombo
//! ```
//!
//! This is exactly `vfri2_bridge`'s quotient step
//! `fPlus = (rawComp − oodsComboPos) / (px − z_x)` rearranged to avoid division
//! (so it is a single degree-2 polynomial identity).  `px` is the query point's
//! x-coordinate (an M31 element embedded into QM31 as `(px,0,0,0)`), `z_x` is the
//! QM31 OODS point, and `fₚ`, `compValue`, `oodsCombo` are QM31.
//!
//! The same shape covers both the positive query (`px`) and the antipodal query
//! (`−px`): the caller passes whichever x-coordinate applies.
//!
//! # Honest-prover construction
//!
//! In the recursive verifier `compValue` is Merkle-committed and `fₚ` is the
//! derived quotient.  The AIR proves the *relation*, so the trace builder takes
//! `(fₚ, px, z_x, oodsCombo)` as free inputs and derives
//! `compValue = fₚ·(px − z_x) + oodsCombo` — algebraically identical, and it
//! needs no inverse.  (The verifier's `px = ±z_x` degenerate-denominator guard
//! is a separate range/identity check, not part of this arithmetic relation.)
//!
//! # Trace layout (17 columns, no preprocessed columns)
//!
//! ```text
//!  0..4   fₚ        (QM31 quotient value)
//!  4      px        (M31 query x-coordinate)
//!  5..9   z_x       (QM31 OODS point)
//!  9..13  compValue (QM31 committed composition value)
//! 13..17  oodsCombo (QM31 OODS-evaluation combo)
//! ```
//!
//! # Constraints (4, degree 2)
//!
//! With `d = (px,0,0,0) − z_x` and `prod = fₚ · d` (QM31 mul):
//! `prod_k − (compValue_k − oodsCombo_k) = 0`, k = 0..3.

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
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

use crate::recursive::qm31_mul_air::{add_limbs, limbs, mul_limbs, pack, sub_limbs};
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub const N_COLS: usize = 17;
pub const MIN_LOG_SIZE: u32 = 1;
pub const MAX_LOG_SIZE: u32 = 20;

const M31_P: u64 = (1u64 << 31) - 1;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub type OodsComponent = FrameworkComponent<OodsEval>;

/// One OODS quotient operation: `(fₚ, px, z_x, oodsCombo)`.
pub type OodsOp = (u128, u32, u128, u128);

/// Reference: the committed composition value implied by the relation,
/// `compValue = fₚ·(px − z_x) + oodsCombo`. Matches the rearranged
/// `vfri2_bridge` quotient `fPlus = (rawComp − oodsCombo)/(px − z_x)`.
pub fn comp_value_ref(f_p: u128, px: u32, z_x: u128, oods_combo: u128) -> u128 {
    let px_q = pack([px as u64, 0, 0, 0]);
    let d = sub_limbs(limbs(px_q), limbs(z_x));
    pack(add_limbs(mul_limbs(limbs(f_p), d), limbs(oods_combo)))
}

// ── AIR ──────────────────────────────────────────────────────────────────────

pub struct OodsEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for OodsEval {
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
        let f = [c[0].clone(), c[1].clone(), c[2].clone(), c[3].clone()];
        let px = c[4].clone();
        let zx = [c[5].clone(), c[6].clone(), c[7].clone(), c[8].clone()];
        let cv = [c[9].clone(), c[10].clone(), c[11].clone(), c[12].clone()];
        let oc = [c[13].clone(), c[14].clone(), c[15].clone(), c[16].clone()];
        let two = BaseField::from_u32_unchecked(2);

        // d = (px,0,0,0) − z_x  (px embeds into the QM31 real-of-real limb only)
        let zero = px.clone() - px.clone();
        let d = [
            px - zx[0].clone(),
            zero.clone() - zx[1].clone(),
            zero.clone() - zx[2].clone(),
            zero - zx[3].clone(),
        ];

        // prod = fₚ · d  (QM31 mul; x = f, y = d)
        let u = f[2].clone() * d[2].clone() - f[3].clone() * d[3].clone();
        let v = f[2].clone() * d[3].clone() + f[3].clone() * d[2].clone();
        let prod0 = f[0].clone() * d[0].clone() - f[1].clone() * d[1].clone() + u.clone() * two - v.clone();
        let prod1 = f[0].clone() * d[1].clone() + f[1].clone() * d[0].clone() + u + v * two;
        let prod2 = f[0].clone() * d[2].clone() - f[1].clone() * d[3].clone()
            + f[2].clone() * d[0].clone() - f[3].clone() * d[1].clone();
        let prod3 = f[0].clone() * d[3].clone() + f[1].clone() * d[2].clone()
            + f[2].clone() * d[1].clone() + f[3].clone() * d[0].clone();
        let prod = [prod0, prod1, prod2, prod3];

        // C: prod_k = compValue_k − oodsCombo_k
        for k in 0..4 {
            eval.add_constraint(prod[k].clone() - (cv[k].clone() - oc[k].clone()));
        }

        eval
    }
}

fn new_component(log_n_rows: u32) -> OodsComponent {
    OodsComponent::new(
        &mut TraceLocationAllocator::default(),
        OodsEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ──────────────────────────────────────────────────────────────

pub fn compute_log_size(n_ops: usize) -> u32 {
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < n_ops.max(1) {
        log += 1;
    }
    log
}

/// Build the OODS-quotient trace from a batch of `(fₚ, px, z_x, oodsCombo)`
/// operations. Each row derives the consistent `compValue` so the relation
/// holds. Padding rows are all-zero (`0·(0−0) = 0 − 0`).
///
/// **Precondition:** all packed QM31 limbs and `px` must be canonical M31
/// elements (`< M31_P`); debug-asserted.
pub fn build_trace(ops: &[OodsOp], log_n_rows: u32) -> TraceColumns {
    let n = 1usize << log_n_rows;
    debug_assert!(ops.len() <= n, "ops exceed trace capacity");
    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_COLS];

    for (r, &(f_p, px, z_x, oods_combo)) in ops.iter().enumerate() {
        let fl = limbs(f_p);
        let zl = limbs(z_x);
        let ol = limbs(oods_combo);
        debug_assert!(
            fl.iter().chain(zl.iter()).chain(ol.iter()).all(|&l| l < M31_P) && (px as u64) < M31_P,
            "non-canonical limb (>= M31_P) in oods build_trace input",
        );
        let cv = limbs(comp_value_ref(f_p, px, z_x, oods_combo));

        for k in 0..4 {
            cols[k][r] = BaseField::from_u32_unchecked(fl[k] as u32);
            cols[5 + k][r] = BaseField::from_u32_unchecked(zl[k] as u32);
            cols[9 + k][r] = BaseField::from_u32_unchecked(cv[k] as u32);
            cols[13 + k][r] = BaseField::from_u32_unchecked(ol[k] as u32);
        }
        cols[4][r] = BaseField::from_u32_unchecked(px);
    }

    for col in cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }

    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

// ── Prove / verify roundtrip ────────────────────────────────────────────────────

/// Prove a batch of OODS quotient relations. Returns `(proof_bytes, log_size)`.
pub fn prove_oods(ops: &[OodsOp]) -> Result<(Vec<u8>, u32), String> {
    if ops.is_empty() {
        return Err("ops must not be empty".into());
    }
    let log_size = compute_log_size(ops.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("too many ops: log_size {log_size} exceeds {MAX_LOG_SIZE}"));
    }
    prove_columns(build_trace(ops, log_size), log_size)
}

fn prove_columns(columns: TraceColumns, log_size: u32) -> Result<(Vec<u8>, u32), String> {
    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]); // Tree 0: no preprocessed columns
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns); // Tree 1: main trace (17 columns)
    tree_builder.commit(channel);

    let component = new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;
    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;
    Ok((proof_bytes, log_size))
}

/// Verify a proof produced by [`prove_oods`].
pub fn verify_oods(proof_bytes: &[u8], log_size: u32) -> Result<bool, String> {
    if !(MIN_LOG_SIZE..=MAX_LOG_SIZE).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range [{MIN_LOG_SIZE}, {MAX_LOG_SIZE}]"));
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
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    let result = verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof);
    Ok(result.is_ok())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_m31(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) % M31_P
    }

    fn rand_qm31(seed: &mut u64) -> u128 {
        (rand_m31(seed) as u128) << 96
            | (rand_m31(seed) as u128) << 64
            | (rand_m31(seed) as u128) << 32
            | rand_m31(seed) as u128
    }

    #[test]
    fn test_comp_value_zero_quotient_is_combo() {
        // fₚ = 0 ⇒ compValue = oodsCombo (the quotient term vanishes).
        let oc = pack([7, 11, 13, 17]);
        assert_eq!(comp_value_ref(0, 12345, pack([1, 2, 3, 4]), oc), oc);
    }

    #[test]
    fn test_comp_value_relation_holds() {
        // compValue − oodsCombo == fₚ·(px − z_x) by construction.
        let mut seed = 0x1357;
        let f_p = rand_qm31(&mut seed);
        let px = rand_m31(&mut seed) as u32;
        let z_x = rand_qm31(&mut seed);
        let oc = rand_qm31(&mut seed);
        let cv = comp_value_ref(f_p, px, z_x, oc);
        let lhs = mul_limbs(limbs(f_p), sub_limbs(limbs(pack([px as u64, 0, 0, 0])), limbs(z_x)));
        assert_eq!(sub_limbs(limbs(cv), limbs(oc)), lhs);
    }

    #[test]
    fn test_build_trace_dimensions() {
        let ops: Vec<OodsOp> = vec![(pack([1, 2, 3, 4]), 9, pack([5, 6, 7, 8]), pack([1, 1, 1, 1]))];
        let log = compute_log_size(ops.len());
        let cols = build_trace(&ops, log);
        assert_eq!(cols.len(), N_COLS);
        assert_eq!(cols[0].values.len(), 1 << log);
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let mut seed = 0xACE0_BA5E;
        let ops: Vec<OodsOp> = (0..16)
            .map(|_| (rand_qm31(&mut seed), rand_m31(&mut seed) as u32, rand_qm31(&mut seed), rand_qm31(&mut seed)))
            .collect();
        let (proof, log_size) = prove_oods(&ops).expect("prove");
        assert!(verify_oods(&proof, log_size).expect("verify"), "valid OODS proof must verify");
    }

    #[test]
    fn test_single_op_roundtrip() {
        let ops = vec![(pack([2, 0, 1, 0]), 5, pack([0, 1, 0, 1]), pack([3, 1, 4, 1]))];
        let (proof, log_size) = prove_oods(&ops).expect("prove");
        assert!(verify_oods(&proof, log_size).expect("verify"));
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let mut seed = 0xDEAD_C0DE;
        let ops: Vec<OodsOp> = (0..8)
            .map(|_| (rand_qm31(&mut seed), rand_m31(&mut seed) as u32, rand_qm31(&mut seed), rand_qm31(&mut seed)))
            .collect();
        let (proof, log_size) = prove_oods(&ops).expect("prove");
        let mut bad = proof.clone();
        bad[proof.len() / 2] ^= 0xFF;
        assert!(!verify_oods(&bad, log_size).unwrap_or(false), "tampered OODS proof must not verify");
    }

    #[test]
    fn test_wrong_comp_value_rejected() {
        // Corrupt compValue → the relation breaks → no verifying proof.
        let ops = vec![(pack([3, 1, 4, 1]), 11, pack([5, 9, 2, 6]), pack([2, 7, 1, 8]))];
        let log = compute_log_size(ops.len());
        let mut cols = build_trace(&ops, log);
        let domain = CanonicCoset::new(log).circle_domain();
        let mut vals = cols[9].values.clone(); // column 9 = compValue0
        vals[0] = vals[0] + BaseField::from_u32_unchecked(1);
        cols[9] = CircleEvaluation::new(domain, vals);
        match prove_columns(cols, log) {
            Ok((proof, ls)) => assert!(
                !verify_oods(&proof, ls).unwrap_or(false),
                "a wrong compValue must not yield a verifying proof",
            ),
            Err(_) => {}
        }
    }

    #[test]
    fn test_wrong_oods_combo_rejected() {
        // Corrupt oodsCombo → the relation breaks → no verifying proof.
        let ops = vec![(pack([3, 1, 4, 1]), 11, pack([5, 9, 2, 6]), pack([2, 7, 1, 8]))];
        let log = compute_log_size(ops.len());
        let mut cols = build_trace(&ops, log);
        let domain = CanonicCoset::new(log).circle_domain();
        let mut vals = cols[13].values.clone(); // column 13 = oodsCombo0
        vals[0] = vals[0] + BaseField::from_u32_unchecked(1);
        cols[13] = CircleEvaluation::new(domain, vals);
        match prove_columns(cols, log) {
            Ok((proof, ls)) => assert!(
                !verify_oods(&proof, ls).unwrap_or(false),
                "a wrong oodsCombo must not yield a verifying proof",
            ),
            Err(_) => {}
        }
    }
}
