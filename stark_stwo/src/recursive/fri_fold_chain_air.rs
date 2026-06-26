//! FRI line-fold chain AIR — recursive-verifier gadget (R3.2).
//!
//! Proves K consecutive line-fold rounds where each round's input equals the
//! previous round's output.  Together with [`super::query_step_air`] (which
//! proves OODS± + the *initial* circle fold), this covers the full FRI fold
//! chain the recursive verifier must re-execute per query:
//!
//! ```text
//! Row 0 (is_first=1): output[0] = lineFold(input[0], sibling[0], alpha[0], xInv[0])
//! Row k (k ≥ 1):     output[k] = lineFold(output[k−1], sibling[k], alpha[k], xInv[k])
//!                     ^ enforced via cross-row chain constraint
//! ```
//!
//! Fold formula (identical to [`super::fold_air`]):
//! ```text
//! output = (input + sibling) + alpha·(input − sibling)·xInv
//! ```
//!
//! # Degree lowering
//!
//! `alpha·(input−sibling)·xInv` is degree 3.  Helper column
//! `p = (input − sibling)·xInv` lowers all constraints to degree 2:
//!
//! ```text
//! C_p:    p_k      = (input_k − sibling_k)·xInv_k            (4, deg 2)
//! C_f:    output_k = (input_k + sibling_k) + (alpha_k·p_k)   (4, deg 2)
//! C_chain:(1−is_first)·(input_k − output_{k−1}) = 0           (4, deg 1)
//! ```
//!
//! `is_first` is preprocessed (constant), so C_chain is degree 1 in the trace.
//!
//! # Trace layout (21 main columns + 1 preprocessed)
//!
//! ```text
//! Main:
//!  0.. 4  input   (QM31: c0.re,c0.im,c1.re,c1.im)
//!  4.. 8  sibling (QM31)
//!  8..12  alpha   (QM31 — FRI folding challenge for this round)
//! 12      xInv    (M31 scalar — x-coord inverse, the line twiddle)
//! 13..17  p       (helper: (input−sibling)·xInv, QM31)
//! 17..21  output  (QM31)
//!
//! Preprocessed:
//!  is_first — 1 on row 0, 0 on rows 1..K−1
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
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

use crate::recursive::qm31_mul_air::{add_limbs, limbs, mul_limbs, pack, scale_limbs, sub_limbs};
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub const N_MAIN_COLS: usize = 21;
pub const MIN_LOG_SIZE: u32 = 1;
pub const MAX_LOG_SIZE: u32 = 20;

const M31_P: u64 = (1u64 << 31) - 1;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub type FoldChainComponent = FrameworkComponent<FoldChainEval>;

/// One line-fold round: `(input, sibling, alpha, xInv)`.
/// `input` on round 0 is the circle-fold output from `query_step_air`;
/// on subsequent rounds the trace stores the derived `output[k−1]`.
pub type FoldRound = (u128, u128, u128, u32);

// ── Preprocessed column IDs ───────────────────────────────────────────────────

pub fn pc_is_first() -> PreProcessedColumnId {
    PreProcessedColumnId { id: "ffc_is_first".into() }
}

pub fn preprocessed_column_ids() -> Vec<PreProcessedColumnId> {
    vec![pc_is_first()]
}

// ── Reference fold ──────────────────────────────────────────────────────────────

fn fold_one(input: u128, sibling: u128, alpha: u128, x_inv: u32) -> u128 {
    let inp = limbs(input);
    let sib = limbs(sibling);
    let diff = sub_limbs(inp, sib);
    let p = scale_limbs(diff, x_inv as u64);
    pack(add_limbs(add_limbs(inp, sib), mul_limbs(limbs(alpha), p)))
}

/// Compute the full chain of K fold rounds.  `rounds[0].0` is the initial input
/// (the circle-fold output); subsequent inputs are the previous output.
pub fn fold_chain_ref(rounds: &[FoldRound]) -> Vec<u128> {
    let mut outputs = Vec::with_capacity(rounds.len());
    for (i, &(input, sibling, alpha, x_inv)) in rounds.iter().enumerate() {
        let actual_input = if i == 0 { input } else { outputs[i - 1] };
        outputs.push(fold_one(actual_input, sibling, alpha, x_inv));
    }
    outputs
}

/// Convenience: just the final fold output.
pub fn fold_chain_final(rounds: &[FoldRound]) -> u128 {
    fold_chain_ref(rounds).into_iter().last().unwrap_or(0)
}

// ── AIR ──────────────────────────────────────────────────────────────────────

pub struct FoldChainEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for FoldChainEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // C_p and C_f are degree 2; C_chain is degree 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_first = eval.get_preprocessed_column(pc_is_first());

        // Input columns: current row only (chain constraint uses inp_curr vs out_prev)
        let [inp0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [inp1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [inp2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [inp3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let [sib0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [sib1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [sib2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [sib3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let [al0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [al1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [al2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [al3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let [x_inv] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        let [p0] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [p1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [p2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);
        let [p3] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize]);

        // Output columns: current AND previous (chain: input[k] = output[k-1])
        let [out0_c, out0_p] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [out1_c, out1_p] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [out2_c, out2_p] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);
        let [out3_c, out3_p] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, -1_isize]);

        let inp = [inp0, inp1, inp2, inp3];
        let sib = [sib0, sib1, sib2, sib3];
        let alpha = [al0, al1, al2, al3];
        let p = [p0, p1, p2, p3];
        let out = [out0_c, out1_c, out2_c, out3_c];
        let out_prev = [out0_p, out1_p, out2_p, out3_p];

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let not_first = one - is_first;

        // C_p: p_k = (input_k − sibling_k)·xInv  (deg 2)
        for k in 0..4 {
            eval.add_constraint(
                p[k].clone() - (inp[k].clone() - sib[k].clone()) * x_inv.clone(),
            );
        }

        // C_f: output_k = (input_k + sibling_k) + QM31_mul(alpha_k, p_k)  (deg 2)
        let sum = [
            inp[0].clone() + sib[0].clone(),
            inp[1].clone() + sib[1].clone(),
            inp[2].clone() + sib[2].clone(),
            inp[3].clone() + sib[3].clone(),
        ];
        let two = BaseField::from_u32_unchecked(2);
        let u = alpha[2].clone() * p[2].clone() - alpha[3].clone() * p[3].clone();
        let v = alpha[2].clone() * p[3].clone() + alpha[3].clone() * p[2].clone();
        let ap = [
            alpha[0].clone() * p[0].clone() - alpha[1].clone() * p[1].clone()
                + u.clone() * two
                - v.clone(),
            alpha[0].clone() * p[1].clone() + alpha[1].clone() * p[0].clone()
                + u
                + v * two,
            alpha[0].clone() * p[2].clone() - alpha[1].clone() * p[3].clone()
                + alpha[2].clone() * p[0].clone()
                - alpha[3].clone() * p[1].clone(),
            alpha[0].clone() * p[3].clone() + alpha[1].clone() * p[2].clone()
                + alpha[2].clone() * p[1].clone()
                + alpha[3].clone() * p[0].clone(),
        ];
        for k in 0..4 {
            eval.add_constraint(out[k].clone() - (sum[k].clone() + ap[k].clone()));
        }

        // C_chain: (1−is_first)·(input[k] − output[k−1]) = 0  (deg 1)
        // inp[k] = current row's input; out_prev[k] = previous row's output
        for k in 0..4 {
            eval.add_constraint(
                not_first.clone() * (inp[k].clone() - out_prev[k].clone()),
            );
        }

        eval
    }
}

fn new_component(log_n_rows: u32) -> FoldChainComponent {
    FoldChainComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_column_ids()),
        FoldChainEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ──────────────────────────────────────────────────────────────

pub fn compute_log_size(n_rounds: usize) -> u32 {
    let mut log = MIN_LOG_SIZE;
    while (1usize << log) < n_rounds.max(1) {
        log += 1;
    }
    log
}

/// Build the fold-chain main trace and preprocessed `is_first` column from `rounds`.
///
/// Row k stores `actual_input[k]` (= `output[k-1]` for k≥1, `rounds[0].0` for k=0)
/// in the input columns; the output column holds the computed fold output.
pub fn build_trace(
    rounds: &[FoldRound],
    log_n_rows: u32,
) -> (TraceColumns, Vec<TraceCol>) {
    let n = 1usize << log_n_rows;
    debug_assert!(!rounds.is_empty(), "rounds must not be empty");
    debug_assert!(rounds.len() <= n, "rounds exceed trace capacity");

    let domain = CanonicCoset::new(log_n_rows).circle_domain();
    let bf0 = BaseField::from_u32_unchecked(0);

    let mut cols: Vec<Vec<BaseField>> = vec![vec![bf0; n]; N_MAIN_COLS];
    let mut is_first_col: Vec<BaseField> = vec![bf0; n];

    let set_qm31 = |cols: &mut Vec<Vec<BaseField>>, base: usize, row: usize, q: u128| {
        let l = limbs(q);
        for k in 0..4 {
            cols[base + k][row] = BaseField::from_u32_unchecked(l[k] as u32);
        }
    };

    let mut prev_output: u128 = 0;
    for (r, &(input, sibling, alpha, x_inv)) in rounds.iter().enumerate() {
        debug_assert!(
            [input, sibling, alpha]
                .iter()
                .all(|&q| limbs(q).iter().all(|&l| l < M31_P))
                && (x_inv as u64) < M31_P,
            "non-canonical limb in fri_fold_chain build_trace",
        );
        let actual_input = if r == 0 { input } else { prev_output };
        let diff = sub_limbs(limbs(actual_input), limbs(sibling));
        let p_val = scale_limbs(diff, x_inv as u64);
        let output = fold_one(actual_input, sibling, alpha, x_inv);

        set_qm31(&mut cols, 0, r, actual_input);
        set_qm31(&mut cols, 4, r, sibling);
        set_qm31(&mut cols, 8, r, alpha);
        cols[12][r] = BaseField::from_u32_unchecked(x_inv);
        set_qm31(&mut cols, 13, r, pack(p_val));
        set_qm31(&mut cols, 17, r, output);

        if r == 0 {
            is_first_col[0] = BaseField::from_u32_unchecked(1);
        }
        prev_output = output;
    }

    // Break the chain at the first padding row so the all-zero padding
    // doesn't violate `input[k] = output[k-1]` (since output[last_actual] ≠ 0).
    if rounds.len() < n {
        is_first_col[rounds.len()] = BaseField::from_u32_unchecked(1);
    }

    for col in cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    bit_reverse_coset_to_circle_domain_order(&mut is_first_col);

    let main_trace: TraceColumns = cols
        .into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect();
    let preproc: Vec<TraceCol> =
        vec![CircleEvaluation::new(domain, is_first_col)];

    (main_trace, preproc)
}

// ── Prove / verify roundtrip ────────────────────────────────────────────────────

/// Prove K line-fold rounds in a chain.
/// Returns `(proof_bytes, log_size, final_output)`.
pub fn prove_fold_chain(rounds: &[FoldRound]) -> Result<(Vec<u8>, u32, u128), String> {
    if rounds.is_empty() {
        return Err("rounds must not be empty".into());
    }
    let log_size = compute_log_size(rounds.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("too many rounds: log_size {log_size} exceeds {MAX_LOG_SIZE}"));
    }

    let final_output = fold_chain_final(rounds);
    let (main_trace, preproc) = build_trace(rounds, log_size);
    let proof_bytes = prove_columns(preproc, main_trace, log_size)?;
    Ok((proof_bytes, log_size, final_output))
}

fn prove_columns(
    preproc: Vec<TraceCol>,
    main_trace: TraceColumns,
    log_size: u32,
) -> Result<Vec<u8>, String> {
    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree = commitment_scheme.tree_builder();
    tree.extend_evals(preproc);
    tree.commit(channel);

    let mut tree = commitment_scheme.tree_builder();
    tree.extend_evals(main_trace);
    tree.commit(channel);

    let component = new_component(log_size);
    let proof =
        prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
            .map_err(|e| format!("proving error: {e:?}"))?;

    bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))
}

/// Verify a proof produced by [`prove_fold_chain`].
pub fn verify_fold_chain(proof_bytes: &[u8], log_size: u32) -> Result<bool, String> {
    if !(MIN_LOG_SIZE..=MAX_LOG_SIZE).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range"));
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
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

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

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursive::fold_air::fold_ref;

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

    // Single-round chain must match fold_ref exactly
    #[test]
    fn test_single_round_consistent_with_fold_ref() {
        let mut s = 0xabcd_1234u64;
        let input = rand_qm31(&mut s);
        let sib = rand_qm31(&mut s);
        let alpha = rand_qm31(&mut s);
        let x_inv = rand_m31(&mut s) as u32;

        let chain_out = fold_chain_ref(&[(input, sib, alpha, x_inv)]);
        let ref_out = fold_ref(input, sib, alpha, x_inv);
        assert_eq!(chain_out[0], ref_out, "single-round chain must match fold_ref");
    }

    // 3-round chain: each round's input is the previous output
    #[test]
    fn test_3_round_chaining() {
        let mut s = 0x1234u64;
        let rounds: Vec<FoldRound> = (0..3)
            .map(|_| {
                (rand_qm31(&mut s), rand_qm31(&mut s), rand_qm31(&mut s), rand_m31(&mut s) as u32)
            })
            .collect();

        let chain = fold_chain_ref(&rounds);

        let r0 = fold_ref(rounds[0].0, rounds[0].1, rounds[0].2, rounds[0].3);
        assert_eq!(chain[0], r0);
        let r1 = fold_ref(r0, rounds[1].1, rounds[1].2, rounds[1].3);
        assert_eq!(chain[1], r1);
        let r2 = fold_ref(r1, rounds[2].1, rounds[2].2, rounds[2].3);
        assert_eq!(chain[2], r2);
    }

    // Roundtrip: 1 round
    #[test]
    fn test_prove_verify_1_round() {
        let mut s = 0xaau64;
        let rounds = vec![(rand_qm31(&mut s), rand_qm31(&mut s), rand_qm31(&mut s), rand_m31(&mut s) as u32)];
        let (bytes, log_size, final_out) = prove_fold_chain(&rounds).unwrap();
        assert!(verify_fold_chain(&bytes, log_size).unwrap());
        assert_eq!(final_out, fold_chain_final(&rounds));
    }

    // Roundtrip: 4 rounds (typical production num_folds)
    #[test]
    fn test_prove_verify_4_rounds() {
        let mut s = 0x1111u64;
        let rounds: Vec<FoldRound> = (0..4)
            .map(|_| {
                (rand_qm31(&mut s), rand_qm31(&mut s), rand_qm31(&mut s), rand_m31(&mut s) as u32)
            })
            .collect();
        let (bytes, log_size, final_out) = prove_fold_chain(&rounds).unwrap();
        assert!(verify_fold_chain(&bytes, log_size).unwrap());
        assert_eq!(final_out, fold_chain_final(&rounds));
    }

    // Roundtrip: 6 rounds (production num_folds=6)
    #[test]
    fn test_prove_verify_6_rounds() {
        let mut s = 0x2222u64;
        let rounds: Vec<FoldRound> = (0..6)
            .map(|_| {
                (rand_qm31(&mut s), rand_qm31(&mut s), rand_qm31(&mut s), rand_m31(&mut s) as u32)
            })
            .collect();
        let (bytes, log_size, _) = prove_fold_chain(&rounds).unwrap();
        assert!(verify_fold_chain(&bytes, log_size).unwrap());
    }

    // Rejection: tampered proof bytes
    #[test]
    fn test_tampered_proof_rejected() {
        let mut s = 0x3333u64;
        let rounds: Vec<FoldRound> = (0..2)
            .map(|_| {
                (rand_qm31(&mut s), rand_qm31(&mut s), rand_qm31(&mut s), rand_m31(&mut s) as u32)
            })
            .collect();
        let (mut bytes, log_size, _) = prove_fold_chain(&rounds).unwrap();
        let n = bytes.len();
        if n > 8 {
            bytes[n - 4] ^= 0xff;
        }
        assert!(verify_fold_chain(&bytes, log_size).is_err());
    }

    // Rejection: corrupted output column in trace
    #[test]
    fn test_wrong_output_rejected() {
        let mut s = 0x4444u64;
        let rounds: Vec<FoldRound> = (0..2)
            .map(|_| {
                (rand_qm31(&mut s), rand_qm31(&mut s), rand_qm31(&mut s), rand_m31(&mut s) as u32)
            })
            .collect();
        let log_size = compute_log_size(rounds.len());
        let (mut main_trace, preproc) = build_trace(&rounds, log_size);

        // Corrupt output col 17 (first limb of `output`) at index 0
        {
            let col = &mut main_trace[17];
            let mut vals: Vec<BaseField> = col.values.to_vec();
            vals[0] = BaseField::from_u32_unchecked(12345);
            let domain = CanonicCoset::new(log_size).circle_domain();
            *col = CircleEvaluation::new(domain, vals);
        }

        let result = prove_columns(preproc, main_trace, log_size);
        assert!(result.is_err());
    }

    // Rejection: broken chain (input of round 1 ≠ output of round 0)
    #[test]
    fn test_broken_chain_rejected() {
        let mut s = 0x5555u64;
        let rounds: Vec<FoldRound> = (0..2)
            .map(|_| {
                (rand_qm31(&mut s), rand_qm31(&mut s), rand_qm31(&mut s), rand_m31(&mut s) as u32)
            })
            .collect();
        let log_size = compute_log_size(rounds.len());
        let (mut main_trace, preproc) = build_trace(&rounds, log_size);

        // Corrupt input col 0 (first limb of `input`) at index 1 (row 1) to break chain
        {
            let col = &mut main_trace[0];
            let mut vals: Vec<BaseField> = col.values.to_vec();
            vals[1] = BaseField::from_u32_unchecked(99999);
            let domain = CanonicCoset::new(log_size).circle_domain();
            *col = CircleEvaluation::new(domain, vals);
        }

        let result = prove_columns(preproc, main_trace, log_size);
        assert!(result.is_err());
    }

    // Error on empty rounds
    #[test]
    fn test_empty_rounds_error() {
        assert!(prove_fold_chain(&[]).is_err());
    }
}
