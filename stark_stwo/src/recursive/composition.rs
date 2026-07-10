//! Recursive composition — per-query verification + Merkle membership in ONE STARK
//! (R3, first genuine multi-gadget composition).
//!
//! Combines two C1/C2-hardened gadgets into a **single** proof (one FRI
//! commitment → one on-chain verify), proving for one FRI query:
//!
//! ```text
//! ┌ recursive_verifier ┐  finalFold   (verifier)   leaf      ┌ merkle_path ┐
//! │ OODS± + circle fold│ ───────────▶ hashLeaf ───────────▶ │ leaf @ index │──▶ root
//! │ + K line folds     │  (pinned)                 (pinned)  │ + siblings   │
//! └────────────────────┘                                     └──────────────┘
//! ```
//!
//! Both components live in one commitment (shared `TraceLocationAllocator`,
//! combined Tree 0 = both preprocessed sets, Tree 1 = both main traces), at a
//! shared `log_size`.  The connecting value is bound end-to-end:
//!
//! - `recursive_verifier` pins the claimed `finalFold` in its `fin` preprocessed
//!   columns and its `is_output` constraint forces the trace's fold output to
//!   equal it (C1);
//! - the verifier computes `leaf = qm31_leaf_hash(finalFold)` off-circuit (cheap,
//!   from the *pinned* finalFold) and pins it in `merkle_path`'s `leaf` column,
//!   whose `is_first` constraint forces the trace leaf to equal it (C1);
//! - the whole combined preprocessed tree is pinned via
//!   [`canonical_composition_preproc_root`] (C2).
//!
//! So a malicious prover cannot (a) claim a `finalFold` its fold chain didn't
//! produce, (b) feed a `leaf ≠ hashLeaf(finalFold)` into the Merkle path, or
//! (c) forge any selector — the composition proves the *whole* per-query FRI
//! membership check as one recursive statement.  `root` is still bound via
//! Fiat-Shamir (it is the committed FRI-layer root the caller checks).
//!
//! This is the mini-scale composition the roadmap calls for before scaling to the
//! full N-query VFRI11 verifier (reduces gadget-composition risk).

use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::TraceLocationAllocator;

use crate::recursive::integration::qm31_leaf_hash;
use crate::recursive::merkle_path_air as merkle;
use crate::recursive::qm31_mul_air::limbs;
use crate::recursive::recursive_verifier as rv;
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

/// Per-query fold-chain inputs (see [`rv::StepOp`]) plus the Merkle path.
pub type QueryStep = rv::StepOp;
pub type FoldRound = rv::FoldRound;

const RV_MAIN_COLS: usize = rv::N_MAIN_COLS; // 42
const MERKLE_MAIN_COLS: usize = merkle::N_MAIN_COLS; // 10
// is_step, chain_on, is_output, fin0..3, alpha_p0..3, px, zx0..3, inv
const RV_PREPROC_COLS: usize = 17;
const MERKLE_PREPROC_COLS: usize = 6; // rc0, rc1, is_init, is_first, idx_bit, leaf
const TOTAL_MAIN_COLS: usize = RV_MAIN_COLS + MERKLE_MAIN_COLS; // 52
const TOTAL_PREPROC_COLS: usize = RV_PREPROC_COLS + MERKLE_PREPROC_COLS; // 23

/// Shared `log_size` that fits both a 1-query fold chain (`1 + num_folds` rows)
/// and a `depth`-compression Merkle path (`depth · 8` rows).
pub fn composition_log_size(num_folds: usize, depth: usize) -> u32 {
    rv::compute_log_size(1 + num_folds).max(merkle::compute_log_size(depth))
}

/// Combined preprocessed column IDs, in commit order: recursive_verifier's, then
/// merkle_path's. The shared allocator registers exactly these.
fn combined_preproc_ids() -> Vec<stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId>
{
    let mut ids = rv::preprocessed_column_ids();
    ids.extend(merkle::preprocessed_column_ids());
    ids
}

/// Build the combined canonical preprocessed columns (verifier-fixed): the
/// recursive_verifier selectors + pinned `finalFold`, then the merkle selectors +
/// pinned `leaf`/`index`.
fn combined_preproc(
    final_fold: u128,
    challenges: &rv::QueryChallenges,
    num_folds: usize,
    leaf: u64,
    index: u32,
    log_size: u32,
) -> rv::TraceColumns {
    let mut cols = rv::build_preproc(
        &[final_fold],
        std::slice::from_ref(challenges),
        num_folds,
        log_size,
    );
    cols.extend(merkle::build_preproc(leaf, index, log_size));
    cols
}

/// Recompute the combined Tree-0 commitment root (both preprocessed sets), pinned
/// by the verifier (audit gap C2 across the composition).
fn canonical_composition_preproc_root(
    final_fold: u128,
    challenges: &rv::QueryChallenges,
    num_folds: usize,
    leaf: u64,
    index: u32,
    log_size: u32,
) -> <Blake2sM31MerkleHasher as stwo::core::vcs_lifted::MerkleHasherLifted>::Hash {
    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();
    let mut throwaway = Blake2sM31Channel::default();
    let mut tree = scheme.tree_builder();
    tree.extend_evals(combined_preproc(final_fold, challenges, num_folds, leaf, index, log_size));
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

fn mix_public(channel: &mut Blake2sM31Channel, px: u32, final_fold: u128, leaf: u64, index: u32, root: u64) {
    let l = limbs(final_fold);
    channel.mix_u32s(&[px, l[0] as u32, l[1] as u32, l[2] as u32, l[3] as u32]);
    channel.mix_u32s(&[(leaf % ((1u64 << 31) - 1)) as u32, index, (root % ((1u64 << 31) - 1)) as u32]);
}

/// Result of a composition proof.
pub struct QueryMembershipResult {
    pub proof: Vec<u8>,
    pub log_size: u32,
    pub num_folds: usize,
    pub depth: usize,
    pub challenges: rv::QueryChallenges,
    pub final_fold: u128,
    pub leaf: u64,
    pub index: u32,
    pub root: u64,
}

/// Prove, in one STARK, that the per-query fold chain `(step, rounds)` yields a
/// final fold value whose leaf hash is Merkle-authenticated by `(sibs, bits)`.
pub fn prove_query_membership(
    step: &QueryStep,
    rounds: &[FoldRound],
    sibs: &[u64],
    bits: &[bool],
) -> Result<QueryMembershipResult, String> {
    if sibs.len() != bits.len() {
        return Err("sibs/bits length mismatch".into());
    }
    if sibs.is_empty() {
        return Err("path must have depth ≥ 1".into());
    }
    let num_folds = rounds.len();
    let depth = sibs.len();
    let log_size = composition_log_size(num_folds, depth);
    if log_size > rv::MAX_LOG_SIZE.min(merkle::MAX_LOG_SIZE) {
        return Err(format!("composition log_size {log_size} too large"));
    }

    let final_fold = rv::recursive_query_final(step, rounds);
    let leaf = qm31_leaf_hash(final_fold);
    let index = merkle::bits_to_index(bits);
    let root = merkle::merkle_path_root(leaf, sibs, bits);
    let px = step.2;

    // Build both traces at the shared log_size.
    let (rv_main, rv_preproc) = rv::build_trace(step, rounds, log_size);
    let (merkle_main, merkle_preproc, merkle_root) = merkle::build_trace(leaf, sibs, bits, log_size);
    debug_assert_eq!(merkle_root, root);
    debug_assert_eq!(rv_main.len(), RV_MAIN_COLS);
    debug_assert_eq!(merkle_main.len(), MERKLE_MAIN_COLS);

    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let channel = &mut Blake2sM31Channel::default();
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    // Tree 0: combined preprocessed (rv preproc ++ merkle preproc).
    let mut combined_preproc_cols = rv_preproc;
    combined_preproc_cols.extend(merkle_preproc);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(combined_preproc_cols);
    tree.commit(channel);

    // Tree 1: combined main (rv main ++ merkle main).
    let mut combined_main = rv_main;
    combined_main.extend(merkle_main);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(combined_main);
    tree.commit(channel);

    mix_public(channel, px, final_fold, leaf, index, root);

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&combined_preproc_ids());
    let rv_comp = rv::RecursiveVerifierComponent::new(
        &mut alloc,
        rv::RecursiveVerifierEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let merkle_comp = merkle::MerklePathComponent::new(
        &mut alloc,
        merkle::MerklePathEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&rv_comp, &merkle_comp],
        channel,
        scheme,
    )
    .map_err(|e| format!("composition prove error: {e:?}"))?;

    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("composition serialize error: {e:?}"))?;

    Ok(QueryMembershipResult {
        proof: bytes,
        log_size,
        num_folds,
        depth,
        challenges: rv::query_challenges(step, rounds),
        final_fold,
        leaf,
        index,
        root,
    })
}

/// Verify a composition proof against the claimed public I/O
/// `(num_folds, px, final_fold, index, root)`. The `leaf` is *recomputed* by the
/// verifier as `qm31_leaf_hash(final_fold)` and pinned — so the Merkle path is
/// authenticating exactly the hash of the fold-chain output.
pub fn verify_query_membership(
    proof_bytes: &[u8],
    log_size: u32,
    num_folds: usize,
    challenges: &rv::QueryChallenges,
    px: u32,
    final_fold: u128,
    index: u32,
    root: u64,
) -> Result<bool, String> {
    let leaf = qm31_leaf_hash(final_fold);

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("composition deserialize error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&combined_preproc_ids());
    let rv_comp = rv::RecursiveVerifierComponent::new(
        &mut alloc,
        rv::RecursiveVerifierEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let merkle_comp = merkle::MerklePathComponent::new(
        &mut alloc,
        merkle::MerklePathEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    if proof.commitments.len() < 2 {
        return Err(format!(
            "composition: expected ≥ 2 commitments, got {}",
            proof.commitments.len()
        ));
    }

    // C1/C2: pin the combined preprocessed tree — selectors, the pinned finalFold
    // (recursive_verifier) and the pinned leaf/index (merkle) must all be canonical.
    let canonical_root =
        canonical_composition_preproc_root(final_fold, challenges, num_folds, leaf, index, log_size);
    if proof.commitments[0] != canonical_root {
        return Ok(false);
    }

    commitment_scheme.commit(proof.commitments[0], &[log_size; TOTAL_PREPROC_COLS], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &[log_size; TOTAL_MAIN_COLS], verifier_channel);

    mix_public(verifier_channel, px, final_fold, leaf, index, root);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&rv_comp, &merkle_comp],
        verifier_channel,
        commitment_scheme,
        proof,
    )
    .is_ok())
}

// ── N-query composition (the VFRI11 shape: N queries + N paths, one proof) ──────

/// Shared log_size fitting N query blocks of `1 + num_folds` rows AND `n_paths`
/// Merkle paths of `depth` compressions.
fn queries_log_size(n_queries: usize, num_folds: usize, depth: usize) -> u32 {
    rv::compute_log_size(n_queries * (1 + num_folds))
        .max(merkle::compute_log_size_multi(n_queries, depth))
}

fn canonical_queries_preproc_root(
    finals: &[u128],
    challenges: &[rv::QueryChallenges],
    num_folds: usize,
    leaves: &[u64],
    indices: &[u32],
    depth: usize,
    log_size: u32,
) -> <Blake2sM31MerkleHasher as stwo::core::vcs_lifted::MerkleHasherLifted>::Hash {
    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();
    let mut throwaway = Blake2sM31Channel::default();
    let mut cols = rv::build_preproc(finals, challenges, num_folds, log_size);
    cols.extend(merkle::build_preproc_multi(leaves, indices, depth, log_size));
    let mut tree = scheme.tree_builder();
    tree.extend_evals(cols);
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

fn mix_public_queries(
    channel: &mut Blake2sM31Channel,
    pxs: &[u32],
    finals: &[u128],
    leaves: &[u64],
    indices: &[u32],
    roots: &[u64],
) {
    let mut words = Vec::new();
    for i in 0..finals.len() {
        let l = limbs(finals[i]);
        words.extend_from_slice(&[pxs[i], l[0] as u32, l[1] as u32, l[2] as u32, l[3] as u32]);
    }
    channel.mix_u32s(&words);
    let mut mwords = Vec::new();
    for p in 0..leaves.len() {
        mwords.extend_from_slice(&[(leaves[p] % ((1u64 << 31) - 1)) as u32, indices[p], (roots[p] % ((1u64 << 31) - 1)) as u32]);
    }
    channel.mix_u32s(&mwords);
}

/// Result of an N-query composition proof.
pub struct QueriesMembershipResult {
    pub proof: Vec<u8>,
    pub log_size: u32,
    pub num_folds: usize,
    pub depth: usize,
    pub challenges: Vec<rv::QueryChallenges>,
    pub finals: Vec<u128>,
    pub leaves: Vec<u64>,
    pub indices: Vec<u32>,
    pub roots: Vec<u64>,
}

/// Prove, in ONE STARK, that each of N per-query fold chains yields a final fold
/// value whose leaf hash is Merkle-authenticated by its path — the VFRI11 shape
/// (N queries + N paths). All queries share `num_folds`; all paths share `depth`.
pub fn prove_queries_membership(
    queries: &[(QueryStep, Vec<FoldRound>)],
    paths: &[(Vec<u64>, Vec<bool>)],
) -> Result<QueriesMembershipResult, String> {
    if queries.is_empty() {
        return Err("need ≥ 1 query".into());
    }
    if queries.len() != paths.len() {
        return Err("queries/paths length mismatch".into());
    }
    let num_folds = queries[0].1.len();
    if queries.iter().any(|(_, r)| r.len() != num_folds) {
        return Err("all queries must share num_folds".into());
    }
    let depth = paths[0].0.len();
    if paths.iter().any(|(s, b)| s.len() != depth || b.len() != depth) {
        return Err("all paths must share depth".into());
    }
    let n = queries.len();
    let log_size = queries_log_size(n, num_folds, depth);

    let finals = rv::recursive_queries_final(queries);
    let leaves: Vec<u64> = finals.iter().map(|&f| qm31_leaf_hash(f)).collect();
    let sibs: Vec<Vec<u64>> = paths.iter().map(|(s, _)| s.clone()).collect();
    let bits: Vec<Vec<bool>> = paths.iter().map(|(_, b)| b.clone()).collect();
    let indices: Vec<u32> = bits.iter().map(|b| merkle::bits_to_index(b)).collect();
    let pxs: Vec<u32> = queries.iter().map(|(s, _)| s.2).collect();

    let (rv_main, rv_preproc) = rv::build_trace_multi(queries, log_size);
    let (merkle_main, merkle_preproc, roots) = merkle::build_trace_multi(&leaves, &sibs, &bits, log_size);

    let config = make_config(log_size);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_BLOWUP + 1).circle_domain().half_coset,
    );
    let channel = &mut Blake2sM31Channel::default();
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    let mut combined_preproc = rv_preproc;
    combined_preproc.extend(merkle_preproc);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(combined_preproc);
    tree.commit(channel);

    let mut combined_main = rv_main;
    combined_main.extend(merkle_main);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(combined_main);
    tree.commit(channel);

    mix_public_queries(channel, &pxs, &finals, &leaves, &indices, &roots);

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&combined_preproc_ids());
    let rv_comp = rv::RecursiveVerifierComponent::new(
        &mut alloc,
        rv::RecursiveVerifierEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let merkle_comp = merkle::MerklePathComponent::new(
        &mut alloc,
        merkle::MerklePathEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&rv_comp, &merkle_comp],
        channel,
        scheme,
    )
    .map_err(|e| format!("N-query composition prove error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("N-query composition serialize error: {e:?}"))?;

    let challenges: Vec<rv::QueryChallenges> = queries.iter().map(|(s, r)| rv::query_challenges(s, r)).collect();
    Ok(QueriesMembershipResult { proof: bytes, log_size, num_folds, depth, challenges, finals, leaves, indices, roots })
}

/// Verify an N-query composition proof against the claimed per-query public I/O.
pub fn verify_queries_membership(
    proof_bytes: &[u8],
    log_size: u32,
    num_folds: usize,
    depth: usize,
    challenges: &[rv::QueryChallenges],
    pxs: &[u32],
    finals: &[u128],
    indices: &[u32],
    roots: &[u64],
) -> Result<bool, String> {
    if finals.is_empty() || pxs.len() != finals.len() || indices.len() != finals.len() || roots.len() != finals.len() || challenges.len() != finals.len() {
        return Err("public-input length mismatch".into());
    }
    let leaves: Vec<u64> = finals.iter().map(|&f| qm31_leaf_hash(f)).collect();

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("N-query deserialize error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&combined_preproc_ids());
    let rv_comp = rv::RecursiveVerifierComponent::new(
        &mut alloc,
        rv::RecursiveVerifierEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );
    let merkle_comp = merkle::MerklePathComponent::new(
        &mut alloc,
        merkle::MerklePathEval { log_n_rows: log_size },
        SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    if proof.commitments.len() < 2 {
        return Err(format!("N-query: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    let canonical_root =
        canonical_queries_preproc_root(finals, challenges, num_folds, &leaves, indices, depth, log_size);
    if proof.commitments[0] != canonical_root {
        return Ok(false);
    }

    commitment_scheme.commit(proof.commitments[0], &[log_size; TOTAL_PREPROC_COLS], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &[log_size; TOTAL_MAIN_COLS], verifier_channel);

    mix_public_queries(verifier_channel, pxs, finals, &leaves, indices, roots);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&rv_comp, &merkle_comp],
        verifier_channel,
        commitment_scheme,
        proof,
    )
    .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const M31_P: u64 = (1u64 << 31) - 1;

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
    fn sample_step(seed: &mut u64) -> QueryStep {
        (
            rand_qm31(seed),
            rand_qm31(seed),
            rand_m31(seed) as u32,
            rand_qm31(seed),
            rand_qm31(seed),
            rand_qm31(seed),
            rand_qm31(seed),
            rand_m31(seed) as u32,
        )
    }
    fn sample_rounds(seed: &mut u64, k: usize) -> Vec<FoldRound> {
        (0..k).map(|_| (rand_qm31(seed), rand_qm31(seed), rand_m31(seed) as u32)).collect()
    }

    // End-to-end: prove per-query fold chain + Merkle membership in ONE proof.
    #[test]
    fn test_composition_roundtrip() {
        let mut s = 0xC0117u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 6);
        let depth = 2;
        let sibs: Vec<u64> = (0..depth).map(|_| rand_m31(&mut s)).collect();
        let bits: Vec<bool> = (0..depth).map(|_| rand_m31(&mut s) & 1 == 1).collect();

        let r = prove_query_membership(&step, &rounds, &sibs, &bits).unwrap();
        assert_eq!(r.final_fold, rv::recursive_query_final(&step, &rounds));
        assert_eq!(r.leaf, qm31_leaf_hash(r.final_fold));
        assert_eq!(r.root, merkle::merkle_path_root(r.leaf, &sibs, &bits));
        assert!(
            verify_query_membership(&r.proof, r.log_size, r.num_folds, &r.challenges, step.2, r.final_fold, r.index, r.root)
                .unwrap(),
            "an honest composition proof must verify",
        );
    }

    // A wrong claimed final fold changes the pinned finalFold AND the recomputed
    // leaf → different canonical preproc root → rejected.
    #[test]
    fn test_composition_wrong_final_rejected() {
        let mut s = 0xBADC0u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 4);
        let depth = 3;
        let sibs: Vec<u64> = (0..depth).map(|_| rand_m31(&mut s)).collect();
        let bits: Vec<bool> = (0..depth).map(|_| rand_m31(&mut s) & 1 == 1).collect();

        let r = prove_query_membership(&step, &rounds, &sibs, &bits).unwrap();
        assert!(verify_query_membership(&r.proof, r.log_size, r.num_folds, &r.challenges, step.2, r.final_fold, r.index, r.root).unwrap());
        assert!(
            !verify_query_membership(&r.proof, r.log_size, r.num_folds, &r.challenges, step.2, r.final_fold ^ 1, r.index, r.root)
                .unwrap_or(false),
            "a wrong final fold must not verify",
        );
    }

    // N-query composition: N per-query fold chains + N Merkle paths in ONE proof.
    #[test]
    fn test_queries_membership_roundtrip() {
        let mut s = 0x4e51u64;
        let n = 3;
        let num_folds = 4;
        let depth = 2;
        let queries: Vec<(QueryStep, Vec<FoldRound>)> =
            (0..n).map(|_| (sample_step(&mut s), sample_rounds(&mut s, num_folds))).collect();
        let paths: Vec<(Vec<u64>, Vec<bool>)> = (0..n)
            .map(|_| {
                (
                    (0..depth).map(|_| rand_m31(&mut s)).collect(),
                    (0..depth).map(|_| rand_m31(&mut s) & 1 == 1).collect(),
                )
            })
            .collect();

        let r = prove_queries_membership(&queries, &paths).unwrap();
        let pxs: Vec<u32> = queries.iter().map(|(st, _)| st.2).collect();
        // finals match each query's reference.
        for (i, (st, rd)) in queries.iter().enumerate() {
            assert_eq!(r.finals[i], rv::recursive_query_final(st, rd));
        }
        assert!(
            verify_queries_membership(&r.proof, r.log_size, r.num_folds, r.depth, &r.challenges, &pxs, &r.finals, &r.indices, &r.roots)
                .unwrap(),
            "an honest N-query composition must verify",
        );
        // A wrong final for one query must fail (changes its pinned fin + leaf).
        let mut bad = r.finals.clone();
        bad[1] ^= 1;
        assert!(
            !verify_queries_membership(&r.proof, r.log_size, r.num_folds, r.depth, &r.challenges, &pxs, &bad, &r.indices, &r.roots)
                .unwrap_or(false),
            "a wrong final fold must not verify",
        );
    }

    // A wrong claimed root (not the one the path hashes to) must not verify.
    #[test]
    fn test_composition_wrong_root_rejected() {
        let mut s = 0xBAD8007u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 5);
        let depth = 2;
        let sibs: Vec<u64> = (0..depth).map(|_| rand_m31(&mut s)).collect();
        let bits: Vec<bool> = (0..depth).map(|_| rand_m31(&mut s) & 1 == 1).collect();

        let r = prove_query_membership(&step, &rounds, &sibs, &bits).unwrap();
        assert!(
            !verify_query_membership(&r.proof, r.log_size, r.num_folds, &r.challenges, step.2, r.final_fold, r.index, r.root ^ 1)
                .unwrap_or(false),
            "a wrong Merkle root must not verify",
        );
    }
}
