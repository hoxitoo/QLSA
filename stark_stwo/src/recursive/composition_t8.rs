//! Recursive composition on the **wide (t=8) inner hash** — per-query verification
//! + t=8 Merkle membership in ONE STARK (R3.15).
//!
//! The t=8 analogue of [`super::composition`]: it swaps the inner hash from the
//! t=2 `merkle_path_air` (31-bit nodes → 2^15.5 collision) to the
//! [`super::merkle_path_t8_air`] (4-word/124-bit nodes → 2^62 collision), the hash
//! a **VFRI11** FRI-layer decommitment actually uses.  For one FRI query it proves:
//!
//! ```text
//! ┌ recursive_verifier ┐  finalFold   (verifier)   leaf4     ┌ merkle_path_t8 ┐
//! │ OODS± + circle fold│ ───────────▶ hashLeaf_t8 ────────▶ │ leaf @ index    │──▶ root
//! │ + K line folds     │  (pinned)                (pinned)   │ + siblings (t8) │
//! └────────────────────┘                                     └─────────────────┘
//! ```
//!
//! Value-bound end-to-end, fully in-circuit:
//! - `recursive_verifier` pins the claimed `finalFold` (`fin` columns + `is_output`
//!   constraint, C1) — the fold-chain arithmetic is QM31, unchanged from t=2;
//! - the verifier computes `leaf4 = qm31_leaf_hash_t8(finalFold)` off-circuit (a
//!   deterministic public function of the *pinned* finalFold) and pins it in
//!   `merkle_path_t8`'s 4-word `leaf` columns (C1 leaf binding);
//! - `merkle_path_t8` pins the claimed `root` in-circuit (C1 root binding) and
//!   authenticates `leaf4 @ index + siblings → root` over 4-word nodes;
//! - the whole combined preprocessed tree is pinned via one canonical root (C2).
//!
//! Only the inner-hash gadget changes vs [`super::composition`]; the fold-chain
//! component and the finalFold→leaf binding pattern are identical.  This is the
//! step that lifts the recursion's inner-hash node collision to ~2^62; t=16
//! (128-bit) is the same swap once a t=16 path AIR exists.

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

use crate::recursive::integration::qm31_leaf_hash_t8;
use crate::recursive::merkle_path_t8_air as merkle;
use crate::recursive::qm31_mul_air::limbs;
use crate::recursive::recursive_verifier as rv;
use crate::poseidon2::M31_P;
use crate::{make_config, LOG_BLOWUP, MAX_PROOF_BYTES, N_FRI_QUERIES, POW_BITS};

pub type QueryStep = rv::StepOp;
pub type FoldRound = rv::FoldRound;

const RV_MAIN_COLS: usize = rv::N_MAIN_COLS; // 42
const MERKLE_MAIN_COLS: usize = merkle::N_MAIN_COLS; // 45
const RV_PREPROC_COLS: usize = 17;
const MERKLE_PREPROC_COLS: usize = 22; // rc x8 + 4 selectors + idx_bit + leaf x4 + is_root + root x4
const TOTAL_MAIN_COLS: usize = RV_MAIN_COLS + MERKLE_MAIN_COLS; // 87
const TOTAL_PREPROC_COLS: usize = RV_PREPROC_COLS + MERKLE_PREPROC_COLS; // 39

/// Shared `log_size` fitting a 1-query fold chain (`1 + num_folds` rows) and a
/// `depth`-compression t=8 Merkle path (`depth · 22` rows).
pub fn composition_log_size(num_folds: usize, depth: usize) -> u32 {
    rv::compute_log_size(1 + num_folds).max(merkle::compute_log_size(depth))
}

fn combined_preproc_ids(
) -> Vec<stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId> {
    let mut ids = rv::preprocessed_column_ids();
    ids.extend(merkle::preprocessed_column_ids());
    ids
}

#[allow(clippy::too_many_arguments)]
fn combined_preproc(
    final_fold: u128,
    challenges: &rv::QueryChallenges,
    num_folds: usize,
    leaf: [u64; 4],
    index: u32,
    root: [u64; 4],
    depth: usize,
    log_size: u32,
) -> rv::TraceColumns {
    let mut cols = rv::build_preproc(&[final_fold], std::slice::from_ref(challenges), num_folds, log_size);
    cols.extend(merkle::build_preproc(leaf, index, root, depth, log_size));
    cols
}

#[allow(clippy::too_many_arguments)]
fn canonical_composition_preproc_root(
    final_fold: u128,
    challenges: &rv::QueryChallenges,
    num_folds: usize,
    leaf: [u64; 4],
    index: u32,
    root: [u64; 4],
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
    let mut tree = scheme.tree_builder();
    tree.extend_evals(combined_preproc(final_fold, challenges, num_folds, leaf, index, root, depth, log_size));
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

fn mix_public(
    channel: &mut Blake2sM31Channel,
    px: u32,
    final_fold: u128,
    leaf: [u64; 4],
    index: u32,
    root: [u64; 4],
) {
    let l = limbs(final_fold);
    let w = |v: u64| (v % M31_P) as u32;
    channel.mix_u32s(&[px, l[0] as u32, l[1] as u32, l[2] as u32, l[3] as u32]);
    channel.mix_u32s(&[
        w(leaf[0]), w(leaf[1]), w(leaf[2]), w(leaf[3]),
        index,
        w(root[0]), w(root[1]), w(root[2]), w(root[3]),
    ]);
}

/// Result of a t=8 composition proof.
pub struct QueryMembershipT8Result {
    pub proof: Vec<u8>,
    pub log_size: u32,
    pub num_folds: usize,
    pub depth: usize,
    pub challenges: rv::QueryChallenges,
    pub final_fold: u128,
    pub leaf: [u64; 4],
    pub index: u32,
    pub root: [u64; 4],
}

/// Prove, in one STARK, that the per-query fold chain `(step, rounds)` yields a
/// final fold value whose t=8 leaf hash is Merkle-authenticated by `(sibs, bits)`
/// over 4-word nodes.
pub fn prove_query_membership_t8(
    step: &QueryStep,
    rounds: &[FoldRound],
    sibs: &[[u64; 4]],
    bits: &[bool],
) -> Result<QueryMembershipT8Result, String> {
    if sibs.len() != bits.len() {
        return Err("sibs/bits length mismatch".into());
    }
    if sibs.is_empty() {
        return Err("path must have depth ≥ 1".into());
    }
    let num_folds = rounds.len();
    let depth = sibs.len();
    if num_folds > rv::MAX_NUM_FOLDS {
        return Err(format!("num_folds {num_folds} exceeds MAX_NUM_FOLDS {}", rv::MAX_NUM_FOLDS));
    }
    if depth > merkle::MAX_DEPTH {
        return Err(format!("path depth {depth} exceeds MAX_DEPTH {}", merkle::MAX_DEPTH));
    }
    let log_size = composition_log_size(num_folds, depth);
    if log_size > rv::MAX_LOG_SIZE.min(merkle::MAX_LOG_SIZE) {
        return Err(format!("composition log_size {log_size} too large"));
    }

    let final_fold = rv::recursive_query_final(step, rounds);
    let leaf = qm31_leaf_hash_t8(final_fold);
    let index = merkle::bits_to_index(bits);
    let px = step.2;

    let (rv_main, rv_preproc) = rv::build_trace(step, rounds, log_size);
    let (merkle_main, root) = merkle::build_trace(leaf, sibs, bits, log_size);
    let merkle_preproc = merkle::build_preproc(leaf, index, root, depth, log_size);
    debug_assert_eq!(root, merkle::merkle_path_root_t8(leaf, sibs, bits));
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

    // Tree 0: combined preprocessed (rv preproc ++ merkle_t8 preproc).
    let mut combined_preproc_cols = rv_preproc;
    combined_preproc_cols.extend(merkle_preproc);
    let mut tree = scheme.tree_builder();
    tree.extend_evals(combined_preproc_cols);
    tree.commit(channel);

    // Tree 1: combined main (rv main ++ merkle_t8 main).
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
    let merkle_comp = merkle::MerklePathT8Component::new(
        &mut alloc,
        merkle::MerklePathT8Eval { log_n_rows: log_size },
        SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&rv_comp, &merkle_comp], channel, scheme)
        .map_err(|e| format!("t8 composition prove error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("t8 composition serialize error: {e:?}"))?;

    Ok(QueryMembershipT8Result {
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

/// Verify a t=8 composition proof against the claimed public I/O
/// `(num_folds, depth, px, final_fold, index, root)`. The `leaf` is *recomputed*
/// by the verifier as `qm31_leaf_hash_t8(final_fold)` and pinned — so the t=8
/// Merkle path authenticates exactly the wide hash of the fold-chain output.
#[allow(clippy::too_many_arguments)]
pub fn verify_query_membership_t8(
    proof_bytes: &[u8],
    log_size: u32,
    num_folds: usize,
    depth: usize,
    challenges: &rv::QueryChallenges,
    px: u32,
    final_fold: u128,
    index: u32,
    root: [u64; 4],
) -> Result<bool, String> {
    let max_log = rv::MAX_LOG_SIZE.min(merkle::MAX_LOG_SIZE);
    if !(merkle::MIN_LOG_SIZE..=max_log).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range"));
    }
    if num_folds > rv::MAX_NUM_FOLDS {
        return Err(format!("num_folds {num_folds} exceeds MAX_NUM_FOLDS {}", rv::MAX_NUM_FOLDS));
    }
    if !(1..=merkle::MAX_DEPTH).contains(&depth) {
        return Err(format!("depth {depth} out of range [1, {}]", merkle::MAX_DEPTH));
    }
    let n = 1usize << log_size;
    if 1 + num_folds > n || depth * 22 > n {
        return Err(format!("blocks exceed trace capacity at log_size {log_size}"));
    }
    let leaf = qm31_leaf_hash_t8(final_fold);

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("t8 composition deserialize error: {e:?}"))?;

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
    let merkle_comp = merkle::MerklePathT8Component::new(
        &mut alloc,
        merkle::MerklePathT8Eval { log_n_rows: log_size },
        SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    if proof.commitments.len() < 2 {
        return Err(format!("t8 composition: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }

    // C1/C2: pin the combined preprocessed tree — selectors, the pinned finalFold
    // (recursive_verifier) and the pinned leaf/index/root (merkle_t8).
    let canonical_root =
        canonical_composition_preproc_root(final_fold, challenges, num_folds, leaf, index, root, depth, log_size);
    if proof.commitments[0] != canonical_root {
        return Ok(false);
    }

    commitment_scheme.commit(proof.commitments[0], &[log_size; TOTAL_PREPROC_COLS], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &[log_size; TOTAL_MAIN_COLS], verifier_channel);

    mix_public(verifier_channel, px, final_fold, leaf, index, root);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&rv_comp, &merkle_comp], verifier_channel, commitment_scheme, proof).is_ok())
}

// ── N-query t=8 composition (the VFRI11 shape: N queries + N wide paths) ─────────

/// Shared log_size fitting N query blocks of `1 + num_folds` rows AND `n_paths`
/// t=8 Merkle paths of `depth` compressions (22 rows each).
fn queries_log_size(n_queries: usize, num_folds: usize, depth: usize) -> u32 {
    rv::compute_log_size(n_queries * (1 + num_folds))
        .max(merkle::compute_log_size_multi(n_queries, depth))
}

#[allow(clippy::too_many_arguments)]
fn canonical_queries_preproc_root(
    finals: &[u128],
    challenges: &[rv::QueryChallenges],
    num_folds: usize,
    leaves: &[[u64; 4]],
    indices: &[u32],
    roots: &[[u64; 4]],
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
    cols.extend(merkle::build_preproc_multi(leaves, indices, roots, depth, log_size));
    let mut tree = scheme.tree_builder();
    tree.extend_evals(cols);
    tree.commit(&mut throwaway);
    scheme.roots()[0]
}

fn mix_public_queries(
    channel: &mut Blake2sM31Channel,
    pxs: &[u32],
    finals: &[u128],
    leaves: &[[u64; 4]],
    indices: &[u32],
    roots: &[[u64; 4]],
) {
    let w = |v: u64| (v % M31_P) as u32;
    let mut words = Vec::with_capacity(finals.len() * 5);
    for i in 0..finals.len() {
        let l = limbs(finals[i]);
        words.extend_from_slice(&[pxs[i], l[0] as u32, l[1] as u32, l[2] as u32, l[3] as u32]);
    }
    channel.mix_u32s(&words);
    let mut mwords = Vec::with_capacity(leaves.len() * 9);
    for p in 0..leaves.len() {
        mwords.extend_from_slice(&[
            w(leaves[p][0]), w(leaves[p][1]), w(leaves[p][2]), w(leaves[p][3]),
            indices[p],
            w(roots[p][0]), w(roots[p][1]), w(roots[p][2]), w(roots[p][3]),
        ]);
    }
    channel.mix_u32s(&mwords);
}

/// Result of an N-query t=8 composition proof.
pub struct QueriesMembershipT8Result {
    pub proof: Vec<u8>,
    pub log_size: u32,
    pub num_folds: usize,
    pub depth: usize,
    pub challenges: Vec<rv::QueryChallenges>,
    pub finals: Vec<u128>,
    pub leaves: Vec<[u64; 4]>,
    pub indices: Vec<u32>,
    pub roots: Vec<[u64; 4]>,
}

/// Prove, in ONE STARK, that each of N per-query fold chains yields a final fold
/// value whose t=8 leaf hash is Merkle-authenticated by its wide path — the
/// VFRI11 shape (N queries + N paths) on the t=8 inner hash. All queries share
/// `num_folds`; all paths share `depth`.
pub fn prove_queries_membership_t8(
    queries: &[(QueryStep, Vec<FoldRound>)],
    paths: &[(Vec<[u64; 4]>, Vec<bool>)],
) -> Result<QueriesMembershipT8Result, String> {
    if queries.is_empty() {
        return Err("need ≥ 1 query".into());
    }
    if queries.len() != paths.len() {
        return Err("queries/paths length mismatch".into());
    }
    if queries.len() > rv::MAX_QUERIES {
        return Err(format!("query count {} exceeds MAX_QUERIES {}", queries.len(), rv::MAX_QUERIES));
    }
    let num_folds = queries[0].1.len();
    if num_folds > rv::MAX_NUM_FOLDS {
        return Err(format!("num_folds {num_folds} exceeds MAX_NUM_FOLDS {}", rv::MAX_NUM_FOLDS));
    }
    if queries.iter().any(|(_, r)| r.len() != num_folds) {
        return Err("all queries must share num_folds".into());
    }
    let depth = paths[0].0.len();
    if depth == 0 {
        return Err("path depth must be ≥ 1".into());
    }
    if depth > merkle::MAX_DEPTH {
        return Err(format!("path depth {depth} exceeds MAX_DEPTH {}", merkle::MAX_DEPTH));
    }
    if paths.iter().any(|(s, b)| s.len() != depth || b.len() != depth) {
        return Err("all paths must share depth".into());
    }
    let n = queries.len();
    let log_size = queries_log_size(n, num_folds, depth);
    if log_size > rv::MAX_LOG_SIZE.min(merkle::MAX_LOG_SIZE) {
        return Err(format!("N-query t8 composition log_size {log_size} too large"));
    }

    let finals = rv::recursive_queries_final(queries);
    let leaves: Vec<[u64; 4]> = finals.iter().map(|&f| qm31_leaf_hash_t8(f)).collect();
    let sibs: Vec<Vec<[u64; 4]>> = paths.iter().map(|(s, _)| s.clone()).collect();
    let bits: Vec<Vec<bool>> = paths.iter().map(|(_, b)| b.clone()).collect();
    let indices: Vec<u32> = bits.iter().map(|b| merkle::bits_to_index(b)).collect();
    let pxs: Vec<u32> = queries.iter().map(|(s, _)| s.2).collect();

    let (rv_main, rv_preproc) = rv::build_trace_multi(queries, log_size);
    let (merkle_main, roots) = merkle::build_trace_multi(&leaves, &sibs, &bits, log_size);
    let merkle_preproc = merkle::build_preproc_multi(&leaves, &indices, &roots, depth, log_size);

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
    let merkle_comp = merkle::MerklePathT8Component::new(
        &mut alloc,
        merkle::MerklePathT8Eval { log_n_rows: log_size },
        SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&rv_comp, &merkle_comp], channel, scheme)
        .map_err(|e| format!("N-query t8 composition prove error: {e:?}"))?;
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("N-query t8 composition serialize error: {e:?}"))?;

    let challenges: Vec<rv::QueryChallenges> =
        queries.iter().map(|(s, r)| rv::query_challenges(s, r)).collect();
    Ok(QueriesMembershipT8Result {
        proof: bytes,
        log_size,
        num_folds,
        depth,
        challenges,
        finals,
        leaves,
        indices,
        roots,
    })
}

/// Verify an N-query t=8 composition proof against the claimed per-query public
/// I/O. Leaves are recomputed as `qm31_leaf_hash_t8(final)` and pinned.
#[allow(clippy::too_many_arguments)]
pub fn verify_queries_membership_t8(
    proof_bytes: &[u8],
    log_size: u32,
    num_folds: usize,
    depth: usize,
    challenges: &[rv::QueryChallenges],
    pxs: &[u32],
    finals: &[u128],
    indices: &[u32],
    roots: &[[u64; 4]],
) -> Result<bool, String> {
    if finals.is_empty()
        || pxs.len() != finals.len()
        || indices.len() != finals.len()
        || roots.len() != finals.len()
        || challenges.len() != finals.len()
    {
        return Err("public-input length mismatch".into());
    }
    let max_log = rv::MAX_LOG_SIZE.min(merkle::MAX_LOG_SIZE);
    if !(merkle::MIN_LOG_SIZE..=max_log).contains(&log_size) {
        return Err(format!("log_size {log_size} out of range"));
    }
    if finals.len() > rv::MAX_QUERIES {
        return Err(format!("query count {} exceeds MAX_QUERIES {}", finals.len(), rv::MAX_QUERIES));
    }
    if num_folds > rv::MAX_NUM_FOLDS {
        return Err(format!("num_folds {num_folds} exceeds MAX_NUM_FOLDS {}", rv::MAX_NUM_FOLDS));
    }
    if !(1..=merkle::MAX_DEPTH).contains(&depth) {
        return Err(format!("depth {depth} out of range [1, {}]", merkle::MAX_DEPTH));
    }
    let n = 1usize << log_size;
    if finals.len().saturating_mul(1 + num_folds) > n
        || finals.len().saturating_mul(depth).saturating_mul(22) > n
    {
        return Err(format!("blocks exceed trace capacity at log_size {log_size}"));
    }
    let leaves: Vec<[u64; 4]> = finals.iter().map(|&f| qm31_leaf_hash_t8(f)).collect();

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("N-query t8 deserialize error: {e:?}"))?;

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
    let merkle_comp = merkle::MerklePathT8Component::new(
        &mut alloc,
        merkle::MerklePathT8Eval { log_n_rows: log_size },
        SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    if proof.commitments.len() < 2 {
        return Err(format!("N-query t8: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    let canonical_root = canonical_queries_preproc_root(
        finals, challenges, num_folds, &leaves, indices, roots, depth, log_size,
    );
    if proof.commitments[0] != canonical_root {
        return Ok(false);
    }

    commitment_scheme.commit(proof.commitments[0], &[log_size; TOTAL_PREPROC_COLS], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &[log_size; TOTAL_MAIN_COLS], verifier_channel);

    mix_public_queries(verifier_channel, pxs, finals, &leaves, indices, roots);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&rv_comp, &merkle_comp], verifier_channel, commitment_scheme, proof).is_ok())
}

// ── Outer-trace export (R4.4) ────────────────────────────────────────────────────

/// Export the OUTER recursive trace (rv fold chains ++ t=8 Merkle paths) as plain
/// natural-order row-major `u32` columns, for VFRI hint generation over the outer
/// trace — the path to on-chain verification of the recursion by the EXISTING
/// deployed VFRI11 machinery at small constant gas (the outer trace is tiny).
/// Returns `(columns, log_size)`; each column has `1 << log_size` entries.
/// Validation mirrors [`prove_queries_membership_t8`].
pub fn outer_trace_columns_t8(
    queries: &[(QueryStep, Vec<FoldRound>)],
    paths: &[(Vec<[u64; 4]>, Vec<bool>)],
) -> Result<(Vec<Vec<u32>>, u32), String> {
    if queries.is_empty() {
        return Err("need ≥ 1 query".into());
    }
    if queries.len() != paths.len() {
        return Err("queries/paths length mismatch".into());
    }
    if queries.len() > rv::MAX_QUERIES {
        return Err(format!("query count {} exceeds MAX_QUERIES {}", queries.len(), rv::MAX_QUERIES));
    }
    let num_folds = queries[0].1.len();
    if num_folds > rv::MAX_NUM_FOLDS {
        return Err(format!("num_folds {num_folds} exceeds MAX_NUM_FOLDS {}", rv::MAX_NUM_FOLDS));
    }
    if queries.iter().any(|(_, r)| r.len() != num_folds) {
        return Err("all queries must share num_folds".into());
    }
    let depth = paths[0].0.len();
    if depth == 0 {
        return Err("path depth must be ≥ 1".into());
    }
    if depth > merkle::MAX_DEPTH {
        return Err(format!("path depth {depth} exceeds MAX_DEPTH {}", merkle::MAX_DEPTH));
    }
    if paths.iter().any(|(s, b)| s.len() != depth || b.len() != depth) {
        return Err("all paths must share depth".into());
    }
    let log_size = queries_log_size(queries.len(), num_folds, depth);
    if log_size > rv::MAX_LOG_SIZE.min(merkle::MAX_LOG_SIZE) {
        return Err(format!("outer trace log_size {log_size} too large"));
    }

    let finals = rv::recursive_queries_final(queries);
    let leaves: Vec<[u64; 4]> = finals.iter().map(|&f| qm31_leaf_hash_t8(f)).collect();
    let sibs: Vec<Vec<[u64; 4]>> = paths.iter().map(|(s, _)| s.clone()).collect();
    let bits: Vec<Vec<bool>> = paths.iter().map(|(_, b)| b.clone()).collect();

    let rv_cols = rv::build_trace_multi_raw(queries, log_size);
    let (merkle_cols, _roots) = merkle::build_trace_multi_raw(&leaves, &sibs, &bits, log_size);

    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(rv_cols.len() + merkle_cols.len());
    for c in rv_cols.into_iter().chain(merkle_cols.into_iter()) {
        cols.push(c.into_iter().map(|v| v.0).collect());
    }
    debug_assert_eq!(cols.len(), TOTAL_MAIN_COLS);
    Ok((cols, log_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    const M31: u64 = (1u64 << 31) - 1;

    fn rand_m31(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*seed >> 33) % M31
    }
    fn rand_qm31(seed: &mut u64) -> u128 {
        (rand_m31(seed) as u128) << 96
            | (rand_m31(seed) as u128) << 64
            | (rand_m31(seed) as u128) << 32
            | rand_m31(seed) as u128
    }
    fn rand_node(seed: &mut u64) -> [u64; 4] {
        [rand_m31(seed), rand_m31(seed), rand_m31(seed), rand_m31(seed)]
    }
    fn sample_step(seed: &mut u64) -> QueryStep {
        (
            rand_qm31(seed), rand_qm31(seed), rand_m31(seed) as u32, rand_qm31(seed),
            rand_qm31(seed), rand_qm31(seed), rand_qm31(seed), rand_m31(seed) as u32,
        )
    }
    fn sample_rounds(seed: &mut u64, k: usize) -> Vec<FoldRound> {
        (0..k).map(|_| (rand_qm31(seed), rand_qm31(seed), rand_m31(seed) as u32)).collect()
    }

    // End-to-end: prove per-query fold chain + t=8 Merkle membership in ONE proof.
    #[test]
    fn test_composition_t8_roundtrip() {
        let mut s = 0xC0117_8_u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 6);
        let depth = 2;
        let sibs: Vec<[u64; 4]> = (0..depth).map(|_| rand_node(&mut s)).collect();
        let bits: Vec<bool> = (0..depth).map(|_| rand_m31(&mut s) & 1 == 1).collect();

        let r = prove_query_membership_t8(&step, &rounds, &sibs, &bits).unwrap();
        assert_eq!(r.final_fold, rv::recursive_query_final(&step, &rounds));
        assert_eq!(r.leaf, qm31_leaf_hash_t8(r.final_fold));
        assert_eq!(r.root, merkle::merkle_path_root_t8(r.leaf, &sibs, &bits));
        assert!(
            verify_query_membership_t8(&r.proof, r.log_size, r.num_folds, r.depth, &r.challenges, step.2, r.final_fold, r.index, r.root)
                .unwrap(),
            "an honest t=8 composition proof must verify",
        );
    }

    // A wrong claimed final fold changes the pinned finalFold AND the recomputed
    // t=8 leaf → different canonical preproc root → rejected.
    #[test]
    fn test_composition_t8_wrong_final_rejected() {
        let mut s = 0xBADC0_8_u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 4);
        let depth = 3;
        let sibs: Vec<[u64; 4]> = (0..depth).map(|_| rand_node(&mut s)).collect();
        let bits: Vec<bool> = (0..depth).map(|_| rand_m31(&mut s) & 1 == 1).collect();

        let r = prove_query_membership_t8(&step, &rounds, &sibs, &bits).unwrap();
        assert!(verify_query_membership_t8(&r.proof, r.log_size, r.num_folds, r.depth, &r.challenges, step.2, r.final_fold, r.index, r.root).unwrap());
        assert!(
            !verify_query_membership_t8(&r.proof, r.log_size, r.num_folds, r.depth, &r.challenges, step.2, r.final_fold ^ 1, r.index, r.root)
                .unwrap_or(false),
            "a wrong final fold must not verify",
        );
    }

    // N-query t=8 composition: N fold chains + N wide paths in ONE proof
    // (the VFRI11 shape on the t=8 inner hash).
    #[test]
    fn test_queries_membership_t8_roundtrip() {
        let mut s = 0x4e51_8_u64;
        let n = 3;
        let num_folds = 4;
        let depth = 2;
        let queries: Vec<(QueryStep, Vec<FoldRound>)> =
            (0..n).map(|_| (sample_step(&mut s), sample_rounds(&mut s, num_folds))).collect();
        let paths: Vec<(Vec<[u64; 4]>, Vec<bool>)> = (0..n)
            .map(|_| {
                (
                    (0..depth).map(|_| rand_node(&mut s)).collect(),
                    (0..depth).map(|_| rand_m31(&mut s) & 1 == 1).collect(),
                )
            })
            .collect();

        let r = prove_queries_membership_t8(&queries, &paths).unwrap();
        let pxs: Vec<u32> = queries.iter().map(|(st, _)| st.2).collect();
        // finals + roots match each query's/path's reference.
        for (i, (st, rd)) in queries.iter().enumerate() {
            assert_eq!(r.finals[i], rv::recursive_query_final(st, rd));
            assert_eq!(r.leaves[i], qm31_leaf_hash_t8(r.finals[i]));
            assert_eq!(r.roots[i], merkle::merkle_path_root_t8(r.leaves[i], &paths[i].0, &paths[i].1));
        }
        assert!(
            verify_queries_membership_t8(&r.proof, r.log_size, r.num_folds, r.depth, &r.challenges, &pxs, &r.finals, &r.indices, &r.roots)
                .unwrap(),
            "an honest N-query t=8 composition must verify",
        );
        // A wrong final for one query must fail (changes its pinned fin + leaf4).
        let mut bad = r.finals.clone();
        bad[1] ^= 1;
        assert!(
            !verify_queries_membership_t8(&r.proof, r.log_size, r.num_folds, r.depth, &r.challenges, &pxs, &bad, &r.indices, &r.roots)
                .unwrap_or(false),
            "a wrong final fold must not verify",
        );
        // A wrong root for one path must fail (changes its pinned root).
        let mut bad_roots = r.roots.clone();
        bad_roots[2][0] ^= 1;
        assert!(
            !verify_queries_membership_t8(&r.proof, r.log_size, r.num_folds, r.depth, &r.challenges, &pxs, &r.finals, &r.indices, &bad_roots)
                .unwrap_or(false),
            "a wrong path root must not verify",
        );
    }

    // Hostile-input caps return Err (no panic/OOM): depth 0, uneven folds.
    #[test]
    fn test_queries_membership_t8_validation_errors() {
        let mut s = 0xE44_u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 2);
        // depth = 0 path
        let bad_paths: Vec<(Vec<[u64; 4]>, Vec<bool>)> = vec![(vec![], vec![])];
        assert!(prove_queries_membership_t8(&[(step, rounds.clone())], &bad_paths).is_err());
        // queries/paths length mismatch
        let ok_path: Vec<(Vec<[u64; 4]>, Vec<bool>)> =
            vec![(vec![rand_node(&mut s)], vec![true]), (vec![rand_node(&mut s)], vec![false])];
        assert!(prove_queries_membership_t8(&[(step, rounds)], &ok_path).is_err());
        // verify: log_size out of range
        assert!(
            verify_queries_membership_t8(&[], 40, 2, 1, &[], &[], &[1u128], &[0], &[[0u64; 4]]).is_err()
        );
    }

    // A wrong claimed root (not the one the t=8 path hashes to) must not verify.
    #[test]
    fn test_composition_t8_wrong_root_rejected() {
        let mut s = 0xBAD8007_8_u64;
        let step = sample_step(&mut s);
        let rounds = sample_rounds(&mut s, 5);
        let depth = 2;
        let sibs: Vec<[u64; 4]> = (0..depth).map(|_| rand_node(&mut s)).collect();
        let bits: Vec<bool> = (0..depth).map(|_| rand_m31(&mut s) & 1 == 1).collect();

        let r = prove_query_membership_t8(&step, &rounds, &sibs, &bits).unwrap();
        let mut bad = r.root;
        bad[0] ^= 1;
        assert!(
            !verify_query_membership_t8(&r.proof, r.log_size, r.num_folds, r.depth, &r.challenges, step.2, r.final_fold, r.index, bad)
                .unwrap_or(false),
            "a wrong Merkle root must not verify",
        );
    }
}
