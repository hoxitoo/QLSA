pub mod air;
pub mod mldsa;
pub mod trace;

use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::verifier::verify;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::TraceLocationAllocator;

use air::{HashChainComponent, HashChainEval};

/// log2 of the FRI blowup factor. 2 → blowup 4× (security margin ~60-bit at 30 FRI rounds).
/// Was 1 (2×, ~30-bit). Increase to 3+ for production.
const LOG_BLOWUP: u32 = 2;

fn make_config(log_size: u32) -> PcsConfig {
    let mut c = PcsConfig::default();
    c.fri_config.log_blowup_factor = LOG_BLOWUP;
    PcsConfig {
        lifting_log_size: Some(log_size + LOG_BLOWUP),
        ..c
    }
}

/// Prove a hash-chain over `leaves`.
///
/// Returns `(proof_bytes, commitment_hex, log_size)`.
/// `commitment_hex` is the 8-char little-endian hex of `h[last_row]` (4 bytes, M31).
pub fn prove_hash_chain(leaves: &[u64]) -> Result<(Vec<u8>, String, u32), String> {
    if leaves.is_empty() {
        return Err("leaves must not be empty".into());
    }

    let (columns, commitment) = trace::build_trace(leaves);
    let log_size = trace::compute_log_size(leaves.len());

    // lifting_log_size = log_size + LOG_BLOWUP so that max_log_degree_bound = log_size.
    // This keeps the OODS mask step (CanonicCoset::new(log_size).step()) and the vanishing
    // denominator consistent between the domain evaluator and the OODS point evaluator.
    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Preprocessed trace (none for this circuit)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    // Main trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    let component = HashChainComponent::new(
        &mut TraceLocationAllocator::default(),
        HashChainEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        channel,
        commitment_scheme,
    )
    .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    let commitment_hex = hex::encode(commitment.0.to_le_bytes());

    Ok((proof_bytes, commitment_hex, log_size))
}

/// Verify a proof previously produced by `prove_hash_chain`.
pub fn verify_hash_chain(
    proof_bytes: &[u8],
    commitment_hex: &str,
    log_size: u32,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;

    let commitment_bytes = hex::decode(commitment_hex)
        .map_err(|e| format!("invalid commitment hex: {e}"))?;
    if commitment_bytes.len() != 4 {
        return Err(format!(
            "commitment must be 4 bytes, got {}",
            commitment_bytes.len()
        ));
    }
    let commitment_val = u32::from_le_bytes(commitment_bytes.try_into().unwrap());
    let _commitment = BaseField::from_u32_unchecked(commitment_val);

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(proof_bytes, bincode::config::standard())
            .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;

    let component = HashChainComponent::new(
        &mut TraceLocationAllocator::default(),
        HashChainEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    // Feed tree commitments in the same order as proving.
    // A well-formed Stwo StarkProof has exactly 2 commitment trees
    // (preprocessed + main trace); validate before indexing.
    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected 2 commitments, got {}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::{assert_constraints_on_trace, FrameworkEval};

    #[test]
    fn test_constraints_on_trace() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (columns, _commitment) = trace::build_trace(&leaves);
        let log_size = trace::compute_log_size(leaves.len());

        let h_vals: Vec<M31> = columns[0].values.clone();
        let leaf_vals: Vec<M31> = columns[1].values.clone();

        // TreeVec: [preprocessed (empty), original trace (h, leaf)]
        let evals: TreeVec<Vec<&Vec<M31>>> =
            TreeVec::new(vec![vec![], vec![&h_vals, &leaf_vals]]);

        let eval_obj = air::HashChainEval { log_n_rows: log_size };
        assert_constraints_on_trace(
            &evals,
            log_size,
            |eval| { eval_obj.evaluate(eval); },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn test_prove_and_verify() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain(&leaves).expect("proving failed");
        let valid = verify_hash_chain(&proof_bytes, &commitment_hex, log_size)
            .expect("verification failed");
        assert!(valid);
    }
}
