pub mod air;
pub mod prover_impl;
pub mod trace;

use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::fields::f64::BaseElement,
    AcceptableOptions, BatchingMethod, FieldExtension, ProofOptions, Prover, Trace,
};

use crate::air::{HashChainAir, PublicInputs};
use crate::prover_impl::{HashChainProver, ProofHasher};

// ──────────────────────────────────────────────────────────────────────────────
// Proof options
// ──────────────────────────────────────────────────────────────────────────────

pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        40,                        // num_queries
        8,                         // blowup_factor (must be ≥ 2 * max_degree = 6)
        0,                         // grinding_factor
        FieldExtension::None,
        4,                         // FRI folding factor
        31,                        // FRI max remainder poly degree (log2)
        BatchingMethod::Algebraic, // constraint batching
        BatchingMethod::Algebraic, // deep poly batching
    )
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// Prove that `leaves` hash to the returned commitment.
///
/// The hash function used inside the STARK (`H(a,b) = a^3 + b`) is a
/// **prototype algebraic hash — not cryptographically secure**.
/// Production will replace it with Rescue Prime via Stwo.
pub fn prove(leaves: Vec<u64>) -> Result<(Vec<u8>, String), String> {
    let prover = HashChainProver::new(default_proof_options());
    let t      = trace::build_trace(&leaves);
    let last   = t.length() - 1;
    let commitment = t.get(0, last);

    let proof = prover.prove(t).map_err(|e| e.to_string())?;
    Ok((proof.to_bytes(), encode_element(commitment)))
}

/// Verify a STARK proof for the hash chain.
pub fn verify(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use winterfell::Proof;

    let proof      = Proof::from_bytes(proof_bytes).map_err(|e| e.to_string())?;
    let commitment = decode_element(commitment_hex)?;
    let pub_inputs = PublicInputs { commitment };
    let acceptable = AcceptableOptions::OptionSet(vec![proof.options().clone()]);

    match winterfell::verify::<
        HashChainAir,
        ProofHasher,
        DefaultRandomCoin<ProofHasher>,
        MerkleTree<ProofHasher>,
    >(proof, pub_inputs, &acceptable)
    {
        Ok(())  => Ok(true),
        Err(_)  => Ok(false),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn encode_element(e: BaseElement) -> String {
    hex::encode(e.as_int().to_le_bytes())
}

fn decode_element(hex_str: &str) -> Result<BaseElement, String> {
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| "commitment must be 8 bytes (16 hex chars)".to_string())?;
    Ok(BaseElement::new(u64::from_le_bytes(arr)))
}
