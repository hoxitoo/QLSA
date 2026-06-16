pub mod air;
pub mod mldsa;
pub mod mldsa_az_air;
pub mod mldsa_az_full_air;
pub mod mldsa_ct1_full_air;
pub mod mldsa_wprime_full_air;
pub mod mldsa_norm_check_batch_air;
pub mod mldsa_range_q_batch_air;
pub mod mldsa_use_hint_batch_air;
pub mod mldsa_intt_batch_air;
pub mod mldsa_ntt_batch_air;
pub mod range_check_air;
pub mod mldsa_hint_weight_air;
pub mod mldsa_intt_air;
pub mod mldsa_norm_check_air;
pub mod mldsa_ntt_air;
pub mod mldsa_use_hint_air;
pub mod mldsa_poly_add_air;
pub mod mldsa_poly_mul_air;
pub mod mldsa_verify_stark;
pub mod poseidon2;
pub mod poseidon2_air;
pub mod poseidon2_merkle_air;
pub mod poseidon2_t4;
pub mod poseidon2_t8;
pub mod trace;
pub mod vfri2_bridge;

use blake2::{Blake2s256, Digest};
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::verifier::verify;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::TraceLocationAllocator;


// ─── Commitment helpers ────────────────────────────────────────────────────────
//
// Two distinct commitment schemes coexist:
//
// A) Hash-chain / Poseidon2 / Merkle circuits (128-bit with proof-binding suffix):
//    bytes [0:4]  — M31 field element (circuit output, le-u32)
//    bytes [4:16] — Blake2s(m31_le ∥ proof[0:32])[0:12]  96-bit proof-binding suffix
//    Used by prove/verify_hash_chain, prove/verify_hash_chain_poseidon2, prove/verify_merkle_root.
//
// B) Polynomial circuits — NTT / INTT / PolyMul / PolyAdd (128-bit output fingerprint):
//    bytes [0:3]  — fp[0] = Blake2s256(output_coeffs)[0:4]  % M31_MODULUS
//    bytes [4:7]  — fp[1] = Blake2s256(output_coeffs)[4:8]  % M31_MODULUS
//    bytes [8:11] — fp[2] = Blake2s256(output_coeffs)[8:12] % M31_MODULUS
//    bytes [12:15]— fp[3] = Blake2s256(output_coeffs)[12:16]% M31_MODULUS
//    ALL 4 words are mixed into the Fiat-Shamir channel → 128-bit FS binding.
//    Used by prove/verify_ntt, prove/verify_poly_mul, prove/verify_poly_add (INTT).
//    Birthday bound: ~2^{-64} for collision in 4 independent M31 words.

// ── Fiat-Shamir seed helper ───────────────────────────────────────────────────

/// Convert arbitrary bytes into M31-safe u32 words for `channel.mix_u32s`.
/// Bytes are chunked by 4 (little-endian); the last partial chunk is zero-padded.
fn seed_to_u32_words(seed: &[u8]) -> Vec<u32> {
    seed.chunks(4).map(|b| {
        let mut arr = [0u8; 4];
        arr[..b.len()].copy_from_slice(b);
        u32::from_le_bytes(arr)
    }).collect()
}

// ── Scheme A helpers ─────────────────────────────────────────────────────────

/// Build a 128-bit commitment (32 hex chars) from the circuit output and proof bytes.
fn build_commitment_128(m31_val: u32, proof_bytes: &[u8]) -> String {
    let m31_le = m31_val.to_le_bytes();
    let mut h = Blake2s256::new();
    h.update(m31_le);
    h.update(&proof_bytes[..proof_bytes.len().min(32)]);
    let hash = h.finalize();
    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&m31_le);
    buf[4..16].copy_from_slice(&hash[0..12]);
    hex::encode(buf)
}

/// Parse and validate a Scheme-A commitment. Returns the M31 value for Fiat-Shamir mixing.
/// Returns Err if the hex is malformed, the M31 is out of range, or the suffix is wrong.
fn parse_commitment_128(commitment_hex: &str, proof_bytes: &[u8]) -> Result<u32, String> {
    let bytes = hex::decode(commitment_hex)
        .map_err(|e| format!("invalid commitment hex: {e}"))?;
    if bytes.len() != 16 {
        return Err(format!(
            "commitment must be 16 bytes (32 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let m31_bytes: [u8; 4] = bytes[0..4].try_into().unwrap();
    let m31_val = u32::from_le_bytes(m31_bytes);
    if m31_val >= M31_MODULUS {
        return Err("commitment M31 component out of M31 field range [0, 2^31 − 2]".into());
    }
    let mut h = Blake2s256::new();
    h.update(m31_bytes);
    h.update(&proof_bytes[..proof_bytes.len().min(32)]);
    let expected = h.finalize();
    if bytes[4..16] != expected[0..12] {
        return Err("commitment integrity check failed (suffix mismatch)".into());
    }
    Ok(m31_val)
}

// ── Scheme B helpers ─────────────────────────────────────────────────────────

/// Compute a 128-bit output fingerprint for polynomial circuits (NTT, INTT, PolyMul, PolyAdd).
///
/// Returns 4 M31-reduced u32 words derived from Blake2s256(output_coefficients).
/// All 4 words must be mixed into the Fiat-Shamir channel via `channel.mix_u32s(&fp)`.
/// This gives 128-bit binding of the FRI query challenges to the circuit output,
/// replacing the previous 32-bit binding that was vulnerable to birthday attacks (~2^16).
pub fn output_fingerprint(coeffs: &[i64]) -> [u32; 4] {
    let mut h = Blake2s256::new();
    for &c in coeffs { h.update(&(c as u32).to_le_bytes()); }
    let hash = h.finalize();
    std::array::from_fn(|i| {
        u32::from_le_bytes(hash[i*4..(i+1)*4].try_into().unwrap()) % M31_MODULUS
    })
}

/// Encode a Scheme-B polynomial commitment as a 32-hex-char string.
pub(crate) fn build_poly_commitment(fp: &[u32; 4]) -> String {
    let mut buf = [0u8; 16];
    for (i, &w) in fp.iter().enumerate() {
        buf[i*4..(i+1)*4].copy_from_slice(&w.to_le_bytes());
    }
    hex::encode(buf)
}

/// Decode and validate a Scheme-B polynomial commitment.
/// Returns Err if hex is malformed or any word exceeds M31_MODULUS.
pub(crate) fn parse_poly_commitment(commitment_hex: &str) -> Result<[u32; 4], String> {
    let bytes = hex::decode(commitment_hex)
        .map_err(|e| format!("invalid commitment hex: {e}"))?;
    if bytes.len() != 16 {
        return Err(format!(
            "commitment must be 16 bytes (32 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let words: [u32; 4] = std::array::from_fn(|i| {
        u32::from_le_bytes(bytes[i*4..(i+1)*4].try_into().unwrap())
    });
    for (i, &w) in words.iter().enumerate() {
        if w >= M31_MODULUS {
            return Err(format!("commitment word {i} = {w} out of M31 range [0, 2^31-2]"));
        }
    }
    Ok(words)
}

/// log2 of the FRI blowup factor.  6 → blowup 64× (polynomial proximity).
/// Do NOT reduce below 4 for any network-facing deployment.
pub(crate) const LOG_BLOWUP: u32 = 6;

/// FRI query count.  Security = LOG_BLOWUP × N_FRI_QUERIES + POW_BITS = 6×20+10 = 130 bits.
pub(crate) const N_FRI_QUERIES: usize = 20;

/// Proof-of-work bits mixed into Fiat-Shamir (adds POW_BITS to total security).
pub(crate) const POW_BITS: u32 = 10;

fn make_config(log_size: u32) -> PcsConfig {
    let mut c = PcsConfig::default();
    c.fri_config.log_blowup_factor = LOG_BLOWUP;
    c.fri_config.n_queries = N_FRI_QUERIES;
    c.pow_bits = POW_BITS;
    PcsConfig {
        lifting_log_size: Some(log_size + LOG_BLOWUP),
        ..c
    }
}

/// Prove a hash-chain over `leaves`.
///
/// Returns `(proof_bytes, commitment_hex, log_size)`.
/// `commitment_hex` is the 8-char little-endian hex of `h[last_row]` (4 bytes, M31).
/// Prove a Poseidon2 hash-chain over `leaves`.
///
/// Delegates to [`prove_hash_chain_poseidon2`] — the hash AIR was upgraded
/// from the prototype `H(a,b) = a³+b` to Poseidon2-over-M31 (8 full rounds,
/// t=2, α=5, MDS [[3,1],[1,3]]).  The external API is unchanged.
///
/// `merkle_root_seed` — if non-empty, mixed into the Fiat-Shamir transcript
/// before the first trace commitment (batch-binding).
pub fn prove_hash_chain(leaves: &[u64], merkle_root_seed: &[u8]) -> Result<(Vec<u8>, String, u32), String> {
    prove_hash_chain_poseidon2(leaves, merkle_root_seed)
}

/// Maximum log2 trace size accepted by the verifier (2^28 rows ≈ 268 M rows).
/// Prevents an untrusted `log_size` field from triggering OOM inside Stwo.
const MAX_LOG_SIZE: u32 = 28;

/// M31 field modulus = 2^31 − 1. Commitments are M31 elements; values ≥ this
/// are not canonical field elements and must be rejected before `from_u32_unchecked`.
const M31_MODULUS: u32 = (1u32 << 31) - 1;

/// Maximum proof size accepted by the verifiers (8 MB).
/// Realistic Stwo proofs are 90–200 KB; 8 MB gives generous headroom while preventing
/// crafted oversized proofs from triggering multi-second heap allocations (DoS risk).
const MAX_PROOF_BYTES: usize = 8 * 1024 * 1024;

/// Verify a proof previously produced by `prove_hash_chain`.
///
/// Delegates to [`verify_hash_chain_poseidon2`] — the hash AIR is now Poseidon2.
/// `merkle_root_seed` must match the value passed to `prove_hash_chain`.
pub fn verify_hash_chain(
    proof_bytes: &[u8],
    commitment_hex: &str,
    log_size: u32,
    merkle_root_seed: &[u8],
) -> Result<bool, String> {
    verify_hash_chain_poseidon2(proof_bytes, commitment_hex, log_size, merkle_root_seed)
}

// ─── Poseidon2-over-M31 hash chain (MVP-3+) ──────────────────────────────────

/// Prove a Poseidon2 sponge hash chain over `leaves`.
///
/// Returns `(proof_bytes, commitment_hex, log_size)`.
/// `commitment_hex` is the 8-char little-endian hex of the M31 commitment (s0 at
/// the last real row — i.e. after absorbing all leaves).
pub fn prove_hash_chain_poseidon2(leaves: &[u64], seed: &[u8]) -> Result<(Vec<u8>, String, u32), String> {
    use poseidon2_air::{build_trace, compute_log_size, preprocessed_column_ids};

    if leaves.is_empty() {
        return Err("leaves must not be empty".into());
    }
    let log_size = compute_log_size(leaves.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("input too large: log_size {log_size} exceeds MAX_LOG_SIZE {MAX_LOG_SIZE}"));
    }

    let (main_cols, preproc_cols, commitment) = build_trace(leaves);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();

    // Bind seed (batch Merkle root) to Fiat-Shamir transcript before first commit.
    if !seed.is_empty() {
        channel.mix_u32s(&seed_to_u32_words(seed));
    }

    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: preprocessed columns (rc0, rc1, is_init, init_row)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: main trace (s0, s1, t0, t1, inp0, leaf)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_cols);
    tree_builder.commit(channel);

    // Bind commitment to Fiat-Shamir transcript (C-2 fix).
    channel.mix_u32s(&[commitment.0]);

    let ids = preprocessed_column_ids();
    let component = poseidon2_air::Poseidon2Component::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&ids),
        poseidon2_air::Poseidon2Eval { log_n_rows: log_size },
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

    let commitment_hex = build_commitment_128(commitment.0, &proof_bytes);
    Ok((proof_bytes, commitment_hex, log_size))
}

/// Verify a proof previously produced by `prove_hash_chain_poseidon2`.
pub fn verify_hash_chain_poseidon2(
    proof_bytes: &[u8],
    commitment_hex: &str,
    log_size: u32,
    seed: &[u8],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use poseidon2_air::preprocessed_column_ids;

    if log_size < poseidon2_air::MIN_LOG_SIZE || log_size > MAX_LOG_SIZE {
        return Err(format!(
            "log_size {log_size} out of valid range [{}, {MAX_LOG_SIZE}]",
            poseidon2_air::MIN_LOG_SIZE
        ));
    }

    // Parse 128-bit commitment, validate suffix, extract M31 for Fiat-Shamir.
    let commitment_val_p2 = parse_commitment_128(commitment_hex, proof_bytes)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(proof_bytes, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>())
            .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let ids = preprocessed_column_ids();
    let component = poseidon2_air::Poseidon2Component::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&ids),
        poseidon2_air::Poseidon2Eval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();

    // Replay seed mixing — must match the prover's transcript exactly.
    if !seed.is_empty() {
        verifier_channel.mix_u32s(&seed_to_u32_words(seed));
    }

    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected 2 commitments, got {}",
            proof.commitments.len()
        ));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Mirror the prover's channel.mix_u32s so the Fiat-Shamir transcript matches (C-2 fix).
    verifier_channel.mix_u32s(&[commitment_val_p2]);

    let result = verify::<Blake2sM31MerkleChannel>(
        &[&component],
        verifier_channel,
        commitment_scheme,
        proof,
    );

    Ok(result.is_ok())
}

// ─── NTT STARK prover/verifier (MVP-3+) ──────────────────────────────────────

/// Prove a forward NTT over Z_q[X]/(X^{256}+1) using a Circle STARK.
///
/// Input `f` must have coefficients in `[0, Q)` (Q = 8 380 417).
///
/// Returns `(proof_bytes, commitment_hex, ntt_out)`:
/// - `proof_bytes`: serialised STARK proof (~90–200 KB)
/// - `commitment_hex`: 32-hex-char 128-bit Scheme-B commitment (4 M31 words)
/// - `ntt_out`: the NTT of `f` (forward transform result)
///
/// # Soundness
/// The butterfly-addition/subtraction constraints (C2–C5) are fully sound in M31.
/// The multiplication constraint (C1) requires range-check arguments for full
/// soundness (planned for MVP-4); the proof is sound for honest provers.
/// Fiat-Shamir binding: 128-bit (4 M31 words mixed into channel).
pub fn prove_ntt(f: &[i64; 256]) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    use mldsa_ntt_air::{MlDsaNttButterflyEval, MlDsaNttButterflyComponent, LOG_N_BUTTERFLIES, build_trace};

    // Input validation: all coefficients must be in [0, Q).
    for (i, &c) in f.iter().enumerate() {
        if c < 0 || c >= Q {
            return Err(format!("f[{i}] = {c} out of range [0, Q)"));
        }
    }

    let log_size = LOG_N_BUTTERFLIES;
    let (columns, ntt_out) = build_trace(f);

    // 128-bit fingerprint of the NTT output mixed into Fiat-Shamir (Scheme B).
    let fp = output_fingerprint(&ntt_out);
    let commitment_hex = build_poly_commitment(&fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: preprocessed (none for this circuit)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    // Tree 1: main trace (9 columns)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    // Mix all 4 fingerprint words (128-bit FS binding).
    channel.mix_u32s(&fp);

    let component = MlDsaNttButterflyComponent::new(
        &mut TraceLocationAllocator::default(),
        MlDsaNttButterflyEval { log_n_rows: log_size },
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

    Ok((proof_bytes, commitment_hex, ntt_out))
}

/// Verify an NTT STARK proof produced by [`prove_ntt`].
///
/// The proof is valid iff the prover correctly computed all 1024 butterfly
/// operations of the forward NTT and committed to the output consistently.
pub fn verify_ntt(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_ntt_air::{MlDsaNttButterflyEval, MlDsaNttButterflyComponent, LOG_N_BUTTERFLIES};

    let log_size = LOG_N_BUTTERFLIES;

    // Parse Scheme-B commitment → 4 M31 words for Fiat-Shamir replay.
    let fp = parse_poly_commitment(commitment_hex)?;

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

    let component = MlDsaNttButterflyComponent::new(
        &mut TraceLocationAllocator::default(),
        MlDsaNttButterflyEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

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

    // Replay Fiat-Shamir: mix the same 4-word fingerprint as the prover.
    verifier_channel.mix_u32s(&fp);

    let result = verify::<Blake2sM31MerkleChannel>(
        &[&component],
        verifier_channel,
        commitment_scheme,
        proof,
    );

    Ok(result.is_ok())
}

// ─── Pointwise multiplication STARK (MVP-3+) ─────────────────────────────────

/// Prove that `c[i] = a[i] × b[i] (mod Q)` for i = 0..255 (NTT-domain product).
///
/// Returns `(proof_bytes, commitment_hex, product)`.
/// The commitment fingerprints the 256 output coefficients via Blake2s.
pub fn prove_poly_mul(
    a: &[i64; 256],
    b: &[i64; 256],
) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    use mldsa_poly_mul_air::{PolyMulEval, PolyMulComponent, LOG_N_ROWS, build_trace};

    for (i, (&av, &bv)) in a.iter().zip(b.iter()).enumerate() {
        if av < 0 || av >= Q { return Err(format!("a[{i}] = {av} out of [0, Q)")); }
        if bv < 0 || bv >= Q { return Err(format!("b[{i}] = {bv} out of [0, Q)")); }
    }

    let log_size = LOG_N_ROWS;
    let (columns, product) = build_trace(a, b);

    let fp = output_fingerprint(&product);
    let commitment_hex = build_poly_commitment(&fp);

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
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    channel.mix_u32s(&fp);

    let component = PolyMulComponent::new(
        &mut TraceLocationAllocator::default(),
        PolyMulEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, product))
}

/// Verify a pointwise-multiplication proof produced by [`prove_poly_mul`].
pub fn verify_poly_mul(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_poly_mul_air::{PolyMulEval, PolyMulComponent, LOG_N_ROWS};

    let log_size = LOG_N_ROWS;
    let fp = parse_poly_commitment(commitment_hex)?;

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

    let component = PolyMulComponent::new(
        &mut TraceLocationAllocator::default(),
        PolyMulEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Polynomial addition STARK (MVP-3+) ──────────────────────────────────────

/// Prove that `c[i] = (a[i] + b[i]) mod Q` for i = 0..255.
///
/// Returns `(proof_bytes, commitment_hex, sum)`.
/// The commitment fingerprints the 256 output coefficients via Blake2s.
///
/// # Soundness
/// The addition/boolean constraints are **fully sound** in M31: all operands are
/// < Q < 2²³, so sums stay below M31 and there is no wrap-around ambiguity.
pub fn prove_poly_add(
    a: &[i64; 256],
    b: &[i64; 256],
) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    use mldsa_poly_add_air::{PolyAddEval, PolyAddComponent, LOG_N_ROWS, build_trace};

    for (i, (&av, &bv)) in a.iter().zip(b.iter()).enumerate() {
        if av < 0 || av >= Q { return Err(format!("a[{i}] = {av} out of [0, Q)")); }
        if bv < 0 || bv >= Q { return Err(format!("b[{i}] = {bv} out of [0, Q)")); }
    }

    let log_size = LOG_N_ROWS;
    let (columns, sum) = build_trace(a, b);

    let fp = output_fingerprint(&sum);
    let commitment_hex = build_poly_commitment(&fp);

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
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    channel.mix_u32s(&fp);

    let component = PolyAddComponent::new(
        &mut TraceLocationAllocator::default(),
        PolyAddEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, sum))
}

/// Verify a polynomial-addition proof produced by [`prove_poly_add`].
pub fn verify_poly_add(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_poly_add_air::{PolyAddEval, PolyAddComponent, LOG_N_ROWS};

    let log_size = LOG_N_ROWS;
    let fp = parse_poly_commitment(commitment_hex)?;

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

    let component = PolyAddComponent::new(
        &mut TraceLocationAllocator::default(),
        PolyAddEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Polynomial subtraction STARK (MVP-3+) ───────────────────────────────────

/// Prove that `c[i] = (a[i] − b[i]) mod Q` for i = 0..255.
///
/// Implemented as `prove_poly_add(a, b_neg)` where `b_neg[i] = (Q − b[i]) mod Q`.
/// This reuses the fully-sound poly_add AIR without introducing a new AIR.
///
/// Returns `(proof_bytes, commitment_hex, diff)`.
pub fn prove_poly_sub(
    a: &[i64; 256],
    b: &[i64; 256],
) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    for (i, (&av, &bv)) in a.iter().zip(b.iter()).enumerate() {
        if av < 0 || av >= Q { return Err(format!("a[{i}] = {av} out of [0, Q)")); }
        if bv < 0 || bv >= Q { return Err(format!("b[{i}] = {bv} out of [0, Q)")); }
    }
    // Negate b in Z_q: b_neg[i] = (Q − b[i]) mod Q.
    let mut b_neg = [0i64; 256];
    for i in 0..256 {
        b_neg[i] = if b[i] == 0 { 0 } else { Q - b[i] };
    }
    prove_poly_add(a, &b_neg)
}

/// Verify a polynomial-subtraction proof produced by [`prove_poly_sub`].
///
/// Verification is identical to [`verify_poly_add`] because the same AIR is used.
pub fn verify_poly_sub(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    verify_poly_add(proof_bytes, commitment_hex)
}

// ─── UseHint STARK (MVP-3+) ───────────────────────────────────────────────────

/// Prove `UseHint(h[i], r[i]) = w₁'[i]` for all 256 coefficients of one polynomial.
///
/// Includes inline `Decompose(r)` proof.  `r` must be in `[0, Q)`.
///
/// Returns `(proof_bytes, commitment_hex, w1_poly)`.
pub fn prove_use_hint(r: &[i64; 256], h_bits: &[bool; 256]) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    use mldsa_use_hint_air::{UseHintEval, UseHintComponent, LOG_N_ROWS, build_trace};

    for (i, &c) in r.iter().enumerate() {
        if c < 0 || c >= Q { return Err(format!("r[{i}] = {c} out of [0, Q)")); }
    }

    let log_size = LOG_N_ROWS;
    let (columns, w1_out) = build_trace(r, h_bits);

    let fp = output_fingerprint(&w1_out);
    let commitment_hex = build_poly_commitment(&fp);

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
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    channel.mix_u32s(&fp);

    let component = UseHintComponent::new(
        &mut TraceLocationAllocator::default(),
        UseHintEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("use_hint proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, w1_out))
}

/// Verify a UseHint proof produced by [`prove_use_hint`].
pub fn verify_use_hint(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_use_hint_air::{UseHintEval, UseHintComponent, LOG_N_ROWS};

    let log_size = LOG_N_ROWS;
    let fp = parse_poly_commitment(commitment_hex)?;

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

    let component = UseHintComponent::new(
        &mut TraceLocationAllocator::default(),
        UseHintEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Coefficient norm check STARK (MVP-3+) ───────────────────────────────────

/// Prove that `norm[i] = min(z[i], Q − z[i])` for i = 0..255 (absolute centered value).
///
/// Returns `(proof_bytes, commitment_hex, norm_poly, max_norm)`:
/// - `norm_poly[i]` is the absolute centered value of each coefficient.
/// - `max_norm` is the ∞-norm of `z` (for external bound check: must be < γ₁ − β).
///
/// The STARK proves the norm computation is correct.  The bound check
/// `max_norm < NORM_BOUND` is asserted externally; range-proof soundness is
/// deferred to MVP-4.
pub fn prove_norm_check(z: &[i64; 256]) -> Result<(Vec<u8>, String, [i64; 256], i64), String> {
    use mldsa::Q;
    use mldsa_norm_check_air::{NormCheckEval, NormCheckComponent, LOG_N_ROWS, build_trace};

    for (i, &c) in z.iter().enumerate() {
        if c < 0 || c >= Q { return Err(format!("z[{i}] = {c} out of [0, Q)")); }
    }

    let log_size = LOG_N_ROWS;
    let (columns, norm_out) = build_trace(z);

    let max_norm = norm_out.iter().copied().max().unwrap_or(0);

    let fp = output_fingerprint(&norm_out);
    let commitment_hex = build_poly_commitment(&fp);

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
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    channel.mix_u32s(&fp);

    let component = NormCheckComponent::new(
        &mut TraceLocationAllocator::default(),
        NormCheckEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("norm_check proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, norm_out, max_norm))
}

/// Verify a norm-check proof produced by [`prove_norm_check`].
pub fn verify_norm_check(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_norm_check_air::{NormCheckEval, NormCheckComponent, LOG_N_ROWS};

    let log_size = LOG_N_ROWS;
    let fp = parse_poly_commitment(commitment_hex)?;

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

    let component = NormCheckComponent::new(
        &mut TraceLocationAllocator::default(),
        NormCheckEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Az row STARK (MVP-3+) ────────────────────────────────────────────────────

/// Prove one row of the NTT-domain matrix-vector product  Az̃[i] = Σ_{j=0}^{L-1} Ã[i][j] ⊙ z̃[j].
///
/// `a_row` is the i-th row of Ã (L=5 polynomials in NTT domain, each of 256 coefficients).
/// `z_hat` is the NTT-domain vector z̃ (L=5 polynomials of 256 coefficients).
///
/// Returns `(proof_bytes, commitment_hex, az_hat_i)` where `az_hat_i` is the output polynomial.
/// The commitment fingerprints the 256 output coefficients via Blake2s (Scheme B, 128-bit).
///
/// The Fiat-Shamir transcript also binds to the L=5 input z̃ polynomials (input fingerprint
/// mixed before the output fingerprint), so `verify_az_row` must receive the same z_hat to
/// reconstruct the same channel state.
///
/// Call this K=6 times (once per output row) to prove the full matrix-vector product.
pub fn prove_az_row(
    a_row: &[[i64; 256]; 5],
    z_hat: &[[i64; 256]; 5],
) -> Result<(Vec<u8>, String, [i64; 256]), String> {
    use mldsa::Q;
    use mldsa_az_air::{AzRowEval, AzRowComponent, LOG_N_ROWS, build_trace};

    for j in 0..5 {
        for (p, (&av, &zv)) in a_row[j].iter().zip(z_hat[j].iter()).enumerate() {
            if av < 0 || av >= Q {
                return Err(format!("a_row[{j}][{p}] = {av} out of [0, Q)"));
            }
            if zv < 0 || zv >= Q {
                return Err(format!("z_hat[{j}][{p}] = {zv} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, az_hat) = build_trace(a_row, z_hat);

    // Input fingerprint: Blake2s of all L z̃ polynomials concatenated.
    // Mixed into channel BEFORE the output fingerprint to bind the proof to the specific z_hat.
    let z_flat: Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let input_fp = output_fingerprint(&z_flat);

    let output_fp = output_fingerprint(&az_hat);
    let commitment_hex = build_poly_commitment(&output_fp);

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
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    // Bind to both input z_hat and output az_hat in this order.
    channel.mix_u32s(&input_fp);
    channel.mix_u32s(&output_fp);

    let component = AzRowComponent::new(
        &mut TraceLocationAllocator::default(),
        AzRowEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, az_hat))
}

/// Verify an Az-row proof produced by [`prove_az_row`].
///
/// `z_hat` must be the same L=5 input polynomials that were used to generate the proof.
/// The input fingerprint is recomputed from `z_hat` and mixed into the verifier channel
/// to reconstruct the same Fiat-Shamir transcript as the prover.
pub fn verify_az_row(
    proof_bytes: &[u8],
    commitment_hex: &str,
    z_hat: &[[i64; 256]],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_az_air::{AzRowEval, AzRowComponent, LOG_N_ROWS};

    let log_size = LOG_N_ROWS;
    let output_fp = parse_poly_commitment(commitment_hex)?;

    // Recompute input fingerprint from the provided z_hat.
    let z_flat: Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let input_fp = output_fingerprint(&z_flat);

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

    let component = AzRowComponent::new(
        &mut TraceLocationAllocator::default(),
        AzRowEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Reconstruct transcript: input fingerprint then output fingerprint (same order as prover).
    verifier_channel.mix_u32s(&input_fp);
    verifier_channel.mix_u32s(&output_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Full-matrix Az STARK (MVP-3+) ────────────────────────────────────────────

/// Prove the full NTT-domain matrix-vector product Az in a single STARK.
///
/// Proves all K=6 output rows simultaneously: az_out[i] = Σ_j Ã[i][j] ⊙ z̃[j].
///
/// `a_hat` — K×L NTT-domain polynomials in row-major order (a_hat[i*L+j] = Ã[i][j]).
/// `z_hat` — L NTT-domain input polynomials.
///
/// Returns `(proof_bytes, commitment_hex, az_out)`.
/// The commitment fingerprints all K output polynomials concatenated (Scheme B, 128-bit).
/// Both input (z_hat) and output fingerprints are mixed into the Fiat-Shamir channel.
pub fn prove_az_full(
    a_hat:        &[[i64; mldsa::N]],
    z_hat:        &[[i64; mldsa::N]; mldsa::params::L],
    c_tilde_seed: &[u8],
) -> Result<(Vec<u8>, String, [[i64; mldsa::N]; mldsa::params::K]), String> {
    use mldsa_az_full_air::{AzFullEval, AzFullComponent, LOG_N_ROWS, build_trace};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    let k = mldsa::params::K;
    let l = mldsa::params::L;
    if a_hat.len() != k * l {
        return Err(format!("a_hat must have k*l={} entries, got {}", k * l, a_hat.len()));
    }
    for (idx, row) in a_hat.iter().enumerate() {
        for (p, &v) in row.iter().enumerate() {
            if v < 0 || v >= mldsa::Q {
                return Err(format!("a_hat[{idx}][{p}] = {v} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, az_out) = build_trace(a_hat, z_hat);

    // Input fingerprint: concatenate all L z_hat polynomials.
    let z_flat: Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let input_fp = output_fingerprint(&z_flat);

    // Output fingerprint: concatenate all K az_out polynomials.
    let az_flat: Vec<i64> = az_out.iter().flat_map(|row| row.iter().copied()).collect();
    let output_fp  = output_fingerprint(&az_flat);
    let commitment_hex = build_poly_commitment(&output_fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    // Mix c_tilde as STARK public input before any trace commitment.
    // This binds the Fiat-Shamir randomness (query positions) to the specific
    // signature challenge, making the proof non-reusable for a different c_tilde.
    if !c_tilde_seed.is_empty() {
        let words: Vec<u32> = c_tilde_seed.chunks(4).map(|b| {
            let mut arr = [0u8; 4];
            arr[..b.len()].copy_from_slice(b);
            u32::from_le_bytes(arr)
        }).collect();
        channel.mix_u32s(&words);
    }
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    // Bind to input z_hat first, then output az_out (same pattern as prove_az_row).
    channel.mix_u32s(&input_fp);
    channel.mix_u32s(&output_fp);

    let component = AzFullComponent::new(
        &mut TraceLocationAllocator::default(),
        AzFullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, az_out))
}

/// Verify a full-matrix Az proof produced by [`prove_az_full`].
///
/// `z_hat` must be the same L polynomials used to generate the proof.
/// The verifier recomputes the input fingerprint from z_hat and mixes it first
/// into the Fiat-Shamir channel, binding the proof to the specific inputs.
pub fn verify_az_full(
    proof_bytes:    &[u8],
    commitment_hex: &str,
    z_hat:          &[[i64; mldsa::N]; mldsa::params::L],
    c_tilde_seed:   &[u8],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_az_full_air::{AzFullEval, AzFullComponent, LOG_N_ROWS};
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;

    let log_size = LOG_N_ROWS;

    // Recompute input fingerprint from z_hat.
    let z_flat: Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let input_fp  = output_fingerprint(&z_flat);
    let output_fp = parse_poly_commitment(commitment_hex)?;

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

    let component = AzFullComponent::new(
        &mut TraceLocationAllocator::default(),
        AzFullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    // Replay c_tilde domain separator to match prover transcript.
    if !c_tilde_seed.is_empty() {
        let words: Vec<u32> = c_tilde_seed.chunks(4).map(|b| {
            let mut arr = [0u8; 4];
            arr[..b.len()].copy_from_slice(b);
            u32::from_le_bytes(arr)
        }).collect();
        verifier_channel.mix_u32s(&words);
    }
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Reconstruct transcript: input fingerprint then output fingerprint.
    verifier_channel.mix_u32s(&input_fp);
    verifier_channel.mix_u32s(&output_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Ct1-full STARK (MVP-3+) ─────────────────────────────────────────────────

/// Prove all K `c_hat × t1_hat[i]` products in a single STARK.
///
/// Replaces K individual `prove_poly_mul` calls with one compact 295-column AIR.
/// Returns `(proof_bytes, commitment_hex, ct1_out)` where `ct1_out[i][p]`
/// is the pointwise product `c_hat[p] × t1_hat[i][p] mod Q`.
pub fn prove_ct1_full(
    c_hat:        &[i64; mldsa::N],
    t1_hat:       &[[i64; mldsa::N]; mldsa::params::K],
    c_tilde_seed: &[u8],
) -> Result<(Vec<u8>, String, [[i64; mldsa::N]; mldsa::params::K]), String> {
    use mldsa_ct1_full_air::{Ct1FullEval, Ct1FullComponent, LOG_N_ROWS, build_trace};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    // Validate inputs.
    for (p, &v) in c_hat.iter().enumerate() {
        if v < 0 || v >= mldsa::Q {
            return Err(format!("c_hat[{p}] = {v} out of [0, Q)"));
        }
    }
    for (i, row) in t1_hat.iter().enumerate() {
        for (p, &v) in row.iter().enumerate() {
            if v < 0 || v >= mldsa::Q {
                return Err(format!("t1_hat[{i}][{p}] = {v} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, ct1_out) = build_trace(c_hat, t1_hat);

    // Input fingerprint: c_hat then all K t1_hat rows.
    let in_flat: Vec<i64> = c_hat.iter().copied()
        .chain(t1_hat.iter().flat_map(|row| row.iter().copied()))
        .collect();
    let input_fp  = output_fingerprint(&in_flat);

    // Output fingerprint: all K ct1_out rows.
    let out_flat: Vec<i64> = ct1_out.iter().flat_map(|row| row.iter().copied()).collect();
    let output_fp  = output_fingerprint(&out_flat);
    let commitment_hex = build_poly_commitment(&output_fp);

    let config  = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    if !c_tilde_seed.is_empty() {
        let words: Vec<u32> = c_tilde_seed.chunks(4).map(|b| {
            let mut arr = [0u8; 4];
            arr[..b.len()].copy_from_slice(b);
            u32::from_le_bytes(arr)
        }).collect();
        channel.mix_u32s(&words);
    }
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    channel.mix_u32s(&input_fp);
    channel.mix_u32s(&output_fp);

    let component = Ct1FullComponent::new(
        &mut TraceLocationAllocator::default(),
        Ct1FullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, ct1_out))
}

/// Verify a Ct1-full proof produced by [`prove_ct1_full`].
///
/// `c_hat` and `t1_hat` must be the same inputs used during proving so the
/// Fiat-Shamir fingerprints can be replayed correctly.
pub fn verify_ct1_full(
    proof_bytes:    &[u8],
    commitment_hex: &str,
    c_hat:          &[i64; mldsa::N],
    t1_hat:         &[[i64; mldsa::N]; mldsa::params::K],
    c_tilde_seed:   &[u8],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_ct1_full_air::{Ct1FullEval, Ct1FullComponent, LOG_N_ROWS};
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;

    let log_size = LOG_N_ROWS;

    let in_flat: Vec<i64> = c_hat.iter().copied()
        .chain(t1_hat.iter().flat_map(|row| row.iter().copied()))
        .collect();
    let input_fp  = output_fingerprint(&in_flat);
    let output_fp = parse_poly_commitment(commitment_hex)?;

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

    let component = Ct1FullComponent::new(
        &mut TraceLocationAllocator::default(),
        Ct1FullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    if !c_tilde_seed.is_empty() {
        let words: Vec<u32> = c_tilde_seed.chunks(4).map(|b| {
            let mut arr = [0u8; 4];
            arr[..b.len()].copy_from_slice(b);
            u32::from_le_bytes(arr)
        }).collect();
        verifier_channel.mix_u32s(&words);
    }
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    verifier_channel.mix_u32s(&input_fp);
    verifier_channel.mix_u32s(&output_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Combined Az+Ct1 STARK (MVP-3+, V16) ─────────────────────────────────────

/// Prove Az (matrix-vector product) **and** Ct1 (c·t1 products) in a single STARK.
///
/// Uses a shared `TraceLocationAllocator` so both components' columns live in the
/// same FRI commitment tree. Saves one proof vs separate Az + Ct1 proofs.
///
/// Returns `(proof_bytes, az_commitment_hex, ct1_commitment_hex, az_out, ct1_out)`.
pub fn prove_az_ct1_combined(
    a_hat:        &[[i64; mldsa::N]],
    z_hat:        &[[i64; mldsa::N]; mldsa::params::L],
    c_hat:        &[i64; mldsa::N],
    t1_hat:       &[[i64; mldsa::N]; mldsa::params::K],
    c_tilde_seed: &[u8],
) -> Result<(Vec<u8>, String, String, [[i64; mldsa::N]; mldsa::params::K], [[i64; mldsa::N]; mldsa::params::K]), String> {
    use mldsa_az_full_air::{AzFullEval, AzFullComponent, LOG_N_ROWS as AZ_LOG_N_ROWS, N_COLS as AZ_N_COLS, build_trace as az_build_trace};
    use mldsa_ct1_full_air::{Ct1FullEval, Ct1FullComponent, N_COLS as CT1_N_COLS, build_trace as ct1_build_trace};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    let k = mldsa::params::K;
    let l = mldsa::params::L;
    if a_hat.len() != k * l {
        return Err(format!("a_hat must have k*l={} entries, got {}", k * l, a_hat.len()));
    }

    let log_size = AZ_LOG_N_ROWS; // both AIRs use LOG_N_ROWS=8

    // Build both traces.
    let (az_columns, az_out) = az_build_trace(a_hat, z_hat);
    let (ct1_columns, ct1_out) = ct1_build_trace(c_hat, t1_hat);

    debug_assert_eq!(az_columns.len(), AZ_N_COLS);
    debug_assert_eq!(ct1_columns.len(), CT1_N_COLS);

    // Fingerprints for Az.
    let z_flat: Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let az_input_fp = output_fingerprint(&z_flat);
    let az_flat: Vec<i64> = az_out.iter().flat_map(|row| row.iter().copied()).collect();
    let az_output_fp = output_fingerprint(&az_flat);
    let az_commitment_hex = build_poly_commitment(&az_output_fp);

    // Fingerprints for Ct1.
    let ct1_in_flat: Vec<i64> = c_hat.iter().copied()
        .chain(t1_hat.iter().flat_map(|row| row.iter().copied()))
        .collect();
    let ct1_input_fp = output_fingerprint(&ct1_in_flat);
    let ct1_flat: Vec<i64> = ct1_out.iter().flat_map(|row| row.iter().copied()).collect();
    let ct1_output_fp = output_fingerprint(&ct1_flat);
    let ct1_commitment_hex = build_poly_commitment(&ct1_output_fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    if !c_tilde_seed.is_empty() {
        let words: Vec<u32> = c_tilde_seed.chunks(4).map(|b| {
            let mut arr = [0u8; 4];
            arr[..b.len()].copy_from_slice(b);
            u32::from_le_bytes(arr)
        }).collect();
        channel.mix_u32s(&words);
    }

    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: empty preprocessed placeholder.
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    // Tree 1: combined Az + Ct1 columns in one commitment.
    let mut combined_columns = az_columns;
    combined_columns.extend(ct1_columns);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(combined_columns);
    tree_builder.commit(channel);

    // Bind transcript to all four fingerprints.
    channel.mix_u32s(&az_input_fp);
    channel.mix_u32s(&az_output_fp);
    channel.mix_u32s(&ct1_input_fp);
    channel.mix_u32s(&ct1_output_fp);

    // Shared allocator so both components are assigned consecutive column ranges.
    let mut alloc = TraceLocationAllocator::default();
    let az_comp = AzFullComponent::new(
        &mut alloc,
        AzFullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let ct1_comp = Ct1FullComponent::new(
        &mut alloc,
        Ct1FullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&az_comp, &ct1_comp], channel, commitment_scheme,
    ).map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, az_commitment_hex, ct1_commitment_hex, az_out, ct1_out))
}

/// Verify a combined Az+Ct1 proof produced by [`prove_az_ct1_combined`].
pub fn verify_az_ct1_combined(
    proof_bytes:        &[u8],
    az_commitment_hex:  &str,
    ct1_commitment_hex: &str,
    z_hat:              &[[i64; mldsa::N]; mldsa::params::L],
    c_hat:              &[i64; mldsa::N],
    t1_hat:             &[[i64; mldsa::N]; mldsa::params::K],
    c_tilde_seed:       &[u8],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_az_full_air::{AzFullEval, AzFullComponent, LOG_N_ROWS as AZ_LOG_N_ROWS, N_COLS as AZ_N_COLS};
    use mldsa_ct1_full_air::{Ct1FullEval, Ct1FullComponent, N_COLS as CT1_N_COLS};
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::CommitmentSchemeVerifier;
    use stwo::core::verifier::verify;
    use stwo_constraint_framework::TraceLocationAllocator;

    let log_size = AZ_LOG_N_ROWS;

    // Recompute fingerprints.
    let z_flat: Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let az_input_fp  = output_fingerprint(&z_flat);
    let az_output_fp = parse_poly_commitment(az_commitment_hex)?;

    let ct1_in_flat: Vec<i64> = c_hat.iter().copied()
        .chain(t1_hat.iter().flat_map(|row| row.iter().copied()))
        .collect();
    let ct1_input_fp  = output_fingerprint(&ct1_in_flat);
    let ct1_output_fp = parse_poly_commitment(ct1_commitment_hex)?;

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

    let mut alloc = TraceLocationAllocator::default();
    let az_comp = AzFullComponent::new(
        &mut alloc,
        AzFullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let ct1_comp = Ct1FullComponent::new(
        &mut alloc,
        Ct1FullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    if !c_tilde_seed.is_empty() {
        let words: Vec<u32> = c_tilde_seed.chunks(4).map(|b| {
            let mut arr = [0u8; 4];
            arr[..b.len()].copy_from_slice(b);
            u32::from_le_bytes(arr)
        }).collect();
        verifier_channel.mix_u32s(&words);
    }

    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    // Combined log sizes: Tree 0 empty, Tree 1 has AZ_N_COLS + CT1_N_COLS columns.
    let combined_log_sizes: Vec<u32> = vec![log_size; AZ_N_COLS + CT1_N_COLS];
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &[], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &combined_log_sizes, verifier_channel);

    // Replay all four fingerprints in prove order.
    verifier_channel.mix_u32s(&az_input_fp);
    verifier_channel.mix_u32s(&az_output_fp);
    verifier_channel.mix_u32s(&ct1_input_fp);
    verifier_channel.mix_u32s(&ct1_output_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&az_comp, &ct1_comp], verifier_channel, commitment_scheme, proof,
    ).is_ok())
}

// ─── WPrime-full STARK (MVP-3+) ───────────────────────────────────────────────

/// Prove all K `az[i] − ct1[i]` subtractions in a single compact STARK.
///
/// Uses poly_add-of-negation (ct1_neg[i] = Q − ct1[i]) — the constraint is
/// fully sound in M31.  24 columns, 12 constraints, no bit-decompositions.
///
/// Returns `(proof_bytes, commitment_hex, w_prime_out)`.
pub fn prove_wprime_full(
    az:  &[[i64; mldsa::N]; mldsa::params::K],
    ct1: &[[i64; mldsa::N]; mldsa::params::K],
) -> Result<(Vec<u8>, String, [[i64; mldsa::N]; mldsa::params::K]), String> {
    use mldsa_wprime_full_air::{WPrimeFullEval, WPrimeFullComponent, LOG_N_ROWS, build_trace};
    use stwo::core::channel::Blake2sM31Channel;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    // Validate inputs.
    for (i, row) in az.iter().enumerate() {
        for (p, &v) in row.iter().enumerate() {
            if v < 0 || v >= mldsa::Q {
                return Err(format!("az[{i}][{p}] = {v} out of [0, Q)"));
            }
        }
    }
    for (i, row) in ct1.iter().enumerate() {
        for (p, &v) in row.iter().enumerate() {
            if v < 0 || v >= mldsa::Q {
                return Err(format!("ct1[{i}][{p}] = {v} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, w_prime_out) = build_trace(az, ct1);

    // Fingerprint over all K output polynomials.
    let out_flat: Vec<i64> = w_prime_out.iter().flat_map(|r| r.iter().copied()).collect();
    let output_fp  = output_fingerprint(&out_flat);
    let commitment_hex = build_poly_commitment(&output_fp);

    let config  = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    use stwo::core::channel::Channel;
    channel.mix_u32s(&output_fp);

    let component = WPrimeFullComponent::new(
        &mut TraceLocationAllocator::default(),
        WPrimeFullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, w_prime_out))
}

/// Verify a WPrime-full proof produced by [`prove_wprime_full`].
pub fn verify_wprime_full(
    proof_bytes:    &[u8],
    commitment_hex: &str,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_wprime_full_air::{WPrimeFullEval, WPrimeFullComponent, LOG_N_ROWS};
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;

    let log_size = LOG_N_ROWS;
    let output_fp = parse_poly_commitment(commitment_hex)?;

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

    let component = WPrimeFullComponent::new(
        &mut TraceLocationAllocator::default(),
        WPrimeFullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    verifier_channel.mix_u32s(&output_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

/// WPrime-full with input-output binding (V14).
///
/// Like [`prove_wprime_full`] but also mixes in an input fingerprint of (az ++ ct1)
/// so the verifier can cross-check that WPrime's inputs match the INTT outputs.
///
/// Returns `(proof_bytes, input_commitment, output_commitment, w_prime)`.
pub fn prove_wprime_full_bound(
    az:  &[[i64; mldsa::N]; mldsa::params::K],
    ct1: &[[i64; mldsa::N]; mldsa::params::K],
) -> Result<(Vec<u8>, String, String, [[i64; mldsa::N]; mldsa::params::K]), String> {
    use mldsa_wprime_full_air::{WPrimeFullEval, WPrimeFullComponent, LOG_N_ROWS, build_trace};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    for (i, row) in az.iter().enumerate() {
        for (p, &v) in row.iter().enumerate() {
            if v < 0 || v >= mldsa::Q {
                return Err(format!("az[{i}][{p}] = {v} out of [0, Q)"));
            }
        }
    }
    for (i, row) in ct1.iter().enumerate() {
        for (p, &v) in row.iter().enumerate() {
            if v < 0 || v >= mldsa::Q {
                return Err(format!("ct1[{i}][{p}] = {v} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, w_prime_out) = build_trace(az, ct1);

    // Input fingerprint: fingerprint of az ++ ct1 (all 2K×N coefficients flat).
    let in_flat: Vec<i64> = az.iter().chain(ct1.iter()).flat_map(|r| r.iter().copied()).collect();
    let input_fp  = output_fingerprint(&in_flat);
    let input_cm  = build_poly_commitment(&input_fp);

    // Output fingerprint.
    let out_flat: Vec<i64> = w_prime_out.iter().flat_map(|r| r.iter().copied()).collect();
    let output_fp  = output_fingerprint(&out_flat);
    let output_cm  = build_poly_commitment(&output_fp);

    let config  = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    // Input-output binding: mix input fingerprint then output fingerprint.
    channel.mix_u32s(&input_fp);
    channel.mix_u32s(&output_fp);

    let component = WPrimeFullComponent::new(
        &mut TraceLocationAllocator::default(),
        WPrimeFullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("prove_wprime_full_bound error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("prove_wprime_full_bound serialize error: {e:?}"))?;

    Ok((proof_bytes, input_cm, output_cm, w_prime_out))
}

/// Verify a WPrime-full proof produced by [`prove_wprime_full_bound`].
pub fn verify_wprime_full_bound(
    proof_bytes: &[u8],
    input_cm:    &str,
    output_cm:   &str,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_wprime_full_air::{WPrimeFullEval, WPrimeFullComponent, LOG_N_ROWS};
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;

    let log_size = LOG_N_ROWS;
    let input_fp  = parse_poly_commitment(input_cm)?;
    let output_fp = parse_poly_commitment(output_cm)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("verify_wprime_full_bound deserialize error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let component = WPrimeFullComponent::new(
        &mut TraceLocationAllocator::default(),
        WPrimeFullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("verify_wprime_full_bound: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Replay transcript: input fingerprint then output fingerprint.
    verifier_channel.mix_u32s(&input_fp);
    verifier_channel.mix_u32s(&output_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── NormCheck-batch STARK (MVP-3+) ──────────────────────────────────────────

/// Prove all L `norm[j]` computations in a single compact STARK.
///
/// Returns `(proof_bytes, commitment_hex, norm_out, max_norms)`.
pub fn prove_norm_check_batch(
    z: &[[i64; mldsa::N]; mldsa::params::L],
) -> Result<(Vec<u8>, String, [[i64; mldsa::N]; mldsa::params::L], [i64; mldsa::params::L]), String> {
    use mldsa_norm_check_batch_air::{NormCheckBatchEval, NormCheckBatchComponent, LOG_N_ROWS, build_trace};
    use stwo::core::channel::Blake2sM31Channel;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    for (j, row) in z.iter().enumerate() {
        for (p, &v) in row.iter().enumerate() {
            if v < 0 || v >= mldsa::Q {
                return Err(format!("z[{j}][{p}] = {v} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, norm_out, max_norms) = build_trace(z);

    let out_flat: Vec<i64> = norm_out.iter().flat_map(|r| r.iter().copied()).collect();
    let output_fp  = output_fingerprint(&out_flat);
    let commitment_hex = build_poly_commitment(&output_fp);

    let config  = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    use stwo::core::channel::Channel;
    channel.mix_u32s(&output_fp);

    let component = NormCheckBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        NormCheckBatchEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, norm_out, max_norms))
}

/// Verify a NormCheck-batch proof produced by [`prove_norm_check_batch`].
pub fn verify_norm_check_batch(
    proof_bytes:    &[u8],
    commitment_hex: &str,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_norm_check_batch_air::{NormCheckBatchEval, NormCheckBatchComponent, LOG_N_ROWS};
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;

    let output_fp = parse_poly_commitment(commitment_hex)?;
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

    let component = NormCheckBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        NormCheckBatchEval { log_n_rows: LOG_N_ROWS },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&output_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── UseHint-batch STARK (MVP-3+) ────────────────────────────────────────────

/// Prove all K `UseHint(hints[i], w_prime[i])` operations in a single STARK.
///
/// Returns `(proof_bytes, commitment_hex, w1_out)`.
pub fn prove_use_hint_batch(
    w_prime: &[[i64; mldsa::N]; mldsa::params::K],
    hints:   &[[bool; mldsa::N]; mldsa::params::K],
) -> Result<(Vec<u8>, String, [[i64; mldsa::N]; mldsa::params::K]), String> {
    use mldsa_use_hint_batch_air::{UseHintBatchEval, UseHintBatchComponent, LOG_N_ROWS, build_trace};
    use stwo::core::channel::Blake2sM31Channel;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    for (i, row) in w_prime.iter().enumerate() {
        for (p, &v) in row.iter().enumerate() {
            if v < 0 || v >= mldsa::Q {
                return Err(format!("w_prime[{i}][{p}] = {v} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, w1_out) = build_trace(w_prime, hints);

    let out_flat: Vec<i64> = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    let output_fp  = output_fingerprint(&out_flat);
    let commitment_hex = build_poly_commitment(&output_fp);

    let config  = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    use stwo::core::channel::Channel;
    channel.mix_u32s(&output_fp);

    let component = UseHintBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        UseHintBatchEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, w1_out))
}

/// UseHint-batch V2: proves UseHint AND hint weight in one STARK.
///
/// Returns `(proof_bytes, commitment_hex, w1_out, hint_weight_total)`.
/// `commitment_hex` = fingerprint of `flatten(w1_prime) ++ [hint_weight_total]`.
pub fn prove_use_hint_batch_v2(
    w_prime: &[[i64; mldsa::N]; mldsa::params::K],
    hints:   &[[bool; mldsa::N]; mldsa::params::K],
) -> Result<(Vec<u8>, String, [[i64; mldsa::N]; mldsa::params::K], usize), String> {
    use mldsa_use_hint_batch_air::{
        LOG_N_ROWS,
        new_component_v2, build_trace_v2,
    };
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};

    for (i, row) in w_prime.iter().enumerate() {
        for (p, &v) in row.iter().enumerate() {
            if v < 0 || v >= mldsa::Q {
                return Err(format!("w_prime[{i}][{p}] = {v} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (main_cols, preproc_cols, w1_out, hint_weight_total) = build_trace_v2(w_prime, hints);

    // Combined fingerprint: w1_prime ++ [hint_weight_total].
    let mut combined_flat: Vec<i64> = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    combined_flat.push(hint_weight_total as i64);
    let output_fp      = output_fingerprint(&combined_flat);
    let commitment_hex = build_poly_commitment(&output_fp);

    let config  = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: preprocessed (is_init_uh).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: main trace (61 columns).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_cols);
    tree_builder.commit(channel);

    channel.mix_u32s(&output_fp);

    let component = new_component_v2(log_size);

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("prove_use_hint_batch_v2 error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("prove_use_hint_batch_v2 serialize error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, w1_out, hint_weight_total))
}

/// Verify a UseHint-batch V2 proof produced by [`prove_use_hint_batch_v2`].
///
/// `w1_out` and `hint_weight_total` must match what was returned from the prover.
pub fn verify_use_hint_batch_v2(
    proof_bytes:        &[u8],
    commitment_hex:     &str,
    w1_out:             &[[i64; mldsa::N]; mldsa::params::K],
    hint_weight_total:  usize,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_use_hint_batch_air::{LOG_N_ROWS, new_component_v2};
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;

    let log_size = LOG_N_ROWS;

    // Rebuild the combined fingerprint and verify it matches commitment_hex.
    let mut combined_flat: Vec<i64> = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    combined_flat.push(hint_weight_total as i64);
    let expected_fp = output_fingerprint(&combined_flat);
    let expected_cm = build_poly_commitment(&expected_fp);
    if expected_cm != commitment_hex {
        return Ok(false);
    }

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("verify_use_hint_batch_v2 deserialize error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let component = new_component_v2(log_size);

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("verify_use_hint_batch_v2: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    verifier_channel.mix_u32s(&expected_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Combined NormCheck+UseHintBatchV2 STARK (MVP-3+, V17) ────────────────────

/// Prove NormCheck AND UseHintBatchV2 in a single multi-component STARK.
///
/// Both AIRs share `LOG_N_ROWS=8`. UseHintBatchV2 has one preprocessed column
/// (`is_init_uh`); NormCheck has none. A shared allocator interleaves their
/// columns in a single commitment tree.
///
/// Returns:
///   `(proof_bytes, norm_commitment, use_hint_commitment,
///     max_norms, w1_out, hint_weight_total)`
pub fn prove_norm_use_hint_combined(
    z:       &[[i64; mldsa::N]; mldsa::params::L],
    w_prime: &[[i64; mldsa::N]; mldsa::params::K],
    hints:   &[[bool; mldsa::N]; mldsa::params::K],
) -> Result<(Vec<u8>, String, String, [i64; mldsa::params::L], [[i64; mldsa::N]; mldsa::params::K], usize), String> {
    use mldsa_norm_check_batch_air::{
        NormCheckBatchEval, NormCheckBatchComponent,
        LOG_N_ROWS as NORM_LOG, N_COLS as NORM_N_COLS, build_trace as norm_build_trace,
    };
    use mldsa_use_hint_batch_air::{
        UseHintBatchV2Eval, UseHintBatchV2Component,
        N_COLS_V2 as UH_N_COLS, build_trace_v2, pc_is_init_uh,
    };
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;
    use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

    let log_size = NORM_LOG; // 8 — same for both AIRs

    // Build traces.
    let (norm_cols, norm_out, max_norms) = norm_build_trace(z);
    let (uh_main_cols, uh_preproc_cols, w1_out, hint_weight_total) = build_trace_v2(w_prime, hints);

    debug_assert_eq!(norm_cols.len(), NORM_N_COLS);
    debug_assert_eq!(uh_main_cols.len(), UH_N_COLS);

    // Fingerprints.
    let norm_flat: Vec<i64> = norm_out.iter().flat_map(|r| r.iter().copied()).collect();
    let norm_fp  = output_fingerprint(&norm_flat);
    let norm_cm  = build_poly_commitment(&norm_fp);

    let mut uh_combined: Vec<i64> = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    uh_combined.push(hint_weight_total as i64);
    let uh_fp = output_fingerprint(&uh_combined);
    let uh_cm = build_poly_commitment(&uh_fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: UseHintBatchV2 preprocessed column (is_init_uh).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(uh_preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: NormCheck cols (15) ++ UseHintBatchV2 main cols (61) = 76.
    let mut combined_main = norm_cols;
    combined_main.extend(uh_main_cols);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(combined_main);
    tree_builder.commit(channel);

    // Transcript: norm fingerprint first, then use_hint fingerprint.
    channel.mix_u32s(&norm_fp);
    channel.mix_u32s(&uh_fp);

    // Shared allocator — UseHintBatchV2 needs is_init_uh registered.
    let pc_ids: Vec<PreProcessedColumnId> = vec![pc_is_init_uh()];
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&pc_ids);

    let norm_comp = NormCheckBatchComponent::new(
        &mut alloc,
        NormCheckBatchEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let uh_comp = UseHintBatchV2Component::new(
        &mut alloc,
        UseHintBatchV2Eval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&norm_comp, &uh_comp], channel, commitment_scheme,
    ).map_err(|e| format!("prove_norm_use_hint_combined error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, norm_cm, uh_cm, max_norms, w1_out, hint_weight_total))
}

/// Verify a combined NormCheck+UseHintBatchV2 proof.
pub fn verify_norm_use_hint_combined(
    proof_bytes:       &[u8],
    norm_commitment:   &str,
    use_hint_commitment: &str,
    w1_out:            &[[i64; mldsa::N]; mldsa::params::K],
    hint_weight_total: usize,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_norm_check_batch_air::{
        NormCheckBatchEval, NormCheckBatchComponent,
        LOG_N_ROWS as NORM_LOG, N_COLS as NORM_N_COLS,
    };
    use mldsa_use_hint_batch_air::{
        UseHintBatchV2Eval, UseHintBatchV2Component,
        N_COLS_V2 as UH_N_COLS, pc_is_init_uh,
    };
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::CommitmentSchemeVerifier;
    use stwo::core::verifier::verify;
    use stwo_constraint_framework::TraceLocationAllocator;
    use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

    let log_size = NORM_LOG;

    let norm_fp = parse_poly_commitment(norm_commitment)?;

    // Rebuild use_hint fingerprint.
    let mut uh_combined: Vec<i64> = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    uh_combined.push(hint_weight_total as i64);
    let expected_uh_fp = output_fingerprint(&uh_combined);
    let expected_uh_cm = build_poly_commitment(&expected_uh_fp);
    if expected_uh_cm != use_hint_commitment {
        return Ok(false);
    }
    let uh_fp = parse_poly_commitment(use_hint_commitment)?;

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

    let pc_ids: Vec<PreProcessedColumnId> = vec![pc_is_init_uh()];
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&pc_ids);

    let norm_comp = NormCheckBatchComponent::new(
        &mut alloc,
        NormCheckBatchEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let uh_comp = UseHintBatchV2Component::new(
        &mut alloc,
        UseHintBatchV2Eval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    // Tree 0: 1 preproc col (is_init_uh) at log_size=8.
    // Tree 1: NORM_N_COLS + UH_N_COLS = 15+61=76 main cols at log_size=8.
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &[log_size; 1], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &[log_size; NORM_N_COLS + UH_N_COLS], verifier_channel);

    verifier_channel.mix_u32s(&norm_fp);
    verifier_channel.mix_u32s(&uh_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&norm_comp, &uh_comp], verifier_channel, commitment_scheme, proof,
    ).is_ok())
}

// ─── Combined Az+Ct1+NormCheck+UseHintBatchV2 STARK (MVP-3+, V19) ─────────────

/// Prove Az-full, Ct1-full, NormCheckBatch, AND UseHintBatchV2 in ONE STARK.
///
/// All four AIRs share LOG_N_ROWS=8.  A shared `TraceLocationAllocator` with
/// `is_init_uh` registered places the four component traces in one 1894-column
/// commitment tree:
///   Az (1523) + Ct1 (295) + NormCheck (15) + UseHintV2 (61) = 1894 main cols
///   + 1 preprocessed col (is_init_uh).
///
/// c_tilde is mixed into the channel before the first tree commit (same as
/// the Az+Ct1 binding in V16), binding the FRI challenge to the signature.
///
/// Returns `(proof_bytes, az_cm, ct1_cm, norm_cm, uh_cm,
///           az_hat_out, ct1_hat_out, max_norms, w1_out, hint_weight_total)`.
pub fn prove_az_ct1_norm_use_hint_combined(
    a_hat:   &[[i64; mldsa::N]],
    z_hat:   &[[i64; mldsa::N]; mldsa::params::L],
    c_hat:   &[i64; mldsa::N],
    t1_hat:  &[[i64; mldsa::N]; mldsa::params::K],
    z:       &[[i64; mldsa::N]; mldsa::params::L],
    w_prime: &[[i64; mldsa::N]; mldsa::params::K],
    hints:   &[[bool; mldsa::N]; mldsa::params::K],
    c_tilde_seed: &[u8],
) -> Result<(
    Vec<u8>, String, String, String, String,
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
    [i64; mldsa::params::L],
    [[i64; mldsa::N]; mldsa::params::K],
    usize,
), String> {
    use mldsa_az_full_air::{
        AzFullEval, AzFullComponent,
        LOG_N_ROWS as AZ_LOG, N_COLS as AZ_N_COLS, build_trace as az_build_trace,
    };
    use mldsa_ct1_full_air::{
        Ct1FullEval, Ct1FullComponent,
        N_COLS as CT1_N_COLS, build_trace as ct1_build_trace,
    };
    use mldsa_norm_check_batch_air::{
        NormCheckBatchEval, NormCheckBatchComponent,
        N_COLS as NORM_N_COLS, build_trace as norm_build_trace,
    };
    use mldsa_use_hint_batch_air::{
        UseHintBatchV2Eval, UseHintBatchV2Component,
        N_COLS_V2 as UH_N_COLS, build_trace_v2, pc_is_init_uh,
    };
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;
    use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

    let log_size = AZ_LOG; // 8 — all four AIRs share this

    // Build all four traces.
    let (az_cols,   az_out)                          = az_build_trace(a_hat, z_hat);
    let (ct1_cols,  ct1_out)                         = ct1_build_trace(c_hat, t1_hat);
    let (norm_cols, norm_out, max_norms)             = norm_build_trace(z);
    let (uh_main_cols, uh_preproc_cols, w1_out, hint_weight_total) = build_trace_v2(w_prime, hints);

    debug_assert_eq!(az_cols.len(),   AZ_N_COLS);
    debug_assert_eq!(ct1_cols.len(),  CT1_N_COLS);
    debug_assert_eq!(norm_cols.len(), NORM_N_COLS);
    debug_assert_eq!(uh_main_cols.len(), UH_N_COLS);

    // Fingerprints for all four components.
    let z_flat:    Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let az_in_fp   = output_fingerprint(&z_flat);
    let az_out_flat: Vec<i64> = az_out.iter().flat_map(|r| r.iter().copied()).collect();
    let az_out_fp  = output_fingerprint(&az_out_flat);
    let az_cm      = build_poly_commitment(&az_out_fp);

    let ct1_in_flat: Vec<i64> = c_hat.iter().copied()
        .chain(t1_hat.iter().flat_map(|r| r.iter().copied())).collect();
    let ct1_in_fp  = output_fingerprint(&ct1_in_flat);
    let ct1_out_flat: Vec<i64> = ct1_out.iter().flat_map(|r| r.iter().copied()).collect();
    let ct1_out_fp = output_fingerprint(&ct1_out_flat);
    let ct1_cm     = build_poly_commitment(&ct1_out_fp);

    let norm_flat: Vec<i64> = norm_out.iter().flat_map(|r| r.iter().copied()).collect();
    let norm_fp    = output_fingerprint(&norm_flat);
    let norm_cm    = build_poly_commitment(&norm_fp);

    let mut uh_flat: Vec<i64> = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    uh_flat.push(hint_weight_total as i64);
    let uh_fp  = output_fingerprint(&uh_flat);
    let uh_cm  = build_poly_commitment(&uh_fp);

    let config  = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    // c_tilde binding: bind FRI challenge to this specific signature (same as V16).
    if !c_tilde_seed.is_empty() {
        let words: Vec<u32> = c_tilde_seed.chunks(4).map(|b| {
            let mut arr = [0u8; 4];
            arr[..b.len()].copy_from_slice(b);
            u32::from_le_bytes(arr)
        }).collect();
        channel.mix_u32s(&words);
    }

    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: UseHintBatchV2 preprocessed column (is_init_uh).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(uh_preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: all 1894 main cols in one commitment.
    let mut combined_main = az_cols;
    combined_main.extend(ct1_cols);
    combined_main.extend(norm_cols);
    combined_main.extend(uh_main_cols);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(combined_main);
    tree_builder.commit(channel);

    // Transcript: Az input→output, Ct1 input→output, Norm output, UseHint output.
    channel.mix_u32s(&az_in_fp);
    channel.mix_u32s(&az_out_fp);
    channel.mix_u32s(&ct1_in_fp);
    channel.mix_u32s(&ct1_out_fp);
    channel.mix_u32s(&norm_fp);
    channel.mix_u32s(&uh_fp);

    // Shared allocator with is_init_uh registered (needed by UseHintBatchV2).
    let pc_ids: Vec<PreProcessedColumnId> = vec![pc_is_init_uh()];
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&pc_ids);
    let az_comp = AzFullComponent::new(
        &mut alloc,
        AzFullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let ct1_comp = Ct1FullComponent::new(
        &mut alloc,
        Ct1FullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let norm_comp = NormCheckBatchComponent::new(
        &mut alloc,
        NormCheckBatchEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let uh_comp = UseHintBatchV2Component::new(
        &mut alloc,
        UseHintBatchV2Eval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&az_comp, &ct1_comp, &norm_comp, &uh_comp], channel, commitment_scheme,
    ).map_err(|e| format!("prove_az_ct1_norm_use_hint_combined error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, az_cm, ct1_cm, norm_cm, uh_cm,
        az_out, ct1_out, max_norms, w1_out, hint_weight_total))
}

/// Verify a combined Az+Ct1+NormCheck+UseHintBatchV2 proof.
pub fn verify_az_ct1_norm_use_hint_combined(
    proof_bytes: &[u8],
    az_cm:       &str,
    ct1_cm:      &str,
    norm_cm:     &str,
    uh_cm:       &str,
    z_hat:       &[[i64; mldsa::N]; mldsa::params::L],
    c_hat:       &[i64; mldsa::N],
    t1_hat:      &[[i64; mldsa::N]; mldsa::params::K],
    az_hat_out:  &[[i64; mldsa::N]; mldsa::params::K],
    ct1_hat_out: &[[i64; mldsa::N]; mldsa::params::K],
    w1_out:      &[[i64; mldsa::N]; mldsa::params::K],
    hint_weight_total: usize,
    c_tilde_seed: &[u8],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_az_full_air::{
        AzFullEval, AzFullComponent,
        LOG_N_ROWS as AZ_LOG, N_COLS as AZ_N_COLS,
    };
    use mldsa_ct1_full_air::{Ct1FullEval, Ct1FullComponent, N_COLS as CT1_N_COLS};
    use mldsa_norm_check_batch_air::{NormCheckBatchEval, NormCheckBatchComponent, N_COLS as NORM_N_COLS};
    use mldsa_use_hint_batch_air::{
        UseHintBatchV2Eval, UseHintBatchV2Component,
        N_COLS_V2 as UH_N_COLS, pc_is_init_uh,
    };
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::CommitmentSchemeVerifier;
    use stwo::core::verifier::verify;
    use stwo_constraint_framework::TraceLocationAllocator;
    use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

    let log_size = AZ_LOG;

    // Recompute fingerprints.
    let z_flat: Vec<i64> = z_hat.iter().flat_map(|zj| zj.iter().copied()).collect();
    let az_in_fp  = output_fingerprint(&z_flat);
    let az_out_flat: Vec<i64> = az_hat_out.iter().flat_map(|r| r.iter().copied()).collect();
    let az_out_fp = output_fingerprint(&az_out_flat);
    if build_poly_commitment(&az_out_fp) != az_cm { return Ok(false); }

    let ct1_in_flat: Vec<i64> = c_hat.iter().copied()
        .chain(t1_hat.iter().flat_map(|r| r.iter().copied())).collect();
    let ct1_in_fp  = output_fingerprint(&ct1_in_flat);
    let ct1_out_flat: Vec<i64> = ct1_hat_out.iter().flat_map(|r| r.iter().copied()).collect();
    let ct1_out_fp = output_fingerprint(&ct1_out_flat);
    if build_poly_commitment(&ct1_out_fp) != ct1_cm { return Ok(false); }

    let norm_fp = parse_poly_commitment(norm_cm)?;

    let mut uh_flat: Vec<i64> = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    uh_flat.push(hint_weight_total as i64);
    let uh_fp      = output_fingerprint(&uh_flat);
    let expected_uh_cm = build_poly_commitment(&uh_fp);
    if expected_uh_cm != uh_cm { return Ok(false); }

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

    let pc_ids: Vec<PreProcessedColumnId> = vec![pc_is_init_uh()];
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&pc_ids);
    let az_comp = AzFullComponent::new(
        &mut alloc,
        AzFullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let ct1_comp = Ct1FullComponent::new(
        &mut alloc,
        Ct1FullEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let norm_comp = NormCheckBatchComponent::new(
        &mut alloc,
        NormCheckBatchEval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let uh_comp = UseHintBatchV2Component::new(
        &mut alloc,
        UseHintBatchV2Eval { log_n_rows: log_size },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    if !c_tilde_seed.is_empty() {
        let words: Vec<u32> = c_tilde_seed.chunks(4).map(|b| {
            let mut arr = [0u8; 4];
            arr[..b.len()].copy_from_slice(b);
            u32::from_le_bytes(arr)
        }).collect();
        verifier_channel.mix_u32s(&words);
    }

    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    // Tree 0: 1 preproc col; Tree 1: 1894 main cols.
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &[log_size; 1], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &[log_size; AZ_N_COLS + CT1_N_COLS + NORM_N_COLS + UH_N_COLS], verifier_channel);

    // Replay transcript.
    verifier_channel.mix_u32s(&az_in_fp);
    verifier_channel.mix_u32s(&az_out_fp);
    verifier_channel.mix_u32s(&ct1_in_fp);
    verifier_channel.mix_u32s(&ct1_out_fp);
    verifier_channel.mix_u32s(&norm_fp);
    verifier_channel.mix_u32s(&uh_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&az_comp, &ct1_comp, &norm_comp, &uh_comp],
        verifier_channel, commitment_scheme, proof,
    ).is_ok())
}

// ─── Combined NTT+AzFull+Ct1Full STARK (MVP-3+, V19) ────────────────────────
//
// Merges AllNttProof + AzCt1ProofV16 (2 sub-proofs, sizes LOG=10 + LOG=8+8)
// into one 3-component mixed-size STARK covering all 12 NTTs, Az-full, and
// Ct1-full in one FRI polynomial commitment.
//
// Tree 1 column layout:
//   NttBatch (LOG=10, 649 cols) ++ AzFull (LOG=8, 1523 cols) ++ Ct1Full (LOG=8, 295 cols)
//   = 2467 total main columns
//
// Twiddles computed at LOG=10+4+1=15 (max component level).

/// Prove all 12 NTTs (z,c,t1), Az-full, and Ct1-full in ONE STARK.
///
/// Returns `(proof_bytes, ntt_cm, az_cm, ct1_cm, z_hat, c_hat, t1_hat, az_hat_out, ct1_hat_out)`.
pub fn prove_ntt_az_ct1_combined(
    z:            &[[i64; mldsa::N]; mldsa::params::L],
    c:            &[i64; mldsa::N],
    t1:           &[[i64; mldsa::N]; mldsa::params::K],
    a_hat:        &[[i64; mldsa::N]],
    c_tilde_seed: &[u8],
) -> Result<(
    Vec<u8>, String, String, String,
    Vec<[i64; mldsa::N]>, [i64; mldsa::N], Vec<[i64; mldsa::N]>,
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
), String> {
    use mldsa_ntt_batch_air::{
        NttBatchEval, LOG_N_ROWS as NTT_LOG, n_cols_for as ntt_n_cols_for,
        build_trace as ntt_build_trace,
    };
    use mldsa_az_full_air::{
        AzFullEval, AzFullComponent,
        LOG_N_ROWS as AZ_LOG, N_COLS as AZ_N_COLS, build_trace as az_build_trace,
    };
    use mldsa_ct1_full_air::{
        Ct1FullEval, Ct1FullComponent,
        LOG_N_ROWS as CT1_LOG, N_COLS as CT1_N_COLS, build_trace as ct1_build_trace,
    };
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    let l = mldsa::params::L;
    let k = mldsa::params::K;
    let n_polys = l + 1 + k; // 12 for ML-DSA-65

    if a_hat.len() != k * l {
        return Err(format!("a_hat must have k*l={} entries, got {}", k * l, a_hat.len()));
    }

    // NTT trace: z[0..L] ++ c ++ t1[0..K] = 12 polys.
    let mut all_ntt_inputs: Vec<[i64; mldsa::N]> = Vec::with_capacity(n_polys);
    all_ntt_inputs.extend_from_slice(z);
    all_ntt_inputs.push(*c);
    all_ntt_inputs.extend_from_slice(t1);
    let (ntt_cols, ntt_outputs) = ntt_build_trace(&all_ntt_inputs);

    let z_hat: Vec<[i64; mldsa::N]> = ntt_outputs[0..l].to_vec();
    let c_hat: [i64; mldsa::N] = ntt_outputs[l];
    let t1_hat: Vec<[i64; mldsa::N]> = ntt_outputs[l + 1..l + 1 + k].to_vec();

    // Az trace using NTT outputs.
    let z_hat_arr: [[i64; mldsa::N]; mldsa::params::L] = z_hat.as_slice().try_into()
        .map_err(|_| "z_hat must have L entries".to_string())?;
    let (az_cols, az_out) = az_build_trace(a_hat, &z_hat_arr);

    // Ct1 trace using NTT outputs.
    let t1_hat_arr: [[i64; mldsa::N]; mldsa::params::K] = t1_hat.as_slice().try_into()
        .map_err(|_| "t1_hat must have K entries".to_string())?;
    let (ct1_cols, ct1_out) = ct1_build_trace(&c_hat, &t1_hat_arr);

    debug_assert_eq!(ntt_cols.len(), ntt_n_cols_for(n_polys));
    debug_assert_eq!(az_cols.len(), AZ_N_COLS);
    debug_assert_eq!(ct1_cols.len(), CT1_N_COLS);

    // NTT output fingerprint (all 12 polys concatenated).
    let ntt_out_flat: Vec<i64> = ntt_outputs.iter().flat_map(|p| p.iter().copied()).collect();
    let ntt_out_fp = output_fingerprint(&ntt_out_flat);
    let ntt_cm = build_poly_commitment(&ntt_out_fp);

    // Az and Ct1 output fingerprints.
    let az_out_flat: Vec<i64> = az_out.iter().flat_map(|r| r.iter().copied()).collect();
    let az_out_fp = output_fingerprint(&az_out_flat);
    let az_cm = build_poly_commitment(&az_out_fp);

    let ct1_out_flat: Vec<i64> = ct1_out.iter().flat_map(|r| r.iter().copied()).collect();
    let ct1_out_fp = output_fingerprint(&ct1_out_flat);
    let ct1_cm = build_poly_commitment(&ct1_out_fp);

    // Twiddles at NTT level (max of the three components: NTT_LOG=10 > AZ_LOG=CT1_LOG=8).
    let max_log = NTT_LOG;
    let config = make_config(max_log);
    let lifting = max_log + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    if !c_tilde_seed.is_empty() {
        let words: Vec<u32> = c_tilde_seed.chunks(4).map(|b| {
            let mut arr = [0u8; 4];
            arr[..b.len()].copy_from_slice(b);
            u32::from_le_bytes(arr)
        }).collect();
        channel.mix_u32s(&words);
    }

    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: empty (no preprocessed columns needed).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    // Tree 1: NTT cols (649, log=10) ++ Az cols (1523, log=8) ++ Ct1 cols (295, log=8) = 2467.
    let mut combined_main = ntt_cols;
    combined_main.extend(az_cols);
    combined_main.extend(ct1_cols);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(combined_main);
    tree_builder.commit(channel);

    // Transcript: NTT output fp (cross-links to Az+Ct1 inputs), Az output fp, Ct1 output fp.
    channel.mix_u32s(&ntt_out_fp);
    channel.mix_u32s(&az_out_fp);
    channel.mix_u32s(&ct1_out_fp);

    // Shared allocator: NTT [0..649], Az [649..2172], Ct1 [2172..2467].
    let mut alloc = TraceLocationAllocator::default();
    let ntt_comp = mldsa_ntt_batch_air::NttBatchComponent::new(
        &mut alloc,
        NttBatchEval { log_n_rows: NTT_LOG, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let az_comp = AzFullComponent::new(
        &mut alloc,
        AzFullEval { log_n_rows: AZ_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let ct1_comp = Ct1FullComponent::new(
        &mut alloc,
        Ct1FullEval { log_n_rows: CT1_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&ntt_comp, &az_comp, &ct1_comp], channel, commitment_scheme,
    ).map_err(|e| format!("prove_ntt_az_ct1_combined error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, ntt_cm, az_cm, ct1_cm, z_hat, c_hat, t1_hat, az_out, ct1_out))
}

/// Verify a combined NTT+AzFull+Ct1Full proof produced by [`prove_ntt_az_ct1_combined`].
pub fn verify_ntt_az_ct1_combined(
    proof_bytes:  &[u8],
    ntt_cm:       &str,
    az_cm:        &str,
    ct1_cm:       &str,
    z_hat:        &[[i64; mldsa::N]],
    c_hat:        &[i64; mldsa::N],
    t1_hat:       &[[i64; mldsa::N]],
    az_hat_out:   &[[i64; mldsa::N]; mldsa::params::K],
    ct1_hat_out:  &[[i64; mldsa::N]; mldsa::params::K],
    c_tilde_seed: &[u8],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_ntt_batch_air::{
        NttBatchEval, LOG_N_ROWS as NTT_LOG, n_cols_for as ntt_n_cols_for,
    };
    use mldsa_az_full_air::{
        AzFullEval, AzFullComponent,
        LOG_N_ROWS as AZ_LOG, N_COLS as AZ_N_COLS,
    };
    use mldsa_ct1_full_air::{
        Ct1FullEval, Ct1FullComponent,
        LOG_N_ROWS as CT1_LOG, N_COLS as CT1_N_COLS,
    };
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::CommitmentSchemeVerifier;
    use stwo::core::verifier::verify;
    use stwo_constraint_framework::TraceLocationAllocator;

    let l = mldsa::params::L;
    let k = mldsa::params::K;
    let n_polys = l + 1 + k; // 12

    // Recompute NTT output fingerprint from stored z_hat, c_hat, t1_hat.
    let ntt_out_flat: Vec<i64> = z_hat.iter().chain(std::iter::once(c_hat as &[i64; mldsa::N]))
        .chain(t1_hat.iter()).flat_map(|p| p.iter().copied()).collect();
    let ntt_out_fp = output_fingerprint(&ntt_out_flat);
    if build_poly_commitment(&ntt_out_fp) != ntt_cm { return Ok(false); }

    // Recompute Az output fingerprint.
    let az_out_flat: Vec<i64> = az_hat_out.iter().flat_map(|r| r.iter().copied()).collect();
    let az_out_fp = output_fingerprint(&az_out_flat);
    if build_poly_commitment(&az_out_fp) != az_cm { return Ok(false); }

    // Recompute Ct1 output fingerprint.
    let ct1_out_flat: Vec<i64> = ct1_hat_out.iter().flat_map(|r| r.iter().copied()).collect();
    let ct1_out_fp = output_fingerprint(&ct1_out_flat);
    if build_poly_commitment(&ct1_out_fp) != ct1_cm { return Ok(false); }

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

    let mut alloc = TraceLocationAllocator::default();
    let ntt_comp = mldsa_ntt_batch_air::NttBatchComponent::new(
        &mut alloc,
        NttBatchEval { log_n_rows: NTT_LOG, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let az_comp = AzFullComponent::new(
        &mut alloc,
        AzFullEval { log_n_rows: AZ_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let ct1_comp = Ct1FullComponent::new(
        &mut alloc,
        Ct1FullEval { log_n_rows: CT1_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    if !c_tilde_seed.is_empty() {
        let words: Vec<u32> = c_tilde_seed.chunks(4).map(|b| {
            let mut arr = [0u8; 4];
            arr[..b.len()].copy_from_slice(b);
            u32::from_le_bytes(arr)
        }).collect();
        verifier_channel.mix_u32s(&words);
    }
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    // Tree 0: empty; Tree 1: [NTT_LOG; ntt_n_cols] ++ [AZ_LOG; AZ_N_COLS] ++ [CT1_LOG; CT1_N_COLS].
    let ntt_n_cols = ntt_n_cols_for(n_polys);
    let mut tree1_sizes: Vec<u32> = vec![NTT_LOG; ntt_n_cols];
    tree1_sizes.extend(vec![AZ_LOG; AZ_N_COLS]);
    tree1_sizes.extend(vec![CT1_LOG; CT1_N_COLS]);

    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &[], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &tree1_sizes, verifier_channel);

    // Replay transcript.
    verifier_channel.mix_u32s(&ntt_out_fp);
    verifier_channel.mix_u32s(&az_out_fp);
    verifier_channel.mix_u32s(&ct1_out_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&ntt_comp, &az_comp, &ct1_comp], verifier_channel, commitment_scheme, proof,
    ).is_ok())
}

// ─── Full ML-DSA.Verify 7-component STARK (MVP-3+, V21) ──────────────────────
//
// Merges ALL 7 circuits into ONE FRI polynomial commitment, achieving the
// minimum possible of 1 sub-proof for the complete ML-DSA.Verify witness.
//
// Component layout (data pipeline order):
//   1. NttBatch    (LOG=10, 649 cols)  — NTT(z,c,t1) → z_hat, c_hat, t1_hat
//   2. AzFull      (LOG=8,  1523 cols) — A×z in NTT domain → az_hat
//   3. Ct1Full     (LOG=8,  295 cols)  — c·t1 in NTT domain → ct1_hat
//   4. InttBatch   (LOG=10, 649 cols)  — INTT(az_hat, ct1_hat) → az_out, ct1_out
//   5. WPrimeFull  (LOG=8,  24 cols)   — w' = az - ct1 → w_prime
//   6. NormCheckBatch (LOG=8, 15 cols) — ‖z‖∞ ≤ GAMMA1−β → max_norms
//   7. UseHintBatchV2 (LOG=8, 61 cols + 1 preproc) — UseHint(w', h) → w1_prime
//
// Tree 0: UseHintBatchV2 preprocessed column (is_init_uh, LOG=8, 1 col)
// Tree 1: [10;649] ++ [8;1523] ++ [8;295] ++ [10;649] ++ [8;24] ++ [8;15] ++ [8;61]
//       = 3216 main trace columns total
// Twiddles at LOG_NTT=10+LOG_BLOWUP+1=15.
//
// Transcript order:
//   c_tilde → Tree0(preproc) → Tree1(3216 cols) →
//   ntt_out_fp → az_out_fp → ct1_out_fp →
//   intt_in_fps × 12 → intt_out_fp → wp_out_fp → norm_fp → uh_fp

/// Prove all 7 ML-DSA.Verify arithmetic components in ONE STARK proof.
///
/// Returns `(proof_bytes, ntt_cm, az_cm, ct1_cm, intt_cm, wp_cm, norm_cm, uh_cm,
///           z_hat, c_hat, t1_hat, az_hat, ct1_hat, az_out, ct1_out,
///           w_prime, max_norms, w1_out, hint_weight_total)`.
#[allow(clippy::too_many_arguments)]
pub fn prove_full_mldsa_witness_combined(
    z:             &[[i64; mldsa::N]; mldsa::params::L],
    c:             &[i64; mldsa::N],
    t1:            &[[i64; mldsa::N]; mldsa::params::K],
    a_hat:         &[[i64; mldsa::N]],
    hints:         &[[bool; mldsa::N]; mldsa::params::K],
    c_tilde_seed:  &[u8],
    extra_binding: &[u8],
) -> Result<(
    Vec<u8>,
    String, String, String, String, String, String, String,
    Vec<[i64; mldsa::N]>, [i64; mldsa::N], Vec<[i64; mldsa::N]>,
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
    [i64; mldsa::params::L],
    [[i64; mldsa::N]; mldsa::params::K],
    usize,
), String> {
    use mldsa_ntt_batch_air::{
        NttBatchEval, LOG_N_ROWS as NTT_LOG, n_cols_for as ntt_n_cols_for,
        build_trace as ntt_build_trace,
    };
    use mldsa_az_full_air::{
        AzFullEval, AzFullComponent,
        LOG_N_ROWS as AZ_LOG, N_COLS as AZ_N_COLS, build_trace as az_build_trace,
    };
    use mldsa_ct1_full_air::{
        Ct1FullEval, Ct1FullComponent,
        LOG_N_ROWS as CT1_LOG, N_COLS as CT1_N_COLS, build_trace as ct1_build_trace,
    };
    use mldsa_intt_batch_air::{
        InttBatchEval, LOG_N_ROWS as INTT_LOG, n_cols_for as intt_n_cols_for,
        build_trace as intt_build_trace,
    };
    use mldsa_wprime_full_air::{
        WPrimeFullEval, WPrimeFullComponent,
        LOG_N_ROWS as WP_LOG, N_COLS as WP_N_COLS, build_trace as wp_build_trace,
    };
    use mldsa_norm_check_batch_air::{
        NormCheckBatchEval, NormCheckBatchComponent,
        LOG_N_ROWS as NORM_LOG, N_COLS as NORM_N_COLS, build_trace as norm_build_trace,
    };
    use mldsa_use_hint_batch_air::{
        UseHintBatchV2Eval, UseHintBatchV2Component,
        N_COLS_V2 as UH_N_COLS, build_trace_v2, pc_is_init_uh,
    };
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;
    use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

    let l = mldsa::params::L;
    let k = mldsa::params::K;

    if a_hat.len() != k * l {
        return Err(format!("a_hat must have k*l={} entries, got {}", k * l, a_hat.len()));
    }

    // ── Step 1: NTT(z, c, t1) ────────────────────────────────────────────────
    let n_ntt_polys = l + 1 + k; // 12 for ML-DSA-65
    let mut ntt_inputs: Vec<[i64; mldsa::N]> = Vec::with_capacity(n_ntt_polys);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);
    let (ntt_cols, ntt_outputs) = ntt_build_trace(&ntt_inputs);

    let z_hat:  Vec<[i64; mldsa::N]> = ntt_outputs[0..l].to_vec();
    let c_hat:  [i64; mldsa::N]      = ntt_outputs[l];
    let t1_hat: Vec<[i64; mldsa::N]> = ntt_outputs[l + 1..l + 1 + k].to_vec();

    // ── Step 2: Az and Ct1 in NTT domain ─────────────────────────────────────
    let z_hat_arr: [[i64; mldsa::N]; mldsa::params::L] = z_hat.as_slice().try_into()
        .map_err(|_| "z_hat must have L entries".to_string())?;
    let t1_hat_arr: [[i64; mldsa::N]; mldsa::params::K] = t1_hat.as_slice().try_into()
        .map_err(|_| "t1_hat must have K entries".to_string())?;

    let (az_cols,  az_hat)  = az_build_trace(a_hat, &z_hat_arr);
    let (ct1_cols, ct1_hat) = ct1_build_trace(&c_hat, &t1_hat_arr);

    // ── Step 3: INTT(az_hat, ct1_hat) ────────────────────────────────────────
    let n_intt_polys = 2 * k; // 12 for ML-DSA-65
    let mut intt_inputs: Vec<[i64; mldsa::N]> = Vec::with_capacity(n_intt_polys);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, intt_out) = intt_build_trace(&intt_inputs);

    let az_out:  [[i64; mldsa::N]; mldsa::params::K] = intt_out[..k].try_into()
        .map_err(|_| "az_out slice err".to_string())?;
    let ct1_out: [[i64; mldsa::N]; mldsa::params::K] = intt_out[k..].try_into()
        .map_err(|_| "ct1_out slice err".to_string())?;

    // ── Step 4: WPrime, NormCheck, UseHint ───────────────────────────────────
    let (wp_cols,   w_prime)                          = wp_build_trace(&az_out, &ct1_out);
    let (norm_cols, norm_out, max_norms)              = norm_build_trace(z);
    let (uh_main_cols, uh_preproc_cols, w1_out, hint_weight_total) =
        build_trace_v2(&w_prime, hints);

    // Column-count assertions (catch wrong constants at test time).
    debug_assert_eq!(ntt_cols.len(),      ntt_n_cols_for(n_ntt_polys));
    debug_assert_eq!(az_cols.len(),       AZ_N_COLS);
    debug_assert_eq!(ct1_cols.len(),      CT1_N_COLS);
    debug_assert_eq!(intt_cols.len(),     intt_n_cols_for(n_intt_polys));
    debug_assert_eq!(wp_cols.len(),       WP_N_COLS);
    debug_assert_eq!(norm_cols.len(),     NORM_N_COLS);
    debug_assert_eq!(uh_main_cols.len(),  UH_N_COLS);

    // ── Fingerprints ──────────────────────────────────────────────────────────
    let ntt_out_flat: Vec<i64> = ntt_outputs.iter().flat_map(|p| p.iter().copied()).collect();
    let ntt_out_fp   = output_fingerprint(&ntt_out_flat);
    let ntt_cm       = build_poly_commitment(&ntt_out_fp);

    let az_out_flat: Vec<i64>  = az_hat.iter().flat_map(|r| r.iter().copied()).collect();
    let az_out_fp    = output_fingerprint(&az_out_flat);
    let az_cm        = build_poly_commitment(&az_out_fp);

    let ct1_out_flat: Vec<i64> = ct1_hat.iter().flat_map(|r| r.iter().copied()).collect();
    let ct1_out_fp   = output_fingerprint(&ct1_out_flat);
    let ct1_cm       = build_poly_commitment(&ct1_out_fp);

    let intt_in_fps: Vec<[u32; 4]> = intt_inputs.iter()
        .map(|p| output_fingerprint(p.as_ref()))
        .collect();
    let intt_out_flat2: Vec<i64> = intt_out.iter().flat_map(|p| p.iter().copied()).collect();
    let intt_out_fp  = output_fingerprint(&intt_out_flat2);
    let intt_cm      = build_poly_commitment(&intt_out_fp);

    let wp_out_flat: Vec<i64>   = w_prime.iter().flat_map(|r| r.iter().copied()).collect();
    let wp_out_fp    = output_fingerprint(&wp_out_flat);
    let wp_cm        = build_poly_commitment(&wp_out_fp);

    let norm_flat: Vec<i64>     = norm_out.iter().flat_map(|r| r.iter().copied()).collect();
    let norm_fp      = output_fingerprint(&norm_flat);
    let norm_cm      = build_poly_commitment(&norm_fp);

    let mut uh_flat: Vec<i64>   = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    uh_flat.push(hint_weight_total as i64);
    let uh_fp        = output_fingerprint(&uh_flat);
    let uh_cm        = build_poly_commitment(&uh_fp);

    // ── STARK setup ───────────────────────────────────────────────────────────
    let max_log = NTT_LOG; // = INTT_LOG = 10
    let config   = make_config(max_log);
    let lifting  = max_log + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    for seed in [c_tilde_seed, extra_binding] {
        if !seed.is_empty() {
            let words: Vec<u32> = seed.chunks(4).map(|b| {
                let mut arr = [0u8; 4];
                arr[..b.len()].copy_from_slice(b);
                u32::from_le_bytes(arr)
            }).collect();
            channel.mix_u32s(&words);
        }
    }

    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: UseHintBatchV2 preprocessed column (is_init_uh, LOG=8).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(uh_preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: 7 components, total 3216 main columns.
    //  [10;649] ++ [8;1523] ++ [8;295] ++ [10;649] ++ [8;24] ++ [8;15] ++ [8;61]
    let mut combined_main = ntt_cols;
    combined_main.extend(az_cols);
    combined_main.extend(ct1_cols);
    combined_main.extend(intt_cols);
    combined_main.extend(wp_cols);
    combined_main.extend(norm_cols);
    combined_main.extend(uh_main_cols);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(combined_main);
    tree_builder.commit(channel);

    // Transcript fingerprints (bind all inter-component data flows).
    channel.mix_u32s(&ntt_out_fp);   // NTT → Az, Ct1
    channel.mix_u32s(&az_out_fp);    // Az → INTT
    channel.mix_u32s(&ct1_out_fp);   // Ct1 → INTT
    for fp in &intt_in_fps {          // INTT inputs (= az_hat ++ ct1_hat)
        channel.mix_u32s(fp);
    }
    channel.mix_u32s(&intt_out_fp);  // INTT → WPrime (shared fingerprint)
    channel.mix_u32s(&wp_out_fp);    // WPrime → UseHint
    channel.mix_u32s(&norm_fp);
    channel.mix_u32s(&uh_fp);

    // ── Components (shared TraceLocationAllocator) ────────────────────────────
    let pc_ids: Vec<PreProcessedColumnId> = vec![pc_is_init_uh()];
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&pc_ids);
    let ntt_comp = mldsa_ntt_batch_air::NttBatchComponent::new(
        &mut alloc,
        NttBatchEval { log_n_rows: NTT_LOG, n_polys: n_ntt_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let az_comp = AzFullComponent::new(
        &mut alloc,
        AzFullEval { log_n_rows: AZ_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let ct1_comp = Ct1FullComponent::new(
        &mut alloc,
        Ct1FullEval { log_n_rows: CT1_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let intt_comp = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut alloc,
        InttBatchEval { log_n_rows: INTT_LOG, n_polys: n_intt_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let wp_comp = WPrimeFullComponent::new(
        &mut alloc,
        WPrimeFullEval { log_n_rows: WP_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let norm_comp = NormCheckBatchComponent::new(
        &mut alloc,
        NormCheckBatchEval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let uh_comp = UseHintBatchV2Component::new(
        &mut alloc,
        UseHintBatchV2Eval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&ntt_comp, &az_comp, &ct1_comp, &intt_comp, &wp_comp, &norm_comp, &uh_comp],
        channel, commitment_scheme,
    ).map_err(|e| format!("prove_full_mldsa_witness_combined error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes,
        ntt_cm, az_cm, ct1_cm, intt_cm, wp_cm, norm_cm, uh_cm,
        z_hat, c_hat, t1_hat,
        az_hat, ct1_hat,
        az_out, ct1_out,
        w_prime, max_norms, w1_out,
        hint_weight_total))
}

/// Verify a combined 7-component ML-DSA.Verify witness proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_full_mldsa_witness_combined(
    proof_bytes:       &[u8],
    ntt_cm:            &str,
    az_cm:             &str,
    ct1_cm:            &str,
    intt_cm:           &str,
    wp_cm:             &str,
    norm_cm:           &str,
    uh_cm:             &str,
    // NTT inputs
    _z:                &[[i64; mldsa::N]; mldsa::params::L],
    _c:                &[i64; mldsa::N],
    _t1:               &[[i64; mldsa::N]; mldsa::params::K],
    // NTT outputs
    z_hat:             &[[i64; mldsa::N]],
    c_hat:             &[i64; mldsa::N],
    t1_hat:            &[[i64; mldsa::N]],
    // Az/Ct1 NTT-domain outputs
    az_hat:            &[[i64; mldsa::N]; mldsa::params::K],
    ct1_hat:           &[[i64; mldsa::N]; mldsa::params::K],
    // INTT outputs
    az_out:            &[[i64; mldsa::N]; mldsa::params::K],
    ct1_out:           &[[i64; mldsa::N]; mldsa::params::K],
    // WPrime output
    w_prime:           &[[i64; mldsa::N]; mldsa::params::K],
    // UseHint output
    w1_out:            &[[i64; mldsa::N]; mldsa::params::K],
    hint_weight_total: usize,
    c_tilde_seed:      &[u8],
    extra_binding:     &[u8],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_ntt_batch_air::{NttBatchEval, LOG_N_ROWS as NTT_LOG, n_cols_for as ntt_n_cols_for};
    use mldsa_az_full_air::{AzFullEval, AzFullComponent, LOG_N_ROWS as AZ_LOG, N_COLS as AZ_N_COLS};
    use mldsa_ct1_full_air::{Ct1FullEval, Ct1FullComponent, LOG_N_ROWS as CT1_LOG, N_COLS as CT1_N_COLS};
    use mldsa_intt_batch_air::{InttBatchEval, LOG_N_ROWS as INTT_LOG, n_cols_for as intt_n_cols_for};
    use mldsa_wprime_full_air::{WPrimeFullEval, WPrimeFullComponent, LOG_N_ROWS as WP_LOG, N_COLS as WP_N_COLS};
    use mldsa_norm_check_batch_air::{NormCheckBatchEval, NormCheckBatchComponent, LOG_N_ROWS as NORM_LOG, N_COLS as NORM_N_COLS};
    use mldsa_use_hint_batch_air::{UseHintBatchV2Eval, UseHintBatchV2Component, N_COLS_V2 as UH_N_COLS, pc_is_init_uh};
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::CommitmentSchemeVerifier;
    use stwo::core::verifier::verify;
    use stwo_constraint_framework::TraceLocationAllocator;
    use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

    let l = mldsa::params::L;
    let k = mldsa::params::K;
    let n_ntt_polys  = l + 1 + k;
    let n_intt_polys = 2 * k;

    // ── Recompute fingerprints ────────────────────────────────────────────────
    let mut ntt_out_v: Vec<i64> = Vec::new();
    for p in z_hat   { ntt_out_v.extend_from_slice(p); }
    ntt_out_v.extend_from_slice(c_hat);
    for p in t1_hat  { ntt_out_v.extend_from_slice(p); }
    let ntt_out_fp = output_fingerprint(&ntt_out_v);
    if build_poly_commitment(&ntt_out_fp) != ntt_cm { return Ok(false); }

    let az_flat: Vec<i64>  = az_hat.iter().flat_map(|r| r.iter().copied()).collect();
    let az_out_fp = output_fingerprint(&az_flat);
    if build_poly_commitment(&az_out_fp) != az_cm { return Ok(false); }

    let ct1_flat: Vec<i64> = ct1_hat.iter().flat_map(|r| r.iter().copied()).collect();
    let ct1_out_fp = output_fingerprint(&ct1_flat);
    if build_poly_commitment(&ct1_out_fp) != ct1_cm { return Ok(false); }

    // INTT inputs = az_hat ++ ct1_hat (already checked via az_cm/ct1_cm above).
    let mut intt_inputs: Vec<[i64; mldsa::N]> = az_hat.to_vec();
    intt_inputs.extend_from_slice(ct1_hat);
    let intt_in_fps: Vec<[u32; 4]> = intt_inputs.iter()
        .map(|p| output_fingerprint(p.as_ref()))
        .collect();

    let intt_out_flat: Vec<i64> = az_out.iter().chain(ct1_out.iter())
        .flat_map(|r| r.iter().copied()).collect();
    let intt_out_fp = output_fingerprint(&intt_out_flat);
    if build_poly_commitment(&intt_out_fp) != intt_cm { return Ok(false); }

    let wp_flat: Vec<i64>   = w_prime.iter().flat_map(|r| r.iter().copied()).collect();
    let wp_out_fp = output_fingerprint(&wp_flat);
    if build_poly_commitment(&wp_out_fp) != wp_cm { return Ok(false); }

    let norm_fp = parse_poly_commitment(norm_cm)?;

    let mut uh_flat: Vec<i64> = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    uh_flat.push(hint_weight_total as i64);
    let uh_fp = output_fingerprint(&uh_flat);
    if build_poly_commitment(&uh_fp) != uh_cm { return Ok(false); }

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        ).map_err(|e| format!("deserialization error: {e:?}"))?;

    // Must use make_config(NTT_LOG) to match the prover's lifting_log_size=Some(16).
    // Using PcsConfig::default() would set lifting_log_size=None, causing Tree 0
    // (preprocessed, LOG=8 after blowup=14) to use height=14 while the prover
    // used lifting_log_size=16, resulting in WitnessTooLong errors.
    let config = make_config(NTT_LOG);

    // ── Build components (same allocator order as prover) ─────────────────────
    let pc_ids: Vec<PreProcessedColumnId> = vec![pc_is_init_uh()];
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&pc_ids);
    let ntt_comp = mldsa_ntt_batch_air::NttBatchComponent::new(
        &mut alloc,
        NttBatchEval { log_n_rows: NTT_LOG, n_polys: n_ntt_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let az_comp = AzFullComponent::new(
        &mut alloc,
        AzFullEval { log_n_rows: AZ_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let ct1_comp = Ct1FullComponent::new(
        &mut alloc,
        Ct1FullEval { log_n_rows: CT1_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let intt_comp = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut alloc,
        InttBatchEval { log_n_rows: INTT_LOG, n_polys: n_intt_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let wp_comp = WPrimeFullComponent::new(
        &mut alloc,
        WPrimeFullEval { log_n_rows: WP_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let norm_comp = NormCheckBatchComponent::new(
        &mut alloc,
        NormCheckBatchEval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let uh_comp = UseHintBatchV2Component::new(
        &mut alloc,
        UseHintBatchV2Eval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    // Tree 0: 1 preproc col (is_init_uh) at NORM_LOG=8.
    // Tree 1: [NTT_LOG; ntt_cols] ++ [AZ_LOG; AZ_N_COLS] ++ [CT1_LOG; CT1_N_COLS]
    //      ++ [INTT_LOG; intt_cols] ++ [WP_LOG; WP_N_COLS]
    //      ++ [NORM_LOG; NORM_N_COLS] ++ [NORM_LOG; UH_N_COLS]
    let ntt_n_cols  = ntt_n_cols_for(n_ntt_polys);
    let intt_n_cols = intt_n_cols_for(n_intt_polys);
    let mut tree1_sizes: Vec<u32> = vec![NTT_LOG;  ntt_n_cols];
    tree1_sizes.extend(vec![AZ_LOG;   AZ_N_COLS]);
    tree1_sizes.extend(vec![CT1_LOG;  CT1_N_COLS]);
    tree1_sizes.extend(vec![INTT_LOG; intt_n_cols]);
    tree1_sizes.extend(vec![WP_LOG;   WP_N_COLS]);
    tree1_sizes.extend(vec![NORM_LOG; NORM_N_COLS]);
    tree1_sizes.extend(vec![NORM_LOG; UH_N_COLS]);

    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }

    // Replay transcript (must match prover exactly).
    for seed in [c_tilde_seed, extra_binding] {
        if !seed.is_empty() {
            let words: Vec<u32> = seed.chunks(4).map(|b| {
                let mut arr = [0u8; 4];
                arr[..b.len()].copy_from_slice(b);
                u32::from_le_bytes(arr)
            }).collect();
            verifier_channel.mix_u32s(&words);
        }
    }

    commitment_scheme.commit(proof.commitments[0], &[NORM_LOG; 1], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &tree1_sizes, verifier_channel);

    verifier_channel.mix_u32s(&ntt_out_fp);
    verifier_channel.mix_u32s(&az_out_fp);
    verifier_channel.mix_u32s(&ct1_out_fp);
    for fp in &intt_in_fps {
        verifier_channel.mix_u32s(fp);
    }
    verifier_channel.mix_u32s(&intt_out_fp);
    verifier_channel.mix_u32s(&wp_out_fp);
    verifier_channel.mix_u32s(&norm_fp);
    verifier_channel.mix_u32s(&uh_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&ntt_comp, &az_comp, &ct1_comp, &intt_comp, &wp_comp, &norm_comp, &uh_comp],
        verifier_channel, commitment_scheme, proof,
    ).is_ok())
}

// ─── V23: 8-component combined STARK (V22 + RangeQBatch) ─────────────────────
//
// Extends V22 (7-component) by adding RangeQBatch(LOG=8, 288 cols) as the
// 8th component, proving az_hat[i][p] ∈ [0, Q) for all K output polynomials.
// This closes the primary soundness gap in the AzFull multiplication constraints.
//
// Tree 0: UseHintBatchV2 preprocessed column (is_init_uh, LOG=8, 1 col)
// Tree 1: 3216 main cols (V22) + 288 RangeQ cols = 3504 total main columns
// Total: 3504 main + 1 preproc = 3505 columns.
//
// No new transcript fingerprint — az_hat is already bound via az_out_fp.

/// Prove the 8-component V23 ML-DSA.Verify STARK (V22 + RangeQBatch).
#[allow(clippy::too_many_arguments)]
pub fn prove_full_mldsa_witness_v23(
    z:             &[[i64; mldsa::N]; mldsa::params::L],
    c:             &[i64; mldsa::N],
    t1:            &[[i64; mldsa::N]; mldsa::params::K],
    a_hat:         &[[i64; mldsa::N]],
    hints:         &[[bool; mldsa::N]; mldsa::params::K],
    c_tilde_seed:  &[u8],
    extra_binding: &[u8],
) -> Result<(
    Vec<u8>,
    String, String, String, String, String, String, String,
    Vec<[i64; mldsa::N]>, [i64; mldsa::N], Vec<[i64; mldsa::N]>,
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
    [i64; mldsa::params::L],
    [[i64; mldsa::N]; mldsa::params::K],
    usize,
), String> {
    use mldsa_range_q_batch_air::{
        RangeQBatchEval, RangeQBatchComponent,
        LOG_N_ROWS as RQ_LOG, N_COLS as RQ_N_COLS, build_trace as rq_build_trace,
    };
    use mldsa_ntt_batch_air::{
        NttBatchEval, LOG_N_ROWS as NTT_LOG, n_cols_for as ntt_n_cols_for,
        build_trace as ntt_build_trace,
    };
    use mldsa_az_full_air::{
        AzFullEval, AzFullComponent,
        LOG_N_ROWS as AZ_LOG, N_COLS as AZ_N_COLS, build_trace as az_build_trace,
    };
    use mldsa_ct1_full_air::{
        Ct1FullEval, Ct1FullComponent,
        LOG_N_ROWS as CT1_LOG, N_COLS as CT1_N_COLS, build_trace as ct1_build_trace,
    };
    use mldsa_intt_batch_air::{
        InttBatchEval, LOG_N_ROWS as INTT_LOG, n_cols_for as intt_n_cols_for,
        build_trace as intt_build_trace,
    };
    use mldsa_wprime_full_air::{
        WPrimeFullEval, WPrimeFullComponent,
        LOG_N_ROWS as WP_LOG, N_COLS as WP_N_COLS, build_trace as wp_build_trace,
    };
    use mldsa_norm_check_batch_air::{
        NormCheckBatchEval, NormCheckBatchComponent,
        LOG_N_ROWS as NORM_LOG, N_COLS as NORM_N_COLS, build_trace as norm_build_trace,
    };
    use mldsa_use_hint_batch_air::{
        UseHintBatchV2Eval, UseHintBatchV2Component,
        N_COLS_V2 as UH_N_COLS, build_trace_v2, pc_is_init_uh,
    };
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;
    use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

    let l = mldsa::params::L;
    let k = mldsa::params::K;

    if a_hat.len() != k * l {
        return Err(format!("a_hat must have k*l={} entries, got {}", k * l, a_hat.len()));
    }

    // ── Step 1: NTT(z, c, t1) ────────────────────────────────────────────────
    let n_ntt_polys = l + 1 + k;
    let mut ntt_inputs: Vec<[i64; mldsa::N]> = Vec::with_capacity(n_ntt_polys);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);
    let (ntt_cols, ntt_outputs) = ntt_build_trace(&ntt_inputs);

    let z_hat:  Vec<[i64; mldsa::N]> = ntt_outputs[0..l].to_vec();
    let c_hat:  [i64; mldsa::N]      = ntt_outputs[l];
    let t1_hat: Vec<[i64; mldsa::N]> = ntt_outputs[l + 1..l + 1 + k].to_vec();

    // ── Step 2: Az and Ct1 in NTT domain ─────────────────────────────────────
    let z_hat_arr: [[i64; mldsa::N]; mldsa::params::L] = z_hat.as_slice().try_into()
        .map_err(|_| "z_hat must have L entries".to_string())?;
    let t1_hat_arr: [[i64; mldsa::N]; mldsa::params::K] = t1_hat.as_slice().try_into()
        .map_err(|_| "t1_hat must have K entries".to_string())?;

    let (az_cols,  az_hat)  = az_build_trace(a_hat, &z_hat_arr);
    let (ct1_cols, ct1_hat) = ct1_build_trace(&c_hat, &t1_hat_arr);

    // ── Step 2b: RangeQ trace for az_hat (proves az_hat ∈ [0, Q)) ────────────
    let (rq_cols, rq_valid) = rq_build_trace(&az_hat);
    if !rq_valid {
        return Err("RangeQBatch: az_hat contains values outside [0, Q)".to_string());
    }

    // ── Step 3: INTT(az_hat, ct1_hat) ────────────────────────────────────────
    let n_intt_polys = 2 * k;
    let mut intt_inputs: Vec<[i64; mldsa::N]> = Vec::with_capacity(n_intt_polys);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, intt_out) = intt_build_trace(&intt_inputs);

    let az_out:  [[i64; mldsa::N]; mldsa::params::K] = intt_out[..k].try_into()
        .map_err(|_| "az_out slice err".to_string())?;
    let ct1_out: [[i64; mldsa::N]; mldsa::params::K] = intt_out[k..].try_into()
        .map_err(|_| "ct1_out slice err".to_string())?;

    // ── Step 4: WPrime, NormCheck, UseHint ───────────────────────────────────
    let (wp_cols,   w_prime)                          = wp_build_trace(&az_out, &ct1_out);
    let (norm_cols, norm_out, max_norms)              = norm_build_trace(z);
    let (uh_main_cols, uh_preproc_cols, w1_out, hint_weight_total) =
        build_trace_v2(&w_prime, hints);

    // Column-count assertions.
    debug_assert_eq!(ntt_cols.len(),      ntt_n_cols_for(n_ntt_polys));
    debug_assert_eq!(az_cols.len(),       AZ_N_COLS);
    debug_assert_eq!(ct1_cols.len(),      CT1_N_COLS);
    debug_assert_eq!(intt_cols.len(),     intt_n_cols_for(n_intt_polys));
    debug_assert_eq!(wp_cols.len(),       WP_N_COLS);
    debug_assert_eq!(norm_cols.len(),     NORM_N_COLS);
    debug_assert_eq!(uh_main_cols.len(),  UH_N_COLS);
    debug_assert_eq!(rq_cols.len(),       RQ_N_COLS);

    // ── Fingerprints ──────────────────────────────────────────────────────────
    let ntt_out_flat: Vec<i64> = ntt_outputs.iter().flat_map(|p| p.iter().copied()).collect();
    let ntt_out_fp   = output_fingerprint(&ntt_out_flat);
    let ntt_cm       = build_poly_commitment(&ntt_out_fp);

    let az_out_flat: Vec<i64>  = az_hat.iter().flat_map(|r| r.iter().copied()).collect();
    let az_out_fp    = output_fingerprint(&az_out_flat);
    let az_cm        = build_poly_commitment(&az_out_fp);

    let ct1_out_flat: Vec<i64> = ct1_hat.iter().flat_map(|r| r.iter().copied()).collect();
    let ct1_out_fp   = output_fingerprint(&ct1_out_flat);
    let ct1_cm       = build_poly_commitment(&ct1_out_fp);

    let intt_in_fps: Vec<[u32; 4]> = intt_inputs.iter()
        .map(|p| output_fingerprint(p.as_ref()))
        .collect();
    let intt_out_flat2: Vec<i64> = intt_out.iter().flat_map(|p| p.iter().copied()).collect();
    let intt_out_fp  = output_fingerprint(&intt_out_flat2);
    let intt_cm      = build_poly_commitment(&intt_out_fp);

    let wp_out_flat: Vec<i64>   = w_prime.iter().flat_map(|r| r.iter().copied()).collect();
    let wp_out_fp    = output_fingerprint(&wp_out_flat);
    let wp_cm        = build_poly_commitment(&wp_out_fp);

    let norm_flat: Vec<i64>     = norm_out.iter().flat_map(|r| r.iter().copied()).collect();
    let norm_fp      = output_fingerprint(&norm_flat);
    let norm_cm      = build_poly_commitment(&norm_fp);

    let mut uh_flat: Vec<i64>   = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    uh_flat.push(hint_weight_total as i64);
    let uh_fp        = output_fingerprint(&uh_flat);
    let uh_cm        = build_poly_commitment(&uh_fp);

    // ── STARK setup ───────────────────────────────────────────────────────────
    let max_log = NTT_LOG;
    let config   = make_config(max_log);
    let lifting  = max_log + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    for seed in [c_tilde_seed, extra_binding] {
        if !seed.is_empty() {
            let words: Vec<u32> = seed.chunks(4).map(|b| {
                let mut arr = [0u8; 4];
                arr[..b.len()].copy_from_slice(b);
                u32::from_le_bytes(arr)
            }).collect();
            channel.mix_u32s(&words);
        }
    }

    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: UseHintBatchV2 preprocessed column (is_init_uh, LOG=8).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(uh_preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: 8 components, total 3504 main columns.
    //  [10;649] ++ [8;1523] ++ [8;295] ++ [10;649] ++ [8;24] ++ [8;15] ++ [8;61] ++ [8;288]
    let mut combined_main = ntt_cols;
    combined_main.extend(az_cols);
    combined_main.extend(ct1_cols);
    combined_main.extend(intt_cols);
    combined_main.extend(wp_cols);
    combined_main.extend(norm_cols);
    combined_main.extend(uh_main_cols);
    combined_main.extend(rq_cols);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(combined_main);
    tree_builder.commit(channel);

    // Transcript fingerprints (bind all inter-component data flows).
    // RangeQBatch has no new output data — az_hat already bound via az_out_fp.
    channel.mix_u32s(&ntt_out_fp);
    channel.mix_u32s(&az_out_fp);
    channel.mix_u32s(&ct1_out_fp);
    for fp in &intt_in_fps {
        channel.mix_u32s(fp);
    }
    channel.mix_u32s(&intt_out_fp);
    channel.mix_u32s(&wp_out_fp);
    channel.mix_u32s(&norm_fp);
    channel.mix_u32s(&uh_fp);

    // ── Components ────────────────────────────────────────────────────────────
    let pc_ids: Vec<PreProcessedColumnId> = vec![pc_is_init_uh()];
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&pc_ids);
    let ntt_comp = mldsa_ntt_batch_air::NttBatchComponent::new(
        &mut alloc,
        NttBatchEval { log_n_rows: NTT_LOG, n_polys: n_ntt_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let az_comp = AzFullComponent::new(
        &mut alloc,
        AzFullEval { log_n_rows: AZ_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let ct1_comp = Ct1FullComponent::new(
        &mut alloc,
        Ct1FullEval { log_n_rows: CT1_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let intt_comp = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut alloc,
        InttBatchEval { log_n_rows: INTT_LOG, n_polys: n_intt_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let wp_comp = WPrimeFullComponent::new(
        &mut alloc,
        WPrimeFullEval { log_n_rows: WP_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let norm_comp = NormCheckBatchComponent::new(
        &mut alloc,
        NormCheckBatchEval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let uh_comp = UseHintBatchV2Component::new(
        &mut alloc,
        UseHintBatchV2Eval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let rq_comp = RangeQBatchComponent::new(
        &mut alloc,
        RangeQBatchEval { log_n_rows: RQ_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&ntt_comp, &az_comp, &ct1_comp, &intt_comp, &wp_comp, &norm_comp, &uh_comp, &rq_comp],
        channel, commitment_scheme,
    ).map_err(|e| format!("prove_full_mldsa_witness_v23 error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes,
        ntt_cm, az_cm, ct1_cm, intt_cm, wp_cm, norm_cm, uh_cm,
        z_hat, c_hat, t1_hat,
        az_hat, ct1_hat,
        az_out, ct1_out,
        w_prime, max_norms, w1_out,
        hint_weight_total))
}

/// Verify a combined 8-component ML-DSA.Verify witness proof (V23).
#[allow(clippy::too_many_arguments)]
pub fn verify_full_mldsa_witness_v23(
    proof_bytes:       &[u8],
    ntt_cm:            &str,
    az_cm:             &str,
    ct1_cm:            &str,
    intt_cm:           &str,
    wp_cm:             &str,
    norm_cm:           &str,
    uh_cm:             &str,
    _z:                &[[i64; mldsa::N]; mldsa::params::L],
    _c:                &[i64; mldsa::N],
    _t1:               &[[i64; mldsa::N]; mldsa::params::K],
    z_hat:             &[[i64; mldsa::N]],
    c_hat:             &[i64; mldsa::N],
    t1_hat:            &[[i64; mldsa::N]],
    az_hat:            &[[i64; mldsa::N]; mldsa::params::K],
    ct1_hat:           &[[i64; mldsa::N]; mldsa::params::K],
    az_out:            &[[i64; mldsa::N]; mldsa::params::K],
    ct1_out:           &[[i64; mldsa::N]; mldsa::params::K],
    w_prime:           &[[i64; mldsa::N]; mldsa::params::K],
    w1_out:            &[[i64; mldsa::N]; mldsa::params::K],
    hint_weight_total: usize,
    c_tilde_seed:      &[u8],
    extra_binding:     &[u8],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_range_q_batch_air::{
        RangeQBatchEval, RangeQBatchComponent, LOG_N_ROWS as RQ_LOG, N_COLS as RQ_N_COLS,
    };
    use mldsa_ntt_batch_air::{NttBatchEval, LOG_N_ROWS as NTT_LOG, n_cols_for as ntt_n_cols_for};
    use mldsa_az_full_air::{AzFullEval, AzFullComponent, LOG_N_ROWS as AZ_LOG, N_COLS as AZ_N_COLS};
    use mldsa_ct1_full_air::{Ct1FullEval, Ct1FullComponent, LOG_N_ROWS as CT1_LOG, N_COLS as CT1_N_COLS};
    use mldsa_intt_batch_air::{InttBatchEval, LOG_N_ROWS as INTT_LOG, n_cols_for as intt_n_cols_for};
    use mldsa_wprime_full_air::{WPrimeFullEval, WPrimeFullComponent, LOG_N_ROWS as WP_LOG, N_COLS as WP_N_COLS};
    use mldsa_norm_check_batch_air::{NormCheckBatchEval, NormCheckBatchComponent, LOG_N_ROWS as NORM_LOG, N_COLS as NORM_N_COLS};
    use mldsa_use_hint_batch_air::{UseHintBatchV2Eval, UseHintBatchV2Component, N_COLS_V2 as UH_N_COLS, pc_is_init_uh};
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::CommitmentSchemeVerifier;
    use stwo::core::verifier::verify;
    use stwo_constraint_framework::TraceLocationAllocator;
    use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

    let l = mldsa::params::L;
    let k = mldsa::params::K;
    let n_ntt_polys  = l + 1 + k;
    let n_intt_polys = 2 * k;

    // ── Recompute fingerprints ────────────────────────────────────────────────
    let mut ntt_out_v: Vec<i64> = Vec::new();
    for p in z_hat   { ntt_out_v.extend_from_slice(p); }
    ntt_out_v.extend_from_slice(c_hat);
    for p in t1_hat  { ntt_out_v.extend_from_slice(p); }
    let ntt_out_fp = output_fingerprint(&ntt_out_v);
    if build_poly_commitment(&ntt_out_fp) != ntt_cm { return Ok(false); }

    let az_flat: Vec<i64>  = az_hat.iter().flat_map(|r| r.iter().copied()).collect();
    let az_out_fp = output_fingerprint(&az_flat);
    if build_poly_commitment(&az_out_fp) != az_cm { return Ok(false); }

    let ct1_flat: Vec<i64> = ct1_hat.iter().flat_map(|r| r.iter().copied()).collect();
    let ct1_out_fp = output_fingerprint(&ct1_flat);
    if build_poly_commitment(&ct1_out_fp) != ct1_cm { return Ok(false); }

    let mut intt_inputs: Vec<[i64; mldsa::N]> = az_hat.to_vec();
    intt_inputs.extend_from_slice(ct1_hat);
    let intt_in_fps: Vec<[u32; 4]> = intt_inputs.iter()
        .map(|p| output_fingerprint(p.as_ref()))
        .collect();

    let intt_out_flat: Vec<i64> = az_out.iter().chain(ct1_out.iter())
        .flat_map(|r| r.iter().copied()).collect();
    let intt_out_fp = output_fingerprint(&intt_out_flat);
    if build_poly_commitment(&intt_out_fp) != intt_cm { return Ok(false); }

    let wp_flat: Vec<i64>   = w_prime.iter().flat_map(|r| r.iter().copied()).collect();
    let wp_out_fp = output_fingerprint(&wp_flat);
    if build_poly_commitment(&wp_out_fp) != wp_cm { return Ok(false); }

    let norm_fp = parse_poly_commitment(norm_cm)?;

    let mut uh_flat: Vec<i64> = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    uh_flat.push(hint_weight_total as i64);
    let uh_fp = output_fingerprint(&uh_flat);
    if build_poly_commitment(&uh_fp) != uh_cm { return Ok(false); }

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        ).map_err(|e| format!("deserialization error: {e:?}"))?;

    // Must use make_config(NTT_LOG) to match the prover's lifting_log_size=Some(16).
    let config = make_config(NTT_LOG);

    // ── Build components (same allocator order as prover) ─────────────────────
    let pc_ids: Vec<PreProcessedColumnId> = vec![pc_is_init_uh()];
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&pc_ids);
    let ntt_comp = mldsa_ntt_batch_air::NttBatchComponent::new(
        &mut alloc,
        NttBatchEval { log_n_rows: NTT_LOG, n_polys: n_ntt_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let az_comp = AzFullComponent::new(
        &mut alloc,
        AzFullEval { log_n_rows: AZ_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let ct1_comp = Ct1FullComponent::new(
        &mut alloc,
        Ct1FullEval { log_n_rows: CT1_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let intt_comp = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut alloc,
        InttBatchEval { log_n_rows: INTT_LOG, n_polys: n_intt_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let wp_comp = WPrimeFullComponent::new(
        &mut alloc,
        WPrimeFullEval { log_n_rows: WP_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let norm_comp = NormCheckBatchComponent::new(
        &mut alloc,
        NormCheckBatchEval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let uh_comp = UseHintBatchV2Component::new(
        &mut alloc,
        UseHintBatchV2Eval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let rq_comp = RangeQBatchComponent::new(
        &mut alloc,
        RangeQBatchEval { log_n_rows: RQ_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    // Tree 0: 1 preproc col (is_init_uh) at NORM_LOG=8.
    // Tree 1: [NTT_LOG; ntt_cols] ++ [AZ_LOG; AZ_N_COLS] ++ [CT1_LOG; CT1_N_COLS]
    //      ++ [INTT_LOG; intt_cols] ++ [WP_LOG; WP_N_COLS]
    //      ++ [NORM_LOG; NORM_N_COLS] ++ [NORM_LOG; UH_N_COLS] ++ [RQ_LOG; RQ_N_COLS]
    let ntt_n_cols  = ntt_n_cols_for(n_ntt_polys);
    let intt_n_cols = intt_n_cols_for(n_intt_polys);
    let mut tree1_sizes: Vec<u32> = vec![NTT_LOG;  ntt_n_cols];
    tree1_sizes.extend(vec![AZ_LOG;   AZ_N_COLS]);
    tree1_sizes.extend(vec![CT1_LOG;  CT1_N_COLS]);
    tree1_sizes.extend(vec![INTT_LOG; intt_n_cols]);
    tree1_sizes.extend(vec![WP_LOG;   WP_N_COLS]);
    tree1_sizes.extend(vec![NORM_LOG; NORM_N_COLS]);
    tree1_sizes.extend(vec![NORM_LOG; UH_N_COLS]);
    tree1_sizes.extend(vec![RQ_LOG;   RQ_N_COLS]);

    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }

    // Replay transcript (must match prover exactly).
    for seed in [c_tilde_seed, extra_binding] {
        if !seed.is_empty() {
            let words: Vec<u32> = seed.chunks(4).map(|b| {
                let mut arr = [0u8; 4];
                arr[..b.len()].copy_from_slice(b);
                u32::from_le_bytes(arr)
            }).collect();
            verifier_channel.mix_u32s(&words);
        }
    }

    commitment_scheme.commit(proof.commitments[0], &[NORM_LOG; 1], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &tree1_sizes, verifier_channel);

    verifier_channel.mix_u32s(&ntt_out_fp);
    verifier_channel.mix_u32s(&az_out_fp);
    verifier_channel.mix_u32s(&ct1_out_fp);
    for fp in &intt_in_fps {
        verifier_channel.mix_u32s(fp);
    }
    verifier_channel.mix_u32s(&intt_out_fp);
    verifier_channel.mix_u32s(&wp_out_fp);
    verifier_channel.mix_u32s(&norm_fp);
    verifier_channel.mix_u32s(&uh_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&ntt_comp, &az_comp, &ct1_comp, &intt_comp, &wp_comp, &norm_comp, &uh_comp, &rq_comp],
        verifier_channel, commitment_scheme, proof,
    ).is_ok())
}

// ─── Combined INTT+WPrime+NormCheck+UseHintBatchV2 STARK (MVP-3+, V20) ────────
//
// Merges InttWPrimeProofV18 + NormUseHintProofV17 (2 sub-proofs) into one
// 4-component mixed-size STARK.  Combined with AllNttAzCt1ProofV19 this gives
// 2 total sub-proofs for the full ML-DSA.Verify witness.
//
// Tree 0: UseHintBatchV2 preprocessed column (is_init_uh, LOG=8, 1 col)
// Tree 1 column layout:
//   InttBatch (LOG=10, 649 cols) ++ WPrime (LOG=8, 24 cols)
//   ++ NormCheckBatch (LOG=8, 15 cols) ++ UseHintBatchV2 (LOG=8, 61 cols)
//   = 749 total main columns
// Twiddles at LOG=10+4+1=15.

/// Prove INTT-batch, WPrime, NormCheck, and UseHintBatchV2 in ONE STARK.
///
/// Returns `(proof_bytes, intt_cm, wp_cm, norm_cm, uh_cm,
///           az_out, ct1_out, w_prime, max_norms, w1_out, hint_weight_total)`.
pub fn prove_intt_wprime_norm_use_hint_combined(
    az_hat: &[[i64; mldsa::N]; mldsa::params::K],
    ct1_hat: &[[i64; mldsa::N]; mldsa::params::K],
    z:       &[[i64; mldsa::N]; mldsa::params::L],
    hints:   &[[bool; mldsa::N]; mldsa::params::K],
) -> Result<(
    Vec<u8>, String, String, String, String,
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
    [[i64; mldsa::N]; mldsa::params::K],
    [i64; mldsa::params::L],
    [[i64; mldsa::N]; mldsa::params::K],
    usize,
), String> {
    use mldsa_intt_batch_air::{
        InttBatchEval, LOG_N_ROWS as INTT_LOG, n_cols_for as intt_n_cols_for,
        build_trace as intt_build_trace,
    };
    use mldsa_wprime_full_air::{
        WPrimeFullEval, WPrimeFullComponent,
        LOG_N_ROWS as WP_LOG, N_COLS as WP_N_COLS, build_trace as wp_build_trace,
    };
    use mldsa_norm_check_batch_air::{
        NormCheckBatchEval, NormCheckBatchComponent,
        LOG_N_ROWS as NORM_LOG, N_COLS as NORM_N_COLS, build_trace as norm_build_trace,
    };
    use mldsa_use_hint_batch_air::{
        UseHintBatchV2Eval, UseHintBatchV2Component,
        N_COLS_V2 as UH_N_COLS, build_trace_v2, pc_is_init_uh,
    };
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;
    use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

    let k = mldsa::params::K;
    let n_polys = 2 * k; // 12 for ML-DSA-65

    // Build INTT trace for az_hat ++ ct1_hat.
    let mut all_inputs: Vec<[i64; mldsa::N]> = Vec::with_capacity(n_polys);
    all_inputs.extend_from_slice(az_hat);
    all_inputs.extend_from_slice(ct1_hat);
    let (intt_cols, intt_out) = intt_build_trace(&all_inputs);

    let az_out:  [[i64; mldsa::N]; mldsa::params::K] = intt_out[..k].try_into().map_err(|_| "az slice err".to_string())?;
    let ct1_out: [[i64; mldsa::N]; mldsa::params::K] = intt_out[k..].try_into().map_err(|_| "ct1 slice err".to_string())?;

    // Build WPrime trace from INTT outputs.
    let (wp_cols, w_prime_out) = wp_build_trace(&az_out, &ct1_out);

    // Build NormCheck trace from z.
    let (norm_cols, norm_out, max_norms) = norm_build_trace(z);

    // Build UseHint trace from w_prime and hints.
    let (uh_main_cols, uh_preproc_cols, w1_out, hint_weight_total) = build_trace_v2(&w_prime_out, hints);

    let intt_n_cols = intt_n_cols_for(n_polys);
    debug_assert_eq!(intt_cols.len(), intt_n_cols);
    debug_assert_eq!(wp_cols.len(), WP_N_COLS);
    debug_assert_eq!(norm_cols.len(), NORM_N_COLS);
    debug_assert_eq!(uh_main_cols.len(), UH_N_COLS);

    // INTT output = WPrime input (shared cross-link fingerprint).
    let intt_out_flat: Vec<i64> = intt_out.iter().flat_map(|p| p.iter().copied()).collect();
    let intt_out_fp   = output_fingerprint(&intt_out_flat);
    let intt_cm       = build_poly_commitment(&intt_out_fp);

    let wp_out_flat: Vec<i64> = w_prime_out.iter().flat_map(|r| r.iter().copied()).collect();
    let wp_out_fp   = output_fingerprint(&wp_out_flat);
    let wp_cm       = build_poly_commitment(&wp_out_fp);

    let norm_flat: Vec<i64> = norm_out.iter().flat_map(|r| r.iter().copied()).collect();
    let norm_fp    = output_fingerprint(&norm_flat);
    let norm_cm    = build_poly_commitment(&norm_fp);

    let mut uh_flat: Vec<i64> = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    uh_flat.push(hint_weight_total as i64);
    let uh_fp  = output_fingerprint(&uh_flat);
    let uh_cm  = build_poly_commitment(&uh_fp);

    // Twiddles at INTT level (max of the four components).
    let max_log = INTT_LOG; // 10 > WP_LOG=NORM_LOG=UH_LOG=8
    let config  = make_config(max_log);
    let lifting = max_log + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: UseHintBatchV2 preprocessed column (is_init_uh, LOG=8).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(uh_preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: intt(649,log=10) ++ wp(24,log=8) ++ norm(15,log=8) ++ uh(61,log=8) = 749.
    let mut combined_main = intt_cols;
    combined_main.extend(wp_cols);
    combined_main.extend(norm_cols);
    combined_main.extend(uh_main_cols);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(combined_main);
    tree_builder.commit(channel);

    // Transcript: per-input INTT fps, shared INTT→WPrime fp, WPrime out, Norm out, UH out.
    for poly in all_inputs.iter() {
        channel.mix_u32s(&output_fingerprint(poly));
    }
    channel.mix_u32s(&intt_out_fp);  // = wp_in_fp (INTT out = WPrime in, shared once)
    channel.mix_u32s(&wp_out_fp);
    channel.mix_u32s(&norm_fp);
    channel.mix_u32s(&uh_fp);

    // Shared allocator with is_init_uh registered (needed by UseHintBatchV2).
    let pc_ids: Vec<PreProcessedColumnId> = vec![pc_is_init_uh()];
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&pc_ids);
    let intt_comp = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut alloc,
        InttBatchEval { log_n_rows: INTT_LOG, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let wp_comp = WPrimeFullComponent::new(
        &mut alloc,
        WPrimeFullEval { log_n_rows: WP_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let norm_comp = NormCheckBatchComponent::new(
        &mut alloc,
        NormCheckBatchEval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let uh_comp = UseHintBatchV2Component::new(
        &mut alloc,
        UseHintBatchV2Eval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&intt_comp, &wp_comp, &norm_comp, &uh_comp], channel, commitment_scheme,
    ).map_err(|e| format!("prove_intt_wprime_norm_use_hint_combined error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, intt_cm, wp_cm, norm_cm, uh_cm,
        az_out, ct1_out, w_prime_out, max_norms, w1_out, hint_weight_total))
}

/// Verify a combined INTT+WPrime+NormCheck+UseHintBatchV2 proof.
pub fn verify_intt_wprime_norm_use_hint_combined(
    proof_bytes:       &[u8],
    intt_cm:           &str,
    wp_cm:             &str,
    norm_cm:           &str,
    uh_cm:             &str,
    az_hat:            &[[i64; mldsa::N]; mldsa::params::K],
    ct1_hat:           &[[i64; mldsa::N]; mldsa::params::K],
    az_out:            &[[i64; mldsa::N]; mldsa::params::K],
    ct1_out:           &[[i64; mldsa::N]; mldsa::params::K],
    w_prime:           &[[i64; mldsa::N]; mldsa::params::K],
    w1_out:            &[[i64; mldsa::N]; mldsa::params::K],
    hint_weight_total: usize,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_intt_batch_air::{
        InttBatchEval, LOG_N_ROWS as INTT_LOG, n_cols_for as intt_n_cols_for,
    };
    use mldsa_wprime_full_air::{
        WPrimeFullEval, WPrimeFullComponent,
        LOG_N_ROWS as WP_LOG, N_COLS as WP_N_COLS,
    };
    use mldsa_norm_check_batch_air::{
        NormCheckBatchEval, NormCheckBatchComponent,
        LOG_N_ROWS as NORM_LOG, N_COLS as NORM_N_COLS,
    };
    use mldsa_use_hint_batch_air::{
        UseHintBatchV2Eval, UseHintBatchV2Component,
        N_COLS_V2 as UH_N_COLS, pc_is_init_uh,
    };
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::CommitmentSchemeVerifier;
    use stwo::core::verifier::verify;
    use stwo_constraint_framework::TraceLocationAllocator;
    use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

    let k = mldsa::params::K;
    let n_polys = 2 * k;

    // Recompute INTT output fingerprint from az_out ++ ct1_out.
    let intt_out_flat: Vec<i64> = az_out.iter().chain(ct1_out.iter()).flat_map(|r| r.iter().copied()).collect();
    let intt_out_fp = output_fingerprint(&intt_out_flat);
    if build_poly_commitment(&intt_out_fp) != intt_cm { return Ok(false); }

    // Recompute WPrime output fingerprint.
    let wp_out_flat: Vec<i64> = w_prime.iter().flat_map(|r| r.iter().copied()).collect();
    let wp_out_fp = output_fingerprint(&wp_out_flat);
    if build_poly_commitment(&wp_out_fp) != wp_cm { return Ok(false); }

    // Norm commitment check (parse from stored cm).
    let norm_fp = parse_poly_commitment(norm_cm)?;

    // UseHint commitment check.
    let mut uh_flat: Vec<i64> = w1_out.iter().flat_map(|r| r.iter().copied()).collect();
    uh_flat.push(hint_weight_total as i64);
    let uh_fp = output_fingerprint(&uh_flat);
    if build_poly_commitment(&uh_fp) != uh_cm { return Ok(false); }

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("deserialization error: {e:?}"))?;

    // Must use make_config(INTT_LOG) to match the prover's lifting_log_size=Some(16).
    let config = make_config(INTT_LOG);

    let pc_ids: Vec<PreProcessedColumnId> = vec![pc_is_init_uh()];
    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&pc_ids);
    let intt_comp = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut alloc,
        InttBatchEval { log_n_rows: INTT_LOG, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let wp_comp = WPrimeFullComponent::new(
        &mut alloc,
        WPrimeFullEval { log_n_rows: WP_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let norm_comp = NormCheckBatchComponent::new(
        &mut alloc,
        NormCheckBatchEval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let uh_comp = UseHintBatchV2Component::new(
        &mut alloc,
        UseHintBatchV2Eval { log_n_rows: NORM_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    // Tree 0: 1 preproc col (is_init_uh) at NORM_LOG=8.
    // Tree 1: [INTT_LOG; intt_n_cols] ++ [WP_LOG; WP_N_COLS] ++ [NORM_LOG; NORM_N_COLS] ++ [NORM_LOG; UH_N_COLS].
    let intt_n_cols = intt_n_cols_for(n_polys);
    let mut tree1_sizes: Vec<u32> = vec![INTT_LOG; intt_n_cols];
    tree1_sizes.extend(vec![WP_LOG; WP_N_COLS]);
    tree1_sizes.extend(vec![NORM_LOG; NORM_N_COLS]);
    tree1_sizes.extend(vec![NORM_LOG; UH_N_COLS]);

    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &[NORM_LOG; 1], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &tree1_sizes, verifier_channel);

    // Replay transcript.
    let mut all_inputs: Vec<[i64; mldsa::N]> = az_hat.to_vec();
    all_inputs.extend_from_slice(ct1_hat);
    for poly in all_inputs.iter() {
        verifier_channel.mix_u32s(&output_fingerprint(poly));
    }
    verifier_channel.mix_u32s(&intt_out_fp);
    verifier_channel.mix_u32s(&wp_out_fp);
    verifier_channel.mix_u32s(&norm_fp);
    verifier_channel.mix_u32s(&uh_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&intt_comp, &wp_comp, &norm_comp, &uh_comp],
        verifier_channel, commitment_scheme, proof,
    ).is_ok())
}

/// Verify a UseHint-batch proof produced by [`prove_use_hint_batch`].
pub fn verify_use_hint_batch(
    proof_bytes:    &[u8],
    commitment_hex: &str,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_use_hint_batch_air::{UseHintBatchEval, UseHintBatchComponent, LOG_N_ROWS};
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;

    let output_fp = parse_poly_commitment(commitment_hex)?;
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

    let component = UseHintBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        UseHintBatchEval { log_n_rows: LOG_N_ROWS },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&output_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Q-range check STARK (MVP-3+) ────────────────────────────────────────────

/// Prove that all N=256 coefficients of `poly` are in [0, Q).
///
/// Uses a 23-bit decomposition circuit: for each v, also proves d = Q-1-v has a
/// 23-bit decomposition, which together prove v ∈ [0, Q) exactly.
///
/// Returns `(proof_bytes, commitment_hex)`.  The verifier does not need the input
/// polynomial — the proof is self-contained.
pub fn prove_range_q(poly: &[i64; mldsa::N]) -> Result<(Vec<u8>, String), String> {
    use range_check_air::{LOG_N_ROWS, build_trace};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};

    let (columns, valid) = build_trace(poly);
    if !valid {
        return Err("prove_range_q: one or more coefficients are outside [0, Q)".to_string());
    }

    let log_size = LOG_N_ROWS;
    let input_fp = output_fingerprint(poly);
    let commitment = build_poly_commitment(&input_fp);

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
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    channel.mix_u32s(&input_fp);

    let component = range_check_air::new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("prove_range_q: proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("prove_range_q: serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment))
}

/// Verify a Q-range proof produced by [`prove_range_q`].
///
/// The `commitment_hex` must match the one returned by the prover.
pub fn verify_range_q(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use range_check_air::LOG_N_ROWS;
    use stwo::core::proof::StarkProof;
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;

    let log_size = LOG_N_ROWS;
    let fp = parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("verify_range_q: deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let component = range_check_air::new_component(log_size);
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("verify_range_q: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Batch range-Q STARK (MVP-3+) ────────────────────────────────────────────

/// Prove that all K=6 polynomial outputs lie in [0, Q) in one compact STARK.
///
/// Replaces K individual `prove_range_q` calls with one 288-column proof.
/// Returns `(proof_bytes, commitment_hex)`.
pub fn prove_range_q_batch(polys: &[[i64; mldsa::N]; mldsa::params::K]) -> Result<(Vec<u8>, String), String> {
    use mldsa_range_q_batch_air::{LOG_N_ROWS, build_trace};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};

    let (columns, valid) = build_trace(polys);
    if !valid {
        return Err("prove_range_q_batch: some coefficient is outside [0, Q)".to_string());
    }

    // Commitment fingerprints all K input polynomials concatenated.
    let mut flat: Vec<i64> = Vec::with_capacity(mldsa::params::K * mldsa::N);
    for p in polys.iter() { flat.extend_from_slice(p); }
    let input_fp = output_fingerprint(&flat);
    let commitment = build_poly_commitment(&input_fp);

    let log_size = LOG_N_ROWS;
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
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(columns);
    tree_builder.commit(channel);

    channel.mix_u32s(&input_fp);

    let component = mldsa_range_q_batch_air::new_component(log_size);
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("prove_range_q_batch: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("prove_range_q_batch: serialize error: {e:?}"))?;

    Ok((proof_bytes, commitment))
}

/// Verify a batch range-Q proof produced by [`prove_range_q_batch`].
pub fn verify_range_q_batch(proof_bytes: &[u8], commitment_hex: &str) -> Result<bool, String> {
    use mldsa_range_q_batch_air::LOG_N_ROWS;
    use stwo::core::proof::StarkProof;
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;

    let log_size = LOG_N_ROWS;
    let fp = parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("verify_range_q_batch: deserialize error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let component = mldsa_range_q_batch_air::new_component(log_size);
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("verify_range_q_batch: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verifier_channel.mix_u32s(&fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Batch INTT STARK (MVP-3+) ───────────────────────────────────────────────

/// Prove K=6 inverse NTTs in one batch STARK (325 columns, 1024 rows).
///
/// All K polynomials share the same GS butterfly sequence and twiddle factors,
/// so a single `zeta_inv` column is sufficient for the batch.
///
/// The Fiat-Shamir transcript binds to all K inputs (mixed in order) and then
/// to the concatenated output fingerprint, so the proof is valid only for the
/// exact set of input polynomials supplied.
///
/// Returns `(proof_bytes, commitment_hex, outputs)`.  `commitment_hex`
/// fingerprints all K INTT outputs concatenated (same scheme as `prove_az_full`).
pub fn prove_intt_batch(
    polys: &[[i64; mldsa::N]; mldsa::params::K],
) -> Result<(Vec<u8>, String, [[i64; mldsa::N]; mldsa::params::K]), String> {
    use mldsa_intt_batch_air::{InttBatchEval, LOG_N_ROWS, build_trace as intt_batch_trace};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    let n_polys = mldsa::params::K;

    for (j, poly) in polys.iter().enumerate() {
        for (i, &c) in poly.iter().enumerate() {
            if c < 0 || c >= mldsa::Q {
                return Err(format!("polys[{j}][{i}] = {c} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, outputs_vec) = intt_batch_trace(polys.as_slice());
    let outputs: [[i64; mldsa::N]; mldsa::params::K] = outputs_vec.try_into()
        .map_err(|_| "intt_batch output length mismatch".to_string())?;

    // Output commitment: fingerprint all K outputs concatenated.
    let flat_out: Vec<i64> = outputs.iter().flat_map(|p| p.iter().copied()).collect();
    let out_fp = output_fingerprint(&flat_out);
    let commitment_hex = build_poly_commitment(&out_fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(vec![]);
    tb.commit(channel);

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(columns);
    tb.commit(channel);

    // Bind to all K inputs first (in order), then to the batch output.
    for poly in polys.iter() {
        let fp = output_fingerprint(poly);
        channel.mix_u32s(&fp);
    }
    channel.mix_u32s(&out_fp);

    let component = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        InttBatchEval { log_n_rows: log_size, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("prove_intt_batch error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("prove_intt_batch serialize error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, outputs))
}

/// Verify a batch INTT proof produced by [`prove_intt_batch`].
///
/// `inputs` must be the same K polynomials passed to the prover.
/// The verifier recomputes the input fingerprints (mixed in order) and the
/// output fingerprint from `commitment_hex`, replaying the same transcript.
pub fn verify_intt_batch(
    proof_bytes:    &[u8],
    commitment_hex: &str,
    inputs:         &[[i64; mldsa::N]; mldsa::params::K],
) -> Result<bool, String> {
    use mldsa_intt_batch_air::{InttBatchEval, LOG_N_ROWS};
    use stwo::core::proof::StarkProof;
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;

    let log_size = LOG_N_ROWS;
    let out_fp = parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("verify_intt_batch deserialize error: {e:?}"))?;

    let mut pcs_config = PcsConfig::default();
    pcs_config.fri_config.log_blowup_factor = LOG_BLOWUP;
    pcs_config.fri_config.n_queries = N_FRI_QUERIES;
    pcs_config.pow_bits = POW_BITS;

    let component = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        InttBatchEval { log_n_rows: log_size, n_polys: mldsa::params::K },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(pcs_config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("verify_intt_batch: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Replay transcript: all K input fingerprints first, then output.
    for poly in inputs.iter() {
        let fp = output_fingerprint(poly);
        verifier_channel.mix_u32s(&fp);
    }
    verifier_channel.mix_u32s(&out_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Combined INTT+WPrime STARK (MVP-3+, V18) ────────────────────────────────

/// Prove the 2K-poly INTT batch AND the K-poly WPrime subtraction in one STARK.
///
/// INTT batch uses LOG_N_ROWS=10 (1024 rows, 649 cols); WPrime uses LOG_N_ROWS=8
/// (256 rows, 24 cols).  A shared `TraceLocationAllocator` places INTT cols
/// [0..649] and WPrime cols [649..673] in Tree 1.  Twiddles are computed at the
/// INTT level (LOG=10+4+1=15) so they cover both domains.
///
/// The transcript mixes 2K per-input INTT fingerprints, then the shared
/// INTT-output = WPrime-input fingerprint (once), then the WPrime output
/// fingerprint — collapsing the cross-check into the FRI channel itself.
///
/// Returns `(proof_bytes, intt_commitment, wprime_commitment, az_out, ct1_out, w_prime)`.
pub fn prove_intt_wprime_combined(
    az_hat:  &[[i64; mldsa::N]; mldsa::params::K],
    ct1_hat: &[[i64; mldsa::N]; mldsa::params::K],
) -> Result<(Vec<u8>, String, String,
            [[i64; mldsa::N]; mldsa::params::K],
            [[i64; mldsa::N]; mldsa::params::K],
            [[i64; mldsa::N]; mldsa::params::K]), String> {
    use mldsa_intt_batch_air::{
        InttBatchEval, LOG_N_ROWS as INTT_LOG, n_cols_for as intt_n_cols_for,
        build_trace as intt_build_trace,
    };
    use mldsa_wprime_full_air::{
        WPrimeFullEval, WPrimeFullComponent,
        LOG_N_ROWS as WP_LOG, N_COLS as WP_N_COLS, build_trace as wp_build_trace,
    };
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    let k = mldsa::params::K;
    let n_polys = 2 * k; // 12 for ML-DSA-65

    // Build INTT trace for az_hat ++ ct1_hat (2K inputs).
    let mut all_inputs: Vec<[i64; mldsa::N]> = Vec::with_capacity(n_polys);
    all_inputs.extend_from_slice(az_hat);
    all_inputs.extend_from_slice(ct1_hat);
    let (intt_cols, intt_out) = intt_build_trace(&all_inputs);

    let az_out:  [[i64; mldsa::N]; mldsa::params::K] = intt_out[..k].try_into().map_err(|_| "az slice err".to_string())?;
    let ct1_out: [[i64; mldsa::N]; mldsa::params::K] = intt_out[k..].try_into().map_err(|_| "ct1 slice err".to_string())?;

    // Build WPrime trace from INTT outputs.
    let (wp_cols, w_prime_out) = wp_build_trace(&az_out, &ct1_out);

    let intt_n_cols = intt_n_cols_for(n_polys);
    debug_assert_eq!(intt_cols.len(), intt_n_cols);
    debug_assert_eq!(wp_cols.len(), WP_N_COLS);

    // INTT fingerprints: per-input (2K) + concatenated output.
    let intt_out_flat: Vec<i64> = intt_out.iter().flat_map(|p| p.iter().copied()).collect();
    let intt_out_fp   = output_fingerprint(&intt_out_flat);
    let intt_cm       = build_poly_commitment(&intt_out_fp);

    // WPrime fingerprints: input = INTT output (shared), output = w_prime.
    let wp_in_flat: Vec<i64> = az_out.iter().chain(ct1_out.iter()).flat_map(|r| r.iter().copied()).collect();
    let wp_in_fp    = output_fingerprint(&wp_in_flat);    // same values as intt_out_fp
    let wp_out_flat: Vec<i64> = w_prime_out.iter().flat_map(|r| r.iter().copied()).collect();
    let wp_out_fp   = output_fingerprint(&wp_out_flat);
    let wp_cm       = build_poly_commitment(&wp_out_fp);

    // Twiddles at INTT level (max of the two components).
    let max_log = INTT_LOG; // 10 > WP_LOG (8)
    let config  = make_config(max_log);
    let lifting = max_log + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: empty (neither component has preprocessed columns).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    // Tree 1: INTT cols (649, log=10) ++ WPrime cols (24, log=8) = 673 total.
    let mut combined_main = intt_cols;
    combined_main.extend(wp_cols);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(combined_main);
    tree_builder.commit(channel);

    // Transcript binding:
    //   1. Per-input INTT fingerprints (2K).
    //   2. INTT output = WPrime input fingerprint (shared, mixed once).
    //   3. WPrime output fingerprint.
    for poly in all_inputs.iter() {
        channel.mix_u32s(&output_fingerprint(poly));
    }
    channel.mix_u32s(&intt_out_fp);   // = wp_in_fp — mixed once as shared binding
    debug_assert_eq!(intt_out_fp, wp_in_fp, "INTT output and WPrime input fingerprints must match");
    channel.mix_u32s(&wp_out_fp);

    // Shared allocator: INTT cols first [0..649], then WPrime cols [649..673].
    let mut alloc = TraceLocationAllocator::default();
    let intt_comp = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut alloc,
        InttBatchEval { log_n_rows: INTT_LOG, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let wp_comp = WPrimeFullComponent::new(
        &mut alloc,
        WPrimeFullEval { log_n_rows: WP_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&intt_comp, &wp_comp], channel, commitment_scheme,
    ).map_err(|e| format!("prove_intt_wprime_combined error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, intt_cm, wp_cm, az_out, ct1_out, w_prime_out))
}

/// Verify a combined INTT+WPrime proof.
pub fn verify_intt_wprime_combined(
    proof_bytes: &[u8],
    intt_cm:     &str,
    wp_cm:       &str,
    az_hat:      &[[i64; mldsa::N]; mldsa::params::K],
    ct1_hat:     &[[i64; mldsa::N]; mldsa::params::K],
    az_out:      &[[i64; mldsa::N]; mldsa::params::K],
    ct1_out:     &[[i64; mldsa::N]; mldsa::params::K],
    w_prime:     &[[i64; mldsa::N]; mldsa::params::K],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_intt_batch_air::{
        InttBatchEval, LOG_N_ROWS as INTT_LOG, n_cols_for as intt_n_cols_for,
    };
    use mldsa_wprime_full_air::{
        WPrimeFullEval, WPrimeFullComponent,
        LOG_N_ROWS as WP_LOG, N_COLS as WP_N_COLS,
    };
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::CommitmentSchemeVerifier;
    use stwo::core::verifier::verify;
    use stwo_constraint_framework::TraceLocationAllocator;

    let k = mldsa::params::K;
    let n_polys = 2 * k;

    // Recompute INTT output fingerprint.
    let intt_out_flat: Vec<i64> = az_out.iter().chain(ct1_out.iter()).flat_map(|r| r.iter().copied()).collect();
    let intt_out_fp   = output_fingerprint(&intt_out_flat);

    // Verify stored commitments match reconstructed fingerprints.
    let expected_intt_cm = build_poly_commitment(&intt_out_fp);
    if expected_intt_cm != intt_cm {
        return Ok(false);
    }
    let wp_out_flat: Vec<i64> = w_prime.iter().flat_map(|r| r.iter().copied()).collect();
    let wp_out_fp   = output_fingerprint(&wp_out_flat);
    let expected_wp_cm = build_poly_commitment(&wp_out_fp);
    if expected_wp_cm != wp_cm {
        return Ok(false);
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

    let mut alloc = TraceLocationAllocator::default();
    let intt_comp = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut alloc,
        InttBatchEval { log_n_rows: INTT_LOG, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    let wp_comp = WPrimeFullComponent::new(
        &mut alloc,
        WPrimeFullEval { log_n_rows: WP_LOG },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    // Tree 0: empty; Tree 1: [INTT_LOG; n_cols_intt] ++ [WP_LOG; WP_N_COLS].
    let intt_n_cols = intt_n_cols_for(n_polys);
    let mut tree1_sizes: Vec<u32> = vec![INTT_LOG; intt_n_cols];
    tree1_sizes.extend(vec![WP_LOG; WP_N_COLS]);

    if proof.commitments.len() < 2 {
        return Err(format!("malformed proof: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &[], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &tree1_sizes, verifier_channel);

    // Replay transcript: per-input INTT fingerprints, shared IO fingerprint, WPrime output.
    let mut all_inputs: Vec<[i64; mldsa::N]> = az_hat.to_vec();
    all_inputs.extend_from_slice(ct1_hat);
    for poly in all_inputs.iter() {
        verifier_channel.mix_u32s(&output_fingerprint(poly));
    }
    verifier_channel.mix_u32s(&intt_out_fp);
    verifier_channel.mix_u32s(&wp_out_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(
        &[&intt_comp, &wp_comp], verifier_channel, commitment_scheme, proof,
    ).is_ok())
}

// ─── Batch INTT STARK — arbitrary M polynomials (MVP-3+) ────────────────────

/// Prove M inverse NTTs in one batch STARK (1 + M×54 columns, 1024 rows).
///
/// Uses input-output binding: transcript mixes all M input fingerprints (in
/// order), then the concatenated output fingerprint.  Verifier must supply the
/// same M input polynomials to replay the transcript.
///
/// Returns `(proof_bytes, commitment_hex, outputs)`.
pub fn prove_intt_batch_m(
    polys: &[[i64; mldsa::N]],
) -> Result<(Vec<u8>, String, Vec<[i64; mldsa::N]>), String> {
    use mldsa_intt_batch_air::{InttBatchEval, LOG_N_ROWS, build_trace as intt_batch_trace};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    let n_polys = polys.len();
    if n_polys == 0 {
        return Err("prove_intt_batch_m: polys must not be empty".to_string());
    }

    for (j, poly) in polys.iter().enumerate() {
        for (i, &c) in poly.iter().enumerate() {
            if c < 0 || c >= mldsa::Q {
                return Err(format!("polys[{j}][{i}] = {c} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, outputs) = intt_batch_trace(polys);

    let flat_out: Vec<i64> = outputs.iter().flat_map(|p| p.iter().copied()).collect();
    let out_fp = output_fingerprint(&flat_out);
    let commitment_hex = build_poly_commitment(&out_fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(vec![]);
    tb.commit(channel);

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(columns);
    tb.commit(channel);

    // Input-output binding: mix each input fingerprint in order, then output.
    for poly in polys.iter() {
        let fp = output_fingerprint(poly);
        channel.mix_u32s(&fp);
    }
    channel.mix_u32s(&out_fp);

    let component = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        InttBatchEval { log_n_rows: log_size, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("prove_intt_batch_m error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("prove_intt_batch_m serialize error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, outputs))
}

/// Verify a batch INTT proof produced by [`prove_intt_batch_m`].
///
/// `inputs` must be the same M polynomials passed to the prover (input-output binding).
pub fn verify_intt_batch_m(
    proof_bytes:    &[u8],
    commitment_hex: &str,
    inputs:         &[[i64; mldsa::N]],
) -> Result<bool, String> {
    use mldsa_intt_batch_air::{InttBatchEval, LOG_N_ROWS};
    use stwo::core::proof::StarkProof;
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;

    let n_polys = inputs.len();
    if n_polys == 0 {
        return Err("verify_intt_batch_m: inputs must not be empty".to_string());
    }

    let log_size = LOG_N_ROWS;
    let out_fp = parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("verify_intt_batch_m deserialize error: {e:?}"))?;

    let mut pcs_config = PcsConfig::default();
    pcs_config.fri_config.log_blowup_factor = LOG_BLOWUP;
    pcs_config.fri_config.n_queries = N_FRI_QUERIES;
    pcs_config.pow_bits = POW_BITS;

    let component = mldsa_intt_batch_air::InttBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        InttBatchEval { log_n_rows: log_size, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(pcs_config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("verify_intt_batch_m: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Replay transcript: all M input fingerprints, then output fingerprint.
    for poly in inputs.iter() {
        let fp = output_fingerprint(poly);
        verifier_channel.mix_u32s(&fp);
    }
    verifier_channel.mix_u32s(&out_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Batch NTT STARK (MVP-3+) ────────────────────────────────────────────────

/// Prove K=6 forward NTTs in one batch STARK (325 columns, 1024 rows).
///
/// Mirrors [`prove_intt_batch`] for the forward NTT direction.
/// Transcript binds to all K outputs (mixed in order) then to the concatenated
/// output fingerprint; outputs are fingerprinted individually for cross-checks.
///
/// Returns `(proof_bytes, commitment_hex, outputs)`.  `commitment_hex`
/// fingerprints all K NTT outputs concatenated.
pub fn prove_ntt_batch(
    polys: &[[i64; mldsa::N]; mldsa::params::K],
) -> Result<(Vec<u8>, String, [[i64; mldsa::N]; mldsa::params::K]), String> {
    use mldsa_ntt_batch_air::{NttBatchEval, LOG_N_ROWS, build_trace as ntt_batch_trace};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    let n_polys = mldsa::params::K;

    for (j, poly) in polys.iter().enumerate() {
        for (i, &c) in poly.iter().enumerate() {
            if c < 0 || c >= mldsa::Q {
                return Err(format!("polys[{j}][{i}] = {c} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, outputs_vec) = ntt_batch_trace(polys.as_slice());
    let outputs: [[i64; mldsa::N]; mldsa::params::K] = outputs_vec.try_into()
        .map_err(|_| "ntt_batch output length mismatch".to_string())?;

    let flat_out: Vec<i64> = outputs.iter().flat_map(|p| p.iter().copied()).collect();
    let out_fp = output_fingerprint(&flat_out);
    let commitment_hex = build_poly_commitment(&out_fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(vec![]);
    tb.commit(channel);

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(columns);
    tb.commit(channel);

    // Output-only binding (mirrors single prove_ntt): mix the concatenated output fingerprint.
    channel.mix_u32s(&out_fp);

    let component = mldsa_ntt_batch_air::NttBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        NttBatchEval { log_n_rows: log_size, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("prove_ntt_batch error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("prove_ntt_batch serialize error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, outputs))
}

/// Verify a batch NTT proof produced by [`prove_ntt_batch`].
///
/// Uses output-only binding (same as [`crate::verify_ntt`]): no inputs required.
/// `commitment_hex` encodes the fingerprint of all K NTT outputs concatenated.
pub fn verify_ntt_batch(
    proof_bytes:    &[u8],
    commitment_hex: &str,
) -> Result<bool, String> {
    use mldsa_ntt_batch_air::{NttBatchEval, LOG_N_ROWS};
    use stwo::core::proof::StarkProof;
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;

    let log_size = LOG_N_ROWS;
    let out_fp = parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("verify_ntt_batch deserialize error: {e:?}"))?;

    let mut pcs_config = PcsConfig::default();
    pcs_config.fri_config.log_blowup_factor = LOG_BLOWUP;
    pcs_config.fri_config.n_queries = N_FRI_QUERIES;
    pcs_config.pow_bits = POW_BITS;

    let component = mldsa_ntt_batch_air::NttBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        NttBatchEval { log_n_rows: log_size, n_polys: mldsa::params::K },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(pcs_config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("verify_ntt_batch: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Output-only binding: just the concatenated output fingerprint.
    verifier_channel.mix_u32s(&out_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Batch NTT STARK — arbitrary M polynomials (MVP-3+) ─────────────────────

/// Prove M forward NTTs in one batch STARK (1 + M×54 columns, 1024 rows).
///
/// Unlike [`prove_ntt_batch`] (K=6 fixed), this variant accepts any number of
/// polynomials M ≥ 1.  Useful for L=5 (NTT-z in AzProofV6).
///
/// Output-only binding: the Fiat-Shamir transcript mixes the fingerprint of all
/// M outputs concatenated.  Verifier requires only `commitment_hex` + `n_polys`.
///
/// Returns `(proof_bytes, commitment_hex, outputs)`.
pub fn prove_ntt_batch_m(
    polys: &[[i64; mldsa::N]],
) -> Result<(Vec<u8>, String, Vec<[i64; mldsa::N]>), String> {
    use mldsa_ntt_batch_air::{NttBatchEval, LOG_N_ROWS, build_trace as ntt_batch_trace};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
    use stwo::prover::backend::CpuBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove, CommitmentSchemeProver};
    use stwo_constraint_framework::TraceLocationAllocator;

    let n_polys = polys.len();
    if n_polys == 0 {
        return Err("prove_ntt_batch_m: polys must not be empty".to_string());
    }

    for (j, poly) in polys.iter().enumerate() {
        for (i, &c) in poly.iter().enumerate() {
            if c < 0 || c >= mldsa::Q {
                return Err(format!("polys[{j}][{i}] = {c} out of [0, Q)"));
            }
        }
    }

    let log_size = LOG_N_ROWS;
    let (columns, outputs) = ntt_batch_trace(polys);

    let flat_out: Vec<i64> = outputs.iter().flat_map(|p| p.iter().copied()).collect();
    let out_fp = output_fingerprint(&flat_out);
    let commitment_hex = build_poly_commitment(&out_fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(vec![]);
    tb.commit(channel);

    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(columns);
    tb.commit(channel);

    channel.mix_u32s(&out_fp);

    let component = mldsa_ntt_batch_air::NttBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        NttBatchEval { log_n_rows: log_size, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("prove_ntt_batch_m error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("prove_ntt_batch_m serialize error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, outputs))
}

/// Verify a batch NTT proof produced by [`prove_ntt_batch_m`].
///
/// `n_polys` must match the value used when the proof was generated.
pub fn verify_ntt_batch_m(
    proof_bytes:    &[u8],
    commitment_hex: &str,
    n_polys:        usize,
) -> Result<bool, String> {
    use mldsa_ntt_batch_air::{NttBatchEval, LOG_N_ROWS};
    use stwo::core::proof::StarkProof;
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
    use stwo::core::channel::{Blake2sM31Channel, Channel};
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::verifier::verify;
    use stwo::core::air::Component;
    use stwo_constraint_framework::TraceLocationAllocator;

    if n_polys == 0 {
        return Err("verify_ntt_batch_m: n_polys must not be zero".to_string());
    }

    let log_size = LOG_N_ROWS;
    let out_fp = parse_poly_commitment(commitment_hex)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(
            proof_bytes,
            bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
        )
        .map_err(|e| format!("verify_ntt_batch_m deserialize error: {e:?}"))?;

    let mut pcs_config = PcsConfig::default();
    pcs_config.fri_config.log_blowup_factor = LOG_BLOWUP;
    pcs_config.fri_config.n_queries = N_FRI_QUERIES;
    pcs_config.pow_bits = POW_BITS;

    let component = mldsa_ntt_batch_air::NttBatchComponent::new(
        &mut TraceLocationAllocator::default(),
        NttBatchEval { log_n_rows: log_size, n_polys },
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(pcs_config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!("verify_ntt_batch_m: expected ≥ 2 commitments, got {}", proof.commitments.len()));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    verifier_channel.mix_u32s(&out_fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── Hint weight check STARK (MVP-3+) ────────────────────────────────────────

/// Prove that the total hint weight Σᵢ ||h[i]||₁ ≤ ω (ML-DSA-65: ω=55).
///
/// `hints[i][j]` is the hint bit for polynomial i, coefficient j.
/// `hints` must have `K=6` rows, each of length `N=256`.
///
/// Returns `(proof_bytes, commitment_hex, total_weight)`.
/// `commitment_hex` fingerprints the running-sum polynomial (Scheme B, 128-bit).
/// The caller must check `total_weight ≤ OMEGA` — this is not enforced by the circuit.
///
/// The circuit proves:
///   - Each hint bit ∈ {0,1}
///   - Padding rows (≥ 1536) have h=0
///   - The running sum is sequential: s[r] = s[r−1] + h[r]
pub fn prove_hint_weight(hints: &[Vec<bool>]) -> Result<(Vec<u8>, String, usize), String> {
    use mldsa_hint_weight_air::{LOG_N_ROWS, build_trace, new_component};
    use mldsa::params::K;
    use mldsa::N;

    if hints.len() != K {
        return Err(format!("hints must have K={K} rows, got {}", hints.len()));
    }
    for (i, row) in hints.iter().enumerate() {
        if row.len() != N {
            return Err(format!("hints[{i}] must have N={N} columns, got {}", row.len()));
        }
    }

    let log_size = LOG_N_ROWS;
    let (main_cols, preproc_cols, total_weight) = build_trace(hints);

    // The "output" we fingerprint is the running-sum column (col 0 = s after column ordering fix).
    let s_col_raw: Vec<i64> = main_cols[0].values.iter().map(|v| v.0 as i64).collect();
    let fp = output_fingerprint(&s_col_raw);
    let commitment_hex = build_poly_commitment(&fp);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: preprocessed columns (is_init, is_valid).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: main trace (h, s).
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_cols);
    tree_builder.commit(channel);

    // Bind output fingerprint to Fiat-Shamir transcript.
    channel.mix_u32s(&fp);

    let component = new_component(log_size);

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
        .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    Ok((proof_bytes, commitment_hex, total_weight))
}

/// Verify a hint weight STARK proof produced by [`prove_hint_weight`].
///
/// Returns `Ok(true)` iff the STARK proof is valid for the given commitment.
/// The caller is responsible for checking `total_weight ≤ OMEGA` using the
/// `total_weight` value returned from `prove_hint_weight`.
pub fn verify_hint_weight(
    proof_bytes: &[u8],
    commitment_hex: &str,
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;
    use mldsa_hint_weight_air::{LOG_N_ROWS, new_component};

    let log_size = LOG_N_ROWS;
    let fp = parse_poly_commitment(commitment_hex)?;

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
    verifier_channel.mix_u32s(&fp);

    Ok(verify::<Blake2sM31MerkleChannel>(&[&component], verifier_channel, commitment_scheme, proof).is_ok())
}

// ─── ML-DSA batch verification + STARK proof ─────────────────────────────────

/// Verify N ML-DSA-65 signatures and generate a STARK proof over the valid set.
///
/// Each entry is `(pk, msg, sig)` as raw byte slices.
/// Returns `(proof_bytes, commitment_hex, log_size, verified_count, rejected_count)`.
///
/// Only valid signatures contribute to the proof. At least one must be valid.
pub fn prove_mldsa_batch(
    entries: &[(Vec<u8>, Vec<u8>, Vec<u8>)],
) -> Result<(Vec<u8>, String, u32, usize, usize), String> {
    use sha3::{Sha3_256, Digest};
    use mldsa::verify::ml_dsa_verify;

    let mut leaves: Vec<u64> = Vec::new();
    let mut rejected = 0usize;

    for (pk, msg, sig) in entries {
        if ml_dsa_verify(pk, msg, sig) {
            // Leaf = first 8 bytes of SHA3-256(pk ∥ msg) as little-endian u64.
            let mut h = Sha3_256::new();
            h.update(pk);
            h.update(msg);
            let digest = h.finalize();
            let leaf = u64::from_le_bytes(digest[..8].try_into().unwrap());
            leaves.push(leaf);
        } else {
            rejected += 1;
        }
    }

    let verified = leaves.len();
    if leaves.is_empty() {
        return Err("no valid ML-DSA-65 signatures in batch".into());
    }

    let (proof_bytes, commitment, log_size) = prove_hash_chain(&leaves, &[])?;
    Ok((proof_bytes, commitment, log_size, verified, rejected))
}

// ─── Poseidon2 Merkle-tree STARK ─────────────────────────────────────────────

/// Prove that `leaves` hash to a Merkle root via Poseidon2 compression.
///
/// Returns `(proof_bytes, commitment_hex, log_size)`.
/// `commitment_hex` is the 8-char little-endian hex of the Merkle root (M31).
pub fn prove_merkle_root(leaves: &[u64], seed: &[u8]) -> Result<(Vec<u8>, String, u32), String> {
    use poseidon2_merkle_air::{build_trace, compute_log_size};

    if leaves.is_empty() {
        return Err("leaves must not be empty".into());
    }
    let log_size = compute_log_size(leaves.len());
    if log_size > MAX_LOG_SIZE {
        return Err(format!("input too large: log_size {log_size} exceeds MAX_LOG_SIZE {MAX_LOG_SIZE}"));
    }

    let (main_cols, preproc_cols, commitment) = build_trace(leaves);

    let config = make_config(log_size);
    let lifting = log_size + LOG_BLOWUP;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting + 1).circle_domain().half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();

    // Bind seed (batch Merkle root) to Fiat-Shamir transcript before first commit.
    if !seed.is_empty() {
        channel.mix_u32s(&seed_to_u32_words(seed));
    }

    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    // Tree 0: preprocessed columns (rc0, rc1, is_init)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preproc_cols);
    tree_builder.commit(channel);

    // Tree 1: main trace (s0, s1, t0, t1, inp0, left, inp1, right)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(main_cols);
    tree_builder.commit(channel);

    // Bind commitment to Fiat-Shamir transcript (C-2 fix).
    channel.mix_u32s(&[commitment.0]);

    let component = poseidon2_merkle_air::new_component(log_size);

    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        channel,
        commitment_scheme,
    )
    .map_err(|e| format!("proving error: {e:?}"))?;

    let proof_bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| format!("serialization error: {e:?}"))?;

    let commitment_hex = build_commitment_128(commitment.0, &proof_bytes);
    Ok((proof_bytes, commitment_hex, log_size))
}

/// Verify a proof previously produced by `prove_merkle_root`.
pub fn verify_merkle_root(
    proof_bytes: &[u8],
    commitment_hex: &str,
    log_size: u32,
    seed: &[u8],
) -> Result<bool, String> {
    use stwo::core::proof::StarkProof;

    if log_size < poseidon2_merkle_air::MIN_LOG_SIZE || log_size > MAX_LOG_SIZE {
        return Err(format!(
            "log_size {log_size} out of valid range [{}, {MAX_LOG_SIZE}]",
            poseidon2_merkle_air::MIN_LOG_SIZE
        ));
    }

    // Parse 128-bit commitment, validate suffix, extract M31 for Fiat-Shamir.
    let commitment_val_merkle = parse_commitment_128(commitment_hex, proof_bytes)?;

    let (proof, _): (StarkProof<Blake2sM31MerkleHasher>, usize) =
        bincode::serde::decode_from_slice(proof_bytes, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>())
            .map_err(|e| format!("deserialization error: {e:?}"))?;

    let mut config = PcsConfig::default();
    config.fri_config.log_blowup_factor = LOG_BLOWUP;
    config.fri_config.n_queries = N_FRI_QUERIES;
    config.pow_bits = POW_BITS;

    let component = poseidon2_merkle_air::new_component(log_size);

    let verifier_channel = &mut Blake2sM31Channel::default();

    // Replay seed mixing — must match the prover's transcript exactly.
    if !seed.is_empty() {
        verifier_channel.mix_u32s(&seed_to_u32_words(seed));
    }

    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    if proof.commitments.len() < 2 {
        return Err(format!(
            "malformed proof: expected 2 commitments, got {}",
            proof.commitments.len()
        ));
    }
    commitment_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);

    // Mirror the prover's channel.mix_u32s so the Fiat-Shamir transcript matches (C-2 fix).
    verifier_channel.mix_u32s(&[commitment_val_merkle]);

    let result = verify::<Blake2sM31MerkleChannel>(
        &[&component],
        verifier_channel,
        commitment_scheme,
        proof,
    );

    Ok(result.is_ok())
}

// ─── PyO3 Python extension module ────────────────────────────────────────────
//
// Compiled only with `--features python` (e.g. `maturin develop --features python`).
// Exports the six prove/verify functions plus `prove_mldsa` as a Python native
// extension module named `qlsa_stark_stwo`.
//
//   cd stark_stwo && maturin develop --features python --release
//   python -c "import qlsa_stark_stwo; proof, c, n = qlsa_stark_stwo.prove([1,2,3,4])"

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// prove(leaves) -> (proof: bytes, commitment: str, log_size: int)
#[cfg(feature = "python")]
/// prove(leaves, merkle_root=None) -> (proof: bytes, commitment: str, log_size: int)
///
/// `merkle_root` — optional bytes; if provided, mixed into Fiat-Shamir before
/// the first trace commitment, binding the proof to this specific root.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(name = "prove")]
#[pyo3(signature = (leaves, merkle_root=None))]
fn py_prove(leaves: Vec<u64>, merkle_root: Option<Vec<u8>>) -> PyResult<(Vec<u8>, String, u32)> {
    let seed = merkle_root.as_deref().unwrap_or(&[]);
    prove_hash_chain(&leaves, seed).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// verify(proof, commitment, log_size, merkle_root=None) -> bool
///
/// `merkle_root` must match the value used during proving (same bytes = same
/// FRI queries).  Pass `None` for proofs produced without a root seed.
/// Returns False on any verification failure; never raises.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(name = "verify")]
#[pyo3(signature = (proof, commitment, log_size, merkle_root=None))]
fn py_verify(proof: Vec<u8>, commitment: String, log_size: u32, merkle_root: Option<Vec<u8>>) -> bool {
    let seed = merkle_root.as_deref().unwrap_or(&[]);
    verify_hash_chain(&proof, &commitment, log_size, seed).unwrap_or(false)
}

/// prove_p2(leaves, seed=None) -> (proof: bytes, commitment: str, log_size: int)
///
/// `seed` (optional bytes): batch Merkle root to mix into the Fiat-Shamir transcript
/// as a domain separator, binding the proof to a specific batch.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (leaves, seed=None))]
fn prove_p2(leaves: Vec<u64>, seed: Option<Vec<u8>>) -> PyResult<(Vec<u8>, String, u32)> {
    prove_hash_chain_poseidon2(&leaves, seed.as_deref().unwrap_or(&[]))
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// verify_p2(proof, commitment, log_size, seed=None) -> bool
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (proof, commitment, log_size, seed=None))]
fn verify_p2(proof: Vec<u8>, commitment: String, log_size: u32, seed: Option<Vec<u8>>) -> bool {
    verify_hash_chain_poseidon2(&proof, &commitment, log_size, seed.as_deref().unwrap_or(&[]))
        .unwrap_or(false)
}

/// prove_merkle(leaves, seed=None) -> (proof: bytes, commitment: str, log_size: int)
///
/// `seed` (optional bytes): batch Merkle root to mix into the Fiat-Shamir transcript
/// as a domain separator, binding the proof to a specific batch.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (leaves, seed=None))]
fn prove_merkle(leaves: Vec<u64>, seed: Option<Vec<u8>>) -> PyResult<(Vec<u8>, String, u32)> {
    prove_merkle_root(&leaves, seed.as_deref().unwrap_or(&[]))
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// verify_merkle(proof, commitment, log_size, seed=None) -> bool
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (proof, commitment, log_size, seed=None))]
fn verify_merkle(proof: Vec<u8>, commitment: String, log_size: u32, seed: Option<Vec<u8>>) -> bool {
    verify_merkle_root(&proof, &commitment, log_size, seed.as_deref().unwrap_or(&[]))
        .unwrap_or(false)
}

/// prove_ntt_py(f) -> (proof: bytes, commitment: str, ntt_out: list[int])
///
/// `f` is a list of 256 ints in [0, Q) (Q = 8 380 417).
#[cfg(feature = "python")]
#[pyfunction]
fn prove_ntt_py(f: Vec<i64>) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let arr: [i64; 256] = f
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("f must have exactly 256 elements"))?;
    let (proof, commitment, ntt_out) = prove_ntt(&arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, ntt_out.to_vec()))
}

/// verify_ntt_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_ntt_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_ntt(&proof, &commitment).unwrap_or(false)
}

/// prove_mldsa(entries) -> (proof: bytes, commitment: str, log_size: int, verified: int, rejected: int)
///
/// `entries` is a list of ``(pk, msg, sig)`` tuples (all ``bytes``).
/// At least one signature must be valid; raises RuntimeError otherwise.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_mldsa(
    entries: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
) -> PyResult<(Vec<u8>, String, u32, usize, usize)> {
    prove_mldsa_batch(&entries).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// wipe_bytes(buf) — zero a Python bytearray in-place using volatile writes.
///
/// Unlike a pure-Python loop, `volatile_set` prevents the compiler from
/// optimising away the writes.  Call this instead of `for i in range(...): buf[i]=0`
/// when zeroing cryptographic key material.
///
/// Safety contract: the caller must hold the only Rust-side reference to `buf`
/// at the time of the call (Python-side references are fine; we hold the GIL).
#[cfg(feature = "python")]
#[pyfunction]
fn wipe_bytes(buf: pyo3::Bound<'_, pyo3::types::PyByteArray>) -> PyResult<()> {
    use zeroize::Zeroize;
    // SAFETY: we hold the GIL and this is the only Rust reference to the buffer.
    let slice = unsafe { buf.as_bytes_mut() };
    slice.zeroize();
    Ok(())
}

/// gen_poseidon2_vfri2_hints(leaves, batch_merkle_root, n_queries) -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// Generates a VFRI2-compatible proof and ABI-encoded queryHints for the
/// Poseidon2 hash-chain circuit.  `batch_merkle_root` is 32 bytes.
/// Returns `(proof_bytes, commitment_hex, abi_encoded_hints)`.
#[cfg(feature = "python")]
#[pyfunction]
fn gen_poseidon2_vfri2_hints_py(
    leaves: Vec<u64>,
    batch_merkle_root: Vec<u8>,
    n_queries: usize,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    vfri2_bridge::gen_poseidon2_vfri2_hints(&leaves, &batch_merkle_root, n_queries)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

#[cfg(feature = "python")]
#[pyfunction]
fn gen_poseidon2_vfri3_real_py(
    leaves: Vec<u64>,
    batch_merkle_root: Vec<u8>,
    n_queries: usize,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    vfri2_bridge::gen_poseidon2_vfri3_real(&leaves, &batch_merkle_root, n_queries)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

#[cfg(feature = "python")]
#[pyfunction]
fn gen_poseidon2_vfri4_real_py(
    leaves: Vec<u64>,
    batch_merkle_root: Vec<u8>,
    n_queries: usize,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    vfri2_bridge::gen_poseidon2_vfri4_real(&leaves, &batch_merkle_root, n_queries)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

#[cfg(feature = "python")]
#[pyfunction]
fn gen_ntt_batch_vfri3_hints_py(
    polys: Vec<Vec<i64>>,
    batch_merkle_root: Vec<u8>,
    n_queries: usize,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    let polys_arr: Vec<[i64; 256]> = polys
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("polys[{i}] must have exactly 256 coefficients")
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    vfri2_bridge::gen_ntt_batch_vfri3_hints(&polys_arr, &batch_merkle_root, n_queries)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

#[cfg(feature = "python")]
#[pyfunction]
fn gen_ntt_batch_vfri3_hints_nfolds_py(
    polys: Vec<Vec<i64>>,
    batch_merkle_root: Vec<u8>,
    n_queries: usize,
    num_folds: usize,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    let polys_arr: Vec<[i64; 256]> = polys
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("polys[{i}] must have exactly 256 coefficients")
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    vfri2_bridge::gen_ntt_batch_vfri3_hints_nfolds(
        &polys_arr, &batch_merkle_root, n_queries, Some(num_folds)
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri3_hints(z, c, t1, a_hat, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// Generates VFRI3-compatible hints from V23's NttBatch + InttBatch components
/// (both LOG=10, 649 cols each → 1298 combined columns).
///
/// Proves on-chain via QLSAVerifierVFRI3 that NTT(z,c,t1) and INTT(az,ct1)
/// were computed correctly, forming the first on-chain V23 proof segment.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri3_hints_py(
    z:                  Vec<Vec<i64>>,
    c:                  Vec<i64>,
    t1:                 Vec<Vec<i64>>,
    a_hat:              Vec<Vec<i64>>,
    batch_merkle_root:  Vec<u8>,
    n_queries:          usize,
    num_folds:          Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    // Convert z: Vec<Vec<i64>> → [[i64;256];5]
    if z.len() != 5 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z must have 5 polynomials (L=5), got {}", z.len())
        ));
    }
    let z_arr: [[i64; 256]; 5] = z.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("z[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 5 entries"))?;

    // Convert c: Vec<i64> → [i64;256]
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 coefficients"))?;

    // Convert t1: Vec<Vec<i64>> → [[i64;256];6]
    if t1.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("t1 must have 6 polynomials (K=6), got {}", t1.len())
        ));
    }
    let t1_arr: [[i64; 256]; 6] = t1.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("t1[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("t1 must have exactly 6 entries"))?;

    // Convert a_hat: Vec<Vec<i64>> → Vec<[i64;256]>
    let a_hat_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("a_hat[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?;

    vfri2_bridge::gen_mldsa_v23_vfri3_hints(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri4_hints_py(z, c, t1, a_hat, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI4 variant of gen_mldsa_v23_vfri3_hints_py. Combines NttBatch (649 cols) +
/// InttBatch (649 cols) = 1298 total trace columns, then generates VFRI4-compatible
/// ABI-encoded hints (Poseidon2 sponge OODS transcript).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri4_hints_py(
    z:                  Vec<Vec<i64>>,
    c:                  Vec<i64>,
    t1:                 Vec<Vec<i64>>,
    a_hat:              Vec<Vec<i64>>,
    batch_merkle_root:  Vec<u8>,
    n_queries:          usize,
    num_folds:          Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    if z.len() != 5 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z must have 5 polynomials (L=5), got {}", z.len())
        ));
    }
    let z_arr: [[i64; 256]; 5] = z.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("z[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 5 entries"))?;

    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 coefficients"))?;

    if t1.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("t1 must have 6 polynomials (K=6), got {}", t1.len())
        ));
    }
    let t1_arr: [[i64; 256]; 6] = t1.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("t1[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("t1 must have exactly 6 entries"))?;

    let a_hat_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("a_hat[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?;

    vfri2_bridge::gen_mldsa_v23_vfri4_hints(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_ntt_batch_vfri4_hints_nfolds_py(polys, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI4 variant of gen_ntt_batch_vfri3_hints_nfolds — uses Poseidon2 sponge for
/// OODS eval channel commitment (4 M31 words per OODS set instead of n_cols*4 words).
/// queryHints ABI format is identical to VFRI3; only the Fiat-Shamir transcript differs.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (polys, batch_merkle_root, n_queries=1, num_folds=9))]
fn gen_ntt_batch_vfri4_hints_nfolds_py(
    polys:             Vec<Vec<i64>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         usize,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    let polys_arr: Vec<[i64; 256]> = polys
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("polys[{i}] must have exactly 256 coefficients")
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    vfri2_bridge::gen_ntt_batch_vfri4_hints_nfolds(
        &polys_arr, &batch_merkle_root, n_queries, Some(num_folds)
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_ntt_batch_vfri5_hints_nfolds_py(polys, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI5 variant of gen_ntt_batch_vfri4_hints_nfolds. Adds a composition polynomial
/// Merkle tree (`compRoot`) so per-query hints carry only compValue + Merkle proof
/// instead of all n_cols column values. For 649 cols (12-poly NttBatch), this reduces
/// per-query calldata from ~41 KB to O(treeDepth × 32) bytes.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (polys, batch_merkle_root, n_queries=1, num_folds=9))]
fn gen_ntt_batch_vfri5_hints_nfolds_py(
    polys:             Vec<Vec<i64>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         usize,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    let polys_arr: Vec<[i64; 256]> = polys
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("polys[{i}] must have exactly 256 coefficients")
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    vfri2_bridge::gen_ntt_batch_vfri5_hints_nfolds(
        &polys_arr, &batch_merkle_root, n_queries, Some(num_folds)
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_ntt_batch_vfri6_hints_nfolds_py(polys, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI6 variant — removes oodsEvalsPos/Neg arrays entirely. Prover precomputes
/// oodsComboPos/Neg off-chain; only 2 uint128 values passed. Eliminates O(n_cols)
/// on-chain work, enabling 649-col NttBatch verification within 15 M gas.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (polys, batch_merkle_root, n_queries=1, num_folds=9))]
fn gen_ntt_batch_vfri6_hints_nfolds_py(
    polys:             Vec<Vec<i64>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         usize,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    let polys_arr: Vec<[i64; 256]> = polys
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("polys[{i}] must have exactly 256 coefficients")
            ))
        })
        .collect::<PyResult<Vec<_>>>()?;
    vfri2_bridge::gen_ntt_batch_vfri6_hints_nfolds(
        &polys_arr, &batch_merkle_root, n_queries, Some(num_folds)
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri6_hints_py(z, c, t1, a_hat, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI6 variant for V23's NttBatch+InttBatch combined trace (1298 columns, LOG=10).
/// On-chain gas does NOT scale with n_cols: only 8 M31 words mixed per call.
/// 1298-col trace fits within 15M gas — same as 649-col in VFRI6.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri6_hints_py(
    z:                 Vec<Vec<i64>>,
    c:                 Vec<i64>,
    t1:                Vec<Vec<i64>>,
    a_hat:             Vec<Vec<i64>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    if z.len() != 5 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z must have 5 polynomials (L=5), got {}", z.len())
        ));
    }
    let z_arr: [[i64; 256]; 5] = z.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("z[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 5 entries"))?;

    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 coefficients"))?;

    if t1.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("t1 must have 6 polynomials (K=6), got {}", t1.len())
        ));
    }
    let t1_arr: [[i64; 256]; 6] = t1.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("t1[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("t1 must have exactly 6 entries"))?;

    let a_hat_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("a_hat[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?;

    vfri2_bridge::gen_mldsa_v23_vfri6_hints(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri6_hints_log8_py(z, c, t1, a_hat, hints, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI6 hint generator for V23's LOG=8 component group:
/// AzFull (1523) + Ct1Full (295) + RangeQBatch (288) +
/// WPrimeFull (24) + NormCheckBatch (15) + UseHintBatchV2 (61) = 2206 columns.
/// Hint size is O(1) in n_cols: ~3.5 KB regardless of column count.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, hints, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri6_hints_log8_py(
    z:                 Vec<Vec<i64>>,
    c:                 Vec<i64>,
    t1:                Vec<Vec<i64>>,
    a_hat:             Vec<Vec<i64>>,
    hints:             Vec<Vec<bool>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    if z.len() != 5 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z must have 5 polynomials (L=5), got {}", z.len())
        ));
    }
    let z_arr: [[i64; 256]; 5] = z.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("z[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 5 entries"))?;

    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 coefficients"))?;

    if t1.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("t1 must have 6 polynomials (K=6), got {}", t1.len())
        ));
    }
    let t1_arr: [[i64; 256]; 6] = t1.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("t1[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("t1 must have exactly 6 entries"))?;

    let a_hat_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("a_hat[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?;

    if hints.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("hints must have 6 arrays (K=6), got {}", hints.len())
        ));
    }
    let hints_arr: [[bool; 256]; 6] = hints.into_iter()
        .enumerate()
        .map(|(i, h)| h.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("hints[{i}] must have 256 entries")
        )))
        .collect::<PyResult<Vec<[bool; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("hints must have exactly 6 entries"))?;

    vfri2_bridge::gen_mldsa_v23_vfri6_hints_log8(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr, &hints_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri7_hints_py(z, c, t1, a_hat, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI7 = VFRI6 + mixRoot(batch_merkle_root) before drawQueries.
/// Binds FRI query indices to the external batch context (MVP-5 Priority 2).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri7_hints_py(
    z:                 Vec<Vec<i64>>,
    c:                 Vec<i64>,
    t1:                Vec<Vec<i64>>,
    a_hat:             Vec<Vec<i64>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    if z.len() != 5 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z must have 5 polynomials (L=5), got {}", z.len())
        ));
    }
    let z_arr: [[i64; 256]; 5] = z.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("z[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 5 entries"))?;

    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 coefficients"))?;

    if t1.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("t1 must have 6 polynomials (K=6), got {}", t1.len())
        ));
    }
    let t1_arr: [[i64; 256]; 6] = t1.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("t1[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("t1 must have exactly 6 entries"))?;

    let a_hat_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("a_hat[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?;

    vfri2_bridge::gen_mldsa_v23_vfri7_hints(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri7_hints_log8_py(z, c, t1, a_hat, hints, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI7 hint generator for V23's LOG=8 component group (2206 columns).
/// Adds mixRoot(batch_merkle_root) before drawQueries vs VFRI6.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, hints, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri7_hints_log8_py(
    z:                 Vec<Vec<i64>>,
    c:                 Vec<i64>,
    t1:                Vec<Vec<i64>>,
    a_hat:             Vec<Vec<i64>>,
    hints:             Vec<Vec<bool>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    if z.len() != 5 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z must have 5 polynomials (L=5), got {}", z.len())
        ));
    }
    let z_arr: [[i64; 256]; 5] = z.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("z[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 5 entries"))?;

    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 coefficients"))?;

    if t1.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("t1 must have 6 polynomials (K=6), got {}", t1.len())
        ));
    }
    let t1_arr: [[i64; 256]; 6] = t1.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("t1[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("t1 must have exactly 6 entries"))?;

    let a_hat_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("a_hat[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?;

    if hints.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("hints must have 6 arrays (K=6), got {}", hints.len())
        ));
    }
    let hints_arr: [[bool; 256]; 6] = hints.into_iter()
        .enumerate()
        .map(|(i, h)| h.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("hints[{i}] must have 256 entries")
        )))
        .collect::<PyResult<Vec<[bool; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("hints must have exactly 6 entries"))?;

    vfri2_bridge::gen_mldsa_v23_vfri7_hints_log8(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr, &hints_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri7_cross_bound_hints_py(z, c, t1, a_hat, hints, batch_root, n_queries, num_folds)
///   -> (proof10, commit10, hints10, proof8, commit8, hints8)
///
/// Two-pass cross-proof binding for MVP-5 Priority 2.
/// Returns hints for both LOG=10 and LOG=8 groups, where each proof's FRI query
/// indices depend on the other's trace commitment via cross-bound roots:
///   bound_root_10 = keccak256(batch_root ‖ proof8[8:40])
///   bound_root_8  = keccak256(batch_root ‖ proof10[8:40])
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, hints, batch_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri7_cross_bound_hints_py(
    z:          Vec<Vec<i64>>,
    c:          Vec<i64>,
    t1:         Vec<Vec<i64>>,
    a_hat:      Vec<Vec<i64>>,
    hints:      Vec<Vec<bool>>,
    batch_root: Vec<u8>,
    n_queries:  usize,
    num_folds:  Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>, Vec<u8>, String, Vec<u8>)> {
    if z.len() != 5 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z must have 5 polynomials (L=5), got {}", z.len())
        ));
    }
    let z_arr: [[i64; 256]; 5] = z.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("z[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 5 entries"))?;

    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 coefficients"))?;

    if t1.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("t1 must have 6 polynomials (K=6), got {}", t1.len())
        ));
    }
    let t1_arr: [[i64; 256]; 6] = t1.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("t1[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("t1 must have exactly 6 entries"))?;

    let a_hat_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("a_hat[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?;

    if hints.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("hints must have 6 arrays (K=6), got {}", hints.len())
        ));
    }
    let hints_arr: [[bool; 256]; 6] = hints.into_iter()
        .enumerate()
        .map(|(i, h)| h.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("hints[{i}] must have 256 entries")
        )))
        .collect::<PyResult<Vec<[bool; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("hints must have exactly 6 entries"))?;

    vfri2_bridge::gen_mldsa_v23_vfri7_cross_bound_hints(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr, &hints_arr,
        &batch_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri8_hints_py(z, c, t1, a_hat, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI8 = VFRI7 with Poseidon2 replacing Blake2s for Merkle hashing and the
/// Fiat-Shamir channel.  LOG=10 group (NttBatch + InttBatch, 1298 cols).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri8_hints_py(
    z:                 Vec<Vec<i64>>,
    c:                 Vec<i64>,
    t1:                Vec<Vec<i64>>,
    a_hat:             Vec<Vec<i64>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    if z.len() != 5 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z must have 5 polynomials (L=5), got {}", z.len())
        ));
    }
    let z_arr: [[i64; 256]; 5] = z.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("z[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 5 entries"))?;

    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 coefficients"))?;

    if t1.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("t1 must have 6 polynomials (K=6), got {}", t1.len())
        ));
    }
    let t1_arr: [[i64; 256]; 6] = t1.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("t1[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("t1 must have exactly 6 entries"))?;

    let a_hat_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("a_hat[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?;

    vfri2_bridge::gen_mldsa_v23_vfri8_hints(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri8_hints_log8_py(z, c, t1, a_hat, hints, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI8 hint generator for V23's LOG=8 component group (2206 columns).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, hints, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri8_hints_log8_py(
    z:                 Vec<Vec<i64>>,
    c:                 Vec<i64>,
    t1:                Vec<Vec<i64>>,
    a_hat:             Vec<Vec<i64>>,
    hints:             Vec<Vec<bool>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    if z.len() != 5 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z must have 5 polynomials (L=5), got {}", z.len())
        ));
    }
    let z_arr: [[i64; 256]; 5] = z.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("z[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 5 entries"))?;

    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 coefficients"))?;

    if t1.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("t1 must have 6 polynomials (K=6), got {}", t1.len())
        ));
    }
    let t1_arr: [[i64; 256]; 6] = t1.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("t1[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("t1 must have exactly 6 entries"))?;

    let a_hat_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("a_hat[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?;

    if hints.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("hints must have 6 arrays (K=6), got {}", hints.len())
        ));
    }
    let hints_arr: [[bool; 256]; 6] = hints.into_iter()
        .enumerate()
        .map(|(i, h)| h.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("hints[{i}] must have 256 entries")
        )))
        .collect::<PyResult<Vec<[bool; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("hints must have exactly 6 entries"))?;

    vfri2_bridge::gen_mldsa_v23_vfri8_hints_log8(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr, &hints_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri8_cross_bound_hints_py(z, c, t1, a_hat, hints, batch_root, n_queries, num_folds)
///   -> (proof10, commit10, hints10, proof8, commit8, hints8)
///
/// Two-pass cross-proof binding using VFRI8 (Poseidon2) backends:
///   bound_root_10 = keccak256(batch_root ‖ proof8[8:40])
///   bound_root_8  = keccak256(batch_root ‖ proof10[8:40])
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, hints, batch_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri8_cross_bound_hints_py(
    z:          Vec<Vec<i64>>,
    c:          Vec<i64>,
    t1:         Vec<Vec<i64>>,
    a_hat:      Vec<Vec<i64>>,
    hints:      Vec<Vec<bool>>,
    batch_root: Vec<u8>,
    n_queries:  usize,
    num_folds:  Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>, Vec<u8>, String, Vec<u8>)> {
    if z.len() != 5 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z must have 5 polynomials (L=5), got {}", z.len())
        ));
    }
    let z_arr: [[i64; 256]; 5] = z.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("z[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 5 entries"))?;

    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 coefficients"))?;

    if t1.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("t1 must have 6 polynomials (K=6), got {}", t1.len())
        ));
    }
    let t1_arr: [[i64; 256]; 6] = t1.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("t1[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("t1 must have exactly 6 entries"))?;

    let a_hat_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("a_hat[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?;

    if hints.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("hints must have 6 arrays (K=6), got {}", hints.len())
        ));
    }
    let hints_arr: [[bool; 256]; 6] = hints.into_iter()
        .enumerate()
        .map(|(i, h)| h.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("hints[{i}] must have 256 entries")
        )))
        .collect::<PyResult<Vec<[bool; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("hints must have exactly 6 entries"))?;

    vfri2_bridge::gen_mldsa_v23_vfri8_cross_bound_hints(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr, &hints_arr,
        &batch_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

// ── VFRI9 PyO3 conversion helpers ─────────────────────────────────────────────

#[cfg(feature = "python")]
fn _conv_z(z: Vec<Vec<i64>>) -> PyResult<[[i64; 256]; 5]> {
    if z.len() != 5 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z must have 5 polynomials (L=5), got {}", z.len())
        ));
    }
    z.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("z[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 5 entries"))
}

#[cfg(feature = "python")]
fn _conv_c(c: Vec<i64>) -> PyResult<[i64; 256]> {
    c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 coefficients"))
}

#[cfg(feature = "python")]
fn _conv_t1(t1: Vec<Vec<i64>>) -> PyResult<[[i64; 256]; 6]> {
    if t1.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("t1 must have 6 polynomials (K=6), got {}", t1.len())
        ));
    }
    t1.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("t1[{i}] must have 256 coefficients")
        )))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("t1 must have exactly 6 entries"))
}

#[cfg(feature = "python")]
fn _conv_a_hat(a_hat: Vec<Vec<i64>>) -> PyResult<Vec<[i64; 256]>> {
    a_hat.into_iter()
        .enumerate()
        .map(|(i, p)| p.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("a_hat[{i}] must have 256 coefficients")
        )))
        .collect()
}

#[cfg(feature = "python")]
fn _conv_hints(hints: Vec<Vec<bool>>) -> PyResult<[[bool; 256]; 6]> {
    if hints.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("hints must have 6 arrays (K=6), got {}", hints.len())
        ));
    }
    hints.into_iter()
        .enumerate()
        .map(|(i, h)| h.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
            format!("hints[{i}] must have 256 entries")
        )))
        .collect::<PyResult<Vec<[bool; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("hints must have exactly 6 entries"))
}

/// gen_mldsa_v23_vfri9_hints_py(z, c, t1, a_hat, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI9 = VFRI8 with wide (62-bit) Poseidon2 Merkle nodes, full-root
/// Fiat-Shamir absorption, and the last-layer FRI bounded-degree check.
/// LOG=10 group (NttBatch + InttBatch, 1298 cols).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri9_hints_py(
    z:                 Vec<Vec<i64>>,
    c:                 Vec<i64>,
    t1:                Vec<Vec<i64>>,
    a_hat:             Vec<Vec<i64>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    let z_arr = _conv_z(z)?;
    let c_arr = _conv_c(c)?;
    let t1_arr = _conv_t1(t1)?;
    let a_hat_arr = _conv_a_hat(a_hat)?;
    vfri2_bridge::gen_mldsa_v23_vfri9_hints(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri9_hints_log8_py(z, c, t1, a_hat, hints, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI9 hint generator for V23's LOG=8 component group (2206 columns).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, hints, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri9_hints_log8_py(
    z:                 Vec<Vec<i64>>,
    c:                 Vec<i64>,
    t1:                Vec<Vec<i64>>,
    a_hat:             Vec<Vec<i64>>,
    hints:             Vec<Vec<bool>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    let z_arr = _conv_z(z)?;
    let c_arr = _conv_c(c)?;
    let t1_arr = _conv_t1(t1)?;
    let a_hat_arr = _conv_a_hat(a_hat)?;
    let hints_arr = _conv_hints(hints)?;
    vfri2_bridge::gen_mldsa_v23_vfri9_hints_log8(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr, &hints_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri9_cross_bound_hints_py(z, c, t1, a_hat, hints, batch_root, n_queries, num_folds)
///   -> (proof10, commit10, hints10, proof8, commit8, hints8)
///
/// Two-pass cross-proof binding using VFRI9 (wide Poseidon2) backends:
///   bound_root_10 = keccak256(batch_root ‖ proof8[8:40])
///   bound_root_8  = keccak256(batch_root ‖ proof10[8:40])
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, hints, batch_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri9_cross_bound_hints_py(
    z:          Vec<Vec<i64>>,
    c:          Vec<i64>,
    t1:         Vec<Vec<i64>>,
    a_hat:      Vec<Vec<i64>>,
    hints:      Vec<Vec<bool>>,
    batch_root: Vec<u8>,
    n_queries:  usize,
    num_folds:  Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>, Vec<u8>, String, Vec<u8>)> {
    let z_arr = _conv_z(z)?;
    let c_arr = _conv_c(c)?;
    let t1_arr = _conv_t1(t1)?;
    let a_hat_arr = _conv_a_hat(a_hat)?;
    let hints_arr = _conv_hints(hints)?;
    vfri2_bridge::gen_mldsa_v23_vfri9_cross_bound_hints(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr, &hints_arr,
        &batch_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri10_hints_py(z, c, t1, a_hat, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI10 = VFRI9 protocol on the Poseidon2 t=4 hash backend (t=4 wide Merkle +
/// t=4 Fiat-Shamir channel). LOG=10 group (NttBatch + InttBatch, 1298 cols).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri10_hints_py(
    z:                 Vec<Vec<i64>>,
    c:                 Vec<i64>,
    t1:                Vec<Vec<i64>>,
    a_hat:             Vec<Vec<i64>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    let z_arr = _conv_z(z)?;
    let c_arr = _conv_c(c)?;
    let t1_arr = _conv_t1(t1)?;
    let a_hat_arr = _conv_a_hat(a_hat)?;
    vfri2_bridge::gen_mldsa_v23_vfri10_hints(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri10_hints_log8_py(z, c, t1, a_hat, hints, batch_merkle_root, n_queries, num_folds)
///   -> (proof: bytes, commitment: str, query_hints: bytes)
///
/// VFRI10 hint generator for V23's LOG=8 component group (2206 columns).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, hints, batch_merkle_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri10_hints_log8_py(
    z:                 Vec<Vec<i64>>,
    c:                 Vec<i64>,
    t1:                Vec<Vec<i64>>,
    a_hat:             Vec<Vec<i64>>,
    hints:             Vec<Vec<bool>>,
    batch_merkle_root: Vec<u8>,
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>)> {
    let z_arr = _conv_z(z)?;
    let c_arr = _conv_c(c)?;
    let t1_arr = _conv_t1(t1)?;
    let a_hat_arr = _conv_a_hat(a_hat)?;
    let hints_arr = _conv_hints(hints)?;
    vfri2_bridge::gen_mldsa_v23_vfri10_hints_log8(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr, &hints_arr,
        &batch_merkle_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// gen_mldsa_v23_vfri10_cross_bound_hints_py(z, c, t1, a_hat, hints, batch_root, n_queries, num_folds)
///   -> (proof10, commit10, hints10, proof8, commit8, hints8)
///
/// Two-pass cross-proof binding using VFRI10 (t=4 Poseidon2) backends:
///   bound_root_10 = keccak256(batch_root ‖ proof8[8:40])
///   bound_root_8  = keccak256(batch_root ‖ proof10[8:40])
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (z, c, t1, a_hat, hints, batch_root, n_queries=1, num_folds=None))]
fn gen_mldsa_v23_vfri10_cross_bound_hints_py(
    z:          Vec<Vec<i64>>,
    c:          Vec<i64>,
    t1:         Vec<Vec<i64>>,
    a_hat:      Vec<Vec<i64>>,
    hints:      Vec<Vec<bool>>,
    batch_root: Vec<u8>,
    n_queries:  usize,
    num_folds:  Option<usize>,
) -> PyResult<(Vec<u8>, String, Vec<u8>, Vec<u8>, String, Vec<u8>)> {
    let z_arr = _conv_z(z)?;
    let c_arr = _conv_c(c)?;
    let t1_arr = _conv_t1(t1)?;
    let a_hat_arr = _conv_a_hat(a_hat)?;
    let hints_arr = _conv_hints(hints)?;
    vfri2_bridge::gen_mldsa_v23_vfri10_cross_bound_hints(
        &z_arr, &c_arr, &t1_arr, &a_hat_arr, &hints_arr,
        &batch_root, n_queries, num_folds,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

#[cfg(feature = "python")]
#[pymodule]
fn qlsa_stark_stwo(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_prove, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify, m)?)?;
    m.add_function(wrap_pyfunction!(prove_p2, m)?)?;
    m.add_function(wrap_pyfunction!(verify_p2, m)?)?;
    m.add_function(wrap_pyfunction!(prove_merkle, m)?)?;
    m.add_function(wrap_pyfunction!(verify_merkle, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa, m)?)?;
    m.add_function(wrap_pyfunction!(prove_ntt_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_ntt_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_poly_mul_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_poly_mul_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_poly_add_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_poly_add_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_poly_sub_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_poly_sub_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_norm_check_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_norm_check_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_use_hint_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_use_hint_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_az_row_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_az_row_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_az_full_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_az_full_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_intt_bound_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_intt_bound_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_hint_weight_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_hint_weight_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v2_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v2_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v3_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v3_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v4_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v4_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v5_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v5_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v22_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v22_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v23_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v23_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v21_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v21_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v20_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v20_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v19_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v19_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v18_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v18_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v17_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v17_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v16_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v16_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v15_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v15_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v14_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v14_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v13_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v13_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v12_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v12_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v11_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v11_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v10_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v10_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v9_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v9_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v8_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v8_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v6_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v6_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_witness_v7_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_witness_v7_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_mldsa_sig_witness_py, m)?)?;
    m.add_function(wrap_pyfunction!(extract_mldsa_witness_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mldsa_hash_check_py, m)?)?;
    m.add_function(wrap_pyfunction!(prove_range_q_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_range_q_py, m)?)?;
    m.add_function(wrap_pyfunction!(wipe_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(gen_poseidon2_vfri2_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_poseidon2_vfri3_real_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_ntt_batch_vfri3_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_ntt_batch_vfri3_hints_nfolds_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri3_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_ntt_batch_vfri4_hints_nfolds_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_poseidon2_vfri4_real_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri4_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_ntt_batch_vfri5_hints_nfolds_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_ntt_batch_vfri6_hints_nfolds_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri6_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri6_hints_log8_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri7_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri7_hints_log8_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri7_cross_bound_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri8_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri8_hints_log8_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri8_cross_bound_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri9_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri9_hints_log8_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri9_cross_bound_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri10_hints_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri10_hints_log8_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_mldsa_v23_vfri10_cross_bound_hints_py, m)?)?;
    Ok(())
}

/// prove_poly_mul_py(a, b) -> (proof: bytes, commitment: str, product: list[int])
#[cfg(feature = "python")]
#[pyfunction]
fn prove_poly_mul_py(a: Vec<i64>, b: Vec<i64>) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let a_arr: [i64; 256] = a.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("a must have exactly 256 elements"))?;
    let b_arr: [i64; 256] = b.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("b must have exactly 256 elements"))?;
    let (proof, commitment, product) = prove_poly_mul(&a_arr, &b_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, product.to_vec()))
}

/// verify_poly_mul_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_poly_mul_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_poly_mul(&proof, &commitment).unwrap_or(false)
}

/// prove_poly_add_py(a, b) -> (proof: bytes, commitment: str, sum: list[int])
#[cfg(feature = "python")]
#[pyfunction]
fn prove_poly_add_py(a: Vec<i64>, b: Vec<i64>) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let a_arr: [i64; 256] = a.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("a must have exactly 256 elements"))?;
    let b_arr: [i64; 256] = b.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("b must have exactly 256 elements"))?;
    let (proof, commitment, sum) = prove_poly_add(&a_arr, &b_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, sum.to_vec()))
}

/// verify_poly_add_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_poly_add_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_poly_add(&proof, &commitment).unwrap_or(false)
}

/// prove_poly_sub_py(a, b) -> (proof: bytes, commitment: str, diff: list[int])
///
/// Proves c[i] = (a[i] − b[i]) mod Q for all i. Uses the poly_add AIR with negated b.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_poly_sub_py(a: Vec<i64>, b: Vec<i64>) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let a_arr: [i64; 256] = a.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("a must have exactly 256 elements"))?;
    let b_arr: [i64; 256] = b.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("b must have exactly 256 elements"))?;
    let (proof, commitment, diff) = prove_poly_sub(&a_arr, &b_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, diff.to_vec()))
}

/// verify_poly_sub_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_poly_sub_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_poly_sub(&proof, &commitment).unwrap_or(false)
}

/// prove_az_row_py(a_row, z_hat) -> (proof: bytes, commitment: str, az_hat: list[int])
///
/// Proves one row of the NTT-domain matrix-vector product Az̃[i] = Σ_j Ã[i][j] ⊙ z̃[j].
/// `a_row` is a list of 5 lists of 256 ints (ML-DSA-65: L=5).
/// `z_hat` is a list of 5 lists of 256 ints.
/// Returns `(proof_bytes, commitment_hex, az_hat)` where az_hat is 256 ints.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_az_row_py(
    a_row: Vec<Vec<i64>>,
    z_hat: Vec<Vec<i64>>,
) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let a_arr: [[i64; 256]; 5] = (0..5)
        .map(|j| {
            a_row.get(j)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("a_row must have 5 elements"))?
                .clone()
                .try_into()
                .map_err(|_| pyo3::exceptions::PyValueError::new_err("each a_row[j] must have 256 elements"))
        })
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("a_row must have exactly 5 lists"))?;

    let z_arr: [[i64; 256]; 5] = (0..5)
        .map(|j| {
            z_hat.get(j)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("z_hat must have 5 elements"))?
                .clone()
                .try_into()
                .map_err(|_| pyo3::exceptions::PyValueError::new_err("each z_hat[j] must have 256 elements"))
        })
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z_hat must have exactly 5 lists"))?;

    let (proof, commitment, az_hat) = prove_az_row(&a_arr, &z_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, az_hat.to_vec()))
}

/// verify_az_row_py(proof, commitment, z_hat) -> bool
///
/// `z_hat` must be a list of 5 lists of 256 ints — the same input used when proving.
#[cfg(feature = "python")]
#[pyfunction]
fn verify_az_row_py(proof: Vec<u8>, commitment: String, z_hat: Vec<Vec<i64>>) -> bool {
    let z_slices: Vec<[i64; 256]> = z_hat.into_iter()
        .map(|zj| zj.try_into().ok())
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    verify_az_row(&proof, &commitment, &z_slices).unwrap_or(false)
}

/// prove_az_full_py(a_hat, z_hat, c_tilde=None) -> (proof: bytes, commitment: str, az_out: list[list[int]])
///
/// Proves all K=6 rows of Az in one STARK.
/// `a_hat` — list of K*L=30 lists of 256 ints (row-major: a_hat[i*L+j] = Ã[i][j]).
/// `z_hat` — list of L=5 lists of 256 ints.
/// `c_tilde` — optional bytes; if provided, mixed into Fiat-Shamir channel as public input.
/// Returns `(proof_bytes, commitment_hex, az_out)` where az_out is K lists of 256 ints.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z_hat, c_tilde=None))]
fn prove_az_full_py(
    a_hat:   Vec<Vec<i64>>,
    z_hat:   Vec<Vec<i64>>,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, String, Vec<Vec<i64>>)> {
    use mldsa::params::{K, L};
    if a_hat.len() != K * L {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("a_hat must have K*L={} lists, got {}", K * L, a_hat.len())
        ));
    }
    if z_hat.len() != L {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("z_hat must have L={} lists, got {}", L, z_hat.len())
        ));
    }
    let a_arr: Vec<[i64; 256]> = a_hat.into_iter()
        .map(|row| row.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("each a_hat[k] must have 256 elements")))
        .collect::<PyResult<_>>()?;
    let z_arr: [[i64; 256]; 5] = (0..L)
        .map(|j| z_hat[j].clone().try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("each z_hat[j] must have 256 elements")))
        .collect::<PyResult<Vec<[i64; 256]>>>()?
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z_hat must have exactly L=5 lists"))?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);
    let (proof, commitment, az_out) = prove_az_full(&a_arr, &z_arr, seed)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    let az_out_py: Vec<Vec<i64>> = az_out.iter().map(|row| row.to_vec()).collect();
    Ok((proof, commitment, az_out_py))
}

/// verify_az_full_py(proof, commitment, z_hat, c_tilde=None) -> bool
///
/// `z_hat` must be the same L=5 lists of 256 ints used when proving.
/// `c_tilde` must match the value passed during proving (if any).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (proof, commitment, z_hat, c_tilde=None))]
fn verify_az_full_py(
    proof:      Vec<u8>,
    commitment: String,
    z_hat:      Vec<Vec<i64>>,
    c_tilde:    Option<Vec<u8>>,
) -> bool {
    use mldsa::params::L;
    let z_arr: [[i64; 256]; 5] = match (0..L)
        .map(|j| z_hat.get(j).and_then(|zj| zj.clone().try_into().ok()))
        .collect::<Option<Vec<[i64; 256]>>>()
        .and_then(|v| v.try_into().ok())
    {
        Some(a) => a,
        None => return false,
    };
    let seed = c_tilde.as_deref().unwrap_or(&[]);
    verify_az_full(&proof, &commitment, &z_arr, seed).unwrap_or(false)
}

/// prove_intt_bound_py(f) -> (proof: bytes, commitment: str)
///
/// Like `prove_intt` but also mixes the input fingerprint of `f` into the
/// Fiat-Shamir channel before the output fingerprint, binding the proof to the
/// specific input polynomial.  Use `verify_intt_bound_py` to verify.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_intt_bound_py(f: Vec<i64>) -> PyResult<(Vec<u8>, String)> {
    use mldsa_verify_stark::prove_intt_with_binding;
    let f_arr: [i64; 256] = f.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("f must have exactly 256 elements"))?;
    let (proof, commitment, _out) = prove_intt_with_binding(&f_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment))
}

/// verify_intt_bound_py(proof, commitment, input) -> bool
///
/// Verify an INTT proof produced by `prove_intt_bound_py`.
/// `input` must be the same 256-element list of ints that was passed to the prover.
#[cfg(feature = "python")]
#[pyfunction]
fn verify_intt_bound_py(proof: Vec<u8>, commitment: String, input: Vec<i64>) -> bool {
    use mldsa_verify_stark::verify_intt_with_binding;
    let input_arr: [i64; 256] = match input.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    verify_intt_with_binding(&proof, &commitment, &input_arr).unwrap_or(false)
}

/// prove_hint_weight_py(hints) -> (proof: bytes, commitment: str, total_weight: int)
///
/// `hints` must be a list of K=6 lists of N=256 booleans.
/// Returns a STARK proof that each bit ∈ {0,1} and the running sum is sequential.
/// The caller checks `total_weight ≤ 55` (ML-DSA-65 ω bound).
#[cfg(feature = "python")]
#[pyfunction]
fn prove_hint_weight_py(hints: Vec<Vec<bool>>) -> PyResult<(Vec<u8>, String, usize)> {
    prove_hint_weight(&hints)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// verify_hint_weight_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_hint_weight_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_hint_weight(&proof, &commitment).unwrap_or(false)
}

/// prove_norm_check_py(z) -> (proof: bytes, commitment: str, norm: list[int], max_norm: int)
///
/// Proves norm[i] = min(z[i], Q − z[i]) for all i.
/// Returns also `max_norm` = ||z||_∞  for external bound checking (must be < γ₁ − β = 524092).
#[cfg(feature = "python")]
#[pyfunction]
fn prove_norm_check_py(z: Vec<i64>) -> PyResult<(Vec<u8>, String, Vec<i64>, i64)> {
    let z_arr: [i64; 256] = z.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("z must have exactly 256 elements"))?;
    let (proof, commitment, norm, max_norm) = prove_norm_check(&z_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, norm.to_vec(), max_norm))
}

/// verify_norm_check_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_norm_check_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_norm_check(&proof, &commitment).unwrap_or(false)
}

/// prove_use_hint_py(r, h_bits) -> (proof: bytes, commitment: str, w1: list[int])
///
/// Proves UseHint(h_bits[i], r[i]) = w1[i] for all 256 coefficients.
/// `r` must be 256 ints in [0, Q).  `h_bits` must be 256 bools.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_use_hint_py(r: Vec<i64>, h_bits: Vec<bool>) -> PyResult<(Vec<u8>, String, Vec<i64>)> {
    let r_arr: [i64; 256] = r.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("r must have exactly 256 elements"))?;
    let h_arr: [bool; 256] = h_bits.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("h_bits must have exactly 256 elements"))?;
    let (proof, commitment, w1) = prove_use_hint(&r_arr, &h_arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;
    Ok((proof, commitment, w1.to_vec()))
}

/// verify_use_hint_py(proof, commitment) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_use_hint_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_use_hint(&proof, &commitment).unwrap_or(false)
}

// ── ML-DSA full arithmetic witness pipeline ───────────────────────────────────

/// prove_mldsa_witness_py(a_hat, z, c, t1, hints, k, l)
///   -> (proof_bundle: bytes, max_norms: list[int], w1_prime: list[list[int]])
///
/// Proves the full ML-DSA.Verify arithmetic witness:
///   Az  →  c·t₁  →  poly_sub  →  norm_check  →  UseHint
///
/// Inputs (all coefficients in [0, Q)):
///   a_hat : k*l flat list of 256-int polynomials (NTT-domain, row-major)
///   z     : l polynomials (signature)
///   c     : 256-int challenge polynomial
///   t1    : k polynomials (public key components)
///   hints : k lists of 256 bools (hint bits from the signature)
///   k, l  : matrix dimensions (ML-DSA-65: k=6, l=5)
///
/// Returns:
///   proof_bundle : bincode-serialized VerifyMldsaProof (pass to verify_mldsa_witness_py)
///   max_norms    : l values — ||z[j]||_∞; caller checks each < 524 092
///   w1_prime     : k rows of 256 ints — UseHint outputs for hash comparison
#[cfg(feature = "python")]
#[pyfunction]
fn prove_mldsa_witness_py(
    a_hat:  Vec<Vec<i64>>,
    z:      Vec<Vec<i64>>,
    c:      Vec<i64>,
    t1:     Vec<Vec<i64>>,
    hints:  Vec<Vec<bool>>,
    k:      usize,
    l:      usize,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>)> {
    // Convert Vec<Vec<i64>> → Vec<[i64; 256]>.
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;

    // Convert hints Vec<Vec<bool>> → Vec<Vec<bool>> (already the right type).
    let hints_vv: Vec<Vec<bool>> = hints;

    let proof = mldsa_verify_stark::prove_verify_mldsa_witness(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints_vv, k, l,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.w1_prime.iter().map(|p| p.to_vec()).collect();

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime))
}

/// verify_mldsa_witness_py(proof_bundle: bytes) -> bool
///
/// Verifies all STARK sub-proofs in a bundle produced by prove_mldsa_witness_py.
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProof, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_proofs(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v2_py — same interface as prove_mldsa_witness_py but uses
/// the Az-row AIR circuit (53 sub-proofs vs 101). Requires l = 5 (ML-DSA-65).
#[cfg(feature = "python")]
#[pyfunction]
fn prove_mldsa_witness_v2_py(
    a_hat:  Vec<Vec<i64>>,
    z:      Vec<Vec<i64>>,
    c:      Vec<i64>,
    t1:     Vec<Vec<i64>>,
    hints:  Vec<Vec<bool>>,
    k:      usize,
    l:      usize,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;

    let proof = mldsa_verify_stark::prove_verify_mldsa_v2(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.w1_prime.iter().map(|p| p.to_vec()).collect();

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime))
}

/// verify_mldsa_witness_v2_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v2_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV2, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v2(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v3_py — full-matrix Az AIR + hint weight proof (49 sub-proofs).
///
/// Returns `(bundle: bytes, max_norms: list[int], w1_prime: list[list[int]], hint_weight_total: int)`.
/// Requires k = 6, l = 5 (ML-DSA-65).
/// `c_tilde` — optional bytes; if provided, mixed into Fiat-Shamir as STARK public input.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v3_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v3(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.w1_prime.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v3_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v3_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV3, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v3(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v4_py — Ct1-full AIR (50 sub-proofs, saves 5 vs V3).
///
/// Returns `(bundle: bytes, max_norms: list[int], w1_prime: list[list[int]], hint_weight_total: int)`.
/// Requires k = 6, l = 5 (ML-DSA-65).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v4_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v4(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.w1_prime.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v4_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v4_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV4, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v4(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v5_py — WPrime-full AIR (45 sub-proofs, saves 5 vs V4).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v5_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v5(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.w1_prime.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v5_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v5_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV5, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v5(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v8_py — RangeQ-batch AIR (31 sub-proofs, saves 5 vs V7).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v8_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v8(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v8_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v8_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV8, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v8(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v6_py — NormCheck-batch AIR (41 sub-proofs, saves 4 vs V5).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v6_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v6(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.w1_prime.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v6_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v6_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV6, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v6(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v7_py — UseHint-batch AIR (36 sub-proofs, saves 5 vs V6).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v7_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v7(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v7_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v7_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV7, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v7(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v9_py — batch INTT for Az (26 sub-proofs, saves 5 vs V8).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v9_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v9(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v9_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v9_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV9, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v9(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v10_py — batch NTT-t1 + batch INTT-ct1 (16 sub-proofs, saves 10 vs V9).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v10_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v10(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v10_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v10_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV10, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v10(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v19_py — NTT+Az+Ct1 merged multi-component STARK (3 sub-proofs).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v19_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };
    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v19(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_use_hint_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.norm_use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.norm_use_hint_proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;
    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v19_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v19_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV19, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v19(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v21_py — single 7-component STARK (1 sub-proof total, the minimum).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v21_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };
    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v21(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;
    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v21_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v21_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV21, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v21(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v22_py — V21 + Merkle root bound into Fiat-Shamir transcript.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None, merkle_root=None))]
fn prove_mldsa_witness_v22_py(
    a_hat:       Vec<Vec<i64>>,
    z:           Vec<Vec<i64>>,
    c:           Vec<i64>,
    t1:          Vec<Vec<i64>>,
    hints:       Vec<Vec<bool>>,
    k:           usize,
    l:           usize,
    c_tilde:     Option<Vec<u8>>,
    merkle_root: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };
    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr   = to_poly_vec(t1, "t1")?;
    let seed     = c_tilde.as_deref().unwrap_or(&[]);
    let root     = merkle_root.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v22(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed, root,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;
    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;
    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v22_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v22_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV22, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v22(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v23_py — V22 + RangeQBatch (8-component STARK, 3504 main cols + 1 preproc).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None, merkle_root=None))]
fn prove_mldsa_witness_v23_py(
    a_hat:       Vec<Vec<i64>>,
    z:           Vec<Vec<i64>>,
    c:           Vec<i64>,
    t1:          Vec<Vec<i64>>,
    hints:       Vec<Vec<bool>>,
    k:           usize,
    l:           usize,
    c_tilde:     Option<Vec<u8>>,
    merkle_root: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };
    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr   = to_poly_vec(t1, "t1")?;
    let seed     = c_tilde.as_deref().unwrap_or(&[]);
    let root     = merkle_root.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v23(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed, root,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;
    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;
    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v23_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v23_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV23, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v23(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v20_py — 4-component INTT+WPrime+Norm+UseHint STARK (2 sub-proofs total).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v20_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };
    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v20(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.intt_wp_norm_uh_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.intt_wp_norm_uh_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.intt_wp_norm_uh_proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;
    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v20_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v20_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV20, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v20(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v18_py — INTT+WPrime merged multi-component STARK (4 sub-proofs).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v18_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };
    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v18(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_use_hint_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.norm_use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.norm_use_hint_proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;
    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v18_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v18_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV18, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v18(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v17_py — NormCheck+UseHintBatchV2 merged (5 sub-proofs).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v17_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };
    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v17(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_use_hint_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.norm_use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.norm_use_hint_proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;
    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v17_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v17_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV17, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v17(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v16_py — Az+Ct1 merged multi-component STARK (6 sub-proofs).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v16_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };
    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v16(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.use_hint_proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;
    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v16_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v16_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV16, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v16(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v15_py — UseHintBatchV2+HintWeight merged (7 sub-proofs).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v15_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };
    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v15(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.use_hint_proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;
    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v15_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v15_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV15, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v15(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v14_py — merged INTT+WPrime (8 sub-proofs, saves 1 vs V13).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v14_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };
    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v14(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;
    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v14_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v14_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV14, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v14(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v13_py — combined INTT az+ct1 (9 sub-proofs, saves 1 vs V12).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v13_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };
    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v13(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;
    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v13_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v13_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV13, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v13(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v12_py — combined NTT for z+c+t1 (10 sub-proofs, saves 2 vs V11).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v12_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v12(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v12_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v12_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV12, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v12(&proof).unwrap_or(false)
}

/// prove_mldsa_witness_v11_py — batch NTT-z for Az (12 sub-proofs, saves 4 vs V10).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (a_hat, z, c, t1, hints, k, l, c_tilde=None))]
fn prove_mldsa_witness_v11_py(
    a_hat:   Vec<Vec<i64>>,
    z:       Vec<Vec<i64>>,
    c:       Vec<i64>,
    t1:      Vec<Vec<i64>>,
    hints:   Vec<Vec<bool>>,
    k:       usize,
    l:       usize,
    c_tilde: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, usize)> {
    let to_poly_vec = |vv: Vec<Vec<i64>>, name: &str| -> PyResult<Vec<[i64; 256]>> {
        vv.into_iter().enumerate().map(|(i, v)| {
            v.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err(
                format!("{name}[{i}] must have exactly 256 elements")
            ))
        }).collect()
    };

    let a_hat_arr = to_poly_vec(a_hat, "a_hat")?;
    let z_arr     = to_poly_vec(z,     "z")?;
    let c_arr: [i64; 256] = c.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("c must have exactly 256 elements"))?;
    let t1_arr  = to_poly_vec(t1, "t1")?;
    let seed = c_tilde.as_deref().unwrap_or(&[]);

    let proof = mldsa_verify_stark::prove_verify_mldsa_v11(
        &a_hat_arr, &z_arr, &c_arr, &t1_arr, &hints, k, l, seed,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms = proof.norm_proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.use_hint_proof.output.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    Ok((bundle, max_norms, w1_prime, hint_weight_total))
}

/// verify_mldsa_witness_v11_py(proof_bundle: bytes) -> bool
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_witness_v11_py(proof_bundle: Vec<u8>) -> bool {
    let Ok((proof, _)) = bincode::decode_from_slice::<
        mldsa_verify_stark::VerifyMldsaProofV11, _
    >(&proof_bundle, bincode::config::standard().with_limit::<MAX_PROOF_BYTES>()) else {
        return false;
    };
    mldsa_verify_stark::verify_mldsa_witness_v11(&proof).unwrap_or(false)
}

/// prove_mldsa_sig_witness_py(pk: bytes, msg: bytes, sig: bytes)
///   -> (proof_bundle: bytes, max_norms: list[int], w1_prime: list[list[int]])
///
/// End-to-end function: decodes an ML-DSA-65 signature, verifies it, then
/// proves the full arithmetic witness pipeline:
///   Az  →  c·t₁·2^d  →  poly_sub  →  norm_check  →  UseHint
///
/// Raises PyRuntimeError if the signature is invalid or any sub-proof fails.
#[cfg(feature = "python")]
#[pyfunction]
fn prove_mldsa_sig_witness_py(
    pk:  Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<i64>, Vec<Vec<i64>>, String, String, usize)> {
    use mldsa::encoding::{pk_decode, sig_decode};
    use mldsa::xof::{expand_a, sample_in_ball};
    use mldsa::field;
    use mldsa::params::{K, L, D};
    use mldsa::N;

    // Verify first — reject invalid signatures immediately.
    if !mldsa::verify::ml_dsa_verify(&pk, &msg, &sig) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "ML-DSA-65 signature verification failed — cannot prove invalid witness"
        ));
    }

    // Decode public key: rho + t1 (K polynomials in [0, 2^T1_BITS)).
    let (rho, t1) = pk_decode(&pk)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(
            format!("pk_decode failed: {e}")
        ))?;

    // Decode signature: c_tilde + z (L polys, signed) + hints (K × N bools).
    let (c_tilde, z, hints) = sig_decode(&sig)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(
            format!("sig_decode failed: {e}")
        ))?;

    // a_hat = ExpandA(rho) — K×L NTT-domain matrix (already in [0, Q)).
    let a_hat_matrix = expand_a(&rho);
    let mut a_hat_flat: Vec<[i64; N]> = Vec::with_capacity(K * L);
    for row in &a_hat_matrix.rows {
        for poly in &row.0 {
            a_hat_flat.push(poly.coeffs);
        }
    }

    // c = SampleInBall(c_tilde) — challenge polynomial.
    let c_poly = sample_in_ball(&c_tilde);
    // Reduce challenge to [0, Q) (SampleInBall produces coeffs ∈ {-1, 0, 1}).
    let mut c_arr = [0i64; N];
    for (i, &v) in c_poly.coeffs.iter().enumerate() {
        c_arr[i] = field::reduce(v);
    }

    // z_reduced: signature z polynomials reduced from signed to [0, Q).
    let mut z_arr: Vec<[i64; N]> = Vec::with_capacity(L);
    for poly in &z.0 {
        let mut coeffs = [0i64; N];
        for (i, &v) in poly.coeffs.iter().enumerate() {
            coeffs[i] = field::reduce(v);
        }
        z_arr.push(coeffs);
    }

    // t1_scaled = t1 * 2^D mod Q — the FIPS 204 scaling of public key components.
    let t1_scaled = t1.scale_power2(D);
    let mut t1_arr: Vec<[i64; N]> = Vec::with_capacity(K);
    for poly in &t1_scaled.0 {
        t1_arr.push(poly.coeffs);
    }

    // Run the full V3 STARK witness pipeline (Az-full AIR + hint weight, 49 sub-proofs).
    // c_tilde is mixed into the Az-full Fiat-Shamir channel as a STARK public input,
    // binding the proof to this specific signature challenge.
    let proof = mldsa_verify_stark::prove_verify_mldsa_v3(
        &a_hat_flat, &z_arr, &c_arr, &t1_arr, &hints, K, L, &c_tilde,
    ).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

    let max_norms       = proof.max_norms.clone();
    let w1_prime: Vec<Vec<i64>> = proof.w1_prime.iter().map(|p| p.to_vec()).collect();
    let hint_weight_total = proof.hint_weight_total;

    let bundle = bincode::encode_to_vec(&proof, bincode::config::standard())
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("bincode serialize failed: {e}")
        ))?;

    // onchain_commitment = Blake2s(bundle[:32] ∥ c_tilde[:32])[:16]
    let binding_input: Vec<u8> = bundle[..32.min(bundle.len())]
        .iter()
        .chain(c_tilde.iter().take(32))
        .copied()
        .collect();
    use blake2::{Blake2s256, Digest};
    let digest = Blake2s256::digest(&binding_input);
    let onchain_commitment = hex::encode(&digest[..16]);

    // c_tilde as hex — lets the caller re-derive the hash check off-circuit.
    let c_tilde_hex = hex::encode(&c_tilde);

    Ok((bundle, max_norms, w1_prime, onchain_commitment, c_tilde_hex, hint_weight_total))
}

/// extract_mldsa_witness_py(pk, msg, sig) -> (z, c, t1, a_hat, hints)
///
/// Decodes an ML-DSA-65 signature and returns the arithmetic witness components
/// needed by gen_mldsa_v23_vfri7_cross_bound_hints_py.
///
/// Returns:
///   z:     L=5 polynomials of 256 coefficients each, reduced to [0, Q)
///   c:     challenge polynomial, 256 coefficients in [0, Q)
///   t1:    K=6 public-key polynomials scaled by 2^D, 256 coefficients each
///   a_hat: K×L=30 NTT matrix polynomials, 256 coefficients each
///   hints: K=6 UseHint boolean arrays, 256 booleans each
///
/// Raises ValueError if the signature fails ML-DSA-65 verification.
#[cfg(feature = "python")]
#[pyfunction]
fn extract_mldsa_witness_py(
    pk:  Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
) -> PyResult<(Vec<Vec<i64>>, Vec<i64>, Vec<Vec<i64>>, Vec<Vec<i64>>, Vec<Vec<bool>>)> {
    use mldsa::encoding::{pk_decode, sig_decode};
    use mldsa::xof::{expand_a, sample_in_ball};
    use mldsa::field;
    use mldsa::params::D;

    if !mldsa::verify::ml_dsa_verify(&pk, &msg, &sig) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "ML-DSA-65 signature verification failed — cannot extract witness for invalid signature"
        ));
    }

    let (rho, t1) = pk_decode(&pk)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("pk_decode failed: {e}")))?;
    let (c_tilde, z, hints) = sig_decode(&sig)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("sig_decode failed: {e}")))?;

    let a_hat_matrix = expand_a(&rho);
    let a_hat_flat: Vec<Vec<i64>> = a_hat_matrix.rows.iter()
        .flat_map(|row| row.0.iter().map(|poly| poly.coeffs.to_vec()))
        .collect();

    let c_poly = sample_in_ball(&c_tilde);
    let c_arr: Vec<i64> = c_poly.coeffs.iter().map(|&v| field::reduce(v)).collect();

    let z_arr: Vec<Vec<i64>> = z.0.iter()
        .map(|poly| poly.coeffs.iter().map(|&v| field::reduce(v)).collect())
        .collect();

    let t1_scaled = t1.scale_power2(D);
    let t1_arr: Vec<Vec<i64>> = t1_scaled.0.iter()
        .map(|poly| poly.coeffs.to_vec())
        .collect();

    Ok((z_arr, c_arr, t1_arr, a_hat_flat, hints))
}

/// prove_range_q_py(poly: list[int]) -> (proof: bytes, commitment: str)
///
/// Proves all 256 coefficients of `poly` are in [0, Q) using the 48-column
/// Circle STARK range-check circuit.  Raises ValueError if any coefficient
/// is outside [0, Q).
#[cfg(feature = "python")]
#[pyfunction]
fn prove_range_q_py(poly: Vec<i64>) -> PyResult<(Vec<u8>, String)> {
    let arr: [i64; mldsa::N] = poly.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err(
            "poly must have exactly 256 elements"
        ))?;
    prove_range_q(&arr)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// verify_range_q_py(proof: bytes, commitment: str) -> bool
///
/// Verifies a proof produced by `prove_range_q_py`.
#[cfg(feature = "python")]
#[pyfunction]
fn verify_range_q_py(proof: Vec<u8>, commitment: String) -> bool {
    verify_range_q(&proof, &commitment).unwrap_or(false)
}

/// verify_mldsa_hash_check_py(pk, msg, w1_prime, c_tilde_hex) -> bool
///
/// Off-circuit ML-DSA.Verify hash step: recomputes
///   μ = SHAKE-256(SHAKE-256(pk) ∥ M')
///   c̃' = SHAKE-256(μ ∥ w1Encode(w1_prime))
/// and checks that c̃' == c_tilde.
///
/// This ties the STARK witness (w1_prime) back to the original message and
/// public key, completing the logical chain of ML-DSA.Verify.
///
/// `pk`         — raw public key bytes (PK_BYTES = 1952 for ML-DSA-65).
/// `msg`        — original message bytes.
/// `w1_prime`   — K rows × N coefficients (UseHint output, values in [0, m=16)).
/// `c_tilde_hex`— hex-encoded c_tilde returned by prove_mldsa_sig_witness_py.
#[cfg(feature = "python")]
#[pyfunction]
fn verify_mldsa_hash_check_py(
    pk:          Vec<u8>,
    msg:         Vec<u8>,
    w1_prime:    Vec<Vec<i64>>,
    c_tilde_hex: String,
) -> PyResult<bool> {
    use mldsa::xof::{hash_pk, hash_mu, hash_commit};
    use mldsa::encoding::w1_encode;
    use mldsa::polyvec::PolyVec;
    use mldsa::poly::Poly;
    use mldsa::params::{K, LAMBDA_BYTES};
    use mldsa::N;

    // Decode w1_prime into PolyVec.
    if w1_prime.len() != K {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("w1_prime must have K={K} rows, got {}", w1_prime.len())
        ));
    }
    let w1_polyvec = PolyVec(w1_prime.into_iter().map(|row| {
        let coeffs: [i64; N] = row.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err(
                "each w1_prime row must have exactly 256 elements"
            ))?;
        Ok(Poly::from_coeffs(coeffs))
    }).collect::<PyResult<Vec<_>>>()?);

    // Decode c_tilde from hex.
    let c_tilde = hex::decode(&c_tilde_hex)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(
            format!("c_tilde_hex is not valid hex: {e}")
        ))?;
    if c_tilde.len() != LAMBDA_BYTES {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("c_tilde must be {LAMBDA_BYTES} bytes, got {}", c_tilde.len())
        ));
    }

    // Recompute μ = SHAKE-256(tr ∥ M')  where M' = [0x00, 0x00] ∥ msg.
    let tr = hash_pk(&pk);
    let mut m_prime = vec![0u8, 0u8];
    m_prime.extend_from_slice(&msg);
    let mu = hash_mu(&tr, &m_prime);

    // Recompute c̃' = SHAKE-256(μ ∥ w1Encode(w1_prime), LAMBDA_BYTES).
    let w1_enc = w1_encode(&w1_polyvec);
    let c_tilde_prime = hash_commit(&mu, &w1_enc, LAMBDA_BYTES);

    Ok(c_tilde_prime == c_tilde)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::{BaseField, M31};
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
            prove_hash_chain(&leaves, &[]).expect("proving failed");
        let valid = verify_hash_chain(&proof_bytes, &commitment_hex, log_size, &[])
            .expect("verification failed");
        assert!(valid);
    }

    #[test]
    fn test_hash_chain_merkle_root_binding() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let root_a = b"merkle_root_batch_A_64_bytes_padding_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let root_b = b"merkle_root_batch_B_64_bytes_padding_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain(&leaves, root_a).expect("proving failed");

        // Same root → must verify.
        let ok = verify_hash_chain(&proof_bytes, &commitment_hex, log_size, root_a)
            .expect("verify failed");
        assert!(ok, "same root must verify");

        // Different root → must fail (different FRI query positions).
        let fail = verify_hash_chain(&proof_bytes, &commitment_hex, log_size, root_b)
            .unwrap_or(false);
        assert!(!fail, "different root must not verify");
    }

    // ── Poseidon2 tests ───────────────────────────────────────────────────────

    #[test]
    fn test_poseidon2_prove_and_verify() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain_poseidon2(&leaves, &[]).expect("poseidon2 proving failed");
        let valid = verify_hash_chain_poseidon2(&proof_bytes, &commitment_hex, log_size, &[])
            .expect("poseidon2 verification failed");
        assert!(valid);
    }

    #[test]
    fn test_poseidon2_commitment_matches_chain() {
        use poseidon2::poseidon2_chain;
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (_, commitment_hex, _) =
            prove_hash_chain_poseidon2(&leaves, &[]).expect("poseidon2 proving failed");
        let (expected_s0, _) = poseidon2_chain(&leaves);
        let expected_m31_hex = hex::encode(BaseField::from_u32_unchecked(expected_s0 as u32).0.to_le_bytes());
        // Commitment is now 128-bit; the first 8 chars (4 bytes) encode the M31 value.
        assert_eq!(&commitment_hex[..8], expected_m31_hex);
    }

    #[test]
    fn test_poseidon2_tampered_proof_fails() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain_poseidon2(&leaves, &[]).expect("poseidon2 proving failed");
        let mut bad_proof = proof_bytes.clone();
        bad_proof[20] ^= 0xFF;
        let result = verify_hash_chain_poseidon2(&bad_proof, &commitment_hex, log_size, &[])
            .unwrap_or(false);
        assert!(!result);
    }

    #[test]
    fn test_poseidon2_seed_binds_proof() {
        // A proof generated with seed_a must NOT verify against seed_b.
        // The seed is mixed into the Fiat-Shamir channel before the first tree commit,
        // so any seed mismatch causes divergent FRI query positions → verification fails.
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let seed_a = b"batch_merkle_root_32_bytes_aaaaaa";
        let seed_b = b"batch_merkle_root_32_bytes_bbbbbb";

        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain_poseidon2(&leaves, seed_a).expect("poseidon2 proving failed");

        // Same seed → should verify.
        assert!(
            verify_hash_chain_poseidon2(&proof_bytes, &commitment_hex, log_size, seed_a)
                .unwrap_or(false),
            "proof should verify with correct seed"
        );

        // Different seed → should fail.
        assert!(
            !verify_hash_chain_poseidon2(&proof_bytes, &commitment_hex, log_size, seed_b)
                .unwrap_or(false),
            "proof should NOT verify with wrong seed"
        );

        // Empty seed → should also fail.
        assert!(
            !verify_hash_chain_poseidon2(&proof_bytes, &commitment_hex, log_size, &[])
                .unwrap_or(false),
            "proof should NOT verify with no seed when proven with seed"
        );
    }

    #[test]
    fn test_merkle_seed_binds_proof() {
        let leaves = vec![1u64, 2, 3, 4];
        let seed_a = b"merkle_seed_aaaaaaaaaaaaaaaaaaaaa";
        let seed_b = b"merkle_seed_bbbbbbbbbbbbbbbbbbbbb";

        let (proof_bytes, commitment_hex, log_size) =
            prove_merkle_root(&leaves, seed_a).expect("merkle proving failed");

        assert!(
            verify_merkle_root(&proof_bytes, &commitment_hex, log_size, seed_a)
                .unwrap_or(false),
            "proof should verify with correct seed"
        );
        assert!(
            !verify_merkle_root(&proof_bytes, &commitment_hex, log_size, seed_b)
                .unwrap_or(false),
            "proof should NOT verify with wrong seed"
        );
    }

    #[test]
    fn test_wrong_commitment_fails_hash_chain() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain(&leaves, &[]).expect("proving failed");
        // Mutate the M31 component (bytes [0:4]) — the suffix check will catch it.
        let bad_commitment = {
            let mut bytes = hex::decode(&commitment_hex).unwrap();
            let mut val = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            val = val.wrapping_add(1) % M31_MODULUS;
            bytes[0..4].copy_from_slice(&val.to_le_bytes());
            hex::encode(&bytes)
        };
        // Wrong commitment → suffix mismatch; parse_commitment_128 returns Err → false.
        let result = verify_hash_chain(&proof_bytes, &bad_commitment, log_size, &[])
            .unwrap_or(false);
        assert!(!result, "wrong commitment should cause verification failure");
    }

    #[test]
    fn test_wrong_commitment_fails_poseidon2() {
        let leaves = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain_poseidon2(&leaves, &[]).expect("poseidon2 proving failed");
        let bad_commitment = {
            let mut bytes = hex::decode(&commitment_hex).unwrap();
            let mut val = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            val = val.wrapping_add(1) % M31_MODULUS;
            bytes[0..4].copy_from_slice(&val.to_le_bytes());
            hex::encode(&bytes)
        };
        let result = verify_hash_chain_poseidon2(&proof_bytes, &bad_commitment, log_size, &[])
            .unwrap_or(false);
        assert!(!result, "wrong commitment should cause poseidon2 verification failure");
    }

    #[test]
    fn test_poseidon2_one_leaf() {
        // log_size=3 is the minimum; exercises the smallest valid Poseidon2 trace.
        let leaves = vec![999u64];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain_poseidon2(&leaves, &[]).expect("proving failed");
        assert_eq!(log_size, 3);
        let valid = verify_hash_chain_poseidon2(&proof_bytes, &commitment_hex, log_size, &[])
            .expect("verification failed");
        assert!(valid);
    }

    #[test]
    fn test_poseidon2_two_leaves() {
        // log_size=4; exercises the 2-leaf case used by prove_mldsa_batch.
        let leaves = vec![1u64, 2];
        let (proof_bytes, commitment_hex, log_size) =
            prove_hash_chain_poseidon2(&leaves, &[]).expect("proving failed");
        assert_eq!(log_size, 4);
        let valid = verify_hash_chain_poseidon2(&proof_bytes, &commitment_hex, log_size, &[])
            .expect("verification failed");
        assert!(valid);
    }

    #[test]
    fn test_wrong_commitment_fails_merkle() {
        let leaves = vec![1u64, 2, 3, 4];
        let (proof_bytes, commitment_hex, log_size) =
            prove_merkle_root(&leaves, &[]).expect("merkle proving failed");
        let bad_commitment = {
            let mut bytes = hex::decode(&commitment_hex).unwrap();
            let mut val = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            val = val.wrapping_add(1) % M31_MODULUS;
            bytes[0..4].copy_from_slice(&val.to_le_bytes());
            hex::encode(&bytes)
        };
        let result = verify_merkle_root(&proof_bytes, &bad_commitment, log_size, &[])
            .unwrap_or(false);
        assert!(!result, "wrong commitment should cause merkle verification failure");
    }

    // ── Poseidon2 Merkle tests ────────────────────────────────────────────────

    #[test]
    fn test_merkle_prove_and_verify() {
        let leaves = vec![1u64, 2, 3, 4];
        let (proof_bytes, commitment_hex, log_size) =
            prove_merkle_root(&leaves, &[]).expect("merkle proving failed");
        let valid = verify_merkle_root(&proof_bytes, &commitment_hex, log_size, &[])
            .expect("merkle verification failed");
        assert!(valid);
    }

    #[test]
    fn test_merkle_commitment_matches_root() {
        let leaves = vec![10u64, 20, 30, 40];
        let (_, commitment_hex, _) =
            prove_merkle_root(&leaves, &[]).expect("merkle proving failed");
        let expected = poseidon2_merkle_air::merkle_root(&leaves);
        let expected_m31_hex =
            hex::encode(BaseField::from_u32_unchecked(expected as u32).0.to_le_bytes());
        // Commitment is now 128-bit; the first 8 chars (4 bytes) encode the Merkle root M31.
        assert_eq!(&commitment_hex[..8], expected_m31_hex);
    }

    #[test]
    fn test_merkle_tampered_proof_fails() {
        let leaves = vec![1u64, 2, 3, 4];
        let (proof_bytes, commitment_hex, log_size) =
            prove_merkle_root(&leaves, &[]).expect("merkle proving failed");
        let mut bad_proof = proof_bytes.clone();
        bad_proof[20] ^= 0xFF;
        let result = verify_merkle_root(&bad_proof, &commitment_hex, log_size, &[])
            .unwrap_or(false);
        assert!(!result);
    }

    // ── NTT STARK prover/verifier tests (MVP-3+) ─────────────────────────────

    fn random_ntt_input(seed: u64) -> [i64; 256] {
        let q = mldsa::Q;
        let mut state = seed;
        let mut f = [0i64; 256];
        for c in f.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *c = ((state >> 33) as i64).abs() % q;
        }
        f
    }

    #[test]
    fn test_prove_and_verify_ntt() {
        let f = random_ntt_input(0xc0ffee);
        let (proof_bytes, commitment_hex, ntt_out) =
            prove_ntt(&f).expect("NTT proving failed");

        // Output must match the reference NTT.
        let mut expected = f;
        mldsa::ntt::ntt(&mut expected);
        assert_eq!(ntt_out, expected, "NTT output mismatch");

        // Proof must verify.
        let valid = verify_ntt(&proof_bytes, &commitment_hex).expect("NTT verification failed");
        assert!(valid, "NTT proof should verify");
    }

    #[test]
    fn test_ntt_tampered_proof_fails() {
        let f = random_ntt_input(42);
        let (proof_bytes, commitment_hex, _) = prove_ntt(&f).expect("NTT proving failed");
        let mut bad_proof = proof_bytes.clone();
        bad_proof[20] ^= 0xFF;
        let result = verify_ntt(&bad_proof, &commitment_hex).unwrap_or(false);
        assert!(!result, "tampered NTT proof should not verify");
    }

    #[test]
    fn test_ntt_wrong_commitment_fails() {
        let f = random_ntt_input(7);
        let (proof_bytes, commitment_hex, _) = prove_ntt(&f).expect("NTT proving failed");
        let bad_commitment = {
            let mut bytes = hex::decode(&commitment_hex).unwrap();
            let mut val = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            val = val.wrapping_add(1) % M31_MODULUS;
            bytes[0..4].copy_from_slice(&val.to_le_bytes());
            hex::encode(&bytes)
        };
        let result = verify_ntt(&proof_bytes, &bad_commitment).unwrap_or(false);
        assert!(!result, "wrong commitment should fail NTT verification");
    }

    #[test]
    fn test_ntt_zero_poly() {
        // NTT of the zero polynomial is the zero polynomial.
        let f = [0i64; 256];
        let (proof_bytes, commitment_hex, ntt_out) =
            prove_ntt(&f).expect("NTT proving of zero failed");
        assert_eq!(ntt_out, [0i64; 256]);
        let valid = verify_ntt(&proof_bytes, &commitment_hex).expect("NTT verification failed");
        assert!(valid);
    }

    // ── Pointwise polynomial multiplication tests (MVP-3+) ───────────────────

    fn random_q_poly(seed: u64) -> [i64; 256] {
        let q = mldsa::Q;
        let mut state = seed;
        let mut f = [0i64; 256];
        for c in f.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *c = ((state >> 33) as i64).abs() % q;
        }
        f
    }

    #[test]
    fn test_prove_and_verify_poly_mul() {
        let a = random_q_poly(100);
        let b = random_q_poly(200);
        let (proof_bytes, commitment_hex, product) =
            prove_poly_mul(&a, &b).expect("poly_mul proving failed");

        // Product must match the reference.
        let reference = mldsa::ntt::pointwise_mul(&a, &b);
        assert_eq!(product, reference);

        let valid = verify_poly_mul(&proof_bytes, &commitment_hex)
            .expect("poly_mul verification failed");
        assert!(valid);
    }

    #[test]
    fn test_poly_mul_tampered_proof_fails() {
        let a = random_q_poly(1);
        let b = random_q_poly(2);
        let (proof_bytes, commitment_hex, _) =
            prove_poly_mul(&a, &b).expect("poly_mul proving failed");
        let mut bad = proof_bytes.clone();
        bad[20] ^= 0xFF;
        assert!(!verify_poly_mul(&bad, &commitment_hex).unwrap_or(false));
    }

    #[test]
    fn test_poly_mul_zero_is_zero() {
        let a = [0i64; 256];
        let b = random_q_poly(3);
        let (proof_bytes, commitment_hex, product) =
            prove_poly_mul(&a, &b).expect("poly_mul proving failed");
        assert_eq!(product, [0i64; 256]);
        assert!(verify_poly_mul(&proof_bytes, &commitment_hex).unwrap_or(false));
    }

    // ── Polynomial addition tests (MVP-3+) ───────────────────────────────────

    #[test]
    fn test_prove_and_verify_poly_add() {
        let a = random_q_poly(300);
        let b = random_q_poly(400);
        let (proof_bytes, commitment_hex, sum) =
            prove_poly_add(&a, &b).expect("poly_add proving failed");

        // Sum must be correct mod Q.
        let q = mldsa::Q;
        for i in 0..256 {
            assert_eq!(sum[i], (a[i] + b[i]).rem_euclid(q), "sum[{i}]");
        }

        let valid = verify_poly_add(&proof_bytes, &commitment_hex)
            .expect("poly_add verification failed");
        assert!(valid, "poly_add proof should verify");
    }

    #[test]
    fn test_poly_add_zero_is_identity() {
        let a = random_q_poly(500);
        let z = [0i64; 256];
        let (proof_bytes, commitment_hex, sum) =
            prove_poly_add(&a, &z).expect("poly_add proving failed");
        assert_eq!(sum, a);
        assert!(verify_poly_add(&proof_bytes, &commitment_hex).unwrap_or(false));
    }

    #[test]
    fn test_poly_add_tampered_proof_fails() {
        let a = random_q_poly(10);
        let b = random_q_poly(20);
        let (proof_bytes, commitment_hex, _) =
            prove_poly_add(&a, &b).expect("poly_add proving failed");
        let mut bad = proof_bytes.clone();
        bad[20] ^= 0xFF;
        assert!(!verify_poly_add(&bad, &commitment_hex).unwrap_or(false));
    }

    // ── Polynomial subtraction tests (MVP-3+) ────────────────────────────────

    #[test]
    fn test_prove_and_verify_poly_sub() {
        let q = mldsa::Q;
        let a = random_q_poly(600);
        let b = random_q_poly(700);
        let (proof_bytes, commitment_hex, diff) =
            prove_poly_sub(&a, &b).expect("poly_sub proving failed");

        for i in 0..256 {
            assert_eq!(diff[i], (a[i] - b[i]).rem_euclid(q), "diff[{i}]");
        }

        let valid = verify_poly_sub(&proof_bytes, &commitment_hex)
            .expect("poly_sub verification failed");
        assert!(valid, "poly_sub proof should verify");
    }

    #[test]
    fn test_poly_sub_self_is_zero() {
        let a = random_q_poly(800);
        let (proof_bytes, commitment_hex, diff) =
            prove_poly_sub(&a, &a).expect("poly_sub (a - a) failed");
        assert_eq!(diff, [0i64; 256]);
        assert!(verify_poly_sub(&proof_bytes, &commitment_hex).unwrap_or(false));
    }

    #[test]
    fn test_poly_sub_zero_is_identity() {
        let a = random_q_poly(900);
        let z = [0i64; 256];
        let (proof_bytes, commitment_hex, diff) =
            prove_poly_sub(&a, &z).expect("poly_sub (a - 0) failed");
        assert_eq!(diff, a);
        assert!(verify_poly_sub(&proof_bytes, &commitment_hex).unwrap_or(false));
    }

    // ── Norm check tests (MVP-3+) ─────────────────────────────────────────────

    #[test]
    fn test_prove_and_verify_norm_check() {
        let z = random_q_poly(1000);
        let (proof_bytes, commitment_hex, norm, max_norm) =
            prove_norm_check(&z).expect("norm_check proving failed");

        // Verify norm values.
        let q = mldsa::Q;
        let half = (q - 1) / 2;
        for i in 0..256 {
            let expected = if z[i] > half { q - z[i] } else { z[i] };
            assert_eq!(norm[i], expected, "norm[{i}]");
        }
        let expected_max = norm.iter().copied().max().unwrap_or(0);
        assert_eq!(max_norm, expected_max);

        let valid = verify_norm_check(&proof_bytes, &commitment_hex)
            .expect("norm_check verification failed");
        assert!(valid, "norm_check proof should verify");
    }

    #[test]
    fn test_norm_check_zero_poly() {
        let z = [0i64; 256];
        let (proof_bytes, commitment_hex, norm, max_norm) =
            prove_norm_check(&z).expect("norm_check of zero failed");
        assert_eq!(norm, [0i64; 256]);
        assert_eq!(max_norm, 0);
        assert!(verify_norm_check(&proof_bytes, &commitment_hex).unwrap_or(false));
    }

    #[test]
    fn test_norm_check_tampered_proof_fails() {
        let z = random_q_poly(1100);
        let (proof_bytes, commitment_hex, _, _) =
            prove_norm_check(&z).expect("norm_check proving failed");
        let mut bad = proof_bytes.clone();
        bad[20] ^= 0xFF;
        assert!(!verify_norm_check(&bad, &commitment_hex).unwrap_or(false));
    }

    // ── UseHint STARK tests (MVP-3+) ─────────────────────────────────────────

    #[test]
    fn test_prove_and_verify_use_hint_no_hints() {
        let r   = random_q_poly(1200);
        let h   = [false; 256];
        let (proof_bytes, commitment_hex, w1) =
            prove_use_hint(&r, &h).expect("use_hint proving failed");
        // No hints: w1[i] = HighBits(r[i]).
        for i in 0..256 {
            let (r1, _) = mldsa_use_hint_air::decompose_val_signed(r[i]);
            assert_eq!(w1[i], r1, "no-hint w1[{i}]");
        }
        let valid = verify_use_hint(&proof_bytes, &commitment_hex)
            .expect("use_hint verification failed");
        assert!(valid, "use_hint (no hints) proof should verify");
    }

    #[test]
    fn test_prove_and_verify_use_hint_random() {
        use mldsa::polyvec::use_hint_val;
        let r = random_q_poly(1300);
        let mut state = 1301u64;
        let h: [bool; 256] = std::array::from_fn(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 63) != 0
        });
        let (proof_bytes, commitment_hex, w1) =
            prove_use_hint(&r, &h).expect("use_hint proving failed");
        for i in 0..256 {
            assert_eq!(w1[i], use_hint_val(h[i], r[i]), "w1[{i}]");
        }
        let valid = verify_use_hint(&proof_bytes, &commitment_hex)
            .expect("use_hint verification failed");
        assert!(valid, "use_hint proof should verify");
    }

    #[test]
    fn test_use_hint_tampered_proof_fails() {
        let r = random_q_poly(1400);
        let h = [true; 256];
        let (proof_bytes, commitment_hex, _) =
            prove_use_hint(&r, &h).expect("use_hint proving failed");
        let mut bad = proof_bytes.clone();
        bad[20] ^= 0xFF;
        assert!(!verify_use_hint(&bad, &commitment_hex).unwrap_or(false));
    }

    // ── TwoChannel cross-verification ────────────────────────────────────────
    // These tests produce the reference vectors that must match TwoChannel.sol.
    // Run with: cargo +nightly-2025-07-01 test test_two_channel -- --nocapture

    #[test]
    fn test_two_channel_init_mix_root() {
        use stwo::core::channel::{Blake2sM31Channel, Channel, MerkleChannel};
        use stwo::core::vcs::blake2_hash::Blake2sHash;
        use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;

        // Vector 1: mix_root(zero_digest, zero_root)
        let mut ch = Blake2sM31Channel::default();
        let zero_root = Blake2sHash([0u8; 32]);
        Blake2sM31MerkleChannel::mix_root(&mut ch, zero_root);
        let digest_hex = hex::encode(ch.digest().0);
        println!("mixRoot(zero,zero) digest = 0x{digest_hex}");

        // Vector 2: mix_root(0x01..01 digest, 0xab..ab root)
        let init_digest = Blake2sHash([0x01u8; 32]);
        let ab_root     = Blake2sHash([0xabu8; 32]);
        let mut ch2 = Blake2sM31Channel::default();
        ch2.update_digest(init_digest);
        Blake2sM31MerkleChannel::mix_root(&mut ch2, ab_root);
        let digest2_hex = hex::encode(ch2.digest().0);
        println!("mixRoot(0x01..01, 0xab..ab) digest = 0x{digest2_hex}");
    }

    #[test]
    fn test_two_channel_draw_u32s() {
        use stwo::core::channel::{Blake2sM31Channel, Channel};

        // Vector: drawU32sRaw from zero state (nDraws=0)
        let mut ch = Blake2sM31Channel::default();
        let raw = ch.draw_u32s();
        let raw_hex: String = raw.iter()
            .flat_map(|w| w.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect();
        println!("drawU32sRaw(zero, nDraws=0) = 0x{raw_hex}");
        assert_eq!(raw.len(), 8, "draw_u32s must return 8 words");
        // All values must be < P (M31 output)
        let p = 2_147_483_647u32;
        for &w in &raw {
            assert!(w < p, "word {w} must be < P");
        }

        // nDraws should now be 1
        let raw2 = ch.draw_u32s();
        let raw2_hex: String = raw2.iter()
            .flat_map(|w| w.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect();
        println!("drawU32sRaw(zero, nDraws=1) = 0x{raw2_hex}");
        assert_ne!(raw, raw2, "consecutive draws must differ");
    }

    #[test]
    fn test_two_channel_draw_queries() {
        use stwo::core::channel::{Blake2sM31Channel, Channel};
        use stwo::core::queries::draw_queries;

        let mut ch = Blake2sM31Channel::default();
        let log_domain_size = 3u32;
        let n_queries = 5usize;
        let positions = draw_queries(&mut ch, log_domain_size, n_queries);
        let positions_u32: Vec<u32> = positions.iter().map(|&x| x as u32).collect();
        println!("drawQueries(zero, logSize=3, n=5) = {positions_u32:?}");
        assert_eq!(positions.len(), n_queries);
        for &q in &positions {
            assert!(q < (1 << log_domain_size), "query {q} must be < 2^3");
        }
    }

    #[test]
    fn test_two_channel_sequence() {
        use stwo::core::channel::{Blake2sM31Channel, Channel, MerkleChannel};
        use stwo::core::vcs::blake2_hash::Blake2sHash;
        use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;

        // Two-step: mixRoot(root1), drawU32s, mixRoot(root2), drawU32s
        let root1 = Blake2sHash([0x01u8; 32]);
        let root2 = Blake2sHash([0x02u8; 32]);

        let mut ch = Blake2sM31Channel::default();
        Blake2sM31MerkleChannel::mix_root(&mut ch, root1);
        let draw1: String = ch.draw_u32s().iter()
            .flat_map(|w| w.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect();
        Blake2sM31MerkleChannel::mix_root(&mut ch, root2);
        let draw2: String = ch.draw_u32s().iter()
            .flat_map(|w| w.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect();
        println!("sequence draw1 = 0x{draw1}");
        println!("sequence draw2 = 0x{draw2}");
        assert_ne!(draw1, draw2);
    }

    // ── CirclePoint cross-verification ──────────────────────────────────────
    // Reference vectors for CirclePoint.sol and the FRI fold formulas.
    // Run: cargo +nightly-2025-07-01 test test_circle_point -- --nocapture

    #[test]
    fn test_circle_point_generator() {
        use stwo::core::circle::{CirclePoint, M31_CIRCLE_GEN, M31_CIRCLE_LOG_ORDER};
        use stwo::core::fields::m31::M31;

        println!("GEN_X = {}", M31_CIRCLE_GEN.x.0);
        println!("GEN_Y = {}", M31_CIRCLE_GEN.y.0);
        println!("LOG_ORDER = {M31_CIRCLE_LOG_ORDER}");

        // Verify G is on the circle: x² + y² = 1 (mod P)
        let p = 2_147_483_647u64;
        let x = M31_CIRCLE_GEN.x.0 as u64;
        let y = M31_CIRCLE_GEN.y.0 as u64;
        assert_eq!((x * x % p + y * y % p) % p, 1, "G must be on the circle");

        // Identity: G^0 = (1, 0)
        let id = M31_CIRCLE_GEN.mul(0);
        assert_eq!(id.x.0, 1);
        assert_eq!(id.y.0, 0);

        // G^1 = G
        let g1 = M31_CIRCLE_GEN.mul(1);
        assert_eq!(g1.x.0, M31_CIRCLE_GEN.x.0);
        assert_eq!(g1.y.0, M31_CIRCLE_GEN.y.0);

        // Some test vectors for genMul
        let v17 = M31_CIRCLE_GEN.mul(17);
        println!("genMul(17) = ({}, {})", v17.x.0, v17.y.0);

        let v1000 = M31_CIRCLE_GEN.mul(1000);
        println!("genMul(1000) = ({}, {})", v1000.x.0, v1000.y.0);

        // pointDouble(G) = 2*G
        let doubled = M31_CIRCLE_GEN.double();
        let g2      = M31_CIRCLE_GEN.mul(2);
        assert_eq!(doubled.x, g2.x);
        assert_eq!(doubled.y, g2.y);
        println!("genMul(2) = ({}, {})", g2.x.0, g2.y.0);

        // pointAdd(G, G) = 2*G
        let added = M31_CIRCLE_GEN + M31_CIRCLE_GEN;
        assert_eq!(added.x, g2.x);
        assert_eq!(added.y, g2.y);
    }

    #[test]
    fn test_circle_point_coset_at() {
        use stwo::core::poly::circle::CanonicCoset;

        // CanonicCoset::new(3).at(0..3) — small coset for easy verification
        let c3 = CanonicCoset::new(3);
        for i in 0..4 {
            let p = c3.at(i);
            println!("cosetAt(3, {i}) = ({}, {})", p.x.0, p.y.0);
            // Verify all points are on the circle
            let px = p.x.0 as u64;
            let py = p.y.0 as u64;
            let modp = 2_147_483_647u64;
            assert_eq!((px*px % modp + py*py % modp) % modp, 1,
                "coset point must be on circle");
        }

        // CanonicCoset::new(14).at(0) — typical FRI domain (LOG_N=10, LOG_BLOWUP=4)
        let c14 = CanonicCoset::new(14);
        let p0 = c14.at(0);
        let p1 = c14.at(1);
        let p2 = c14.at(7);
        println!("cosetAt(14, 0) = ({}, {})", p0.x.0, p0.y.0);
        println!("cosetAt(14, 1) = ({}, {})", p1.x.0, p1.y.0);
        println!("cosetAt(14, 7) = ({}, {})", p2.x.0, p2.y.0);
    }

    #[test]
    fn test_circle_fold_formula() {
        use stwo::core::circle::M31_CIRCLE_GEN;
        use stwo::core::fields::m31::M31;
        use stwo::core::fields::qm31::QM31;
        use stwo::core::poly::circle::CanonicCoset;
        use stwo::core::fri::fold_circle_into_line;
        use stwo::core::fields::{Field, FieldExpOps};

        // Use cosetAt(3, 0) as the query point
        let p = CanonicCoset::new(3).at(0);
        println!("fold test p = ({}, {})", p.x.0, p.y.0);

        // Arbitrary f(p) and f(conjugate(p)) = f(-p)
        let f_p     = QM31::from_u32_unchecked(100, 200, 300, 400);
        let f_neg_p = QM31::from_u32_unchecked(50, 60, 70, 80);
        let alpha   = QM31::from_u32_unchecked(7, 11, 13, 17);

        // Circle fold formula: f_new = (f_p + f_neg_p) + alpha * (f_p - f_neg_p) / p.y
        let sum  = f_p + f_neg_p;
        let diff = f_p - f_neg_p;
        let y_inv = p.y.inverse();
        let f_new = sum + alpha * diff * y_inv;
        println!("f_p     QM31 = {:?}", f_p.to_m31_array().map(|x| x.0));
        println!("f_neg_p QM31 = {:?}", f_neg_p.to_m31_array().map(|x| x.0));
        println!("alpha   QM31 = {:?}", alpha.to_m31_array().map(|x| x.0));
        println!("p.y = {}, p.y_inv = {}", p.y.0, y_inv.0);
        println!("f_new   QM31 = {:?}", f_new.to_m31_array().map(|x| x.0));
    }
}
