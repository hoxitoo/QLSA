// ARCHIVED — NOT COMPILED, NOT IN ANY MODULE TREE.
// Removed by the Ф1 narrowing; restored here from stark_stwo/src/vfri2_bridge.rs@f2020d9 so the code
// stays visible in the repository rather than only in git history.
// To bring an item back, paste it into stark_stwo/src/vfri2_bridge.rs and re-run `cargo test`.

fn abi_encode_vfri3_hints(
    last_layer_coeffs: &[u128],
    oods_evals_pos: &[u128],
    oods_evals_neg: &[u128],
    fri_layer_roots: &[[u8; 32]],
    hints: &[QueryHintData],
) -> Vec<u8> {
    let head_size = 5 * 32usize; // 160 bytes

    let coeffs_body = encode_uint128_array(last_layer_coeffs);
    let pos_body    = encode_uint128_array(oods_evals_pos);
    let neg_body    = encode_uint128_array(oods_evals_neg);
    let roots_body  = encode_bytes32_array(fri_layer_roots);
    let hints_body  = encode_query_hints_array(hints);

    // All 5 fields are dynamic; offsets are from start of the encoding.
    let coeffs_offset = head_size;
    let pos_offset    = coeffs_offset + coeffs_body.len();
    let neg_offset    = pos_offset    + pos_body.len();
    let roots_offset  = neg_offset    + neg_body.len();
    let hints_offset  = roots_offset  + roots_body.len();

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_usize(coeffs_offset));  // slot 0: offset to lastLayerCoeffs
    out.extend_from_slice(&abi_word_usize(pos_offset));     // slot 1: offset to oodsEvalsPos
    out.extend_from_slice(&abi_word_usize(neg_offset));     // slot 2: offset to oodsEvalsNeg
    out.extend_from_slice(&abi_word_usize(roots_offset));   // slot 3: offset to friLayerRoots
    out.extend_from_slice(&abi_word_usize(hints_offset));   // slot 4: offset to QueryHints[]
    out.extend_from_slice(&coeffs_body);
    out.extend_from_slice(&pos_body);
    out.extend_from_slice(&neg_body);
    out.extend_from_slice(&roots_body);
    out.extend_from_slice(&hints_body);
    out
}

/// VFRI3-compatible hint generator using the **real** Poseidon2 trace.
///
/// Builds the actual Poseidon2 execution trace from `leaves`, commits it in
/// a Blake2s Merkle tree, performs barycentric OODS evaluation, runs the FRI
/// circle fold and line fold rounds, and ABI-encodes hints for
/// `QLSAVerifierVFRI3.verify()`.
///
/// Protocol:
///   1. Build trace: `poseidon2_air::build_trace(leaves)` → 7 main columns
///   2. Commit Merkle tree: leaf i = Blake2s(col0[i], …, col6[i])
///   3. Fiat-Shamir transcript: mixRoot → z_x → mixU32s(oodsPos) →
///      mixU32s(oodsNeg) → compAlpha → friAlpha → mixRoot(L1) →
///      for k: friAlphas[k] → mixRoot(L(k+2)) → drawQueries
///   4. OODS: barycentric Lagrange interpolation at z_x and −z_x
///   5. FRI L1: circle fold over all domain positions
///   6. FRI line folds: num_folds = tree_depth − 1 rounds
///   7. ABI-encode for VFRI3 (uint128[] lastLayerCoeffs, not scalar)
///
/// Returns: (proof_bytes, commitment_hex, abi_encoded_query_hints_for_VFRI3)
pub fn gen_poseidon2_vfri3_real(
    leaves: &[u64],
    batch_merkle_root: &[u8],
    n_queries: usize,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if leaves.is_empty() {
        return Err("leaves must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    // ── Build actual Poseidon2 trace ──────────────────────────────────────────
    let (main_cols, _preproc_cols, _commitment) =
        crate::poseidon2_air::build_trace(leaves);

    let _n_cols = main_cols.len(); // 7: s0, s1, t0, t1, inp0, leaf, inp1
    let tree_depth = crate::poseidon2_air::compute_log_size(leaves.len());
    let n = 1usize << tree_depth;

    // Extract raw M31 values from circle-domain evaluations.
    // col.values[i] is the value at circle-domain position i (after bit-reversal).
    // Merkle leaf i uses these values, and coset_at(tree_depth, i).x is its x-coord.
    let cols: Vec<Vec<u32>> = main_cols
        .iter()
        .map(|col| col.values.iter().map(|v| v.0).collect::<Vec<u32>>())
        .collect();

    // ── Trace Merkle tree ─────────────────────────────────────────────────────
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // ── Fiat-Shamir channel ───────────────────────────────────────────────────
    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x = chan.draw_secure_felt(); // QM31 OODS line point

    // ── OODS evaluations via even-part barycentric interpolation ─────────────
    // The CanonicCoset of size N has N/2 distinct x-coordinates (each appears
    // twice as conjugate pair (k, N-1-k)).  We evaluate the even part of each
    // circle polynomial:  a(z) = Σ_k w_k·col_even[k]/(z-x_k) / Σ_k w_k/(z-x_k)
    // where col_even[k] = (col[k]+col[N-1-k])/2.
    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);

    let z_neg = qm31_neg(z_x); // −z_x for oodsEvalsNeg

    let oods_evals_pos: Vec<u128> = cols
        .iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols
        .iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    // Mix OODS evals into channel (4 words per QM31).
    {
        let pos_words: Vec<u32> = oods_evals_pos.iter()
            .flat_map(|&v| qm31_words(v))
            .collect();
        chan.mix_u32s(&pos_words);
        let neg_words: Vec<u32> = oods_evals_neg.iter()
            .flat_map(|&v| qm31_words(v))
            .collect();
        chan.mix_u32s(&neg_words);
    }

    let comp_alpha = chan.draw_secure_felt();
    let fri_alpha  = chan.draw_secure_felt();

    // ── Precompute composition sums for OODS ─────────────────────────────────
    // oodsComboPos = Σ_j compAlpha^j * oodsEvalsPos[j]
    // oodsComboNeg = Σ_j compAlpha^j * oodsEvalsNeg[j]
    let oods_combo_pos = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_pos {
            acc = qm31_add(acc, qm31_mul(ap, ev));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_neg {
            acc = qm31_add(acc, qm31_mul(ap, ev));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    };

    // ── FRI Layer 1: circle fold over all n domain positions ─────────────────
    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);

        // rawComp    = Σ_j compAlpha^j * col_j[q]
        // rawCompNeg = Σ_j compAlpha^j * col_j[anti_q]
        let raw_comp = {
            let mut acc = 0u128;
            let mut ap  = qm31_from_m31(1);
            for c in &cols {
                acc = qm31_add(acc, qm31_mul_m31(ap, c[q]));
                ap  = qm31_mul(ap, comp_alpha);
            }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128;
            let mut ap  = qm31_from_m31(1);
            for c in &cols {
                acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_q]));
                ap  = qm31_mul(ap, comp_alpha);
            }
            acc
        };

        // fPlus  = (rawComp    - oodsComboPos) / (px - z_x)
        // fMinus = (rawCompNeg - oodsComboNeg) / (-px - z_x)
        let px_qm31    = qm31_from_m31(px);
        let denom_pos  = qm31_sub(px_qm31, z_x);
        let denom_neg  = qm31_sub(qm31_neg(px_qm31), z_x);

        // Guard against degenerate denominators (extremely unlikely for random z_x).
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!(
                "degenerate OODS denominator at position {q}: denomPos={denom_pos} denomNeg={denom_neg}"
            ));
        }

        let f_plus  = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), denom_neg);

        let y_inv       = m31_inv(py);
        let folded_val  = circle_fold(f_plus, f_minus, fri_alpha, y_inv);
        l1_values.push(folded_val);
    }

    // Build FRI L1 Merkle tree.
    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter()
        .map(|&v| hash_leaf_qm31(v))
        .collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];

    chan.mix_root(&fri_layer1_root);

    // ── Line fold rounds ──────────────────────────────────────────────────────
    // num_folds = tree_depth - 1 (fold down to last_layer_depth = 1, i.e. 2 leaves)
    if tree_depth < 2 {
        return Err(format!(
            "tree_depth={tree_depth} too small (need ≥ 2); use more leaves"
        ));
    }
    let num_folds = (tree_depth - 1) as usize;

    let mut layer_values: Vec<Vec<u128>> = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>  = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>       = Vec::new();

    for k in 0..num_folds {
        let alpha_k    = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);

        let prev_vals  = &layer_values[k];
        let layer_size = prev_vals.len() / 2; // half the previous layer

        let mut new_vals = Vec::with_capacity(layer_size);
        for j in 0..layer_size {
            let sibling = j + layer_size; // paired position

            // Twiddle T_{2^k}(x_j) via k squarings.
            let x_j    = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 {
                return Err(format!("twiddle is zero at fold round k={k}, j={j}"));
            }
            let t_inv = m31_inv(twiddle);

            let g_plus  = prev_vals[j];
            let g_minus = prev_vals[sibling];
            let folded_k = line_fold(g_plus, g_minus, alpha_k, t_inv);
            new_vals.push(folded_k);
        }

        // Build Merkle tree for this fold layer.
        let new_leaves: Vec<[u8; 32]> = new_vals.iter()
            .map(|&v| hash_leaf_qm31(v))
            .collect();
        let new_levels = build_tree(new_leaves);
        let new_root: [u8; 32] = new_levels.last().unwrap()[0];

        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    // Last layer = foldedLayers[num_folds] (2^1 = 2 QM31 values).
    let last_layer_coeffs: Vec<u128> = layer_values[num_folds].clone();

    // ── Draw query indices ────────────────────────────────────────────────────
    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    // ── Build per-query hints ─────────────────────────────────────────────────
    let mut hint_structs: Vec<QueryHintData> = Vec::new();

    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        // Column values at idx and anti_idx.
        let query_values: Vec<u32>     = cols.iter().map(|c| c[idx]).collect();
        let query_values_neg: Vec<u32> = cols.iter().map(|c| c[anti_idx]).collect();

        // Merkle proofs for trace columns.
        let trace_siblings     = proof_path(&trace_levels, idx);
        let trace_siblings_neg = proof_path(&trace_levels, anti_idx);

        // Retrieve pre-computed fPlus and fMinus from FRI L1 computation.
        // We need to recompute them for this specific idx.
        let raw_comp = {
            let mut acc = 0u128;
            let mut ap  = qm31_from_m31(1);
            for c in &cols {
                acc = qm31_add(acc, qm31_mul_m31(ap, c[idx]));
                ap  = qm31_mul(ap, comp_alpha);
            }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128;
            let mut ap  = qm31_from_m31(1);
            for c in &cols {
                acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_idx]));
                ap  = qm31_mul(ap, comp_alpha);
            }
            acc
        };

        let px_qm31    = qm31_from_m31(qp_x);
        let denom_pos  = qm31_sub(px_qm31, z_x);
        let denom_neg  = qm31_sub(qm31_neg(px_qm31), z_x);
        let f_plus     = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), denom_pos);
        let f_minus    = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), denom_neg);

        let y_inv       = m31_inv(qp_y);
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, y_inv);

        // Sanity check: this should match what was stored in l1_values during the loop.
        debug_assert_eq!(folded_value, layer_values[0][idx],
            "folded_value mismatch at idx={idx}");

        // Merkle proof for foldedValue in FRI L1 tree.
        let fri_l1_sib = proof_path(&layer_levels[0], idx);

        // Per-fold hints.
        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;

        for k in 0..num_folds {
            let layer_sz = layer_values[k].len() / 2;
            let sib_idx  = if cur_idx < layer_sz {
                cur_idx + layer_sz
            } else {
                cur_idx - layer_sz
            };
            let new_idx  = cur_idx & (layer_sz - 1);

            let sibling_value = layer_values[k][sib_idx];
            let sibling_proof = proof_path(&layer_levels[k], sib_idx);

            let x_j     = coset_at(tree_depth, new_idx as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            let t_inv   = m31_inv(twiddle);

            let cur_value = if k == 0 {
                folded_value
            } else {
                fold_hints[k - 1].folded_value
            };
            let g_plus  = if cur_idx < layer_sz { cur_value } else { sibling_value };
            let g_minus = if cur_idx < layer_sz { sibling_value } else { cur_value };

            let folded_k = line_fold(g_plus, g_minus, fri_alphas[k], t_inv);
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx],
                "per-query fold mismatch at k={k}, cur_idx={cur_idx}");

            let merkle_proof = proof_path(&layer_levels[k + 1], new_idx);

            fold_hints.push(FoldHintData {
                sibling_value,
                sibling_proof,
                folded_value: folded_k,
                merkle_proof,
            });

            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintData {
            trace_root,
            query_values,
            query_values_neg,
            query_index: idx,
            tree_depth,
            merkle_siblings: trace_siblings,
            merkle_siblings_neg: trace_siblings_neg,
            fri_alpha,
            f_plus,
            f_minus,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    // ── Build proof bytes ─────────────────────────────────────────────────────
    // [0:8]  = nonce as LE u64 = 2
    // [8:40] = trace_root
    // padding to ≥ 700 bytes
    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    // ── Commitment = Blake2s(proof[:32] ‖ batch_merkle_root)[:16] ────────────
    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    // ── ABI-encode queryHints for VFRI3 ──────────────────────────────────────
    let query_hints = abi_encode_vfri3_hints(
        &last_layer_coeffs,
        &oods_evals_pos,
        &oods_evals_neg,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI4 hint generator for a real Poseidon2 AIR trace.
///
/// Builds the Poseidon2 trace from `leaves`, commits it, then runs the
/// VFRI4 Fiat-Shamir transcript (Poseidon2 sponge OODS commitment) to
/// produce ABI-encoded queryHints for `QLSAVerifierVFRI4`.
pub fn gen_poseidon2_vfri4_real(
    leaves: &[u64],
    batch_merkle_root: &[u8],
    n_queries: usize,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if leaves.is_empty() {
        return Err("leaves must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let (main_cols, _preproc_cols, _commitment) =
        crate::poseidon2_air::build_trace(leaves);
    let tree_depth = crate::poseidon2_air::compute_log_size(leaves.len());
    let cols: Vec<Vec<u32>> = main_cols
        .iter()
        .map(|col| col.values.iter().map(|v| v.0).collect())
        .collect();

    gen_vfri4_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, None)
}

/// Generate VFRI3-compatible hints from any flat column trace.
///
/// `cols[j][i]` = value of column j at row i (M31 as u32).
/// All columns must have exactly `2^tree_depth` entries.
/// `num_folds`: number of line-fold rounds (1..=tree_depth−1). Defaults to
///   `tree_depth−1` (last layer has 2 QM31 values). Fewer folds → larger last
///   layer but lower gas cost per query on-chain.
pub fn gen_vfri3_hints_from_cols(
    cols: &[Vec<u32>],
    tree_depth: u32,
    batch_merkle_root: &[u8],
    n_queries: usize,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    gen_vfri3_hints_from_cols_nfolds(cols, tree_depth, batch_merkle_root, n_queries, None)
}

/// Same as `gen_vfri3_hints_from_cols` but with an explicit `num_folds`.
pub fn gen_vfri3_hints_from_cols_nfolds(
    cols: &[Vec<u32>],
    tree_depth: u32,
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds_opt: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!(
                "cols[{j}] has {} entries, expected {n} (2^{tree_depth})",
                col.len()
            ));
        }
    }

    // ── Trace Merkle tree ─────────────────────────────────────────────────────
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // ── Fiat-Shamir channel ───────────────────────────────────────────────────
    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x = chan.draw_secure_felt();

    // ── OODS evaluations via even-part barycentric interpolation ─────────────
    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    {
        let pos_words: Vec<u32> = oods_evals_pos.iter().flat_map(|&v| qm31_words(v)).collect();
        chan.mix_u32s(&pos_words);
        let neg_words: Vec<u32> = oods_evals_neg.iter().flat_map(|&v| qm31_words(v)).collect();
        chan.mix_u32s(&neg_words);
    }

    let comp_alpha = chan.draw_secure_felt();
    let fri_alpha  = chan.draw_secure_felt();

    // ── Precompute composition OODS combos ────────────────────────────────────
    let oods_combo_pos = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    // ── FRI Layer 1 ───────────────────────────────────────────────────────────
    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);

        let raw_comp = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[q])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_q])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };

        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    // ── Line fold rounds ──────────────────────────────────────────────────────
    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j    = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31(v)).collect();
        let new_levels = build_tree(new_leaves);
        let new_root: [u8; 32] = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    let last_layer_coeffs: Vec<u128> = layer_values[num_folds].clone();
    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    // ── Per-query hints ───────────────────────────────────────────────────────
    let mut hint_structs: Vec<QueryHintData> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let query_values: Vec<u32>     = cols.iter().map(|c| c[idx]).collect();
        let query_values_neg: Vec<u32> = cols.iter().map(|c| c[anti_idx]).collect();
        let trace_siblings     = proof_path(&trace_levels, idx);
        let trace_siblings_neg = proof_path(&trace_levels, anti_idx);

        let raw_comp = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[idx])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_idx])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let fri_l1_sib = proof_path(&layer_levels[0], idx);
        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sibling_value = layer_values[k][sib_idx];
            let sibling_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j      = coset_at(tree_depth, new_idx as u64).0;
            let cur_val  = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm) = if cur_idx < layer_sz { (cur_val, sibling_value) } else { (sibling_value, cur_val) };
            let folded_k = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value,
                sibling_proof,
                folded_value: folded_k,
                merkle_proof: proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }
        hint_structs.push(QueryHintData {
            trace_root,
            query_values, query_values_neg,
            query_index: idx, tree_depth,
            merkle_siblings: trace_siblings, merkle_siblings_neg: trace_siblings_neg,
            fri_alpha, f_plus, f_minus, folded_value,
            query_point_x: qp_x, query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib, folds: fold_hints,
        });
    }

    // ── Build proof bytes and commitment ──────────────────────────────────────
    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri3_hints(
        &last_layer_coeffs,
        &oods_evals_pos,
        &oods_evals_neg,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// Generate VFRI3-compatible hints from ML-DSA NttBatch AIR trace.
///
/// `polys` — the input polynomials to NTT: z (L=5), c (1), t1 (K=6) = 12 total.
/// Runs the 649-column NttBatch AIR (LOG=10, 1024 rows) and applies VFRI3's
/// FRI protocol, producing hints for QLSAVerifierVFRI3.verify().
pub fn gen_ntt_batch_vfri3_hints(
    polys: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    gen_ntt_batch_vfri3_hints_nfolds(polys, batch_merkle_root, n_queries, None)
}

/// Same as `gen_ntt_batch_vfri3_hints` but with explicit `num_folds`.
/// Use `num_folds < tree_depth-1` to reduce FRI rounds (smaller last layer,
/// lower gas cost) for testing or research with limited block gas.
pub fn gen_ntt_batch_vfri3_hints_nfolds(
    polys: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    if polys.is_empty() {
        return Err("polys must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let (ntt_cols, _ntt_outputs) = mldsa_ntt_batch_air::build_trace(polys);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let cols: Vec<Vec<u32>> = ntt_cols
        .iter()
        .map(|col| col.values.iter().map(|v| v.0).collect())
        .collect();

    gen_vfri3_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI4 hint generator — identical to VFRI3 except OODS channel mixing.
///
/// VFRI3 transcript: `mixU32s(all_oods_pos_words)` + `mixU32s(all_oods_neg_words)`
/// VFRI4 transcript: `mixU32s([p2sponge(pos_m31s).s0, .s1, p2sponge(neg_m31s).s0, .s1])`
///
/// where each QM31 eval is flattened into 4 M31 u32 values before sponge absorption.
/// The channel always receives exactly 4 M31 words regardless of column count,
/// making the Fiat-Shamir binding independent of n_cols (at verification side).
///
/// queryHints ABI format: identical to VFRI3.
pub fn gen_vfri4_hints_from_cols_nfolds(
    cols: &[Vec<u32>],
    tree_depth: u32,
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds_opt: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!(
                "cols[{j}] has {} entries, expected {n} (2^{tree_depth})",
                col.len()
            ));
        }
    }

    // ── Trace Merkle tree ─────────────────────────────────────────────────────
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // ── Fiat-Shamir channel ───────────────────────────────────────────────────
    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x = chan.draw_secure_felt();

    // ── OODS evaluations via even-part barycentric interpolation ─────────────
    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    // ── VFRI4: Poseidon2 sponge commitment of OODS evals ─────────────────────
    // Each QM31 → 4 M31 words; sponge absorbs all, mixes 4 output words.
    {
        let pos_m31s: Vec<u64> = oods_evals_pos.iter()
            .flat_map(|&v| qm31_words(v).map(|w| w as u64))
            .collect();
        let neg_m31s: Vec<u64> = oods_evals_neg.iter()
            .flat_map(|&v| qm31_words(v).map(|w| w as u64))
            .collect();
        let (ps0, ps1) = crate::poseidon2::poseidon2_chain(&pos_m31s);
        let (ns0, ns1) = crate::poseidon2::poseidon2_chain(&neg_m31s);
        chan.mix_u32s(&[ps0 as u32, ps1 as u32, ns0 as u32, ns1 as u32]);
    }

    let comp_alpha = chan.draw_secure_felt();
    let fri_alpha  = chan.draw_secure_felt();

    // ── Precompute composition OODS combos ────────────────────────────────────
    let oods_combo_pos = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    // ── FRI Layer 1 ───────────────────────────────────────────────────────────
    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);

        let raw_comp = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[q])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_q])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };

        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    // ── Line fold rounds ──────────────────────────────────────────────────────
    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j    = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31(v)).collect();
        let new_levels = build_tree(new_leaves);
        let new_root: [u8; 32] = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    let last_layer_coeffs: Vec<u128> = layer_values[num_folds].clone();
    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    // ── Per-query hints ───────────────────────────────────────────────────────
    let mut hint_structs: Vec<QueryHintData> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let query_values: Vec<u32>     = cols.iter().map(|c| c[idx]).collect();
        let query_values_neg: Vec<u32> = cols.iter().map(|c| c[anti_idx]).collect();
        let trace_siblings     = proof_path(&trace_levels, idx);
        let trace_siblings_neg = proof_path(&trace_levels, anti_idx);

        let raw_comp = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[idx])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let raw_comp_neg = {
            let mut acc = 0u128; let mut ap = qm31_from_m31(1);
            for c in cols { acc = qm31_add(acc, qm31_mul_m31(ap, c[anti_idx])); ap = qm31_mul(ap, comp_alpha); }
            acc
        };
        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(raw_comp,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(raw_comp_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let fri_l1_sib = proof_path(&layer_levels[0], idx);
        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sibling_value = layer_values[k][sib_idx];
            let sibling_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j      = coset_at(tree_depth, new_idx as u64).0;
            let cur_val  = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm) = if cur_idx < layer_sz { (cur_val, sibling_value) } else { (sibling_value, cur_val) };
            let folded_k = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value,
                sibling_proof,
                folded_value: folded_k,
                merkle_proof: proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }
        hint_structs.push(QueryHintData {
            trace_root,
            query_values, query_values_neg,
            query_index: idx, tree_depth,
            merkle_siblings: trace_siblings, merkle_siblings_neg: trace_siblings_neg,
            fri_alpha, f_plus, f_minus, folded_value,
            query_point_x: qp_x, query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib, folds: fold_hints,
        });
    }

    // ── Build proof bytes and commitment ──────────────────────────────────────
    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri3_hints(
        &last_layer_coeffs,
        &oods_evals_pos,
        &oods_evals_neg,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI4 hint generator for ML-DSA NttBatch AIR trace.
pub fn gen_ntt_batch_vfri4_hints_nfolds(
    polys: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    if polys.is_empty() {
        return Err("polys must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!(
            "batch_merkle_root must be 32 bytes, got {}",
            batch_merkle_root.len()
        ));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let (ntt_cols, _ntt_outputs) = mldsa_ntt_batch_air::build_trace(polys);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let cols: Vec<Vec<u32>> = ntt_cols
        .iter()
        .map(|col| col.values.iter().map(|v| v.0).collect())
        .collect();

    gen_vfri4_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// ABI-encode VFRI5 queryHints.
///
/// Layout: abi.encode(uint128[] lastLayerCoeffs, uint128[] oodsEvalsPos,
///   uint128[] oodsEvalsNeg, bytes32 compRoot, bytes32[] friLayerRoots, QueryHints[])
///
/// Note: `compRoot` is a static `bytes32` (not a dynamic array), so it sits
/// directly in the head at slot 3. Head = 6 × 32 = 192 bytes.
fn abi_encode_vfri5_hints(
    last_layer_coeffs: &[u128],
    oods_evals_pos: &[u128],
    oods_evals_neg: &[u128],
    comp_root: &[u8; 32],
    fri_layer_roots: &[[u8; 32]],
    hints: &[QueryHintDataV5],
) -> Vec<u8> {
    // Slots 0,1,2 → dynamic offsets; slot 3 → static bytes32; slots 4,5 → dynamic offsets.
    // Static bytes32 fields do NOT get an offset — their value is placed inline.
    // Offsets for dynamic fields are relative to start of the entire encoding.
    //
    // Head (6 × 32 = 192 bytes):
    //   slot 0: offset → lastLayerCoeffs
    //   slot 1: offset → oodsEvalsPos
    //   slot 2: offset → oodsEvalsNeg
    //   slot 3: compRoot  (static bytes32)
    //   slot 4: offset → friLayerRoots
    //   slot 5: offset → QueryHints[]

    let head_size: usize = 6 * 32;

    let coeffs_body = encode_uint128_array(last_layer_coeffs);
    let pos_body    = encode_uint128_array(oods_evals_pos);
    let neg_body    = encode_uint128_array(oods_evals_neg);
    let roots_body  = encode_bytes32_array(fri_layer_roots);
    let hints_body  = encode_query_hints_array_v5(hints);

    let coeffs_offset = head_size;
    let pos_offset    = coeffs_offset + coeffs_body.len();
    let neg_offset    = pos_offset    + pos_body.len();
    // compRoot is static → no offset, skip its body in offset calculation
    let roots_offset  = neg_offset    + neg_body.len();
    let hints_offset  = roots_offset  + roots_body.len();

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_usize(coeffs_offset));  // 0
    out.extend_from_slice(&abi_word_usize(pos_offset));     // 1
    out.extend_from_slice(&abi_word_usize(neg_offset));     // 2
    out.extend_from_slice(comp_root);                        // 3: static bytes32
    out.extend_from_slice(&abi_word_usize(roots_offset));   // 4
    out.extend_from_slice(&abi_word_usize(hints_offset));   // 5
    out.extend_from_slice(&coeffs_body);
    out.extend_from_slice(&pos_body);
    out.extend_from_slice(&neg_body);
    out.extend_from_slice(&roots_body);
    out.extend_from_slice(&hints_body);
    out
}

/// Generic VFRI5 hint generator.
///
/// Builds a composition polynomial tree in addition to the FRI layer trees.
/// Per-query hints contain only `compValue + compProof` (O(tree_depth) each)
/// instead of all n_cols column values (O(n_cols)).
///
/// Gas improvement vs VFRI4: O(n_cols) computation moved from per-query to
/// once-in-`_buildCtx`; per-query work is O(tree_depth) = O(log n_rows).
pub fn gen_vfri5_hints_from_cols_nfolds(
    cols: &[Vec<u32>],
    tree_depth: u32,
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds_opt: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    // ── Trace Merkle tree ─────────────────────────────────────────────────────
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // ── Fiat-Shamir transcript (VFRI5) ────────────────────────────────────────
    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x = chan.draw_secure_felt();

    // ── OODS evaluations via even-part barycentric interpolation ─────────────
    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    // ── Poseidon2 OODS sponge commitment (same as VFRI4) ─────────────────────
    {
        let pos_m31s: Vec<u64> = oods_evals_pos.iter()
            .flat_map(|&v| qm31_words(v).map(|w| w as u64))
            .collect();
        let neg_m31s: Vec<u64> = oods_evals_neg.iter()
            .flat_map(|&v| qm31_words(v).map(|w| w as u64))
            .collect();
        let (ps0, ps1) = crate::poseidon2::poseidon2_chain(&pos_m31s);
        let (ns0, ns1) = crate::poseidon2::poseidon2_chain(&neg_m31s);
        chan.mix_u32s(&[ps0 as u32, ps1 as u32, ns0 as u32, ns1 as u32]);
    }

    let comp_alpha = chan.draw_secure_felt();

    // ── Composition polynomial tree (NEW in VFRI5) ───────────────────────────
    // F(x) = Σ_j compAlpha^j · col_j(x) for all domain positions x.
    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    // comp_values[i] = F(domain[i]) = Σ_j compAlpha^j · cols[j][i]
    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128;
        let mut ap  = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let comp_levels = build_tree(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    // Mix compRoot into channel (NEW VFRI5 step), then draw friAlpha.
    chan.mix_root(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    // ── FRI Layer 1: circle fold from composition values ─────────────────────
    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],     oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    // ── Line fold rounds ──────────────────────────────────────────────────────
    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j    = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31(v)).collect();
        let new_levels = build_tree(new_leaves);
        let new_root: [u8; 32] = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    let last_layer_coeffs: Vec<u128> = layer_values[num_folds].clone();
    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    // ── Per-query hints (VFRI5: composition proofs instead of column values) ──
    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];

        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);

        let fri_l1_sib = proof_path(&layer_levels[0], idx);

        // Debug check: folded value at idx must match layer_values[0][idx].
        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value: folded_k,
                merkle_proof: proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    // ── Build proof bytes and commitment ──────────────────────────────────────
    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri5_hints(
        &last_layer_coeffs,
        &oods_evals_pos,
        &oods_evals_neg,
        &comp_root,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI5 hint generator for ML-DSA NttBatch AIR trace.
pub fn gen_ntt_batch_vfri5_hints_nfolds(
    polys: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    if polys.is_empty() {
        return Err("polys must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    let (ntt_cols, _) = mldsa_ntt_batch_air::build_trace(polys);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;
    let cols: Vec<Vec<u32>> = ntt_cols.iter().map(|col| col.values.iter().map(|v| v.0).collect()).collect();
    gen_vfri5_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// ABI-encode VFRI6 queryHints.
///
/// Layout: abi.encode(uint128 oodsComboPos, uint128 oodsComboNeg,
///   bytes32 compRoot, bytes32[] friLayerRoots, QueryHints[])
///
/// Head (5 × 32 = 160 bytes):
///   slot 0: oodsComboPos (static uint128)
///   slot 1: oodsComboNeg (static uint128)
///   slot 2: compRoot     (static bytes32)
///   slot 3: offset → friLayerRoots
///   slot 4: offset → QueryHints[]
fn abi_encode_vfri6_hints(
    oods_combo_pos:  u128,
    oods_combo_neg:  u128,
    comp_root:       &[u8; 32],
    fri_layer_roots: &[[u8; 32]],
    hints:           &[QueryHintDataV5],
) -> Vec<u8> {
    let head_size: usize = 5 * 32;

    let roots_body = encode_bytes32_array(fri_layer_roots);
    let hints_body = encode_query_hints_array_v5(hints);

    let roots_offset = head_size;
    let hints_offset = roots_offset + roots_body.len();

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_u128(oods_combo_pos));    // 0: static uint128
    out.extend_from_slice(&abi_word_u128(oods_combo_neg));    // 1: static uint128
    out.extend_from_slice(comp_root);                          // 2: static bytes32
    out.extend_from_slice(&abi_word_usize(roots_offset));      // 3: offset
    out.extend_from_slice(&abi_word_usize(hints_offset));      // 4: offset
    out.extend_from_slice(&roots_body);
    out.extend_from_slice(&hints_body);
    out
}

/// Generic VFRI6 hint generator from flat column data.
pub fn gen_vfri6_hints_from_cols_nfolds(
    cols:              &[Vec<u32>],
    tree_depth:        u32,
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds_opt:     Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    // ── Trace Merkle tree ─────────────────────────────────────────────────────
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // ── Fiat-Shamir transcript (VFRI6) ───────────────────────────────────────
    // Key difference from VFRI5: compAlpha is drawn BEFORE mixing OODS evals.
    // Then oodsComboPos/Neg (8 M31 words) replace the Poseidon2 sponge.
    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x      = chan.draw_secure_felt();
    let comp_alpha = chan.draw_secure_felt();

    // ── OODS evaluations (off-chain, never sent to verifier) ─────────────────
    // Use even-part barycentric: CanonicCoset has N/2 distinct x-coords (each
    // appears twice as conjugate pair (k, N-1-k)).  a(z) = even part of the
    // circle polynomial at z; this gives non-zero oodsCombo with prob. 1-2^{-128}.
    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    // oodsComboPos = Σ compAlpha^j · oodsEvalsPos[j]  (off-chain)
    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    // Mix 8 M31 words (4 from comboPos, 4 from comboNeg) into channel.
    // This binds oodsComboPos/Neg to the transcript without O(n_cols) work on-chain.
    let combo_words = {
        let p = qm31_words(oods_combo_pos);
        let n = qm31_words(oods_combo_neg);
        [p[0], p[1], p[2], p[3], n[0], n[1], n[2], n[3]]
    };
    chan.mix_u32s(&combo_words);

    // ── Composition polynomial tree (same as VFRI5) ──────────────────────────
    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let comp_levels = build_tree(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    chan.mix_root(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    // ── FRI Layer 1: circle fold ──────────────────────────────────────────────
    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],      oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    // ── Line fold rounds ──────────────────────────────────────────────────────
    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None    => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j     = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31(v)).collect();
        let new_levels = build_tree(new_leaves);
        let new_root   = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    // ── Per-query hints (same structure as VFRI5) ─────────────────────────────
    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];
        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);
        let fri_l1_sib     = proof_path(&layer_levels[0], idx);

        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value:  folded_k,
                merkle_proof:  proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    // ── Build proof bytes and commitment ──────────────────────────────────────
    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri6_hints(
        oods_combo_pos,
        oods_combo_neg,
        &comp_root,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI6 hint generator for ML-DSA NttBatch AIR trace.
pub fn gen_ntt_batch_vfri6_hints_nfolds(
    polys:             &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    if polys.is_empty() {
        return Err("polys must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    let (ntt_cols, _) = mldsa_ntt_batch_air::build_trace(polys);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;
    let cols: Vec<Vec<u32>> = ntt_cols.iter()
        .map(|col| col.values.iter().map(|v| v.0).collect())
        .collect();
    gen_vfri6_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// Generate VFRI3-compatible hints from V23's NttBatch + InttBatch components.
///
/// Both components have LOG_N_ROWS=10 (1024 rows, 649 columns each).
/// Combined: 1298 trace columns, all at the same domain size (2^10 = 1024 rows).
///
/// This proves on-chain (via QLSAVerifierVFRI3) that:
/// - NTT(z, c, t1) was computed correctly  (NttBatch — 649 cols)
/// - INTT(az_hat, ct1_hat) was computed correctly  (InttBatch — 649 cols)
///
/// `a_hat` — K×L = 30 NTT-domain polynomials; used to compute az_hat so that
/// the InttBatch inputs are consistent with the V23 AzFull circuit.
///
/// Returns `(proof_bytes, commitment_hex, abi_encoded_query_hints)` accepted by
/// `QLSAVerifierVFRI3.verify()`.
pub fn gen_mldsa_v23_vfri3_hints(
    z: &[[i64; 256]; 5],
    c: &[i64; 256],
    t1: &[[i64; 256]; 6],
    a_hat: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    // ── Step 1: NTT(z, c, t1) ────────────────────────────────────────────────
    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS; // 10

    let z_hat: [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into()
        .map_err(|_| "z_hat slice error".to_string())?;
    let c_hat: [i64; 256] = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into()
        .map_err(|_| "t1_hat slice error".to_string())?;

    // ── Step 2: Az and Ct1 in NTT domain (InttBatch inputs) ──────────────────
    let (_az_cols, az_hat) = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    // ── Step 3: INTT(az_hat, ct1_hat) ────────────────────────────────────────
    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _intt_outputs) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    // ── Step 4: Combine columns (both LOG=10, 1024 rows each) ────────────────
    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        if col.values.len() != n_rows {
            return Err(format!("ntt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }
    for col in &intt_cols {
        if col.values.len() != n_rows {
            return Err(format!("intt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }

    // ── Step 5: Generate VFRI3 hints ─────────────────────────────────────────
    gen_vfri3_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI4 hint generator for V23's NttBatch + InttBatch components.
///
/// Identical to `gen_mldsa_v23_vfri3_hints` but uses the VFRI4 Fiat-Shamir
/// transcript: OODS evals are committed via Poseidon2 sponge (4 M31 words)
/// instead of raw Blake2s mixing (n_cols×4 words).
///
/// queryHints ABI format is identical to VFRI3 — only the transcript differs.
/// VFRI3 hints are NOT accepted by QLSAVerifierVFRI4 and vice versa.
pub fn gen_mldsa_v23_vfri4_hints(
    z: &[[i64; 256]; 5],
    c: &[i64; 256],
    t1: &[[i64; 256]; 6],
    a_hat: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    // ── Step 1: NTT(z, c, t1) ────────────────────────────────────────────────
    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS; // 10

    let z_hat: [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into()
        .map_err(|_| "z_hat slice error".to_string())?;
    let c_hat: [i64; 256] = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into()
        .map_err(|_| "t1_hat slice error".to_string())?;

    // ── Step 2: Az and Ct1 in NTT domain ─────────────────────────────────────
    let (_az_cols, az_hat) = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    // ── Step 3: INTT(az_hat, ct1_hat) ────────────────────────────────────────
    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _intt_outputs) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    // ── Step 4: Combine columns (both LOG=10, 1024 rows each) ────────────────
    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        if col.values.len() != n_rows {
            return Err(format!("ntt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }
    for col in &intt_cols {
        if col.values.len() != n_rows {
            return Err(format!("intt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }

    // ── Step 5: Generate VFRI4 hints ─────────────────────────────────────────
    gen_vfri4_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// Generate VFRI6-compatible hints from V23's NttBatch + InttBatch components.
///
/// Same 1298-column combined trace as gen_mldsa_v23_vfri4_hints, but uses the
/// VFRI6 ABI encoding (off-chain oodsComboPos/Neg, no Poseidon2 sponge).
///
/// Key result: 1298 cols fit within 15M gas — same as 649 cols in VFRI6, because
/// VFRI6's on-chain cost is O(1) in n_cols (only 8 M31 words mixed per call).
pub fn gen_mldsa_v23_vfri6_hints(
    z: &[[i64; 256]; 5],
    c: &[i64; 256],
    t1: &[[i64; 256]; 6],
    a_hat: &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries: usize,
    num_folds: Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let z_hat: [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into()
        .map_err(|_| "z_hat slice error".to_string())?;
    let c_hat: [i64; 256] = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into()
        .map_err(|_| "t1_hat slice error".to_string())?;

    let (_az_cols, az_hat) = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _intt_outputs) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        if col.values.len() != n_rows {
            return Err(format!("ntt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }
    for col in &intt_cols {
        if col.values.len() != n_rows {
            return Err(format!("intt col has {} rows, expected {n_rows}", col.values.len()));
        }
        cols.push(col.values.iter().map(|v| v.0).collect());
    }

    gen_vfri6_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI6 hint generator for V23's LOG=8 component group.
///
/// Covers AzFull (1523) + Ct1Full (295) + RangeQBatch (288) +
/// WPrimeFull (24) + NormCheckBatch (15) + UseHintBatchV2 (60 main + 1 preproc)
/// = 2206 columns at tree_depth=8 (256 rows each).
///
/// Combined with `gen_mldsa_v23_vfri6_hints` (LOG=10 group, 1298 cols),
/// these two calls cover the full V23 trace (3504 main cols).
///
/// Returns `(proof_bytes, commitment_hex, abi_encoded_query_hints)` accepted by
/// `QLSAVerifierVFRI6.verify()`.
pub fn gen_mldsa_v23_vfri6_hints_log8(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;
    use crate::mldsa_wprime_full_air;
    use crate::mldsa_norm_check_batch_air;
    use crate::mldsa_range_q_batch_air;
    use crate::mldsa_use_hint_batch_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    // ── Step 1: NTT(z, c, t1) — intermediate values, columns not included ─────
    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);
    let (_ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    // ── Step 2: AzFull and Ct1Full (LOG=8) ───────────────────────────────────
    let (az_cols,  az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    // ── Step 3: RangeQBatch — proves az_hat ∈ [0, Q) ─────────────────────────
    let (rq_cols, rq_valid) = mldsa_range_q_batch_air::build_trace(&az_hat);
    if !rq_valid {
        return Err("RangeQBatch: az_hat contains values outside [0, Q)".to_string());
    }

    // ── Step 4: INTT(az_hat || ct1_hat) — intermediate, columns not included ──
    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (_intt_cols, intt_out) = mldsa_intt_batch_air::build_trace(&intt_inputs);
    let az_out:  [[i64; 256]; K] = intt_out[..K]
        .try_into().map_err(|_| "az_out slice error".to_string())?;
    let ct1_out: [[i64; 256]; K] = intt_out[K..]
        .try_into().map_err(|_| "ct1_out slice error".to_string())?;

    // ── Step 5: WPrimeFull, NormCheckBatch, UseHintBatchV2 (LOG=8) ───────────
    let (wp_cols,   _w_prime) = mldsa_wprime_full_air::build_trace(&az_out, &ct1_out);
    let w_prime: [[i64; 256]; K] = _w_prime;
    let (norm_cols, _norm_out, _max_norms) = mldsa_norm_check_batch_air::build_trace(z);
    let (uh_main_cols, uh_preproc_cols, _w1_out, _hint_weight) =
        mldsa_use_hint_batch_air::build_trace_v2(&w_prime, hints);

    // ── Step 6: Combine all LOG=8 columns (256 rows each) ────────────────────
    const TREE_DEPTH: u32 = 8;
    let n_rows = 1usize << (TREE_DEPTH as usize);
    let total_cols = az_cols.len() + ct1_cols.len() + rq_cols.len()
        + wp_cols.len() + norm_cols.len() + uh_main_cols.len() + uh_preproc_cols.len();
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(total_cols);
    let groups = [&az_cols, &ct1_cols, &rq_cols, &wp_cols, &norm_cols, &uh_main_cols, &uh_preproc_cols];
    for group in &groups {
        for col in group.iter() {
            if col.values.len() != n_rows {
                return Err(format!(
                    "LOG=8 col has {} rows, expected {n_rows}", col.values.len()
                ));
            }
            cols.push(col.values.iter().map(|v| v.0).collect());
        }
    }

    gen_vfri6_hints_from_cols_nfolds(&cols, TREE_DEPTH, batch_merkle_root, n_queries, num_folds)
}

/// VFRI7 generic hint generator — VFRI6 + batch_merkle_root in Fiat-Shamir transcript.
///
/// Identical to `gen_vfri6_hints_from_cols_nfolds` except that `batch_merkle_root`
/// is mixed into the channel via `chan.mix_root()` immediately before `draw_queries`.
/// The commitment binding is the same: `Blake2s(proof[:32] ‖ batch_merkle_root)[:16]`.
pub fn gen_vfri7_hints_from_cols_nfolds(
    cols:              &[Vec<u32>],
    tree_depth:        u32,
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds_opt:     Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    let mut chan = Channel::init();
    chan.mix_root(&trace_root);
    let z_x       = chan.draw_secure_felt();
    let comp_alpha = chan.draw_secure_felt();

    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    let combo_words = {
        let p = qm31_words(oods_combo_pos);
        let nw = qm31_words(oods_combo_neg);
        [p[0], p[1], p[2], p[3], nw[0], nw[1], nw[2], nw[3]]
    };
    chan.mix_u32s(&combo_words);

    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let comp_levels = build_tree(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    chan.mix_root(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],      oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31(v)).collect();
    let fri_l1_levels = build_tree(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None    => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j     = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31(v)).collect();
        let new_levels = build_tree(new_leaves);
        let new_root   = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    // ── VFRI7: mix batch_merkle_root into channel before drawing queries ───────
    // This binds the FRI query indices to the external batch root, enabling
    // cross-proof binding when cross-bound roots are used (see gen_mldsa_v23_vfri7_cross_bound_hints).
    let mut batch_root_arr = [0u8; 32];
    batch_root_arr.copy_from_slice(batch_merkle_root);
    chan.mix_root(&batch_root_arr);

    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];
        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);
        let fri_l1_sib     = proof_path(&layer_levels[0], idx);

        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value:  folded_k,
                merkle_proof:  proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri6_hints(
        oods_combo_pos,
        oods_combo_neg,
        &comp_root,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI7 wrapper for V23 LOG=10 group (NttBatch + InttBatch, 1298 cols, tree_depth=10).
pub fn gen_mldsa_v23_vfri7_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (_az_cols, az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }
    for col in &intt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }

    gen_vfri7_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI7 wrapper for V23 LOG=8 group (AzFull+Ct1Full+RangeQBatch+WPrimeFull+NormCheckBatch+UseHintBatchV2, 2206 cols).
pub fn gen_mldsa_v23_vfri7_hints_log8(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;
    use crate::mldsa_wprime_full_air;
    use crate::mldsa_norm_check_batch_air;
    use crate::mldsa_range_q_batch_air;
    use crate::mldsa_use_hint_batch_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);
    let (_ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (az_cols,  az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let (rq_cols, rq_valid) = mldsa_range_q_batch_air::build_trace(&az_hat);
    if !rq_valid {
        return Err("RangeQBatch: az_hat contains values outside [0, Q)".to_string());
    }

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (_intt_cols, intt_out) = mldsa_intt_batch_air::build_trace(&intt_inputs);
    let az_out:  [[i64; 256]; K] = intt_out[..K].try_into().map_err(|_| "az_out slice error".to_string())?;
    let ct1_out: [[i64; 256]; K] = intt_out[K..].try_into().map_err(|_| "ct1_out slice error".to_string())?;

    let (wp_cols,   _w_prime) = mldsa_wprime_full_air::build_trace(&az_out, &ct1_out);
    let w_prime: [[i64; 256]; K] = _w_prime;
    let (norm_cols, _, _) = mldsa_norm_check_batch_air::build_trace(z);
    let (uh_main_cols, uh_preproc_cols, _, _) =
        mldsa_use_hint_batch_air::build_trace_v2(&w_prime, hints);

    const TREE_DEPTH: u32 = 8;
    let n_rows = 1usize << (TREE_DEPTH as usize);
    let total_cols = az_cols.len() + ct1_cols.len() + rq_cols.len()
        + wp_cols.len() + norm_cols.len() + uh_main_cols.len() + uh_preproc_cols.len();
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(total_cols);
    let groups = [&az_cols, &ct1_cols, &rq_cols, &wp_cols, &norm_cols, &uh_main_cols, &uh_preproc_cols];
    for group in &groups {
        for col in group.iter() {
            if col.values.len() != n_rows {
                return Err(format!("LOG=8 col has {} rows, expected {n_rows}", col.values.len()));
            }
            cols.push(col.values.iter().map(|v| v.0).collect());
        }
    }

    gen_vfri7_hints_from_cols_nfolds(&cols, TREE_DEPTH, batch_merkle_root, n_queries, num_folds)
}

/// Generate cross-bound VFRI7 hints for V23's two trace groups.
///
/// Cross-proof binding (MVP-5 Priority 2):
///   bound_root_10 = keccak256(batch_root ‖ trace_root_8)
///   bound_root_8  = keccak256(batch_root ‖ trace_root_10)
///
/// The LOG=10 proof is regenerated with `batch_merkle_root = bound_root_10` so
/// its FRI query indices depend on the LOG=8 trace commitment, and vice versa.
/// An adversary combining proofs from different witnesses would fail on-chain
/// because the query indices and Merkle openings would not match.
///
/// Returns `(proof10, commit10_hex, hints10, proof8, commit8_hex, hints8)`.
/// The caller (BatchRegistryV4) should pass:
///   - `boundRoot10 = keccak256(merkleRoot ‖ proof8[8:40])` to VFRI7 verify for LOG=10
///   - `boundRoot8  = keccak256(merkleRoot ‖ proof10[8:40])` to VFRI7 verify for LOG=8
pub fn gen_mldsa_v23_vfri7_cross_bound_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_root:        &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>, Vec<u8>, String, Vec<u8>), String> {
    use sha3::{Keccak256, Digest as Sha3Digest};

    if batch_root.len() != 32 {
        return Err(format!("batch_root must be 32 bytes, got {}", batch_root.len()));
    }

    // ── Pass 1: extract trace roots ───────────────────────────────────────────
    let (proof10_p1, _, _) = gen_mldsa_v23_vfri7_hints(z, c, t1, a_hat, batch_root, 1, num_folds)?;
    let (proof8_p1,  _, _) = gen_mldsa_v23_vfri7_hints_log8(z, c, t1, a_hat, hints, batch_root, 1, num_folds)?;

    if proof10_p1.len() < 40 || proof8_p1.len() < 40 {
        return Err("proof bytes too short to contain trace root at [8:40]".into());
    }
    let trace_root_10: [u8; 32] = proof10_p1[8..40].try_into().unwrap();
    let trace_root_8:  [u8; 32] = proof8_p1[8..40].try_into().unwrap();

    // ── Compute cross-bound merkle roots ──────────────────────────────────────
    // bound_root_10 = keccak256(batch_root ‖ trace_root_8)
    // bound_root_8  = keccak256(batch_root ‖ trace_root_10)
    let bound_root_10: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_8);
        h.finalize().into()
    };
    let bound_root_8: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_10);
        h.finalize().into()
    };

    // ── Pass 2: generate final hints with cross-bound roots ───────────────────
    let (proof10, commit10, hints10) =
        gen_mldsa_v23_vfri7_hints(z, c, t1, a_hat, &bound_root_10, n_queries, num_folds)?;
    let (proof8, commit8, hints8) =
        gen_mldsa_v23_vfri7_hints_log8(z, c, t1, a_hat, hints, &bound_root_8, n_queries, num_folds)?;

    Ok((proof10, commit10, hints10, proof8, commit8, hints8))
}

/// VFRI8 generic hint generator — VFRI7 protocol with Poseidon2 hash backend.
///
/// Transcript (identical to VFRI7 but using P2Channel and P2 Merkle):
///   P2Channel.mix_root(traceRoot)
///   z_x = draw_secure_felt
///   compAlpha = draw_secure_felt
///   mix_u32s([comboPos_words…, comboNeg_words…])
///   mix_root(compRoot)
///   friAlpha = draw_secure_felt
///   mix_root(friLayerRoots[0])
///   for k: friAlphas[k] = draw_secure_felt; mix_root(friLayerRoots[k+1])
///   mix_root(batch_merkle_root)   ← VFRI7 cross-proof binding
///   drawQueries(treeDepth, n)
pub fn gen_vfri8_hints_from_cols_nfolds(
    cols:              &[Vec<u32>],
    tree_depth:        u32,
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds_opt:     Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if tree_depth < 2 {
        return Err(format!("tree_depth={tree_depth} must be ≥ 2"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    // Trace Merkle tree (Poseidon2)
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols_p2(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree_p2(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // Fiat-Shamir (Poseidon2 channel)
    let mut chan = P2Channel::init();
    chan.mix_root(&trace_root);
    let z_x       = chan.draw_secure_felt();
    let comp_alpha = chan.draw_secure_felt();

    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    let combo_words = {
        let p = qm31_words(oods_combo_pos);
        let nw = qm31_words(oods_combo_neg);
        [p[0], p[1], p[2], p[3], nw[0], nw[1], nw[2], nw[3]]
    };
    chan.mix_u32s(&combo_words);

    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    // Composition Merkle tree (Poseidon2)
    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31_p2(v)).collect();
    let comp_levels = build_tree_p2(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    chan.mix_root(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],      oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    // FRI L1 Merkle tree (Poseidon2)
    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31_p2(v)).collect();
    let fri_l1_levels = build_tree_p2(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root(&fri_layer1_root);

    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None    => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j     = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31_p2(v)).collect();
        let new_levels = build_tree_p2(new_leaves);
        let new_root   = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root(&new_root);
        layer_levels.push(new_levels);
    }

    // VFRI7/VFRI8 cross-proof binding: mix batch_merkle_root before drawQueries
    let mut batch_root_arr = [0u8; 32];
    batch_root_arr.copy_from_slice(batch_merkle_root);
    chan.mix_root(&batch_root_arr);

    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];
        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);
        let fri_l1_sib     = proof_path(&layer_levels[0], idx);

        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value:  folded_k,
                merkle_proof:  proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&2u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri6_hints(
        oods_combo_pos,
        oods_combo_neg,
        &comp_root,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI8 wrapper for V23 LOG=10 group (NttBatch + InttBatch, 1298 cols, tree_depth=10).
pub fn gen_mldsa_v23_vfri8_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (_az_cols, az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }
    for col in &intt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }

    gen_vfri8_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI8 wrapper for V23 LOG=8 group (2206 cols).
pub fn gen_mldsa_v23_vfri8_hints_log8(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;
    use crate::mldsa_wprime_full_air;
    use crate::mldsa_norm_check_batch_air;
    use crate::mldsa_range_q_batch_air;
    use crate::mldsa_use_hint_batch_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);
    let (_ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (az_cols,  az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let (rq_cols, rq_valid) = mldsa_range_q_batch_air::build_trace(&az_hat);
    if !rq_valid {
        return Err("RangeQBatch: az_hat contains values outside [0, Q)".to_string());
    }

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (_intt_cols, intt_out) = mldsa_intt_batch_air::build_trace(&intt_inputs);
    let az_out:  [[i64; 256]; K] = intt_out[..K].try_into().map_err(|_| "az_out slice error".to_string())?;
    let ct1_out: [[i64; 256]; K] = intt_out[K..].try_into().map_err(|_| "ct1_out slice error".to_string())?;

    let (wp_cols,   _w_prime) = mldsa_wprime_full_air::build_trace(&az_out, &ct1_out);
    let w_prime: [[i64; 256]; K] = _w_prime;
    let (norm_cols, _, _) = mldsa_norm_check_batch_air::build_trace(z);
    let (uh_main_cols, uh_preproc_cols, _, _) =
        mldsa_use_hint_batch_air::build_trace_v2(&w_prime, hints);

    const TREE_DEPTH: u32 = 8;
    let n_rows = 1usize << (TREE_DEPTH as usize);
    let total_cols = az_cols.len() + ct1_cols.len() + rq_cols.len()
        + wp_cols.len() + norm_cols.len() + uh_main_cols.len() + uh_preproc_cols.len();
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(total_cols);
    let groups = [&az_cols, &ct1_cols, &rq_cols, &wp_cols, &norm_cols, &uh_main_cols, &uh_preproc_cols];
    for group in &groups {
        for col in group.iter() {
            if col.values.len() != n_rows {
                return Err(format!("LOG=8 col has {} rows, expected {n_rows}", col.values.len()));
            }
            cols.push(col.values.iter().map(|v| v.0).collect());
        }
    }

    gen_vfri8_hints_from_cols_nfolds(&cols, TREE_DEPTH, batch_merkle_root, n_queries, num_folds)
}

/// Generate cross-bound VFRI8 hints for V23's two trace groups.
///
/// Identical to gen_mldsa_v23_vfri7_cross_bound_hints but using VFRI8 (Poseidon2) provers.
///
/// bound_root_10 = keccak256(batch_root ‖ trace_root_8)
/// bound_root_8  = keccak256(batch_root ‖ trace_root_10)
pub fn gen_mldsa_v23_vfri8_cross_bound_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_root:        &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>, Vec<u8>, String, Vec<u8>), String> {
    use sha3::{Keccak256, Digest as Sha3Digest};

    if batch_root.len() != 32 {
        return Err(format!("batch_root must be 32 bytes, got {}", batch_root.len()));
    }

    // Pass 1: extract trace roots
    let (proof10_p1, _, _) = gen_mldsa_v23_vfri8_hints(z, c, t1, a_hat, batch_root, 1, num_folds)?;
    let (proof8_p1,  _, _) = gen_mldsa_v23_vfri8_hints_log8(z, c, t1, a_hat, hints, batch_root, 1, num_folds)?;

    if proof10_p1.len() < 40 || proof8_p1.len() < 40 {
        return Err("proof bytes too short to contain trace root at [8:40]".into());
    }
    let trace_root_10: [u8; 32] = proof10_p1[8..40].try_into().unwrap();
    let trace_root_8:  [u8; 32] = proof8_p1[8..40].try_into().unwrap();

    let bound_root_10: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_8);
        h.finalize().into()
    };
    let bound_root_8: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_10);
        h.finalize().into()
    };

    // Pass 2: generate final hints with cross-bound roots
    let (proof10, commit10, hints10) =
        gen_mldsa_v23_vfri8_hints(z, c, t1, a_hat, &bound_root_10, n_queries, num_folds)?;
    let (proof8, commit8, hints8) =
        gen_mldsa_v23_vfri8_hints_log8(z, c, t1, a_hat, hints, &bound_root_8, n_queries, num_folds)?;

    Ok((proof10, commit10, hints10, proof8, commit8, hints8))
}

fn abi_encode_vfri9_hints(
    oods_combo_pos:   u128,
    oods_combo_neg:   u128,
    comp_root:        &[u8; 32],
    last_layer_evals: &[u128],
    fri_layer_roots:  &[[u8; 32]],
    hints:            &[QueryHintDataV5],
) -> Vec<u8> {
    let head_size: usize = 6 * 32;

    let evals_body = encode_uint128_array(last_layer_evals);
    let roots_body = encode_bytes32_array(fri_layer_roots);
    let hints_body = encode_query_hints_array_v5(hints);

    let evals_offset = head_size;
    let roots_offset = evals_offset + evals_body.len();
    let hints_offset = roots_offset + roots_body.len();

    let mut out = Vec::new();
    out.extend_from_slice(&abi_word_u128(oods_combo_pos));    // 0: static uint128
    out.extend_from_slice(&abi_word_u128(oods_combo_neg));    // 1: static uint128
    out.extend_from_slice(comp_root);                          // 2: static bytes32
    out.extend_from_slice(&abi_word_usize(evals_offset));      // 3: offset → uint128[]
    out.extend_from_slice(&abi_word_usize(roots_offset));      // 4: offset → bytes32[]
    out.extend_from_slice(&abi_word_usize(hints_offset));      // 5: offset → QueryHints[]
    out.extend_from_slice(&evals_body);
    out.extend_from_slice(&roots_body);
    out.extend_from_slice(&hints_body);
    out
}

/// VFRI9 generic hint generator — VFRI8 protocol with wide Poseidon2 nodes,
/// full-root Fiat-Shamir absorption, and last-layer evaluations export.
///
/// Transcript:
///   P2Channel.mix_root_full(traceRoot)              ← 8 words (NEW: full root)
///   z_x = draw_secure_felt
///   compAlpha = draw_secure_felt
///   mix_u32s([comboPos_words…, comboNeg_words…])
///   mix_root_w(compRoot)                            ← 2 words (wide node)
///   friAlpha = draw_secure_felt
///   mix_root_w(friLayerRoots[0])
///   for k: friAlphas[k] = draw_secure_felt; mix_root_w(friLayerRoots[k+1])
///   mix_root_full(batch_merkle_root)                ← 8 words (NEW: full root)
///   drawQueries(treeDepth, n)
pub fn gen_vfri9_hints_from_cols_nfolds(
    cols:              &[Vec<u32>],
    tree_depth:        u32,
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds_opt:     Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if !(2..=30).contains(&tree_depth) {
        // Upper bound mirrors the on-chain `logDomainSize > 30` guard and
        // prevents the coset_at shift underflow for oversized depths.
        return Err(format!("tree_depth={tree_depth} must be in 2..=30"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    // Trace Merkle tree (wide Poseidon2 nodes)
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols_p2w(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree_p2w(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // Fiat-Shamir (Poseidon2 channel, full-root absorption)
    let mut chan = P2Channel::init();
    chan.mix_root_full(&trace_root);
    let z_x        = chan.draw_secure_felt();
    let comp_alpha = chan.draw_secure_felt();

    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    let combo_words = {
        let p = qm31_words(oods_combo_pos);
        let nw = qm31_words(oods_combo_neg);
        [p[0], p[1], p[2], p[3], nw[0], nw[1], nw[2], nw[3]]
    };
    chan.mix_u32s(&combo_words);

    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    // Composition Merkle tree (wide Poseidon2 nodes)
    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31_p2w(v)).collect();
    let comp_levels = build_tree_p2w(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    chan.mix_root_w(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],      oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    // FRI L1 Merkle tree (wide Poseidon2 nodes)
    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31_p2w(v)).collect();
    let fri_l1_levels = build_tree_p2w(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root_w(&fri_layer1_root);

    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None    => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j     = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31_p2w(v)).collect();
        let new_levels = build_tree_p2w(new_leaves);
        let new_root   = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root_w(&new_root);
        layer_levels.push(new_levels);
    }

    // Last-layer evaluations: ALL values of the final FRI layer.  The on-chain
    // verifier rebuilds the Merkle tree from these and asserts the root equals
    // friLayerRoots[num_folds] — the bounded-degree check missing in VFRI5..8.
    let last_layer_evals: Vec<u128> = layer_values[num_folds].clone();

    // Cross-proof binding: mix the FULL batch merkle root before drawQueries.
    let mut batch_root_arr = [0u8; 32];
    batch_root_arr.copy_from_slice(batch_merkle_root);
    chan.mix_root_full(&batch_root_arr);

    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];
        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);
        let fri_l1_sib     = proof_path(&layer_levels[0], idx);

        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value:  folded_k,
                merkle_proof:  proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&3u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    let query_hints = abi_encode_vfri9_hints(
        oods_combo_pos,
        oods_combo_neg,
        &comp_root,
        &last_layer_evals,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI10 generic hint generator — identical protocol to VFRI9 with the
/// Poseidon2 t=4 hash backend (wide t=4 Merkle + t=4 Fiat-Shamir channel).
///
/// Every transcript step, OODS combo, composition tree, FRI fold chain, and
/// the queryHints ABI layout match `gen_vfri9_hints_from_cols_nfolds` exactly —
/// only the hash primitives change:
///   hash_leaf_cols_p2w  → hash_leaf_cols_p2t4
///   hash_leaf_qm31_p2w  → hash_leaf_qm31_p2t4
///   build_tree_p2w      → build_tree_p2t4
///   P2Channel           → P2T4Channel
/// The proof version marker is 4 (VFRI9 = 3).
pub fn gen_vfri10_hints_from_cols_nfolds(
    cols:              &[Vec<u32>],
    tree_depth:        u32,
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds_opt:     Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    if cols.is_empty() {
        return Err("cols must not be empty".into());
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }
    if !(2..=30).contains(&tree_depth) {
        // Upper bound mirrors the on-chain `logDomainSize > 30` guard and
        // prevents the `30 - tree_depth` / `31 - tree_depth` shift underflow in
        // coset_at (which has no Result channel of its own).
        return Err(format!("tree_depth={tree_depth} must be in 2..=30"));
    }
    let n = 1usize << tree_depth;
    for (j, col) in cols.iter().enumerate() {
        if col.len() != n {
            return Err(format!("cols[{j}] has {} entries, expected {n}", col.len()));
        }
    }

    // Trace Merkle tree (t=4 wide Poseidon2 nodes)
    let trace_leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| hash_leaf_cols_p2t4(&cols.iter().map(|c| c[i]).collect::<Vec<_>>()))
        .collect();
    let trace_levels = build_tree_p2t4(trace_leaves);
    let trace_root: [u8; 32] = trace_levels.last().unwrap()[0];

    // Fiat-Shamir (t=4 Poseidon2 channel, full-root absorption)
    let mut chan = P2T4Channel::init();
    chan.mix_root_full(&trace_root);
    let z_x        = chan.draw_secure_felt();
    let comp_alpha = chan.draw_secure_felt();

    let half = n / 2;
    let xs_half: Vec<u32> = (0..half).map(|k| coset_at(tree_depth, k as u64).0).collect();
    let weights_half = precompute_bary_weights(&xs_half);
    let z_neg = qm31_neg(z_x);

    let oods_evals_pos: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_x))
        .collect();
    let oods_evals_neg: Vec<u128> = cols.iter()
        .map(|col| eval_circle_even(col, &xs_half, &weights_half, z_neg))
        .collect();

    let oods_combo_pos = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_pos { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };
    let oods_combo_neg = {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for &ev in &oods_evals_neg { acc = qm31_add(acc, qm31_mul(ap, ev)); ap = qm31_mul(ap, comp_alpha); }
        acc
    };

    let combo_words = {
        let p = qm31_words(oods_combo_pos);
        let nw = qm31_words(oods_combo_neg);
        [p[0], p[1], p[2], p[3], nw[0], nw[1], nw[2], nw[3]]
    };
    chan.mix_u32s(&combo_words);

    let comp_values: Vec<u128> = (0..n).map(|i| {
        let mut acc = 0u128; let mut ap = qm31_from_m31(1);
        for c in cols {
            acc = qm31_add(acc, qm31_mul_m31(ap, c[i]));
            ap  = qm31_mul(ap, comp_alpha);
        }
        acc
    }).collect();

    // Composition Merkle tree (t=4 wide Poseidon2 nodes)
    let comp_leaves: Vec<[u8; 32]> = comp_values.iter().map(|&v| hash_leaf_qm31_p2t4(v)).collect();
    let comp_levels = build_tree_p2t4(comp_leaves);
    let comp_root: [u8; 32] = comp_levels.last().unwrap()[0];

    chan.mix_root_w(&comp_root);
    let fri_alpha = chan.draw_secure_felt();

    let mut l1_values: Vec<u128> = Vec::with_capacity(n);
    for q in 0..n {
        let anti_q = antipodal_of(q, tree_depth);
        let (px, py) = coset_at(tree_depth, q as u64);
        let px_qm31   = qm31_from_m31(px);
        let denom_pos = qm31_sub(px_qm31, z_x);
        let denom_neg = qm31_sub(qm31_neg(px_qm31), z_x);
        if denom_pos == 0 || denom_neg == 0 {
            return Err(format!("degenerate OODS denom at q={q}"));
        }
        let f_plus  = qm31_div(qm31_sub(comp_values[q],      oods_combo_pos), denom_pos);
        let f_minus = qm31_div(qm31_sub(comp_values[anti_q], oods_combo_neg), denom_neg);
        l1_values.push(circle_fold(f_plus, f_minus, fri_alpha, m31_inv(py)));
    }

    // FRI L1 Merkle tree (t=4 wide Poseidon2 nodes)
    let fri_l1_leaves: Vec<[u8; 32]> = l1_values.iter().map(|&v| hash_leaf_qm31_p2t4(v)).collect();
    let fri_l1_levels = build_tree_p2t4(fri_l1_leaves);
    let fri_layer1_root: [u8; 32] = fri_l1_levels.last().unwrap()[0];
    chan.mix_root_w(&fri_layer1_root);

    let max_folds = (tree_depth - 1) as usize;
    let num_folds = match num_folds_opt {
        None    => max_folds,
        Some(f) if f >= 1 && f <= max_folds => f,
        Some(f) => return Err(format!("num_folds={f} must be in 1..={max_folds}")),
    };
    let mut layer_values: Vec<Vec<u128>>          = vec![l1_values];
    let mut layer_levels: Vec<Vec<Vec<[u8; 32]>>> = vec![fri_l1_levels];
    let mut layer_roots:  Vec<[u8; 32]>           = vec![fri_layer1_root];
    let mut fri_alphas:   Vec<u128>               = Vec::new();

    for k in 0..num_folds {
        let alpha_k   = chan.draw_secure_felt();
        fri_alphas.push(alpha_k);
        let prev_vals = &layer_values[k];
        let layer_sz  = prev_vals.len() / 2;
        let mut new_vals = Vec::with_capacity(layer_sz);
        for j in 0..layer_sz {
            let x_j     = coset_at(tree_depth, j as u64).0;
            let twiddle = chebyshev_twiddle(x_j, k);
            if twiddle == 0 { return Err(format!("zero twiddle at k={k}, j={j}")); }
            new_vals.push(line_fold(prev_vals[j], prev_vals[j + layer_sz], alpha_k, m31_inv(twiddle)));
        }
        let new_leaves: Vec<[u8; 32]> = new_vals.iter().map(|&v| hash_leaf_qm31_p2t4(v)).collect();
        let new_levels = build_tree_p2t4(new_leaves);
        let new_root   = new_levels.last().unwrap()[0];
        layer_values.push(new_vals);
        layer_roots.push(new_root);
        chan.mix_root_w(&new_root);
        layer_levels.push(new_levels);
    }

    // Last-layer evaluations: ALL values of the final FRI layer (bounded-degree
    // check — verifier rebuilds the Merkle tree and asserts root match).
    let last_layer_evals: Vec<u128> = layer_values[num_folds].clone();

    // Cross-proof binding: mix the FULL batch merkle root before drawQueries.
    let mut batch_root_arr = [0u8; 32];
    batch_root_arr.copy_from_slice(batch_merkle_root);
    chan.mix_root_full(&batch_root_arr);

    let derived_indices = chan.draw_queries(tree_depth, n_queries);

    let mut hint_structs: Vec<QueryHintDataV5> = Vec::new();
    for &idx in &derived_indices {
        let anti_idx = antipodal_of(idx, tree_depth);
        let (qp_x, qp_y) = coset_at(tree_depth, idx as u64);

        let comp_value     = comp_values[idx];
        let comp_value_neg = comp_values[anti_idx];
        let comp_proof     = proof_path(&comp_levels, idx);
        let comp_proof_neg = proof_path(&comp_levels, anti_idx);
        let fri_l1_sib     = proof_path(&layer_levels[0], idx);

        let px_qm31   = qm31_from_m31(qp_x);
        let f_plus    = qm31_div(qm31_sub(comp_value,     oods_combo_pos), qm31_sub(px_qm31, z_x));
        let f_minus   = qm31_div(qm31_sub(comp_value_neg, oods_combo_neg), qm31_sub(qm31_neg(px_qm31), z_x));
        let folded_value = circle_fold(f_plus, f_minus, fri_alpha, m31_inv(qp_y));
        debug_assert_eq!(folded_value, layer_values[0][idx]);

        let mut fold_hints: Vec<FoldHintData> = Vec::new();
        let mut cur_idx = idx;
        for k in 0..num_folds {
            let layer_sz  = layer_values[k].len() / 2;
            let sib_idx   = if cur_idx < layer_sz { cur_idx + layer_sz } else { cur_idx - layer_sz };
            let new_idx   = cur_idx & (layer_sz - 1);
            let sib_val   = layer_values[k][sib_idx];
            let sib_proof = proof_path(&layer_levels[k], sib_idx);
            let x_j       = coset_at(tree_depth, new_idx as u64).0;
            let cur_val   = if k == 0 { folded_value } else { fold_hints[k-1].folded_value };
            let (gp, gm)  = if cur_idx < layer_sz { (cur_val, sib_val) } else { (sib_val, cur_val) };
            let folded_k  = line_fold(gp, gm, fri_alphas[k], m31_inv(chebyshev_twiddle(x_j, k)));
            debug_assert_eq!(folded_k, layer_values[k + 1][new_idx]);
            fold_hints.push(FoldHintData {
                sibling_value: sib_val,
                sibling_proof: sib_proof,
                folded_value:  folded_k,
                merkle_proof:  proof_path(&layer_levels[k + 1], new_idx),
            });
            cur_idx = new_idx;
        }

        hint_structs.push(QueryHintDataV5 {
            query_index: idx,
            tree_depth,
            comp_value,
            comp_proof,
            comp_value_neg,
            comp_proof_neg,
            folded_value,
            query_point_x: qp_x,
            query_point_y: qp_y,
            fri_l1_siblings: fri_l1_sib,
            folds: fold_hints,
        });
    }

    let mut proof = vec![0x01u8; 700];
    proof[0..8].copy_from_slice(&4u64.to_le_bytes());
    proof[8..40].copy_from_slice(&trace_root);

    let mut hash_input = [0u8; 64];
    hash_input[..32].copy_from_slice(&proof[..32]);
    hash_input[32..].copy_from_slice(batch_merkle_root);
    let h: [u8; 32] = Blake2s256::digest(&hash_input).into();
    let commitment_hex = hex::encode(&h[..16]);

    // VFRI10 hints share VFRI9's ABI layout exactly.
    let query_hints = abi_encode_vfri9_hints(
        oods_combo_pos,
        oods_combo_neg,
        &comp_root,
        &last_layer_evals,
        &layer_roots,
        &hint_structs,
    );

    Ok((proof, commitment_hex, query_hints))
}

/// VFRI9 wrapper for V23 LOG=10 group (NttBatch + InttBatch, 1298 cols, tree_depth=10).
pub fn gen_mldsa_v23_vfri9_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (_az_cols, az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }
    for col in &intt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }

    gen_vfri9_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI9 wrapper for V23 LOG=8 group (2206 cols).
pub fn gen_mldsa_v23_vfri9_hints_log8(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;
    use crate::mldsa_wprime_full_air;
    use crate::mldsa_norm_check_batch_air;
    use crate::mldsa_range_q_batch_air;
    use crate::mldsa_use_hint_batch_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);
    let (_ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (az_cols,  az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let (rq_cols, rq_valid) = mldsa_range_q_batch_air::build_trace(&az_hat);
    if !rq_valid {
        return Err("RangeQBatch: az_hat contains values outside [0, Q)".to_string());
    }

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (_intt_cols, intt_out) = mldsa_intt_batch_air::build_trace(&intt_inputs);
    let az_out:  [[i64; 256]; K] = intt_out[..K].try_into().map_err(|_| "az_out slice error".to_string())?;
    let ct1_out: [[i64; 256]; K] = intt_out[K..].try_into().map_err(|_| "ct1_out slice error".to_string())?;

    let (wp_cols,   _w_prime) = mldsa_wprime_full_air::build_trace(&az_out, &ct1_out);
    let w_prime: [[i64; 256]; K] = _w_prime;
    let (norm_cols, _, _) = mldsa_norm_check_batch_air::build_trace(z);
    let (uh_main_cols, uh_preproc_cols, _, _) =
        mldsa_use_hint_batch_air::build_trace_v2(&w_prime, hints);

    const TREE_DEPTH: u32 = 8;
    let n_rows = 1usize << (TREE_DEPTH as usize);
    let total_cols = az_cols.len() + ct1_cols.len() + rq_cols.len()
        + wp_cols.len() + norm_cols.len() + uh_main_cols.len() + uh_preproc_cols.len();
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(total_cols);
    let groups = [&az_cols, &ct1_cols, &rq_cols, &wp_cols, &norm_cols, &uh_main_cols, &uh_preproc_cols];
    for group in &groups {
        for col in group.iter() {
            if col.values.len() != n_rows {
                return Err(format!("LOG=8 col has {} rows, expected {n_rows}", col.values.len()));
            }
            cols.push(col.values.iter().map(|v| v.0).collect());
        }
    }

    gen_vfri9_hints_from_cols_nfolds(&cols, TREE_DEPTH, batch_merkle_root, n_queries, num_folds)
}

/// Generate cross-bound VFRI9 hints for V23's two trace groups.
///
/// Identical to gen_mldsa_v23_vfri8_cross_bound_hints but using VFRI9 generators.
///
/// bound_root_10 = keccak256(batch_root ‖ trace_root_8)
/// bound_root_8  = keccak256(batch_root ‖ trace_root_10)
pub fn gen_mldsa_v23_vfri9_cross_bound_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_root:        &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>, Vec<u8>, String, Vec<u8>), String> {
    use sha3::{Keccak256, Digest as Sha3Digest};

    if batch_root.len() != 32 {
        return Err(format!("batch_root must be 32 bytes, got {}", batch_root.len()));
    }

    // Pass 1: extract trace roots
    let (proof10_p1, _, _) = gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, batch_root, 1, num_folds)?;
    let (proof8_p1,  _, _) = gen_mldsa_v23_vfri9_hints_log8(z, c, t1, a_hat, hints, batch_root, 1, num_folds)?;

    if proof10_p1.len() < 40 || proof8_p1.len() < 40 {
        return Err("proof bytes too short to contain trace root at [8:40]".into());
    }
    let trace_root_10: [u8; 32] = proof10_p1[8..40].try_into().unwrap();
    let trace_root_8:  [u8; 32] = proof8_p1[8..40].try_into().unwrap();

    let bound_root_10: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_8);
        h.finalize().into()
    };
    let bound_root_8: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_10);
        h.finalize().into()
    };

    // Pass 2: generate final hints with cross-bound roots
    let (proof10, commit10, hints10) =
        gen_mldsa_v23_vfri9_hints(z, c, t1, a_hat, &bound_root_10, n_queries, num_folds)?;
    let (proof8, commit8, hints8) =
        gen_mldsa_v23_vfri9_hints_log8(z, c, t1, a_hat, hints, &bound_root_8, n_queries, num_folds)?;

    Ok((proof10, commit10, hints10, proof8, commit8, hints8))
}

/// VFRI10 wrapper for V23 LOG=10 group (NttBatch + InttBatch, 1298 cols, tree_depth=10).
/// Identical trace construction to gen_mldsa_v23_vfri9_hints; only the generic
/// generator changes (t=4 hash backend).
pub fn gen_mldsa_v23_vfri10_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);

    let (ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);
    let tree_depth = mldsa_ntt_batch_air::LOG_N_ROWS;

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (_az_cols, az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (_ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (intt_cols, _) = mldsa_intt_batch_air::build_trace(&intt_inputs);

    let n_rows = 1usize << tree_depth;
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(ntt_cols.len() + intt_cols.len());
    for col in &ntt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }
    for col in &intt_cols {
        cols.push(col.values.iter().map(|v| v.0).collect());
        debug_assert_eq!(cols.last().unwrap().len(), n_rows);
    }

    gen_vfri10_hints_from_cols_nfolds(&cols, tree_depth, batch_merkle_root, n_queries, num_folds)
}

/// VFRI10 wrapper for V23 LOG=8 group (2206 cols). Same trace as the VFRI9 log8
/// wrapper; only the generic generator (t=4 backend) differs.
pub fn gen_mldsa_v23_vfri10_hints_log8(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_merkle_root: &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>), String> {
    use crate::mldsa_ntt_batch_air;
    use crate::mldsa_intt_batch_air;
    use crate::mldsa_az_full_air;
    use crate::mldsa_ct1_full_air;
    use crate::mldsa_wprime_full_air;
    use crate::mldsa_norm_check_batch_air;
    use crate::mldsa_range_q_batch_air;
    use crate::mldsa_use_hint_batch_air;

    const L: usize = 5;
    const K: usize = 6;

    if a_hat.len() != K * L {
        return Err(format!("a_hat must have K*L={} entries, got {}", K * L, a_hat.len()));
    }
    if batch_merkle_root.len() != 32 {
        return Err(format!("batch_merkle_root must be 32 bytes, got {}", batch_merkle_root.len()));
    }
    if n_queries == 0 || n_queries > 64 {
        return Err(format!("n_queries must be 1..64, got {n_queries}"));
    }

    let mut ntt_inputs: Vec<[i64; 256]> = Vec::with_capacity(L + 1 + K);
    ntt_inputs.extend_from_slice(z);
    ntt_inputs.push(*c);
    ntt_inputs.extend_from_slice(t1);
    let (_ntt_cols, ntt_outputs) = mldsa_ntt_batch_air::build_trace(&ntt_inputs);

    let z_hat:  [[i64; 256]; L] = ntt_outputs[0..L]
        .try_into().map_err(|_| "z_hat slice error".to_string())?;
    let c_hat:  [i64; 256]      = ntt_outputs[L];
    let t1_hat: [[i64; 256]; K] = ntt_outputs[L + 1..L + 1 + K]
        .try_into().map_err(|_| "t1_hat slice error".to_string())?;

    let (az_cols,  az_hat)  = mldsa_az_full_air::build_trace(a_hat, &z_hat);
    let (ct1_cols, ct1_hat) = mldsa_ct1_full_air::build_trace(&c_hat, &t1_hat);

    let (rq_cols, rq_valid) = mldsa_range_q_batch_air::build_trace(&az_hat);
    if !rq_valid {
        return Err("RangeQBatch: az_hat contains values outside [0, Q)".to_string());
    }

    let mut intt_inputs: Vec<[i64; 256]> = Vec::with_capacity(2 * K);
    intt_inputs.extend_from_slice(&az_hat);
    intt_inputs.extend_from_slice(&ct1_hat);
    let (_intt_cols, intt_out) = mldsa_intt_batch_air::build_trace(&intt_inputs);
    let az_out:  [[i64; 256]; K] = intt_out[..K].try_into().map_err(|_| "az_out slice error".to_string())?;
    let ct1_out: [[i64; 256]; K] = intt_out[K..].try_into().map_err(|_| "ct1_out slice error".to_string())?;

    let (wp_cols,   _w_prime) = mldsa_wprime_full_air::build_trace(&az_out, &ct1_out);
    let w_prime: [[i64; 256]; K] = _w_prime;
    let (norm_cols, _, _) = mldsa_norm_check_batch_air::build_trace(z);
    let (uh_main_cols, uh_preproc_cols, _, _) =
        mldsa_use_hint_batch_air::build_trace_v2(&w_prime, hints);

    const TREE_DEPTH: u32 = 8;
    let n_rows = 1usize << (TREE_DEPTH as usize);
    let total_cols = az_cols.len() + ct1_cols.len() + rq_cols.len()
        + wp_cols.len() + norm_cols.len() + uh_main_cols.len() + uh_preproc_cols.len();
    let mut cols: Vec<Vec<u32>> = Vec::with_capacity(total_cols);
    let groups = [&az_cols, &ct1_cols, &rq_cols, &wp_cols, &norm_cols, &uh_main_cols, &uh_preproc_cols];
    for group in &groups {
        for col in group.iter() {
            if col.values.len() != n_rows {
                return Err(format!("LOG=8 col has {} rows, expected {n_rows}", col.values.len()));
            }
            cols.push(col.values.iter().map(|v| v.0).collect());
        }
    }

    gen_vfri10_hints_from_cols_nfolds(&cols, TREE_DEPTH, batch_merkle_root, n_queries, num_folds)
}

/// Generate cross-bound VFRI10 hints for V23's two trace groups.
///
/// Identical to gen_mldsa_v23_vfri9_cross_bound_hints but using VFRI10 generators.
///
/// bound_root_10 = keccak256(batch_root ‖ trace_root_8)
/// bound_root_8  = keccak256(batch_root ‖ trace_root_10)
pub fn gen_mldsa_v23_vfri10_cross_bound_hints(
    z:                 &[[i64; 256]; 5],
    c:                 &[i64; 256],
    t1:                &[[i64; 256]; 6],
    a_hat:             &[[i64; 256]],
    hints:             &[[bool; 256]; 6],
    batch_root:        &[u8],
    n_queries:         usize,
    num_folds:         Option<usize>,
) -> Result<(Vec<u8>, String, Vec<u8>, Vec<u8>, String, Vec<u8>), String> {
    use sha3::{Keccak256, Digest as Sha3Digest};

    if batch_root.len() != 32 {
        return Err(format!("batch_root must be 32 bytes, got {}", batch_root.len()));
    }

    // Pass 1: extract trace roots
    let (proof10_p1, _, _) = gen_mldsa_v23_vfri10_hints(z, c, t1, a_hat, batch_root, 1, num_folds)?;
    let (proof8_p1,  _, _) = gen_mldsa_v23_vfri10_hints_log8(z, c, t1, a_hat, hints, batch_root, 1, num_folds)?;

    if proof10_p1.len() < 40 || proof8_p1.len() < 40 {
        return Err("proof bytes too short to contain trace root at [8:40]".into());
    }
    let trace_root_10: [u8; 32] = proof10_p1[8..40].try_into().unwrap();
    let trace_root_8:  [u8; 32] = proof8_p1[8..40].try_into().unwrap();

    let bound_root_10: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_8);
        h.finalize().into()
    };
    let bound_root_8: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(batch_root);
        h.update(&trace_root_10);
        h.finalize().into()
    };

    // Pass 2: generate final hints with cross-bound roots
    let (proof10, commit10, hints10) =
        gen_mldsa_v23_vfri10_hints(z, c, t1, a_hat, &bound_root_10, n_queries, num_folds)?;
    let (proof8, commit8, hints8) =
        gen_mldsa_v23_vfri10_hints_log8(z, c, t1, a_hat, hints, &bound_root_8, n_queries, num_folds)?;

    Ok((proof10, commit10, hints10, proof8, commit8, hints8))
}
