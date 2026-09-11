// ARCHIVED — NOT COMPILED, NOT IN ANY MODULE TREE.
// Removed by the Ф1 narrowing; restored here from stark_stwo/src/lib.rs@f2020d9 so the code
// stays visible in the repository rather than only in git history.
// To bring an item back, paste it into stark_stwo/src/lib.rs and re-run `cargo test`.

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
