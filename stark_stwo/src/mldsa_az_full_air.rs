/// ML-DSA-65 full matrix-vector product AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves ALL K=6 output polynomials of Az̃ simultaneously in a single STARK:
///   az_out[i][p] = Σ_{j=0}^{L-1} Ã[i][j][p] · z̃[j][p]   mod Q
///
/// for every coefficient position p = 0..N-1 = 0..255.
///
/// This replaces K=6 separate `prove_az_row` calls with one proof, reducing
/// the sub-proof count for the Az step from 17 (v2) to 12 (v3: L NTT + K INTT + 1 Az).
///
/// # Trace layout  (143 columns, 256 rows)
///
/// Shared inputs (5 columns):
///   col  0..4    z[j]    = z̃[j][p]          ∈ [0, Q)   shared across all rows
///
/// Per output row i = 0..K-1  (23 columns each):
///   col  5 + i*23 + 0..4    a[i][j]   ∈ [0, Q)  matrix entries
///   col  5 + i*23 + 5..9    t[i][j]   ∈ [0, Q)  products a[i][j]·z[j] mod Q
///   col  5 + i*23 + 10..14  ct[i][j]  ∈ [0, Q)  multiplication carries ⌊a[i][j]·z[j]/Q⌋
///   col  5 + i*23 + 15..18  s[i][r]   ∈ [0, Q)  running accumulator
///   col  5 + i*23 + 19..22  cs[i][r]  ∈ {0,1}   addition carries
///
/// The final accumulator s[i][3] equals az_out[i][p].
///
/// # Constraints  (78 total, max degree 2)
///
/// For each row i in 0..K:
///   C1–C5   a[i][j]·z[j] − t[i][j] − ct[i][j]·Q = 0     (mul mod Q, degree 2)
///   C6      t[i][0]+t[i][1] − s[i][0] − cs[i][0]·Q = 0
///   C7      cs[i][0]² − cs[i][0] = 0
///   C8      s[i][0]+t[i][2] − s[i][1] − cs[i][1]·Q = 0
///   C9      cs[i][1]² − cs[i][1] = 0
///   C10     s[i][1]+t[i][3] − s[i][2] − cs[i][2]·Q = 0
///   C11     cs[i][2]² − cs[i][2] = 0
///   C12     s[i][2]+t[i][4] − s[i][3] − cs[i][3]·Q = 0
///   C13     cs[i][3]² − cs[i][3] = 0
///
/// # Soundness
///
/// Mul constraints (C1–C5) share the M31 wrap-around limitation of the Az-row AIR.
/// Add/boolean constraints (C6–C13) are fully sound since all addends are < Q < 2²³.
/// Range proofs on t[i][j] and ct[i][j] are deferred to MVP-4.

use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

use crate::mldsa::{Q, N};
use crate::mldsa::params::{K, L};

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

/// log₂(N) = 8  →  256 rows (one per NTT coefficient).
pub const LOG_N_ROWS: u32 = 8;

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct AzFullEval {
    pub log_n_rows: u32,
}

pub type AzFullComponent = FrameworkComponent<AzFullEval>;

impl FrameworkEval for AzFullEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        // Shared z columns (5 columns: cols 0..4).
        let z: [E::F; 5] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );

        // Per-row computation (23 columns per row: 5 a + 5 t + 5 ct + 4 s + 4 cs).
        for _i in 0..K {
            let a:  [E::F; 5] = std::array::from_fn(|_|
                eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
            );
            let t:  [E::F; 5] = std::array::from_fn(|_|
                eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
            );
            let ct: [E::F; 5] = std::array::from_fn(|_|
                eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
            );
            let s:  [E::F; 4] = std::array::from_fn(|_|
                eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
            );
            let cs: [E::F; 4] = std::array::from_fn(|_|
                eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
            );

            // C1–C5: a[j] * z[j] = t[j] + ct[j] * Q
            for j in 0..L {
                eval.add_constraint(
                    a[j].clone() * z[j].clone()
                        - t[j].clone()
                        - ct[j].clone() * q,
                );
            }

            // C6–C13: accumulation chain (identical to Az-row AIR per row).
            eval.add_constraint(t[0].clone() + t[1].clone() - s[0].clone() - cs[0].clone() * q);
            eval.add_constraint(cs[0].clone() * cs[0].clone() - cs[0].clone());

            eval.add_constraint(s[0].clone() + t[2].clone() - s[1].clone() - cs[1].clone() * q);
            eval.add_constraint(cs[1].clone() * cs[1].clone() - cs[1].clone());

            eval.add_constraint(s[1].clone() + t[3].clone() - s[2].clone() - cs[2].clone() * q);
            eval.add_constraint(cs[2].clone() * cs[2].clone() - cs[2].clone());

            eval.add_constraint(s[2].clone() + t[4].clone() - s[3].clone() - cs[3].clone() * q);
            eval.add_constraint(cs[3].clone() * cs[3].clone() - cs[3].clone());
        }

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> AzFullComponent {
    AzFullComponent::new(
        &mut TraceLocationAllocator::default(),
        AzFullEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Build the full-matrix Az trace.
///
/// `a_hat` — K*L NTT-domain matrix entries in row-major order:
///           `a_hat[i * L + j]` = Ã[i][j].
/// `z_hat` — L NTT-domain input polynomials z̃[0..L-1].
///
/// Returns `(columns, az_out)` where `az_out[i]` = Σ_j Ã[i][j] ⊙ z̃[j].
pub fn build_trace(
    a_hat: &[[i64; N]],   // K*L entries
    z_hat: &[[i64; N]; L],
) -> (TraceColumns, [[i64; N]; K]) {
    assert_eq!(a_hat.len(), K * L, "a_hat must have exactly K*L = {} entries", K * L);

    let n      = 1_usize << LOG_N_ROWS; // 256
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);
    let bf0    = BaseField::from_u32_unchecked(0);

    // Column buffers: 5 z + 6*(5 a + 5 t + 5 ct + 4 s + 4 cs) = 143 columns.
    let mut z_cols:  [Vec<BaseField>; L] = std::array::from_fn(|_| vec![bf0; n]);

    // Per-row buffers indexed as [K][col_within_row][row_pos].
    let mut a_cols:  Vec<[Vec<BaseField>; L]>      = (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();
    let mut t_cols:  Vec<[Vec<BaseField>; L]>      = (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();
    let mut ct_cols: Vec<[Vec<BaseField>; L]>      = (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();
    let mut s_cols:  Vec<[Vec<BaseField>; 4]>      = (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();
    let mut cs_cols: Vec<[Vec<BaseField>; 4]>      = (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();

    let mut az_out: [[i64; N]; K] = [[0i64; N]; K];

    for p in 0..N {
        // Fill shared z values.
        let zv: [i64; L] = std::array::from_fn(|j| z_hat[j][p]);

        for i in 0..K {
            let av: [i64; L] = std::array::from_fn(|j| a_hat[i * L + j][p]);

            // Products t[j] = av[j] * zv[j] mod Q, carries ct[j].
            let tv:  [i64; L] = std::array::from_fn(|j| (av[j] * zv[j]) % Q);
            let ctv: [i64; L] = std::array::from_fn(|j| (av[j] * zv[j]) / Q);

            // Accumulation chain: s[0]=t[0]+t[1], s[r]=s[r-1]+t[r+2].
            let sv0 = { let r = tv[0] + tv[1]; r - if r >= Q { Q } else { 0 } };
            let sv1 = { let r = sv0 + tv[2];   r - if r >= Q { Q } else { 0 } };
            let sv2 = { let r = sv1 + tv[3];   r - if r >= Q { Q } else { 0 } };
            let sv3 = { let r = sv2 + tv[4];   r - if r >= Q { Q } else { 0 } };

            let sv  = [sv0, sv1, sv2, sv3];
            let csv = [
                if tv[0] + tv[1] >= Q { 1i64 } else { 0 },
                if sv0   + tv[2] >= Q { 1i64 } else { 0 },
                if sv1   + tv[3] >= Q { 1i64 } else { 0 },
                if sv2   + tv[4] >= Q { 1i64 } else { 0 },
            ];

            az_out[i][p] = sv3;

            for j in 0..L {
                a_cols[i][j][p]  = bf(av[j]);
                t_cols[i][j][p]  = bf(tv[j]);
                ct_cols[i][j][p] = bf(ctv[j]);
            }
            for r in 0..4 {
                s_cols[i][r][p]  = bf(sv[r]);
                cs_cols[i][r][p] = bf(csv[r]);
            }
        }
        for j in 0..L {
            z_cols[j][p] = bf(zv[j]);
        }
    }

    // Apply bit-reversal to all column buffers.
    for col in z_cols.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col);
    }
    for i in 0..K {
        for col in a_cols[i].iter_mut()  { bit_reverse_coset_to_circle_domain_order(col); }
        for col in t_cols[i].iter_mut()  { bit_reverse_coset_to_circle_domain_order(col); }
        for col in ct_cols[i].iter_mut() { bit_reverse_coset_to_circle_domain_order(col); }
        for col in s_cols[i].iter_mut()  { bit_reverse_coset_to_circle_domain_order(col); }
        for col in cs_cols[i].iter_mut() { bit_reverse_coset_to_circle_domain_order(col); }
    }

    // Pack into flat column vec matching the evaluate() read order:
    //   z[0..L], then for each i: a[i][0..L], t[i][0..L], ct[i][0..L], s[i][0..4], cs[i][0..4]
    let mut columns: TraceColumns = Vec::with_capacity(L + K * 23);
    for j in 0..L {
        columns.push(CircleEvaluation::new(domain, z_cols[j].clone()));
    }
    for i in 0..K {
        for j in 0..L  { columns.push(CircleEvaluation::new(domain, a_cols[i][j].clone())); }
        for j in 0..L  { columns.push(CircleEvaluation::new(domain, t_cols[i][j].clone())); }
        for j in 0..L  { columns.push(CircleEvaluation::new(domain, ct_cols[i][j].clone())); }
        for r in 0..4  { columns.push(CircleEvaluation::new(domain, s_cols[i][r].clone())); }
        for r in 0..4  { columns.push(CircleEvaluation::new(domain, cs_cols[i][r].clone())); }
    }

    (columns, az_out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    fn random_poly(seed: u64) -> [i64; N] {
        let mut state = seed;
        let mut p = [0i64; N];
        for c in p.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *c = ((state >> 33) as i64).abs() % Q;
        }
        p
    }

    fn reference_az_full(a_hat: &[[i64; N]], z_hat: &[[i64; N]; L]) -> [[i64; N]; K] {
        let mut out = [[0i64; N]; K];
        for i in 0..K {
            for p in 0..N {
                let mut acc = 0i64;
                for j in 0..L {
                    acc = (acc + a_hat[i * L + j][p] * z_hat[j][p]) % Q;
                }
                out[i][p] = acc;
            }
        }
        out
    }

    #[test]
    fn test_az_full_correctness() {
        let a_hat: Vec<[i64; N]> = (0..K * L).map(|k| random_poly(k as u64 * 7)).collect();
        let z_hat: [[i64; N]; L] = std::array::from_fn(|j| random_poly(j as u64 * 100 + 50));

        let (_, az_out) = build_trace(&a_hat, &z_hat);
        let expected = reference_az_full(&a_hat, &z_hat);

        assert_eq!(az_out, expected, "output mismatch");
        for i in 0..K {
            for p in 0..N {
                assert!(az_out[i][p] >= 0 && az_out[i][p] < Q,
                    "az_out[{i}][{p}] = {} out of [0, Q)", az_out[i][p]);
            }
        }
    }

    #[test]
    fn test_az_full_zero_z() {
        let a_hat: Vec<[i64; N]> = (0..K * L).map(|k| random_poly(k as u64 + 1)).collect();
        let z_zero = [[0i64; N]; L];
        let (_, az_out) = build_trace(&a_hat, &z_zero);
        for i in 0..K {
            assert_eq!(az_out[i], [0i64; N], "row {i} must be zero for zero z");
        }
    }

    #[test]
    fn test_az_full_zero_a() {
        let a_zero: Vec<[i64; N]> = vec![[0i64; N]; K * L];
        let z_hat: [[i64; N]; L] = std::array::from_fn(|j| random_poly(j as u64 + 200));
        let (_, az_out) = build_trace(&a_zero, &z_hat);
        for i in 0..K {
            assert_eq!(az_out[i], [0i64; N], "row {i} must be zero for zero A");
        }
    }

    #[test]
    fn test_az_full_matches_az_row_per_row() {
        use crate::mldsa_az_air;
        let a_hat: Vec<[i64; N]> = (0..K * L).map(|k| random_poly(k as u64 * 13 + 3)).collect();
        let z_hat: [[i64; N]; L] = std::array::from_fn(|j| random_poly(j as u64 * 17 + 9));

        let (_, az_full) = build_trace(&a_hat, &z_hat);

        // Each row of az_full must match the per-row Az-row AIR output.
        for i in 0..K {
            let a_row: [[i64; N]; L] = std::array::from_fn(|j| a_hat[i * L + j]);
            let (_, az_row_i) = mldsa_az_air::build_trace(&a_row, &z_hat);
            assert_eq!(az_full[i], az_row_i,
                "row {i}: az_full output disagrees with az_row output");
        }
    }

    #[test]
    fn test_constraints_on_trace() {
        let a_hat: Vec<[i64; N]> = (0..K * L).map(|k| random_poly(k as u64 * 3 + 77)).collect();
        let z_hat: [[i64; N]; L] = std::array::from_fn(|j| random_poly(j as u64 + 300));

        let (cols, _) = build_trace(&a_hat, &z_hat);

        let col_vals: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vals.iter().collect();

        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![],
            col_refs,
        ]);

        let evaluator = AzFullEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
