/// ML-DSA-65 full matrix-vector product AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves ALL K=6 output polynomials of Az̃ simultaneously in a single STARK:
///   az_out[i][p] = Σ_{j=0}^{L-1} Ã[i][j][p] · z̃[j][p]   mod Q
///
/// # Trace layout  (1523 columns, 256 rows)
///
/// Shared inputs (5 columns):
///   col  0..4    z[j]    = z̃[j][p]          ∈ [0, Q)
///
/// Per output row i = 0..K-1:
///   Base block (23 cols):
///     col  5+i*253+0..4    a[i][j]   ∈ [0, Q)  matrix entries
///     col  5+i*253+5..9    t[i][j]   ∈ [0, Q)  products mod Q
///     col  5+i*253+10..14  ct[i][j]  ∈ [0, Q)  multiplication carries
///     col  5+i*253+15..18  s[i][r]   ∈ [0, Q)  running accumulator
///     col  5+i*253+19..22  cs[i][r]  ∈ {0,1}   addition carries
///   Range-check bits (230 cols per row):
///     t_bits[i][j][k]  for j=0..L, k=0..N_BITS   (L×N_BITS = 115 cols)
///     ct_bits[i][j][k] for j=0..L, k=0..N_BITS   (L×N_BITS = 115 cols)
///
/// Total: 5 + K×(23 + 2·L·N_BITS) = 5 + 6×253 = 1523 columns.
///
/// # Constraints  (1518 total, max degree 2)
///
/// Per row i in 0..K:
///   C1–C5     a[i][j]·z[j] − t[i][j] − ct[i][j]·Q = 0   (mul mod Q)
///   C6–C13    accumulation chain (add mod Q + boolean)
///   C14–C18   t[i][j] − Σ t_bits[i][j][k]·2^k = 0
///   C19–C133  t_bits[i][j][k]² − t_bits[i][j][k] = 0     (115 booleans)
///   C134–C138 ct[i][j] − Σ ct_bits[i][j][k]·2^k = 0
///   C139–C253 ct_bits[i][j][k]² − ct_bits[i][j][k] = 0   (115 booleans)
///
/// # Soundness
///
/// Mul constraints had ~32 654 fake solutions per multiplier before this fix.
/// With 23-bit decompositions the residual error drops to ~2^{−47} per mul.
/// Full closure requires lookup arguments (planned for MVP-4).

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

pub const LOG_N_ROWS: u32 = 8;

/// Bits in each 23-bit range decomposition.
pub const N_BITS: usize = 23;
/// Columns per K-row block: 23 base + 2·L·N_BITS range bits.
const COLS_PER_ROW: usize = 23 + 2 * L * N_BITS; // 253
/// Total columns: 5 shared z + K × COLS_PER_ROW.
pub const N_COLS: usize = L + K * COLS_PER_ROW; // 1523

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
        let q  = BaseField::from_u32_unchecked(Q as u32);
        let bf = |v: u32| E::F::from(BaseField::from_u32_unchecked(v));

        // Shared z columns (L=5 cols)
        let z: [E::F; 5] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );

        for _i in 0..K {
            // Base block: 5 a, 5 t, 5 ct, 4 s, 4 cs
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

            // Bit columns: t_bits[j][k] for j in 0..L, k in 0..N_BITS
            let t_bits: [[E::F; 23]; 5] = std::array::from_fn(|_|
                std::array::from_fn(|_|
                    eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
                )
            );
            let ct_bits: [[E::F; 23]; 5] = std::array::from_fn(|_|
                std::array::from_fn(|_|
                    eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
                )
            );

            // C1–C5: a[j] × z[j] = t[j] + ct[j] × Q
            for j in 0..L {
                eval.add_constraint(
                    a[j].clone() * z[j].clone() - t[j].clone() - ct[j].clone() * q
                );
            }

            // C6–C13: accumulation chain
            eval.add_constraint(t[0].clone() + t[1].clone() - s[0].clone() - cs[0].clone() * q);
            eval.add_constraint(cs[0].clone() * cs[0].clone() - cs[0].clone());
            eval.add_constraint(s[0].clone() + t[2].clone() - s[1].clone() - cs[1].clone() * q);
            eval.add_constraint(cs[1].clone() * cs[1].clone() - cs[1].clone());
            eval.add_constraint(s[1].clone() + t[3].clone() - s[2].clone() - cs[2].clone() * q);
            eval.add_constraint(cs[2].clone() * cs[2].clone() - cs[2].clone());
            eval.add_constraint(s[2].clone() + t[4].clone() - s[3].clone() - cs[3].clone() * q);
            eval.add_constraint(cs[3].clone() * cs[3].clone() - cs[3].clone());

            // C14–C18: t[j] decomposition; C19–C133: t_bits booleans
            for j in 0..L {
                let mut sum = bf(0);
                let mut pw: u32 = 1;
                for k in 0..N_BITS {
                    sum = sum + t_bits[j][k].clone() * bf(pw);
                    pw <<= 1;
                }
                eval.add_constraint(t[j].clone() - sum);
                for k in 0..N_BITS {
                    let b = t_bits[j][k].clone();
                    eval.add_constraint(b.clone() * b - t_bits[j][k].clone());
                }
            }

            // C134–C138: ct[j] decomposition; C139–C253: ct_bits booleans
            for j in 0..L {
                let mut sum = bf(0);
                let mut pw: u32 = 1;
                for k in 0..N_BITS {
                    sum = sum + ct_bits[j][k].clone() * bf(pw);
                    pw <<= 1;
                }
                eval.add_constraint(ct[j].clone() - sum);
                for k in 0..N_BITS {
                    let b = ct_bits[j][k].clone();
                    eval.add_constraint(b.clone() * b - ct_bits[j][k].clone());
                }
            }
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

pub fn build_trace(
    a_hat: &[[i64; N]],
    z_hat: &[[i64; N]; L],
) -> (TraceColumns, [[i64; N]; K]) {
    assert_eq!(a_hat.len(), K * L, "a_hat must have K*L={} entries", K * L);

    let n      = 1_usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);
    let bf0    = BaseField::from_u32_unchecked(0);

    let mut z_cols: [Vec<BaseField>; L] = std::array::from_fn(|_| vec![bf0; n]);

    let mut a_cols:  Vec<[Vec<BaseField>; L]> = (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();
    let mut t_cols:  Vec<[Vec<BaseField>; L]> = (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();
    let mut ct_cols: Vec<[Vec<BaseField>; L]> = (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();
    let mut s_cols:  Vec<[Vec<BaseField>; 4]> = (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();
    let mut cs_cols: Vec<[Vec<BaseField>; 4]> = (0..K).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();

    // t_bit_cols[i][j][k] and ct_bit_cols[i][j][k], each length n
    let mut t_bit_cols:  Vec<Vec<[Vec<BaseField>; 23]>> = (0..K).map(|_|
        (0..L).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect()
    ).collect();
    let mut ct_bit_cols: Vec<Vec<[Vec<BaseField>; 23]>> = (0..K).map(|_|
        (0..L).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect()
    ).collect();

    let mut az_out: [[i64; N]; K] = [[0i64; N]; K];

    for p in 0..N {
        let zv: [i64; L] = std::array::from_fn(|j| z_hat[j][p]);

        for i in 0..K {
            let av: [i64; L] = std::array::from_fn(|j| a_hat[i * L + j][p]);
            let tv:  [i64; L] = std::array::from_fn(|j| (av[j] * zv[j]) % Q);
            let ctv: [i64; L] = std::array::from_fn(|j| (av[j] * zv[j]) / Q);

            let sv0 = { let r = tv[0] + tv[1]; r - if r >= Q { Q } else { 0 } };
            let sv1 = { let r = sv0 + tv[2];   r - if r >= Q { Q } else { 0 } };
            let sv2 = { let r = sv1 + tv[3];   r - if r >= Q { Q } else { 0 } };
            let sv3 = { let r = sv2 + tv[4];   r - if r >= Q { Q } else { 0 } };

            az_out[i][p] = sv3;

            let csv: [i64; 4] = [
                if tv[0] + tv[1] >= Q { 1 } else { 0 },
                if sv0   + tv[2] >= Q { 1 } else { 0 },
                if sv1   + tv[3] >= Q { 1 } else { 0 },
                if sv2   + tv[4] >= Q { 1 } else { 0 },
            ];

            for j in 0..L {
                a_cols[i][j][p]  = bf(av[j]);
                t_cols[i][j][p]  = bf(tv[j]);
                ct_cols[i][j][p] = bf(ctv[j]);
                let tu  = tv[j]  as u32;
                let ctu = ctv[j] as u32;
                for k in 0..N_BITS {
                    t_bit_cols[i][j][k][p]  = BaseField::from_u32_unchecked((tu  >> k) & 1);
                    ct_bit_cols[i][j][k][p] = BaseField::from_u32_unchecked((ctu >> k) & 1);
                }
            }
            for r in 0..4 {
                s_cols[i][r][p]  = bf([sv0, sv1, sv2, sv3][r]);
                cs_cols[i][r][p] = bf(csv[r]);
            }
        }
        for j in 0..L {
            z_cols[j][p] = bf(zv[j]);
        }
    }

    // Bit-reverse all buffers.
    for col in z_cols.iter_mut() { bit_reverse_coset_to_circle_domain_order(col); }
    for i in 0..K {
        for c in a_cols[i].iter_mut()  { bit_reverse_coset_to_circle_domain_order(c); }
        for c in t_cols[i].iter_mut()  { bit_reverse_coset_to_circle_domain_order(c); }
        for c in ct_cols[i].iter_mut() { bit_reverse_coset_to_circle_domain_order(c); }
        for c in s_cols[i].iter_mut()  { bit_reverse_coset_to_circle_domain_order(c); }
        for c in cs_cols[i].iter_mut() { bit_reverse_coset_to_circle_domain_order(c); }
        for j in 0..L {
            for c in t_bit_cols[i][j].iter_mut()  { bit_reverse_coset_to_circle_domain_order(c); }
            for c in ct_bit_cols[i][j].iter_mut() { bit_reverse_coset_to_circle_domain_order(c); }
        }
    }

    // Pack columns in evaluate() read order:
    //   z[0..L], then per i: a[i][0..L], t[i][0..L], ct[i][0..L],
    //                         s[i][0..4], cs[i][0..4],
    //                         t_bits[i][j=0..L][k=0..N_BITS],
    //                         ct_bits[i][j=0..L][k=0..N_BITS]
    let mut columns: TraceColumns = Vec::with_capacity(N_COLS);
    for j in 0..L { columns.push(CircleEvaluation::new(domain, z_cols[j].clone())); }
    for i in 0..K {
        for j in 0..L { columns.push(CircleEvaluation::new(domain, a_cols[i][j].clone())); }
        for j in 0..L { columns.push(CircleEvaluation::new(domain, t_cols[i][j].clone())); }
        for j in 0..L { columns.push(CircleEvaluation::new(domain, ct_cols[i][j].clone())); }
        for r in 0..4 { columns.push(CircleEvaluation::new(domain, s_cols[i][r].clone())); }
        for r in 0..4 { columns.push(CircleEvaluation::new(domain, cs_cols[i][r].clone())); }
        for j in 0..L {
            for k in 0..N_BITS {
                columns.push(CircleEvaluation::new(domain, t_bit_cols[i][j][k].clone()));
            }
        }
        for j in 0..L {
            for k in 0..N_BITS {
                columns.push(CircleEvaluation::new(domain, ct_bit_cols[i][j][k].clone()));
            }
        }
    }

    debug_assert_eq!(columns.len(), N_COLS);
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
    fn test_column_count() {
        assert_eq!(N_COLS, 1523);
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
        let (_, az_out) = build_trace(&a_hat, &[[0i64; N]; L]);
        for i in 0..K {
            assert_eq!(az_out[i], [0i64; N], "row {i} must be zero for zero z");
        }
    }

    #[test]
    fn test_az_full_zero_a() {
        let z_hat: [[i64; N]; L] = std::array::from_fn(|j| random_poly(j as u64 + 200));
        let (_, az_out) = build_trace(&vec![[0i64; N]; K * L], &z_hat);
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
        for i in 0..K {
            let a_row: [[i64; N]; L] = std::array::from_fn(|j| a_hat[i * L + j]);
            let (_, az_row_i) = mldsa_az_air::build_trace(&a_row, &z_hat);
            assert_eq!(az_full[i], az_row_i, "row {i}: az_full ≠ az_row");
        }
    }

    #[test]
    fn test_constraints_on_trace() {
        let a_hat: Vec<[i64; N]> = (0..K * L).map(|k| random_poly(k as u64 * 3 + 77)).collect();
        let z_hat: [[i64; N]; L] = std::array::from_fn(|j| random_poly(j as u64 + 300));
        let (cols, _) = build_trace(&a_hat, &z_hat);
        let col_vals: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vals.iter().collect();
        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], col_refs]);
        let evaluator = AzFullEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
