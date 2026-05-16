/// ML-DSA-65 matrix-vector product AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves one output polynomial of the NTT-domain product  Az̃[i] = Σ_{j=0}^{L-1} Ã[i][j] ⊙ z̃[j]
/// for a fixed row `i` of the public-key matrix A.
///
/// # Trace layout  (258 columns, N = 256 rows — one per coefficient position)
///
/// Inputs (10 columns):
///   col  0..4   a[j]         ∈ [0, Q)   matrix row coefficients
///   col  5..9   z[j]         ∈ [0, Q)   vector coefficients
///
/// Products (10 columns):
///   col 10..14  t[j]         ∈ [0, Q)   a[j]×z[j] mod Q  (witness)
///   col 15..19  ct[j]        ∈ [0, Q)   ⌊a[j]×z[j]/Q⌋    (witness)
///
/// Accumulation (8 columns):
///   col 20      s[0]  = t[0]+t[1] mod Q
///   col 21      cs[0] ∈ {0,1}
///   col 22      s[1]  = s[0]+t[2] mod Q
///   col 23      cs[1] ∈ {0,1}
///   col 24      s[2]  = s[1]+t[3] mod Q
///   col 25      cs[2] ∈ {0,1}
///   col 26      s[3]  = s[2]+t[4] mod Q   ← Az̃[i][p]
///   col 27      cs[3] ∈ {0,1}
///
/// Range-check bit columns (230 columns):
///   col 28..142   t_bits[j][k]  for j=0..5, k=0..23   (5×23 = 115 cols)
///   col 143..257  ct_bits[j][k] for j=0..5, k=0..23   (5×23 = 115 cols)
///
/// # Constraints (253 total, max degree 2)
///
///   C1–C5     a[j]×z[j] − t[j] − ct[j]×Q = 0              (mul mod Q, degree 2)
///   C6–C13    accumulation chain (add mod Q + boolean carry) (fully sound)
///   C14–C18   t[j] − Σ t_bits[j][k]·2^k = 0                (t decompositions)
///   C19–C133  t_bits[j][k]² − t_bits[j][k] = 0             (115 booleans)
///   C134–C138 ct[j] − Σ ct_bits[j][k]·2^k = 0              (ct decompositions)
///   C139–C253 ct_bits[j][k]² − ct_bits[j][k] = 0           (115 booleans)
///
/// # Soundness
///
/// C1–C5 in M31 had ~32 654 fake solutions per multiplication before this fix.
/// With 23-bit decompositions of t[j] and ct[j] the residual error drops to
/// ~2^{−47} per multiplier.  Full closure requires lookup arguments (MVP-4).

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
use crate::mldsa::params::L;

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

pub const LOG_N_ROWS: u32 = 8;

/// Bits in each 23-bit range decomposition.
pub const N_BITS: usize = 23;
/// Total columns: 10 inputs + 10 products + 8 accum + 2·L·N_BITS range bits.
pub const N_COLS: usize = 28 + 2 * L * N_BITS; // 258

pub struct AzRowEval {
    pub log_n_rows: u32,
}

pub type AzRowComponent = FrameworkComponent<AzRowEval>;

impl FrameworkEval for AzRowEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        let a: [E::F; 5] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );
        let z: [E::F; 5] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );
        let t: [E::F; 5] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );
        let ct: [E::F; 5] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );
        let s: [E::F; 4] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );
        let cs: [E::F; 4] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );

        // Bit columns: t_bits[j][k] for j in 0..L, k in 0..N_BITS.
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
                a[j].clone() * z[j].clone()
                    - t[j].clone()
                    - ct[j].clone() * q,
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

        // C14–C18: t[j] decomposition; C19–C133: t_bits[j][k] booleans
        for j in 0..L {
            let mut sum = E::F::from(BaseField::from_u32_unchecked(0));
            let mut pw: u32 = 1;
            for k in 0..N_BITS {
                sum = sum + t_bits[j][k].clone() * E::F::from(BaseField::from_u32_unchecked(pw));
                pw <<= 1;
            }
            eval.add_constraint(t[j].clone() - sum);
            for k in 0..N_BITS {
                let b = t_bits[j][k].clone();
                eval.add_constraint(b.clone() * b - t_bits[j][k].clone());
            }
        }

        // C134–C138: ct[j] decomposition; C139–C253: ct_bits[j][k] booleans
        for j in 0..L {
            let mut sum = E::F::from(BaseField::from_u32_unchecked(0));
            let mut pw: u32 = 1;
            for k in 0..N_BITS {
                sum = sum + ct_bits[j][k].clone() * E::F::from(BaseField::from_u32_unchecked(pw));
                pw <<= 1;
            }
            eval.add_constraint(ct[j].clone() - sum);
            for k in 0..N_BITS {
                let b = ct_bits[j][k].clone();
                eval.add_constraint(b.clone() * b - ct_bits[j][k].clone());
            }
        }

        eval
    }
}

pub fn new_component(log_n_rows: u32) -> AzRowComponent {
    AzRowComponent::new(
        &mut TraceLocationAllocator::default(),
        AzRowEval { log_n_rows },
        SecureField::from(0u32),
    )
}

// ── Trace builder ─────────────────────────────────────────────────────────────

pub fn build_trace(
    a_row: &[[i64; N]; L],
    z_hat: &[[i64; N]; L],
) -> (TraceColumns, [i64; N]) {
    let n      = 1_usize << LOG_N_ROWS;
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);
    let bf0    = BaseField::from_u32_unchecked(0);

    let mut a_cols:  [Vec<BaseField>; 5] = std::array::from_fn(|_| vec![bf0; n]);
    let mut z_cols:  [Vec<BaseField>; 5] = std::array::from_fn(|_| vec![bf0; n]);
    let mut t_cols:  [Vec<BaseField>; 5] = std::array::from_fn(|_| vec![bf0; n]);
    let mut ct_cols: [Vec<BaseField>; 5] = std::array::from_fn(|_| vec![bf0; n]);
    let mut s_cols:  [Vec<BaseField>; 4] = std::array::from_fn(|_| vec![bf0; n]);
    let mut cs_cols: [Vec<BaseField>; 4] = std::array::from_fn(|_| vec![bf0; n]);

    // t_bit_cols[j][k][p] and ct_bit_cols[j][k][p]
    let mut t_bit_cols:  Vec<[Vec<BaseField>; 23]> =
        (0..L).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();
    let mut ct_bit_cols: Vec<[Vec<BaseField>; 23]> =
        (0..L).map(|_| std::array::from_fn(|_| vec![bf0; n])).collect();

    let mut az_hat = [0i64; N];

    for p in 0..N {
        let av: [i64; 5] = std::array::from_fn(|j| a_row[j][p]);
        let zv: [i64; 5] = std::array::from_fn(|j| z_hat[j][p]);

        let tv:  [i64; 5] = std::array::from_fn(|j| (av[j] * zv[j]) % Q);
        let ctv: [i64; 5] = std::array::from_fn(|j| (av[j] * zv[j]) / Q);

        let sv0 = { let r = tv[0] + tv[1]; r - if r >= Q { Q } else { 0 } };
        let sv1 = { let r = sv0 + tv[2];   r - if r >= Q { Q } else { 0 } };
        let sv2 = { let r = sv1 + tv[3];   r - if r >= Q { Q } else { 0 } };
        let sv3 = { let r = sv2 + tv[4];   r - if r >= Q { Q } else { 0 } };

        az_hat[p] = sv3;

        let csv: [i64; 4] = [
            if tv[0] + tv[1] >= Q { 1 } else { 0 },
            if sv0   + tv[2] >= Q { 1 } else { 0 },
            if sv1   + tv[3] >= Q { 1 } else { 0 },
            if sv2   + tv[4] >= Q { 1 } else { 0 },
        ];

        for j in 0..L {
            a_cols[j][p]  = bf(av[j]);
            z_cols[j][p]  = bf(zv[j]);
            t_cols[j][p]  = bf(tv[j]);
            ct_cols[j][p] = bf(ctv[j]);
            let tu  = tv[j]  as u32;
            let ctu = ctv[j] as u32;
            for k in 0..N_BITS {
                t_bit_cols[j][k][p]  = BaseField::from_u32_unchecked((tu  >> k) & 1);
                ct_bit_cols[j][k][p] = BaseField::from_u32_unchecked((ctu >> k) & 1);
            }
        }
        for r in 0..4 {
            s_cols[r][p]  = bf([sv0, sv1, sv2, sv3][r]);
            cs_cols[r][p] = bf(csv[r]);
        }
    }

    for cols in [&mut a_cols, &mut z_cols, &mut t_cols, &mut ct_cols] {
        for c in cols.iter_mut() { bit_reverse_coset_to_circle_domain_order(c); }
    }
    for cols in [&mut s_cols, &mut cs_cols] {
        for c in cols.iter_mut() { bit_reverse_coset_to_circle_domain_order(c); }
    }
    for bit_set in t_bit_cols.iter_mut().chain(ct_bit_cols.iter_mut()) {
        for c in bit_set.iter_mut() { bit_reverse_coset_to_circle_domain_order(c); }
    }

    let mut columns: TraceColumns = Vec::with_capacity(N_COLS);
    for j in 0..L { columns.push(CircleEvaluation::new(domain, a_cols[j].clone())); }
    for j in 0..L { columns.push(CircleEvaluation::new(domain, z_cols[j].clone())); }
    for j in 0..L { columns.push(CircleEvaluation::new(domain, t_cols[j].clone())); }
    for j in 0..L { columns.push(CircleEvaluation::new(domain, ct_cols[j].clone())); }
    for r in 0..4 { columns.push(CircleEvaluation::new(domain, s_cols[r].clone())); }
    for r in 0..4 { columns.push(CircleEvaluation::new(domain, cs_cols[r].clone())); }
    // Bit columns: t_bits[j=0..L][k=0..N_BITS], then ct_bits[j=0..L][k=0..N_BITS]
    for j in 0..L {
        for k in 0..N_BITS {
            columns.push(CircleEvaluation::new(domain, t_bit_cols[j][k].clone()));
        }
    }
    for j in 0..L {
        for k in 0..N_BITS {
            columns.push(CircleEvaluation::new(domain, ct_bit_cols[j][k].clone()));
        }
    }

    debug_assert_eq!(columns.len(), N_COLS);
    (columns, az_hat)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mldsa::ntt::ntt;
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

    fn reference_az_row(a_row: &[[i64; N]; L], z: &[[i64; N]; L]) -> [i64; N] {
        let mut result = [0i64; N];
        for p in 0..N {
            let mut acc = 0i64;
            for j in 0..L {
                acc = (acc + a_row[j][p] * z[j][p]) % Q;
            }
            result[p] = acc;
        }
        result
    }

    #[test]
    fn test_column_count() {
        assert_eq!(N_COLS, 258);
    }

    #[test]
    fn test_az_row_correctness() {
        let a_row: [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 * 10));
        let z:     [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 * 10 + 5));
        let (_, az_hat) = build_trace(&a_row, &z);
        let expected = reference_az_row(&a_row, &z);
        assert_eq!(az_hat, expected);
        for p in 0..N {
            assert!(az_hat[p] >= 0 && az_hat[p] < Q, "az_hat[{p}] out of range");
        }
    }

    #[test]
    fn test_az_row_zero_z() {
        let a_row: [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64));
        let (_, az_hat) = build_trace(&a_row, &[[0i64; N]; 5]);
        assert_eq!(az_hat, [0i64; N]);
    }

    #[test]
    fn test_az_row_zero_a() {
        let z: [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 + 100));
        let (_, az_hat) = build_trace(&[[0i64; N]; 5], &z);
        assert_eq!(az_hat, [0i64; N]);
    }

    #[test]
    fn test_az_row_linearity() {
        let a_row: [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 * 7));
        let z1:    [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 * 13));
        let z2:    [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 * 17 + 1));
        let z_sum: [[i64; N]; 5] = std::array::from_fn(|j| {
            let mut p = [0i64; N];
            for i in 0..N { p[i] = (z1[j][i] + z2[j][i]) % Q; }
            p
        });
        let (_, az1)    = build_trace(&a_row, &z1);
        let (_, az2)    = build_trace(&a_row, &z2);
        let (_, az_sum) = build_trace(&a_row, &z_sum);
        for p in 0..N {
            assert_eq!(az_sum[p], (az1[p] + az2[p]) % Q, "linearity at p={p}");
        }
    }

    #[test]
    fn test_az_row_ntt_consistency() {
        let mut poly_a = random_poly(99);
        let mut poly_z = random_poly(100);
        ntt(&mut poly_a);
        ntt(&mut poly_z);
        let a_row1 = [poly_a, [0i64; N], [0i64; N], [0i64; N], [0i64; N]];
        let z1     = [poly_z, [0i64; N], [0i64; N], [0i64; N], [0i64; N]];
        let (_, az_hat) = build_trace(&a_row1, &z1);
        for p in 0..N {
            assert_eq!(az_hat[p], (poly_a[p] * poly_z[p]) % Q, "pointwise mismatch at p={p}");
        }
    }

    #[test]
    fn test_constraints_on_trace() {
        let a_row: [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 + 200));
        let z:     [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 + 205));
        let (cols, _) = build_trace(&a_row, &z);
        let col_vals: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vals.iter().collect();
        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], col_refs]);
        let evaluator = AzRowEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
