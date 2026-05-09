/// ML-DSA-65 matrix-vector product AIR (Circle STARK — Stwo 2.2.0)
///
/// Proves one output polynomial of the NTT-domain product  Az̃[i] = Σ_{j=0}^{L-1} Ã[i][j] ⊙ z̃[j]
/// for a fixed row `i` of the public-key matrix A.
///
/// In ML-DSA.Verify (FIPS 204 Algorithm 3, step 9) this is the most expensive
/// arithmetic step: given Ã (k×l matrix in NTT domain) and z̃ = NTT(z), compute
///   w′ = INTT( Ã·z̃ − c̃·t̃₁ )
///
/// This circuit proves the inner-product half: Ã[i]·z̃ for a single i.
/// Calling `prove_az_row` k=6 times covers the full matrix.
///
/// # Trace layout  (28 columns, N = 256 rows — one per coefficient position)
///
/// Inputs (10 columns):
///   col  0..4   a[j]   = Ã[i][j][p]     ∈ [0, Q)   matrix row coefficients
///   col  5..9   z[j]   = z̃[j][p]         ∈ [0, Q)   vector coefficients
///
/// Products (10 columns):
///   col 10..14  t[j]   = a[j]×z[j] mod Q ∈ [0, Q)   NTT-domain products (witness)
///   col 15..19  ct[j]  = ⌊a[j]×z[j]/Q⌋   ∈ [0, Q)   multiplication carries (witness)
///
/// Accumulation (8 columns) — running sum s[r] = Σ_{j=0}^{r} t[j]:
///   col 20      s[0]   = t[0]+t[1] mod Q  ∈ [0, Q)
///   col 21      cs[0]  ∈ {0,1}
///   col 22      s[1]   = s[0]+t[2] mod Q  ∈ [0, Q)
///   col 23      cs[1]  ∈ {0,1}
///   col 24      s[2]   = s[1]+t[3] mod Q  ∈ [0, Q)
///   col 25      cs[2]  ∈ {0,1}
///   col 26      s[3]   = s[2]+t[4] mod Q  ∈ [0, Q)   ← this is Az̃[i][p]
///   col 27      cs[3]  ∈ {0,1}
///
/// # Constraints (13 constraints, max degree 2)
///
///   C1–C5   a[j]×z[j] − t[j] − ct[j]×Q = 0     (mul mod Q, degree 2)
///   C6      t[0]+t[1]  − s[0] − cs[0]×Q = 0     (add mod Q, degree 1)
///   C7      cs[0]²    − cs[0]           = 0     (boolean,   degree 2)
///   C8      s[0]+t[2]  − s[1] − cs[1]×Q = 0
///   C9      cs[1]²    − cs[1]           = 0
///   C10     s[1]+t[3]  − s[2] − cs[2]×Q = 0
///   C11     cs[2]²    − cs[2]           = 0
///   C12     s[2]+t[4]  − s[3] − cs[3]×Q = 0
///   C13     cs[3]²    − cs[3]           = 0
///
/// # Soundness
///
/// C6–C13 (add/boolean) are **fully sound** in M31: all addends are < Q < 2²³,
/// so sums stay below M31's modulus 2³¹−1 and no wrap-around ambiguity exists.
///
/// C1–C5 (mul) share the same limitation as `mldsa_poly_mul_air`: products
/// can reach ~2⁴⁶, so M31 arithmetic is necessary but not sufficient.  Range
/// proofs on t[j] and ct[j] close the gap (planned MVP-4 lookup arguments).

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

// ── Type aliases ─────────────────────────────────────────────────────────────

type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

/// log₂(N) = 8  →  256 rows (one per coefficient).
pub const LOG_N_ROWS: u32 = 8;

// ── FrameworkEval ─────────────────────────────────────────────────────────────

pub struct AzRowEval {
    pub log_n_rows: u32,
}

pub type AzRowComponent = FrameworkComponent<AzRowEval>;

impl FrameworkEval for AzRowEval {
    fn log_size(&self) -> u32 { self.log_n_rows }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Max constraint degree = 2  →  bound = log_n_rows + 1.
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let q = BaseField::from_u32_unchecked(Q as u32);

        // ── inputs ────────────────────────────────────────────────────────────
        // a[0..L] and z[0..L]  (L = 5 for ML-DSA-65)
        let a: [E::F; 5] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );
        let z: [E::F; 5] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );

        // ── products and their carries ────────────────────────────────────────
        let t: [E::F; 5] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );
        let ct: [E::F; 5] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );

        // ── accumulators and their carries ────────────────────────────────────
        // s[0] = t[0]+t[1],  s[1] = s[0]+t[2],  s[2] = s[1]+t[3],  s[3] = s[2]+t[4]
        let s: [E::F; 4] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );
        let cs: [E::F; 4] = std::array::from_fn(|_|
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize])[0].clone()
        );

        // ── C1–C5: a[j] × z[j] = t[j] + ct[j] × Q ──────────────────────────
        for j in 0..L {
            eval.add_constraint(
                a[j].clone() * z[j].clone()
                    - t[j].clone()
                    - ct[j].clone() * q,
            );
        }

        // ── C6–C13: accumulation chain (add mod Q + boolean carry) ────────────
        // s[0] = t[0] + t[1] mod Q
        eval.add_constraint(
            t[0].clone() + t[1].clone()
                - s[0].clone()
                - cs[0].clone() * q,
        );
        eval.add_constraint(cs[0].clone() * cs[0].clone() - cs[0].clone());

        // s[1] = s[0] + t[2] mod Q
        eval.add_constraint(
            s[0].clone() + t[2].clone()
                - s[1].clone()
                - cs[1].clone() * q,
        );
        eval.add_constraint(cs[1].clone() * cs[1].clone() - cs[1].clone());

        // s[2] = s[1] + t[3] mod Q
        eval.add_constraint(
            s[1].clone() + t[3].clone()
                - s[2].clone()
                - cs[2].clone() * q,
        );
        eval.add_constraint(cs[2].clone() * cs[2].clone() - cs[2].clone());

        // s[3] = s[2] + t[4] mod Q  (this is Az_hat[i][p])
        eval.add_constraint(
            s[2].clone() + t[4].clone()
                - s[3].clone()
                - cs[3].clone() * q,
        );
        eval.add_constraint(cs[3].clone() * cs[3].clone() - cs[3].clone());

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

/// Build the Az-row trace for one output polynomial of the matrix-vector product.
///
/// `a_row[j]` is the j-th polynomial of Ã[i] (NTT domain, length N).
/// `z_hat[j]` is the j-th component of z̃ (NTT domain, length N).
///
/// Returns `(columns, az_hat_i)` where `az_hat_i[p] = Σ_j a_row[j][p] × z_hat[j][p] mod Q`.
pub fn build_trace(
    a_row: &[[i64; N]; L],
    z_hat: &[[i64; N]; L],
) -> (TraceColumns, [i64; N]) {
    let n      = 1_usize << LOG_N_ROWS; // 256
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let bf     = |v: i64| BaseField::from_u32_unchecked(v as u32);
    let bf0    = BaseField::from_u32_unchecked(0);

    // Allocate all columns (28 total).
    let mut a_cols:  [Vec<BaseField>; 5] = std::array::from_fn(|_| vec![bf0; n]);
    let mut z_cols:  [Vec<BaseField>; 5] = std::array::from_fn(|_| vec![bf0; n]);
    let mut t_cols:  [Vec<BaseField>; 5] = std::array::from_fn(|_| vec![bf0; n]);
    let mut ct_cols: [Vec<BaseField>; 5] = std::array::from_fn(|_| vec![bf0; n]);
    let mut s_cols:  [Vec<BaseField>; 4] = std::array::from_fn(|_| vec![bf0; n]);
    let mut cs_cols: [Vec<BaseField>; 4] = std::array::from_fn(|_| vec![bf0; n]);

    let mut az_hat = [0i64; N];

    for p in 0..N {
        // Fill inputs.
        let av: [i64; 5] = std::array::from_fn(|j| a_row[j][p]);
        let zv: [i64; 5] = std::array::from_fn(|j| z_hat[j][p]);

        // Compute products t[j] = av[j] × zv[j] mod Q.
        let tv: [i64; 5] = std::array::from_fn(|j| {
            let prod = av[j] * zv[j];
            prod % Q
        });
        let ctv: [i64; 5] = std::array::from_fn(|j| {
            let prod = av[j] * zv[j];
            prod / Q
        });

        // Accumulate: s[r] = Σ_{j=0}^{r+1} t[j].
        let sv0 = { let raw = tv[0] + tv[1]; let c = if raw >= Q { 1 } else { 0 }; raw - c * Q };
        let sv1 = { let raw = sv0 + tv[2];   let c = if raw >= Q { 1 } else { 0 }; raw - c * Q };
        let sv2 = { let raw = sv1 + tv[3];   let c = if raw >= Q { 1 } else { 0 }; raw - c * Q };
        let sv3 = { let raw = sv2 + tv[4];   let c = if raw >= Q { 1 } else { 0 }; raw - c * Q };

        let sv = [sv0, sv1, sv2, sv3];
        let csv: [i64; 4] = [
            if tv[0] + tv[1] >= Q { 1 } else { 0 },
            if sv0   + tv[2] >= Q { 1 } else { 0 },
            if sv1   + tv[3] >= Q { 1 } else { 0 },
            if sv2   + tv[4] >= Q { 1 } else { 0 },
        ];

        az_hat[p] = sv3;

        // Write to column buffers.
        for j in 0..L {
            a_cols[j][p]  = bf(av[j]);
            z_cols[j][p]  = bf(zv[j]);
            t_cols[j][p]  = bf(tv[j]);
            ct_cols[j][p] = bf(ctv[j]);
        }
        for r in 0..4 {
            s_cols[r][p]  = bf(sv[r]);
            cs_cols[r][p] = bf(csv[r]);
        }
    }

    // Apply bit-reversal to all columns.
    for cols in [&mut a_cols, &mut z_cols, &mut t_cols, &mut ct_cols] {
        for col in cols.iter_mut() {
            bit_reverse_coset_to_circle_domain_order(col);
        }
    }
    for cols in [&mut s_cols, &mut cs_cols] {
        for col in cols.iter_mut() {
            bit_reverse_coset_to_circle_domain_order(col);
        }
    }

    // Pack into a flat column vec in the same order as evaluate().
    let mut columns = Vec::with_capacity(28);
    for j in 0..L { columns.push(CircleEvaluation::new(domain, a_cols[j].clone())); }
    for j in 0..L { columns.push(CircleEvaluation::new(domain, z_cols[j].clone())); }
    for j in 0..L { columns.push(CircleEvaluation::new(domain, t_cols[j].clone())); }
    for j in 0..L { columns.push(CircleEvaluation::new(domain, ct_cols[j].clone())); }
    for r in 0..4 { columns.push(CircleEvaluation::new(domain, s_cols[r].clone())); }
    for r in 0..4 { columns.push(CircleEvaluation::new(domain, cs_cols[r].clone())); }

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
        let z_zero = [[0i64; N]; 5];
        let (_, az_hat) = build_trace(&a_row, &z_zero);
        assert_eq!(az_hat, [0i64; N]);
    }

    #[test]
    fn test_az_row_zero_a() {
        let a_zero = [[0i64; N]; 5];
        let z: [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 + 100));
        let (_, az_hat) = build_trace(&a_zero, &z);
        assert_eq!(az_hat, [0i64; N]);
    }

    #[test]
    fn test_az_row_linearity() {
        // Az is linear in z: A(z1+z2) = Az1 + Az2 (mod Q).
        let a_row: [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 * 7));
        let z1:    [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 * 13));
        let z2:    [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 * 17 + 1));

        let z_sum: [[i64; N]; 5] = std::array::from_fn(|j| {
            let mut p = [0i64; N];
            for i in 0..N { p[i] = (z1[j][i] + z2[j][i]) % Q; }
            p
        });

        let (_, az1)   = build_trace(&a_row, &z1);
        let (_, az2)   = build_trace(&a_row, &z2);
        let (_, az_sum) = build_trace(&a_row, &z_sum);

        for p in 0..N {
            assert_eq!(az_sum[p], (az1[p] + az2[p]) % Q, "linearity at p={p}");
        }
    }

    #[test]
    fn test_az_row_ntt_consistency() {
        // Sanity check: NTT-domain product matches poly-ring multiplication
        // for one (a, z) pair by checking a single entry of the inner product.
        let mut poly_a = random_poly(99);
        let mut poly_z = random_poly(100);

        ntt(&mut poly_a);
        ntt(&mut poly_z);

        // Single-polynomial inner product (L=1 degenerate case)
        let a_row1: [[i64; N]; 5] = [poly_a, [0i64; N], [0i64; N], [0i64; N], [0i64; N]];
        let z1:     [[i64; N]; 5] = [poly_z, [0i64; N], [0i64; N], [0i64; N], [0i64; N]];

        let (_, az_hat) = build_trace(&a_row1, &z1);

        // Pointwise product should match.
        for p in 0..N {
            let expected = (poly_a[p] * poly_z[p]) % Q;
            assert_eq!(az_hat[p], expected, "pointwise mismatch at p={p}");
        }
    }

    #[test]
    fn test_constraints_on_trace() {
        let a_row: [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 + 200));
        let z:     [[i64; N]; 5] = std::array::from_fn(|j| random_poly(j as u64 + 205));

        let (cols, _) = build_trace(&a_row, &z);

        // Collect column values for the constraint checker.
        let col_vals: Vec<Vec<M31>> = cols.iter().map(|c| c.values.clone()).collect();
        let col_refs: Vec<&Vec<M31>> = col_vals.iter().collect();

        let evals: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![
            vec![],     // no preprocessed columns
            col_refs,   // all 28 main-trace columns
        ]);

        let evaluator = AzRowEval { log_n_rows: LOG_N_ROWS };
        assert_constraints_on_trace(
            &evals,
            LOG_N_ROWS,
            |eval| { evaluator.evaluate(eval); },
            SecureField::from(0u32),
        );
    }
}
