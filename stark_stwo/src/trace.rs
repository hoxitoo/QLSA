use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;

/// M31 prime modulus p = 2^31 − 1.
const M31_P: u64 = (1u64 << 31) - 1;

/// Minimum trace length (Stwo requires ≥ 4 rows; we use 8 = 2^3 for safety).
pub const MIN_LOG_SIZE: u32 = 3;

pub type TraceCol = CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>;
pub type TraceColumns = Vec<TraceCol>;

/// Smallest log₂ size such that 2^size ≥ n_leaves + 1 and size ≥ MIN_LOG_SIZE.
///
/// We reserve one row at the end as a "zero row" to satisfy the Circle-STARK
/// wrap-around constraint (see build_trace).
pub fn compute_log_size(n_leaves: usize) -> u32 {
    let needed = (n_leaves + 1).max(1 << MIN_LOG_SIZE);
    let p2 = needed.next_power_of_two();
    (p2.trailing_zeros()).max(MIN_LOG_SIZE)
}

/// Build the 2-column execution trace for the M31 hash chain.
///
/// Returns `(columns, commitment)` where `commitment = h[n-2]`.
///
/// ## Wrap-around design
/// In Circle STARK every constraint is evaluated on ALL n rows, including a
/// "virtual" wrap-around from row n−1 back to row 0.  To satisfy
///
///   h[0] = h[n−1]³ + leaf[0]   (wrap-around)
///
/// with our initialization h[0] = leaf[0], we need h[n−1] = 0.
/// We achieve this by setting the LAST row to a special zero row:
///
///   h[n−1]    = 0
///   leaf[n−1] = –h[n−2]³   (so that h[n−1] = h[n−2]³ + leaf[n−1] = 0)
///
/// The commitment is h[n−2], i.e., the hash of all REAL leaves.
pub fn build_trace(leaves: &[u64]) -> (TraceColumns, BaseField) {
    assert!(!leaves.is_empty(), "leaves must not be empty");

    let log_size = compute_log_size(leaves.len());
    let n = 1_usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();

    let to_m31 = |v: u64| -> BaseField { BaseField::from_u32_unchecked((v % M31_P) as u32) };
    let input_at = |i: usize| -> BaseField {
        if i < leaves.len() {
            to_m31(leaves[i])
        } else {
            BaseField::from_u32_unchecked(0)
        }
    };

    // Build trace in COSET order (indices 0..n-1 are sequential coset steps).
    // In Circle STARK the "next row" follows coset order, not natural index order.
    // We fill in coset order then reorder to circle-domain bit-reversed storage.
    let mut h_col = vec![BaseField::from_u32_unchecked(0); n];
    let mut leaf_col = vec![BaseField::from_u32_unchecked(0); n];

    // Coset step 0: h[0] = leaf[0]
    h_col[0] = input_at(0);
    leaf_col[0] = input_at(0);

    // Coset steps 1..n-2: h[i] = h[i-1]^3 + leaf[i]
    for i in 1..n - 1 {
        let lf = input_at(i);
        leaf_col[i] = lf;
        h_col[i] = h_col[i - 1] * h_col[i - 1] * h_col[i - 1] + lf;
    }

    // Coset step n-1 (zero row): h[n-1] = 0, leaf[n-1] = -h[n-2]^3
    // Ensures the wrap-around constraint holds: h[0] = h[n-1]^3 + leaf[0] = 0 + leaf[0] ✓
    let h_prev = h_col[n - 2];
    let h_prev_cubed = h_prev * h_prev * h_prev;
    leaf_col[n - 1] = BaseField::from_u32_unchecked(0) - h_prev_cubed;
    h_col[n - 1] = BaseField::from_u32_unchecked(0);

    // Commitment is the last real hash: coset step n-2.
    let commitment = h_col[n - 2];

    // Reorder from coset natural order → circle-domain bit-reversed order,
    // which is the storage layout expected by CircleEvaluation<_, _, BitReversedOrder>.
    bit_reverse_coset_to_circle_domain_order(&mut h_col);
    bit_reverse_coset_to_circle_domain_order(&mut leaf_col);

    let columns = vec![
        CircleEvaluation::new(domain, h_col),
        CircleEvaluation::new(domain, leaf_col),
    ];

    (columns, commitment)
}

/// Compute the commitment value without building the full trace (for testing).
pub fn compute_commitment(leaves: &[u64]) -> BaseField {
    let (_, commitment) = build_trace(leaves);
    commitment
}
