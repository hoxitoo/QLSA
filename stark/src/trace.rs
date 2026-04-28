use winterfell::{
    math::{fields::f64::BaseElement, FieldElement},
    TraceTable,
};

// Winterfell requires trace length >= 8
const MIN_TRACE_LEN: usize = 8;

/// Build a 2-column execution trace for the hash chain over `leaves`.
///
/// Column 0 (`h`):    running accumulated hash.
/// Column 1 (`leaf`): leaf values (private witness).
///
/// Row 0:   h[0]   = leaf[0]
/// Row i>0: h[i]   = h[i-1]^3 + leaf[i]   (prototype hash)
///
/// Padded to the next power-of-two ≥ MIN_TRACE_LEN with zero leaves.
pub fn build_trace(leaves: &[u64]) -> TraceTable<BaseElement> {
    assert!(!leaves.is_empty(), "leaves must not be empty");

    let n = trace_len(leaves.len());
    let leaf_fe = make_leaf_fe(leaves, n);

    let mut trace = TraceTable::new(2, n);

    trace.fill(
        |state| {
            state[0] = leaf_fe[0];
            state[1] = leaf_fe[0];
        },
        |step, state| {
            let next_leaf = leaf_fe[step + 1];
            let curr_h    = state[0];
            state[0] = curr_h * curr_h * curr_h + next_leaf;
            state[1] = next_leaf;
        },
    );

    trace
}

/// Compute the commitment that will appear in the last row of the trace.
pub fn compute_commitment(leaves: &[u64]) -> BaseElement {
    assert!(!leaves.is_empty());
    let n = trace_len(leaves.len());
    let leaf_fe = make_leaf_fe(leaves, n);

    let mut h = leaf_fe[0];
    for i in 1..n {
        h = h * h * h + leaf_fe[i];
    }
    h
}

// ──────────────────────────────────────────────────────────────────────────────

fn trace_len(num_leaves: usize) -> usize {
    num_leaves.next_power_of_two().max(MIN_TRACE_LEN)
}

fn make_leaf_fe(leaves: &[u64], n: usize) -> Vec<BaseElement> {
    (0..n)
        .map(|i| {
            if i < leaves.len() {
                BaseElement::new(leaves[i])
            } else {
                BaseElement::ZERO
            }
        })
        .collect()
}
