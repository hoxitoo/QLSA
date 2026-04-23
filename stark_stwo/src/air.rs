use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator, ORIGINAL_TRACE_IDX,
};

// ──────────────────────────────────────────────────────────────────────────────
// Hash-chain AIR over M31 (Circle STARK — Stwo 2.2.0)
//
// Trace layout (2 columns, 2^log_n_rows rows):
//   col 0  h     : running hash accumulator
//   col 1  leaf  : leaf values (private witness)
//
// Initialisation (row 0, boundary claim enforced externally):
//   h[0] = leaf[0]
//
// Transition constraint (degree 3, every row):
//   h[i+1] = h[i]^3 + leaf[i+1]
//   ⟺  h[i+1] − h[i]^3 − leaf[i+1] = 0
//
// Public output: h[last_row]  (the "commitment")
//
// NOTE: H(a,b) = a³+b is a prototype algebraic hash — NOT cryptographically
// secure. Production upgrade: replace with Poseidon2 over M31 (Stwo built-in).
// ──────────────────────────────────────────────────────────────────────────────

pub struct HashChainEval {
    pub log_n_rows: u32,
}

pub type HashChainComponent = FrameworkComponent<HashChainEval>;

impl FrameworkEval for HashChainEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Degree-3 constraint quotient has 2·2^n = 2^(n+1) coefficients → bound = n+1.
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // col 0 (h): current row (offset 0) and next row (offset 1)
        let [h_curr, h_next] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0_isize, 1_isize]);
        // col 1 (leaf): next row (offset 1) — feeds into h_next
        let [leaf_next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [1_isize]);

        // h[i+1] − (h[i]³ + leaf[i+1]) = 0
        let expected = h_curr.clone() * h_curr.clone() * h_curr + leaf_next;
        eval.add_constraint(h_next - expected);

        eval
    }
}

/// Allocate the component from a fresh trace location allocator.
pub fn new_component(log_n_rows: u32) -> HashChainComponent {
    HashChainComponent::new(
        &mut TraceLocationAllocator::default(),
        HashChainEval { log_n_rows },
        SecureField::from(0u32),
    )
}
