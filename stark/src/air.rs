use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
    math::{fields::f64::BaseElement, FieldElement, ToElements},
};

// ──────────────────────────────────────────────────────────────────────────────
// Public inputs
// ──────────────────────────────────────────────────────────────────────────────

/// The only public input: the final accumulated hash (batch commitment).
#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub commitment: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.commitment]
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// AIR definition — Hash Chain
// ──────────────────────────────────────────────────────────────────────────────
//
// Trace columns (width = 2):
//   col 0 (h):    running accumulated hash
//   col 1 (leaf): current leaf value (private witness)
//
// Computation:
//   h[0]   = leaf[0]
//   h[i+1] = h[i]^3 + leaf[i+1]    (prototype hash, NOT cryptographically secure)
//
// Transition constraint (degree 3):
//   next[0] - ( curr[0]^3 + next[1] ) = 0
//
// Boundary assertion:
//   h[last] = commitment  (public)

pub struct HashChainAir {
    context:    AirContext<BaseElement>,
    commitment: BaseElement,
}

impl Air for HashChainAir {
    type BaseField    = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        // One transition constraint, degree 3 (from h^3 term)
        let degrees = vec![TransitionConstraintDegree::new(3)];
        // 1 boundary assertion
        let context = AirContext::new(trace_info, degrees, 1, options);
        HashChainAir {
            context,
            commitment: pub_inputs.commitment,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let curr_h    = frame.current()[0];
        let next_h    = frame.next()[0];
        let next_leaf = frame.next()[1];

        // Prototype hash: h[i+1] = h[i]^3 + leaf[i+1]
        // Constraint: next_h - (curr_h^3 + next_leaf) = 0
        let expected = curr_h * curr_h * curr_h + next_leaf;
        result[0] = next_h - expected;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.trace_length() - 1;
        // Only constraint: the final hash equals the public commitment
        vec![Assertion::single(0, last, self.commitment)]
    }
}
