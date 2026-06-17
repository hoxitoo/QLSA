#!/usr/bin/env python3
"""Regenerate full_v23_vfri11_cross_bound_e2e.json.

VFRI11 (VFRI10 protocol on the Poseidon2 t=8 backend) cross-bound hints for the
full V23 trace, used by QLSAVerifierVFRI11CrossBoundE2E.test.js.

Run from the repo root:
    PYTHONPATH=. python contracts/test/fixtures/gen_full_v23_vfri11_fixture.py

Requires the PyO3 extension (qlsa_stark_stwo). Synthetic V23 inputs seed=16600,
n_queries=1, num_folds=6 — matching the VFRI10 cross-bound fixture convention.
"""
import json
import os

from tests.test_stark_stwo import _v23_inputs, _make_log8_hints
from stark.prover import gen_mldsa_v23_vfri11_cross_bound_hints

SEED = 16600
N_QUERIES = 1
NUM_FOLDS = 6
MERKLE_ROOT = bytes((11 + 7 * i) % 256 for i in range(32))


def main() -> None:
    z, c, t1, a_hat = _v23_inputs(SEED)
    hints = _make_log8_hints()
    r = gen_mldsa_v23_vfri11_cross_bound_hints(
        z, c, t1, a_hat, hints, MERKLE_ROOT,
        n_queries=N_QUERIES, num_folds_log10=NUM_FOLDS, num_folds_log8=NUM_FOLDS,
    )
    fixture = {
        "merkleRoot": "0x" + MERKLE_ROOT.hex(),
        "log10_proof": "0x" + r.log10_proof.hex(),
        "log10_commitment": "0x" + r.log10_commitment,
        "log10_queryHints": "0x" + r.log10_query_hints.hex(),
        "log8_proof": "0x" + r.log8_proof.hex(),
        "log8_commitment": "0x" + r.log8_commitment,
        "log8_queryHints": "0x" + r.log8_query_hints.hex(),
        "n_queries": N_QUERIES,
        "num_folds": NUM_FOLDS,
    }
    out_path = os.path.join(os.path.dirname(__file__), "full_v23_vfri11_cross_bound_e2e.json")
    with open(out_path, "w") as f:
        json.dump(fixture, f, indent=2)
        f.write("\n")
    print(f"wrote {out_path}")
    print(f"  log10 proof={len(r.log10_proof)}B commit={r.log10_commitment} hints={len(r.log10_query_hints)}B")
    print(f"  log8  proof={len(r.log8_proof)}B commit={r.log8_commitment} hints={len(r.log8_query_hints)}B")


if __name__ == "__main__":
    main()
