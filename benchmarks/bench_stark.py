"""
STARK prover / verifier benchmark.

Run with:  python -m benchmarks.bench_stark
Results are printed to stdout and saved to benchmarks/results/stark-YYYY-MM-DD.json

Requires the Rust binary to be built first:
    cd stark_stwo && cargo +nightly-2025-07-01 build --release
"""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path

from core.batch import create_batch
from core.keys import derive_address, generate_keypair, wipe_key
from core.signing import sign
from core.transaction import Transaction
from stark.prover import BINARY, ProofResult, binary_available, prove_batch
from stark.verifier import verify_batch_proof


RESULTS_DIR = Path(__file__).parent / "results"
# Batch sizes to benchmark; STARK traces always have 8 leaves (Merkle root chunks),
# but more transactions → larger Merkle root → same 8 leaves with different values.
# We vary batch size to measure the Python/Merkle overhead, not the STARK itself.
BATCH_SIZES = [10, 50, 100, 500]


def _make_signed_batch(n: int):
    pub, priv = generate_keypair()
    addr = derive_address(pub)
    txs = []
    for i in range(n):
        tx = Transaction(
            sender=addr,
            recipient="e" * 64,
            amount=i + 1,
            nonce=i,
            public_key=pub,
        )
        tx.signature = sign(tx.to_bytes(), priv)
        txs.append(tx)
    wipe_key(priv)
    return create_batch(txs)


def _time(fn, *args, **kwargs) -> tuple[float, object]:
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    return time.perf_counter() - t0, result


def bench_prove(n: int) -> dict:
    batch = _make_signed_batch(n)
    t_prove, result = _time(prove_batch, batch)
    assert isinstance(result, ProofResult)
    t_verify, valid = _time(
        verify_batch_proof, result.proof, result.commitment, result.log_size
    )
    assert valid
    return {
        "n_txs": n,
        "log_size": result.log_size,
        "proof_bytes": len(result.proof),
        "prove_s": t_prove,
        "verify_s": t_verify,
        "commitment": result.commitment,
    }


def run() -> None:
    if not binary_available():
        print(f"ERROR: STARK binary not found at {BINARY}")
        print("Build with: cd stark_stwo && cargo +nightly-2025-07-01 build --release")
        return

    results: dict = {
        "date": str(date.today()),
        "binary": str(BINARY),
        "note": "STARK trace always has 8 leaves (Merkle root chunks). prove/verify time is constant w.r.t. batch size.",
        "runs": [],
    }

    print("=" * 65)
    print("QLSA STARK Benchmark  (Stwo Circle STARK, nightly-2025-07-01)")
    print("=" * 65)
    print(f"  Binary: {BINARY}")
    print()
    print(f"  {'N txs':>6}  {'log_size':>8}  {'proof KB':>8}  {'prove s':>9}  {'verify s':>9}")
    print("  " + "-" * 55)

    for n in BATCH_SIZES:
        r = bench_prove(n)
        results["runs"].append(r)
        print(
            f"  {r['n_txs']:>6}  {r['log_size']:>8}  "
            f"{r['proof_bytes']/1024:>7.1f}K  "
            f"{r['prove_s']:>9.3f}  {r['verify_s']:>9.3f}"
        )

    # Single warm run for clean numbers
    print()
    print("  Note: first run may be slower due to OS page faults.")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"stark-{date.today()}.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to {out}")


if __name__ == "__main__":
    run()
