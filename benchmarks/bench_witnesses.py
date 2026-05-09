"""
ML-DSA witness pipeline benchmark — prove_mldsa_sig_witness_stark per-transaction latency.

Run with:  python -m benchmarks.bench_witnesses
Results are printed to stdout and saved to benchmarks/results/witnesses-YYYY-MM-DD.json

Requires the PyO3 extension to be built first:
    cd stark_stwo && maturin develop --features python --release
"""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path

try:
    import qlsa_stark_stwo as _ext  # noqa: F401
    _HAVE_EXT = True
except ImportError:
    _HAVE_EXT = False

from core.keys import derive_address, generate_keypair, wipe_key
from core.signing import sign
from core.transaction import Transaction
from stark.prover import prove_mldsa_sig_witness_stark

COUNTS = (1, 2, 4, 8)
WARMUP = 1       # warm-up iterations (not measured)
REPEATS = 3      # measured repetitions per count


def _make_signed_tx(nonce: int = 0) -> tuple[Transaction, bytes, bytearray]:
    pub, priv = generate_keypair()
    tx = Transaction(
        sender=derive_address(pub),
        recipient="d" * 64,
        amount=nonce + 1,
        nonce=nonce,
        public_key=pub,
    )
    tx.signature = sign(tx.to_bytes(), priv)
    return tx, pub, priv


def _bench_single(n: int) -> dict:
    """Measure prove_mldsa_sig_witness_stark for each of n transactions, return stats."""
    txs_data: list[tuple[bytes, bytes, bytes]] = []
    privs: list[bytearray] = []

    for i in range(n):
        tx, pub, priv = _make_signed_tx(nonce=i)
        assert tx.signature is not None
        txs_data.append((pub, tx.to_bytes(), tx.signature))
        privs.append(priv)

    # Warm-up (not measured).
    for _ in range(WARMUP):
        prove_mldsa_sig_witness_stark(txs_data[0][0], txs_data[0][1], txs_data[0][2])

    # Measure total time for all n witnesses, REPEATS times.
    times: list[float] = []
    for _ in range(REPEATS):
        t0 = time.perf_counter()
        for pk, msg, sig in txs_data:
            prove_mldsa_sig_witness_stark(pk, msg, sig)
        times.append(time.perf_counter() - t0)

    for p in privs:
        wipe_key(p)

    total_ms   = min(times) * 1000
    per_tx_ms  = total_ms / n
    return {
        "n": n,
        "total_ms": round(total_ms, 2),
        "per_tx_ms": round(per_tx_ms, 2),
        "repeats": REPEATS,
    }


def run() -> None:
    if not _HAVE_EXT:
        print("qlsa_stark_stwo not installed — skipping witness benchmark.")
        print("Build with: cd stark_stwo && maturin develop --features python --release")
        return

    results = []
    print(f"{'N':>4}  {'total (ms)':>12}  {'per-tx (ms)':>12}")
    print("-" * 34)

    for n in COUNTS:
        r = _bench_single(n)
        results.append(r)
        print(f"{n:>4}  {r['total_ms']:>12.2f}  {r['per_tx_ms']:>12.2f}")

    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"witnesses-{date.today()}.json"
    out_path.write_text(json.dumps({"bench": "witnesses", "rows": results}, indent=2))
    print(f"\nResults saved → {out_path}")


if __name__ == "__main__":
    run()
