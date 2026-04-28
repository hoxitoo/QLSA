"""
Run with:  python -m benchmarks.bench_core
Results are printed to stdout and saved to benchmarks/results/YYYY-MM-DD.json
"""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path

from core.keys import derive_address, generate_keypair, wipe_key
from core.merkle import build_merkle_tree, get_merkle_root
from core.signing import sign, verify
from core.transaction import Transaction


BATCH_SIZES = [100, 500, 1000, 3000]
RESULTS_DIR = Path(__file__).parent / "results"


def _time(fn, *args, **kwargs) -> tuple[float, object]:
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    return time.perf_counter() - t0, result


def bench_sign_verify(n: int) -> dict:
    pub, priv = generate_keypair()
    msg = b"benchmark message"

    sign_times = []
    verify_times = []
    sigs = []

    for _ in range(n):
        t, sig = _time(sign, msg, priv)
        sign_times.append(t)
        sigs.append(sig)

    for sig in sigs:
        t, _ = _time(verify, msg, sig, pub)
        verify_times.append(t)

    wipe_key(priv)

    return {
        "n": n,
        "sign_total_s": sum(sign_times),
        "sign_avg_ms": sum(sign_times) / n * 1000,
        "verify_total_s": sum(verify_times),
        "verify_avg_ms": sum(verify_times) / n * 1000,
    }


def bench_merkle(n: int) -> dict:
    leaves = [f"leaf-{i}".encode() for i in range(n)]
    t, tree = _time(build_merkle_tree, leaves)
    root = get_merkle_root(tree)
    return {
        "n": n,
        "merkle_build_s": t,
        "merkle_build_ms": t * 1000,
        "root_hex": root.hex()[:16] + "...",
    }


def bench_full_pipeline(n: int) -> dict:
    """Sign N transactions and build a Merkle tree of their hashes."""
    pub, priv = generate_keypair()
    addr = derive_address(pub)
    recipient = "ab" * 32

    txs = []
    for i in range(n):
        tx = Transaction(
            sender=addr, recipient=recipient, amount=i + 1, nonce=i, public_key=pub
        )
        txs.append(tx)

    t_sign, _ = _time(lambda: [_sign_tx(tx, priv) for tx in txs])
    leaves = [tx.tx_hash() for tx in txs]
    t_merkle, tree = _time(build_merkle_tree, leaves)
    root = get_merkle_root(tree)

    wipe_key(priv)

    return {
        "n": n,
        "sign_all_s": t_sign,
        "merkle_build_s": t_merkle,
        "total_s": t_sign + t_merkle,
        "root_hex": root.hex()[:16] + "...",
    }


def _sign_tx(tx: Transaction, priv: bytearray) -> None:
    tx.signature = sign(tx.to_bytes(), priv)


def run() -> None:
    results: dict = {"date": str(date.today()), "sign_verify": [], "merkle": [], "pipeline": []}

    print("=" * 60)
    print("QLSA Core Benchmark")
    print("=" * 60)

    print("\n[1/3] sign / verify (ML-DSA-65)")
    for n in BATCH_SIZES:
        r = bench_sign_verify(n)
        results["sign_verify"].append(r)
        print(
            f"  N={n:>5}  sign_avg={r['sign_avg_ms']:.2f}ms  "
            f"verify_avg={r['verify_avg_ms']:.2f}ms  "
            f"sign_total={r['sign_total_s']:.2f}s"
        )

    print("\n[2/3] Merkle tree build (SHA3-512)")
    for n in BATCH_SIZES:
        r = bench_merkle(n)
        results["merkle"].append(r)
        print(f"  N={n:>5}  build={r['merkle_build_ms']:.2f}ms")

    print("\n[3/3] Full pipeline (sign + merkle)")
    for n in BATCH_SIZES:
        r = bench_full_pipeline(n)
        results["pipeline"].append(r)
        print(
            f"  N={n:>5}  sign={r['sign_all_s']:.2f}s  "
            f"merkle={r['merkle_build_s']*1000:.2f}ms  "
            f"total={r['total_s']:.2f}s"
        )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"{date.today()}.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to {out}")


if __name__ == "__main__":
    run()
