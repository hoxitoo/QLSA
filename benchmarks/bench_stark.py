"""
STARK prover / verifier benchmark — hash-chain batches and ML-DSA batches.

Run with:  python -m benchmarks.bench_stark
Results are printed to stdout and saved to benchmarks/results/stark-YYYY-MM-DD.json

Requires the PyO3 extension to be built first:
    cd stark_stwo && maturin develop --features python --release
"""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path

try:
    import qlsa_stark_stwo as _ext
    _HAVE_EXT = True
except ImportError:
    _HAVE_EXT = False

from core.batch import create_batch
from core.keys import derive_address, generate_keypair, wipe_key
from core.signing import sign
from core.transaction import Transaction
from stark.prover import ProofResult, prove_batch, prove_mldsa_batch
from stark.verifier import verify_batch_proof


RESULTS_DIR = Path(__file__).parent / "results"
BATCH_SIZES = [10, 50, 100, 500]
MLDSA_BATCH_SIZES = [1, 2, 4, 8]


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


def _make_mldsa_entries(n: int) -> list[tuple[bytes, bytes, bytes]]:
    import oqs
    entries = []
    for i in range(n):
        alg = oqs.Signature("ML-DSA-65")
        pk = alg.generate_keypair()
        msg = f"tx payload {i}".encode()
        sig = alg.sign(msg)
        entries.append((pk, msg, sig))
    return entries


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


def bench_mldsa_prove(n: int) -> dict:
    t_keygen, entries = _time(_make_mldsa_entries, n)
    t_prove, result = _time(prove_mldsa_batch, entries)
    t_verify, valid = _time(
        verify_batch_proof, result.proof, result.commitment, result.log_size
    )
    assert valid
    assert result.verified == n
    return {
        "n_sigs": n,
        "log_size": result.log_size,
        "proof_bytes": len(result.proof),
        "keygen_sign_s": t_keygen,
        "prove_s": t_prove,
        "verify_s": t_verify,
        "total_s": t_keygen + t_prove + t_verify,
        "verified": result.verified,
        "rejected": result.rejected,
    }


def run() -> None:
    if not _HAVE_EXT:
        print("ERROR: qlsa_stark_stwo extension not installed.")
        print("Build with: cd stark_stwo && maturin develop --features python --release")
        return

    results: dict = {
        "date": str(date.today()),
        "extension": "qlsa_stark_stwo (PyO3)",
        "hash_chain_runs": [],
        "mldsa_batch_runs": [],
    }

    print("=" * 70)
    print("QLSA STARK Benchmark — Hash-Chain (Stwo Circle STARK)")
    print("=" * 70)
    print()
    print(f"  {'N txs':>6}  {'log_size':>8}  {'proof KB':>8}  {'prove s':>9}  {'verify s':>9}")
    print("  " + "-" * 57)

    for n in BATCH_SIZES:
        r = bench_prove(n)
        results["hash_chain_runs"].append(r)
        print(
            f"  {r['n_txs']:>6}  {r['log_size']:>8}  "
            f"{r['proof_bytes']/1024:>7.1f}K  "
            f"{r['prove_s']:>9.3f}  {r['verify_s']:>9.3f}"
        )

    print()
    print("  Note: STARK trace always has 8 leaves (Merkle root chunks).")
    print("        prove/verify time is constant w.r.t. batch size.")

    print()
    print("=" * 70)
    print("QLSA STARK Benchmark — ML-DSA-65 Batch (Rust FIPS 204 verifier)")
    print("=" * 70)
    print(f"  {'N sigs':>6}  {'log_size':>8}  {'proof KB':>8}  {'keygen+sign s':>13}  {'prove s':>9}  {'verify s':>9}")
    print("  " + "-" * 65)

    for n in MLDSA_BATCH_SIZES:
        r = bench_mldsa_prove(n)
        results["mldsa_batch_runs"].append(r)
        print(
            f"  {r['n_sigs']:>6}  {r['log_size']:>8}  "
            f"{r['proof_bytes']/1024:>7.1f}K  "
            f"{r['keygen_sign_s']:>13.3f}  "
            f"{r['prove_s']:>9.3f}  {r['verify_s']:>9.3f}"
        )

    print()
    print("  prove_s = Rust ML-DSA-65 verify (FIPS 204) + STARK hash-chain prove.")
    print("  verify_s = PyO3 STARK verifier.")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"stark-{date.today()}.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to {out}")


if __name__ == "__main__":
    run()
