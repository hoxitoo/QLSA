"""
STARK prover / verifier benchmark — hash-chain batches and ML-DSA batches.

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
from stark.prover import BINARY, ProofResult, binary_available, prove_batch, prove_mldsa_batch
from stark.verifier import verify_batch_proof


RESULTS_DIR = Path(__file__).parent / "results"
# Batch sizes for hash-chain benchmark; STARK trace always has 8 leaves.
BATCH_SIZES = [10, 50, 100, 500]
# ML-DSA batch sizes; each entry requires a full FIPS 204 verify + Rust STARK prove.
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
    """Generate n real ML-DSA-65 (pk, msg, sig) triples via liboqs."""
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
    """Benchmark ML-DSA batch: keygen + sign in Python, verify + prove in Rust."""
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
        "prove_s": t_prove,       # Rust ML-DSA verify + STARK prove
        "verify_s": t_verify,     # Python STARK verify (Rust binary)
        "total_s": t_keygen + t_prove + t_verify,
        "verified": result.verified,
        "rejected": result.rejected,
    }


def run() -> None:
    if not binary_available():
        print(f"ERROR: STARK binary not found at {BINARY}")
        print("Build with: cd stark_stwo && cargo +nightly-2025-07-01 build --release")
        return

    results: dict = {
        "date": str(date.today()),
        "binary": str(BINARY),
        "hash_chain_runs": [],
        "mldsa_batch_runs": [],
    }

    # ── Hash-chain benchmark ───────────────────────────────────────────────────
    print("=" * 70)
    print("QLSA STARK Benchmark — Hash-Chain (Stwo Circle STARK, nightly-2025-07-01)")
    print("=" * 70)
    print(f"  Binary: {BINARY}")
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

    # ── ML-DSA batch benchmark ─────────────────────────────────────────────────
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
    print("  verify_s = Python STARK verifier (calls Rust binary).")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"stark-{date.today()}.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to {out}")


if __name__ == "__main__":
    run()
