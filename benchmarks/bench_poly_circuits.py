"""
Polynomial circuit STARK benchmark — MVP-3+ sub-circuits.

Benchmarks the six degree-2 Circle STARK circuits used in the ML-DSA.Verify
witness pipeline:

  poly_sub   — coefficient-wise subtraction mod Q (256 terms)
  norm_check — absolute centred value min(z, Q−z)  (256 terms)
  use_hint   — ML-DSA UseHint(h, r) = w1            (256 terms)

Run with:
    python -m benchmarks.bench_poly_circuits

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

from stark.prover import (
    prove_poly_sub_stark,
    verify_poly_sub_stark,
    prove_norm_check_stark,
    verify_norm_check_stark,
    prove_use_hint_stark,
    verify_use_hint_stark,
    NORM_BOUND,
)

RESULTS_DIR = Path(__file__).parent / "results"
Q = 8_380_417
N = 256
REPS = 5  # repetitions per benchmark; median is reported


# ── Helpers ──────────────────────────────────────────────────────────────────

def _lcg(seed: int) -> "generator":
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFF_FFFF_FFFF_FFFF
        yield (state >> 33) % Q


def _rand_poly(seed: int) -> list[int]:
    g = _lcg(seed)
    return [next(g) for _ in range(N)]


def _rand_hints(seed: int) -> list[bool]:
    g = _lcg(seed + 999)
    return [bool(next(g) & 1) for _ in range(N)]


def _median(times: list[float]) -> float:
    s = sorted(times)
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2


def _timeit(fn, *args, reps: int = REPS):
    times = []
    result = None
    for _ in range(reps):
        t0 = time.perf_counter()
        result = fn(*args)
        times.append(time.perf_counter() - t0)
    return _median(times), result


# ── Individual circuit benchmarks ─────────────────────────────────────────────

def bench_poly_sub() -> dict:
    a = _rand_poly(1)
    b = _rand_poly(2)

    prove_s, result = _timeit(prove_poly_sub_stark, a, b)
    verify_s, ok = _timeit(verify_poly_sub_stark, result)
    assert ok

    return {
        "circuit": "poly_sub",
        "n_coeffs": N,
        "proof_bytes": len(result.proof),
        "prove_s": prove_s,
        "verify_s": verify_s,
    }


def bench_norm_check() -> dict:
    z = _rand_poly(3)

    prove_s, result = _timeit(prove_norm_check_stark, z)
    verify_s, ok = _timeit(verify_norm_check_stark, result)
    assert ok
    assert result.max_norm < NORM_BOUND, f"max_norm {result.max_norm} ≥ NORM_BOUND"

    return {
        "circuit": "norm_check",
        "n_coeffs": N,
        "proof_bytes": len(result.proof),
        "prove_s": prove_s,
        "verify_s": verify_s,
        "max_norm": result.max_norm,
        "norm_bound": NORM_BOUND,
    }


def bench_use_hint() -> dict:
    r = _rand_poly(4)
    h = _rand_hints(4)

    prove_s, result = _timeit(prove_use_hint_stark, r, h)
    verify_s, ok = _timeit(verify_use_hint_stark, result)
    assert ok

    return {
        "circuit": "use_hint",
        "n_coeffs": N,
        "proof_bytes": len(result.proof),
        "prove_s": prove_s,
        "verify_s": verify_s,
    }


def bench_pipeline_3_circuits() -> dict:
    """Wall-clock time to run poly_sub → norm_check → use_hint sequentially."""
    a = _rand_poly(10)
    b = _rand_poly(11)
    h = _rand_hints(10)

    def _pipeline():
        sub  = prove_poly_sub_stark(a, b)
        norm = prove_norm_check_stark(sub.output)
        hint = prove_use_hint_stark(sub.output, h)
        return sub, norm, hint

    total_s, (sub, norm, hint) = _timeit(_pipeline, reps=REPS)

    assert verify_poly_sub_stark(sub)
    assert verify_norm_check_stark(norm)
    assert verify_use_hint_stark(hint)

    proof_bytes = len(sub.proof) + len(norm.proof) + len(hint.proof)
    return {
        "circuit": "pipeline_sub+norm+hint",
        "n_coeffs": N,
        "proof_bytes": proof_bytes,
        "total_prove_s": total_s,
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def run() -> None:
    if not _HAVE_EXT:
        print("ERROR: qlsa_stark_stwo extension not installed.")
        print("Build with: cd stark_stwo && maturin develop --features python --release")
        return

    print("=" * 70)
    print("QLSA Polynomial Circuit STARK Benchmark  (MVP-3+)")
    print(f"  Q={Q}  N={N}  reps={REPS}  (median reported)")
    print("=" * 70)
    print()
    print(f"  {'Circuit':<28}  {'proof KB':>8}  {'prove s':>9}  {'verify s':>9}")
    print("  " + "-" * 62)

    rows = []
    for bench_fn in (bench_poly_sub, bench_norm_check, bench_use_hint):
        r = bench_fn()
        rows.append(r)
        prove_s  = r.get("prove_s", r.get("total_prove_s", 0))
        verify_s = r.get("verify_s", "—")
        kb = r["proof_bytes"] / 1024
        verify_col = f"{verify_s:9.4f}" if isinstance(verify_s, float) else f"{'—':>9}"
        print(f"  {r['circuit']:<28}  {kb:>7.1f}K  {prove_s:>9.4f}  {verify_col}")

    r_pipe = bench_pipeline_3_circuits()
    rows.append(r_pipe)
    kb = r_pipe["proof_bytes"] / 1024
    print(f"  {r_pipe['circuit']:<28}  {kb:>7.1f}K  {r_pipe['total_prove_s']:>9.4f}  {'—':>9}")

    print()
    print("  All circuits: 256 rows, degree ≤ 2, FRI blowup=4.")
    print("  prove_s = median wall-clock (includes trace build + FRI commit + query).")
    print("  verify_s = FRI verify (no batch decommitment overhead).")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"poly-circuits-{date.today()}.json"
    out.write_text(json.dumps({"date": str(date.today()), "runs": rows}, indent=2))
    print(f"\nResults saved to {out}")


if __name__ == "__main__":
    run()
