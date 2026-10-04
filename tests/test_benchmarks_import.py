"""Every benchmark must still import.

Benchmarks are not exercised by the suite, so when a prover entry point is
renamed or retired they break silently. That is exactly what happened in the Ф1
narrowing: `bench_witnesses.py` kept importing `prove_mldsa_sig_vfri7_stark`
after the protocol was retired, and nothing noticed until an audit pass ran the
import by hand.

Importing is all this checks — running a benchmark takes minutes. An import is
enough to catch a dangling name, which is the failure that actually occurs.
"""

import importlib
import pkgutil

import pytest

import benchmarks

_MODULES = sorted(m.name for m in pkgutil.iter_modules(benchmarks.__path__))


def test_there_are_benchmarks_to_check() -> None:
    """Guards the parametrisation: an empty list would make the suite vacuous."""
    assert _MODULES, "no benchmark modules found — has the package moved?"


@pytest.mark.parametrize("name", _MODULES)
def test_benchmark_imports(name: str) -> None:
    importlib.import_module(f"benchmarks.{name}")
