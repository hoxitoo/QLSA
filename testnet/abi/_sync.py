"""Keep ``testnet/abi/*.json`` equal to the compiled contract ABIs.

Why this exists
---------------
``testnet/submit.py`` used to carry its ABIs as inline ``json.loads(\"\"\"...\"\"\")``
blobs, pasted by hand from whatever artifact was current at the time. By
2026-10-04 all three had rotted and NEITHER submitter could place a
transaction:

* ``_REGISTRY_ABI`` declared ``submitBatch(bytes32, bytes16, bytes)`` — three
  parameters, copied from ``BatchRegistryV2`` (its own comment said so).
  ``BatchRegistryV5`` takes seven, and the view it called (``getCommitment``)
  had become ``getCommitmentsLog10`` / ``getCommitmentsLog8``.
* ``_REGISTRY_V7_ABI`` predated ``txListRoot``, so the selector it computed for
  ``submitBatch`` did not exist on the deployed contract.
* ``_REGISTRY_V4_ABI`` was referenced but never defined anywhere — a plain
  ``NameError`` on the DEFAULT ``--stack v7`` path.

None of it was caught, because ``--dry-run`` returns before submitting, CI
never submits, and ``mypy``'s CI scope is ``core/ aggregator/``.

Pasting is the defect, not those three instances. The ABI now has ONE source —
the compiled artifact — and this script moves it, in the same spirit as the
single ``vfri11_fri_chain`` helper behind the hint generator and the recursion
bridge (R4.1): two copies of a thing cannot drift if there is one copy.

Usage
-----
    python -m testnet.abi._sync            # regenerate the JSON files
    python -m testnet.abi._sync --check    # fail if they differ (CI)

``--check`` runs in the ``contracts`` CI job, which compiles anyway;
``contracts/artifacts/`` is gitignored, so the JSON files are committed and the
check is what keeps them honest.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

#: Contracts whose ABI the testnet submitters need.
CONTRACTS = ("BatchRegistryV5", "BatchRegistryV7")

_HERE = Path(__file__).resolve().parent
_ARTIFACTS = _HERE.parent.parent / "contracts" / "artifacts" / "src"


def artifact_path(name: str) -> Path:
    """Where ``npx hardhat compile`` leaves *name*'s artifact."""
    return _ARTIFACTS / f"{name}.sol" / f"{name}.json"


def committed_path(name: str) -> Path:
    """Where this package keeps *name*'s ABI."""
    return _HERE / f"{name}.json"


def load_artifact_abi(name: str) -> list[dict[str, Any]]:
    """Read *name*'s ABI out of its compiled artifact.

    Raises ``FileNotFoundError`` when the contracts have not been compiled —
    callers decide whether that is fatal (``--check`` in CI) or a skip (tests).
    """
    path = artifact_path(name)
    if not path.is_file():
        raise FileNotFoundError(
            f"{path} not found — run `npx hardhat compile` in contracts/ first"
        )
    with path.open(encoding="utf-8") as fh:
        artifact = json.load(fh)
    abi = artifact.get("abi")
    if not isinstance(abi, list):
        raise ValueError(f"{path} has no 'abi' array")
    return abi


def load_committed_abi(name: str) -> list[dict[str, Any]]:
    """Read the ABI committed in this package. This is what ``submit.py`` uses."""
    path = committed_path(name)
    with path.open(encoding="utf-8") as fh:
        abi = json.load(fh)
    if not isinstance(abi, list):
        raise ValueError(f"{path} must contain a JSON array")
    return abi


def _serialise(abi: list[dict[str, Any]]) -> str:
    # sort_keys so a solc version that reorders keys is not reported as drift,
    # and a trailing newline so the file is a well-formed text file.
    return json.dumps(abi, indent=2, sort_keys=True) + "\n"


def write(name: str) -> bool:
    """Write *name*'s ABI from its artifact. Returns True if the file changed."""
    text = _serialise(load_artifact_abi(name))
    path = committed_path(name)
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return False
    path.write_text(text, encoding="utf-8")
    return True


def check(name: str) -> str | None:
    """Return a human-readable reason *name* is out of sync, or None if it is fine."""
    artifact = load_artifact_abi(name)
    if not committed_path(name).is_file():
        return f"{committed_path(name).name} is missing"
    if _serialise(artifact) != committed_path(name).read_text(encoding="utf-8"):
        return (
            f"{committed_path(name).name} differs from the compiled artifact — "
            f"run `python -m testnet.abi._sync` and commit the result"
        )
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if any committed ABI differs from its artifact",
    )
    args = ap.parse_args(argv)

    failures = []
    for name in CONTRACTS:
        if args.check:
            reason = check(name)
            if reason:
                failures.append(reason)
            else:
                print(f"{name}: in sync")
        else:
            changed = write(name)
            print(f"{name}: {'updated' if changed else 'unchanged'}")

    for reason in failures:
        print(f"ERROR: {reason}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
