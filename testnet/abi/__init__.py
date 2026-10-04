"""Compiled contract ABIs for the testnet submitters.

The JSON files here are generated from ``contracts/artifacts/`` by
``testnet.abi._sync`` and kept honest by ``--check`` in CI. Do not edit them by
hand — that is exactly how the previous inline blobs went stale (see
``_sync.py`` for what broke).
"""

from __future__ import annotations

from typing import Any

__all__ = ["abi_for"]


def abi_for(contract: str) -> list[dict[str, Any]]:
    """Return the ABI of *contract*, e.g. ``abi_for("BatchRegistryV7")``."""
    # Imported inside the function, not at module level: `_sync` is also run as
    # `python -m testnet.abi._sync`, and importing it here would load it twice
    # (RuntimeWarning from runpy).
    from testnet.abi._sync import load_committed_abi

    return load_committed_abi(contract)
