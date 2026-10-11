"""Every address recorded in ``deployments/*.json`` must pass its EIP-55 checksum.

These files are written by hand from deploy output. On 2026-05-05 the Sepolia
deployer was recorded as ``0x8Fb3…`` when the account is ``0xBFb3…`` — one
character mistyped. Nothing read the field, so it stayed wrong for five months
and surfaced only when the owner compared it with their wallet. A mixed-case
address carries a checksum, so a typo like that is detectable mechanically;
this test is that check.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

eth_utils = pytest.importorskip("eth_utils")

_DEPLOYMENTS = Path(__file__).resolve().parent.parent / "deployments"
# 40 hex digits not followed by more hex: an address, not a prefix of a tx hash.
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")


def _addresses() -> list[tuple[str, str]]:
    found = []
    for path in sorted(_DEPLOYMENTS.glob("*.json")):
        json.loads(path.read_text(encoding="utf-8"))  # well-formed first
        for addr in _ADDRESS.findall(path.read_text(encoding="utf-8")):
            found.append((path.name, addr))
    return found


def test_there_are_records_to_check() -> None:
    assert _addresses(), "no addresses found in deployments/*.json"


@pytest.mark.parametrize("name,addr", _addresses())
def test_recorded_address_passes_eip55(name: str, addr: str) -> None:
    # An all-lowercase address carries no checksum, so it cannot be verified —
    # record addresses in the checksummed form deploy scripts print.
    assert addr != addr.lower(), f"{name}: {addr} is not checksummed"
    assert eth_utils.is_checksum_address(addr), (
        f"{name}: {addr} fails its EIP-55 checksum — most likely a copy typo"
    )


def test_the_check_catches_the_typo_that_motivated_it() -> None:
    assert not eth_utils.is_checksum_address("0x8Fb32E28c22505c34520e3B0830E6789F1943e3f")
    assert eth_utils.is_checksum_address("0xBFb32E28c22505c34520e3B0830E6789F1943e3f")
