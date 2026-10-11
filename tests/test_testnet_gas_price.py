"""`testnet.submit.gas_price_for` — the one gas-price rule the testnet path uses.

The deploy script (`contracts/scripts/deploy_v8.js`) and the GitHub workflows'
balance checks follow the same rule: the node's ``eth_gasPrice``, raised to
``$QLSA_MIN_GAS_PRICE_WEI`` when that is set and higher. On 2026-10-11 the
deploy check priced the run one way and Hardhat's signer another, and the
deploy was refused for funds the check had said were enough.
"""

from __future__ import annotations

import pytest

pytest.importorskip("web3")

from testnet.submit import GAS_PRICE_FLOOR_ENV, gas_price_for


class _Eth:
    def __init__(self, price: int) -> None:
        self.gas_price = price


class _W3:
    def __init__(self, price: int) -> None:
        self.eth = _Eth(price)


def test_without_a_floor_the_node_suggestion_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(GAS_PRICE_FLOOR_ENV, raising=False)
    assert gas_price_for(_W3(15)) == 15


def test_an_empty_floor_is_no_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(GAS_PRICE_FLOOR_ENV, "  ")
    assert gas_price_for(_W3(15)) == 15


def test_the_floor_raises_a_lower_suggestion(monkeypatch: pytest.MonkeyPatch) -> None:
    # The 2026-10-11 Sepolia case: ~15 wei suggested, 0.1 gwei floor.
    monkeypatch.setenv(GAS_PRICE_FLOOR_ENV, str(100_000_000))
    assert gas_price_for(_W3(15)) == 100_000_000


def test_a_higher_suggestion_wins_over_the_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(GAS_PRICE_FLOOR_ENV, str(100_000_000))
    assert gas_price_for(_W3(3_000_000_000)) == 3_000_000_000


@pytest.mark.parametrize("bad", ["0.1", "1e9", "abc", "-5"])
def test_a_malformed_floor_is_refused_not_ignored(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    # Silently falling back to the suggestion would send at a price the
    # balance check did not assume.
    monkeypatch.setenv(GAS_PRICE_FLOOR_ENV, bad)
    with pytest.raises(ValueError, match=GAS_PRICE_FLOOR_ENV):
        gas_price_for(_W3(15))
