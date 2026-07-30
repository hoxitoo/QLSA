"""Tests for the registry-shape guard in testnet/submit.py.

The three stacks pair a prover protocol with a registry SHAPE:

    --stack v4 / v7 -> BatchRegistryV4 / V5: submitBatch[WithNonces]  (one tx)
    --stack v6      -> BatchRegistryV6:      submitGroup10 + submitGroup8

Pointing ``REGISTRY_ADDRESS`` at the wrong shape otherwise fails deep inside a
transaction with an opaque error, so the submitters probe it up front.  Making v7
the default stack raises the odds of exactly that mismatch (an operator with a
previously deployed V6 registry), which is what these tests pin down.

The probe is exercised against a duck-typed stand-in for ``Web3`` rather than a
live chain: the behaviour under test is the branch logic, not RPC transport.
"""

import pytest

from testnet.submit import (
    _PER_GROUP,
    _SINGLE_SUBMIT,
    detect_registry_kind,
    require_registry_kind,
)

ADDR = "0x" + "11" * 20


class _Fn:
    def __init__(self, *, reverts: bool) -> None:
        self._reverts = reverts

    def call(self):  # noqa: ANN201 - mirrors web3's untyped call()
        if self._reverts:
            raise ValueError("execution reverted")
        return (False, False, False)


class _Functions:
    def __init__(self, *, reverts: bool) -> None:
        self._reverts = reverts

    def pendingGroups(self, _root):  # noqa: N802 - matches the Solidity name
        return _Fn(reverts=self._reverts)


class _Contract:
    def __init__(self, *, reverts: bool) -> None:
        self.functions = _Functions(reverts=reverts)


class _Eth:
    def __init__(self, *, code: bytes, reverts: bool) -> None:
        self._code = code
        self._reverts = reverts

    def get_code(self, _addr):  # noqa: ANN201
        return self._code

    def contract(self, address=None, abi=None):  # noqa: ANN201, ARG002
        return _Contract(reverts=self._reverts)


class _W3:
    """Minimal stand-in exposing only what detect_registry_kind touches."""

    def __init__(self, *, code: bytes = b"\x60\x00", reverts: bool = False) -> None:
        self.eth = _Eth(code=code, reverts=reverts)


def test_detects_a_per_group_registry() -> None:
    """pendingGroups answering means BatchRegistryV6."""
    assert detect_registry_kind(_W3(reverts=False), ADDR) == _PER_GROUP


def test_detects_a_single_submit_registry() -> None:
    """pendingGroups reverting means BatchRegistryV4/V5 (it has no such function)."""
    assert detect_registry_kind(_W3(reverts=True), ADDR) == _SINGLE_SUBMIT


@pytest.mark.parametrize("empty", [b"", b"0x"])
def test_rejects_an_address_with_no_contract(empty) -> None:
    """The most common misconfiguration: wrong network, or never deployed."""
    with pytest.raises(RuntimeError, match="no contract deployed"):
        detect_registry_kind(_W3(code=empty), ADDR)


def test_require_passes_when_the_shape_matches() -> None:
    require_registry_kind(_W3(reverts=True), ADDR, _SINGLE_SUBMIT, "BatchRegistryV5")
    require_registry_kind(_W3(reverts=False), ADDR, _PER_GROUP, "BatchRegistryV6")


def test_require_rejects_v6_registry_for_the_v7_stack() -> None:
    """The mismatch that making v7 the default makes most likely."""
    with pytest.raises(RuntimeError) as exc:
        require_registry_kind(_W3(reverts=False), ADDR, _SINGLE_SUBMIT, "BatchRegistryV5")
    msg = str(exc.value)
    assert _PER_GROUP in msg and "BatchRegistryV5" in msg
    # The message must tell the operator how to resolve it.
    assert "--stack" in msg


def test_require_rejects_v5_registry_for_the_v6_stack() -> None:
    with pytest.raises(RuntimeError) as exc:
        require_registry_kind(_W3(reverts=True), ADDR, _PER_GROUP, "BatchRegistryV6")
    assert _SINGLE_SUBMIT in str(exc.value)


def test_the_two_kinds_are_distinct_labels() -> None:
    """Guards against a refactor collapsing the two shapes into one constant."""
    assert _PER_GROUP != _SINGLE_SUBMIT
