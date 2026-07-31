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

from web3.exceptions import BadFunctionCallOutput, ContractLogicError

from testnet.submit import (
    _PER_GROUP,
    _RECURSIVE,
    _SINGLE_SUBMIT,
    detect_registry_kind,
    require_registry_kind,
)

ADDR = "0x" + "11" * 20


class _Fn:
    def __init__(self, *, raises=None, result=None) -> None:
        self._raises = raises
        self._result = result

    def call(self):  # noqa: ANN201 - mirrors web3's untyped call()
        if self._raises is not None:
            raise self._raises
        return self._result


class _Functions:
    """Models a registry that implements only SOME of the probe selectors.

    `implements` names the selectors present; anything else raises the same
    contract-level error web3 raises for a missing selector, which is what the
    probe must treat as "not this shape".
    """

    def __init__(self, *, implements: set[str], raises=None) -> None:
        self._implements = implements
        self._raises = raises

    def _dispatch(self, name: str, result):  # noqa: ANN001, ANN202
        if self._raises is not None:
            return _Fn(raises=self._raises)
        if name not in self._implements:
            return _Fn(raises=_MISSING_SELECTOR)
        return _Fn(result=result)

    def pendingGroups(self, _root):  # noqa: N802 - matches the Solidity name
        return self._dispatch("pendingGroups", (False, False, False))

    def crossBoundRoot(self, _root, _other):  # noqa: N802
        return self._dispatch("crossBoundRoot", b"\x00" * 32)


class _Contract:
    def __init__(self, *, implements: set[str], raises=None) -> None:
        self.functions = _Functions(implements=implements, raises=raises)


class _Eth:
    def __init__(self, *, code: bytes, implements: set[str], raises=None) -> None:
        self._code = code
        self._implements = implements
        self._raises = raises

    def get_code(self, _addr):  # noqa: ANN201
        return self._code

    def contract(self, address=None, abi=None):  # noqa: ANN201, ARG002
        return _Contract(implements=self._implements, raises=self._raises)


class _W3:
    """Minimal stand-in exposing only what detect_registry_kind touches."""

    def __init__(
        self,
        *,
        code: bytes = b"\x60\x00",
        implements: set[str] | None = None,
        raises=None,
    ) -> None:
        self.eth = _Eth(
            code=code,
            implements=implements if implements is not None else set(),
            raises=raises,
        )


#: What web3 actually raises when the selector is absent (verified against a live
#: node: a contract with code but no such function gives ContractLogicError).
_MISSING_SELECTOR = ContractLogicError("execution reverted")

#: The three deployed registry shapes, by the selector each one uniquely answers.
_V7_RECURSIVE = {"crossBoundRoot"}   # BatchRegistryV7
_V6_PER_GROUP = {"pendingGroups"}    # BatchRegistryV6
_V45_SINGLE: set[str] = set()        # BatchRegistryV4 / V5 answer neither


def test_detects_a_per_group_registry() -> None:
    """pendingGroups answering means BatchRegistryV6."""
    assert detect_registry_kind(_W3(implements=_V6_PER_GROUP), ADDR) == _PER_GROUP


def test_detects_a_single_submit_registry() -> None:
    """pendingGroups reverting means BatchRegistryV4/V5 (it has no such function)."""
    assert detect_registry_kind(_W3(implements=_V45_SINGLE), ADDR) == _SINGLE_SUBMIT


@pytest.mark.parametrize("empty", [b"", b"0x"])
def test_rejects_an_address_with_no_contract(empty) -> None:
    """The most common misconfiguration: wrong network, or never deployed."""
    with pytest.raises(RuntimeError, match="no contract deployed"):
        detect_registry_kind(_W3(code=empty, implements=_V6_PER_GROUP), ADDR)


def test_require_passes_when_the_shape_matches() -> None:
    require_registry_kind(_W3(implements=_V45_SINGLE), ADDR, _SINGLE_SUBMIT, "BatchRegistryV5")
    require_registry_kind(_W3(implements=_V6_PER_GROUP), ADDR, _PER_GROUP, "BatchRegistryV6")


def test_require_rejects_v6_registry_for_the_v7_stack() -> None:
    """The mismatch that making v7 the default makes most likely."""
    with pytest.raises(RuntimeError) as exc:
        require_registry_kind(_W3(implements=_V6_PER_GROUP), ADDR, _SINGLE_SUBMIT, "BatchRegistryV5")
    msg = str(exc.value)
    assert _PER_GROUP in msg and "BatchRegistryV5" in msg
    # The message must tell the operator how to resolve it.
    assert "--stack" in msg


def test_require_rejects_v5_registry_for_the_v6_stack() -> None:
    with pytest.raises(RuntimeError) as exc:
        require_registry_kind(_W3(implements=_V45_SINGLE), ADDR, _PER_GROUP, "BatchRegistryV6")
    assert _SINGLE_SUBMIT in str(exc.value)


class _Transport(Exception):
    """Stands in for requests.ConnectionError / a timeout / a rate limit."""


def test_a_transport_failure_must_propagate_not_classify() -> None:
    """The dangerous case: an RPC outage must NOT be read as "not a V6".

    Swallowing it would classify a BatchRegistryV6 as single-submit and let a
    mismatched submission proceed — the exact failure the guard exists to prevent.
    """
    with pytest.raises(_Transport):
        detect_registry_kind(_W3(implements=_V6_PER_GROUP, raises=_Transport("connection refused")), ADDR)


def test_undecodable_return_data_classifies_as_single_submit() -> None:
    """Some nodes answer a missing selector with empty data rather than a revert."""
    got = detect_registry_kind(_W3(implements=_V6_PER_GROUP, raises=BadFunctionCallOutput("empty")), ADDR)
    assert got == _SINGLE_SUBMIT


def test_detects_a_recursive_registry() -> None:
    """crossBoundRoot answering means BatchRegistryV7 (the v8 stack)."""
    assert detect_registry_kind(_W3(implements=_V7_RECURSIVE), ADDR) == _RECURSIVE


def test_recursive_registry_is_not_mistaken_for_single_submit() -> None:
    """A V7 answers no pendingGroups either, so probe ORDER matters.

    If crossBoundRoot were probed second, a V7 would fall through to the
    pendingGroups check, fail it, and be misread as V4/V5 — letting a v8 submit
    proceed against a registry that cannot serve it.
    """
    assert detect_registry_kind(_W3(implements=_V7_RECURSIVE), ADDR) != _SINGLE_SUBMIT


def test_require_rejects_a_recursive_registry_for_the_v7_stack() -> None:
    with pytest.raises(RuntimeError) as exc:
        require_registry_kind(
            _W3(implements=_V7_RECURSIVE), ADDR, _SINGLE_SUBMIT, "BatchRegistryV5"
        )
    assert _RECURSIVE in str(exc.value)


def test_require_rejects_a_v5_registry_for_the_v8_stack() -> None:
    with pytest.raises(RuntimeError) as exc:
        require_registry_kind(
            _W3(implements=_V45_SINGLE), ADDR, _RECURSIVE, "BatchRegistryV7"
        )
    assert _SINGLE_SUBMIT in str(exc.value)


def test_the_three_kinds_are_distinct_labels() -> None:
    """Guards against a refactor collapsing the shapes into one constant."""
    assert len({_PER_GROUP, _SINGLE_SUBMIT, _RECURSIVE}) == 3
