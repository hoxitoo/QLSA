"""The testnet submitters' ABIs must match the contracts they talk to.

Regression coverage for three defects that coexisted on 2026-10-04 and between
them made it impossible for EITHER submitter to place a transaction. All three
were invisible to the only path CI exercises, because ``testnet.e2e --dry-run``
returns before submitting:

1. ``_REGISTRY_V7_ABI`` predated ``txListRoot``, so it declared
   ``submitBatch(bytes32, RecursiveBundle, RecursiveBundle)`` while
   ``BatchRegistryV7`` takes ``(bytes32, bytes32, RecursiveBundle,
   RecursiveBundle)``. web3 would compute a selector the contract does not have.
2. ``_REGISTRY_ABI`` (used for ``BatchRegistryV5``) was pasted from
   ``BatchRegistryV2`` — a 3-parameter ``submitBatch`` against the contract's 7,
   and a ``getCommitment`` view that had become ``getCommitmentsLog10/Log8``.
3. ``OnchainSubmitterV5.__init__`` referenced ``_REGISTRY_V4_ABI``, a name
   defined nowhere, so the DEFAULT ``--stack v7`` path raised ``NameError``
   before it could even connect.

Two kinds of check live here, and they fail for different reasons:

* ``test_abi_matches_compiled_artifact`` needs ``contracts/artifacts/`` and so
  skips when the contracts have not been compiled. CI runs the same comparison
  as a hard failure in the ``contracts`` job, which compiles.
* everything else needs only the committed JSON, so it runs everywhere — these
  are the ones that would have caught defects 1 and 3 in the python job.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from testnet.abi import abi_for
from testnet.abi._sync import CONTRACTS, artifact_path, check


def _functions(abi: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Map function name -> its ABI entry's inputs."""
    return {e["name"]: e["inputs"] for e in abi if e.get("type") == "function"}


# ── The committed ABIs are well-formed and cover what the submitters call ─────


@pytest.mark.parametrize("contract", CONTRACTS)
def test_committed_abi_is_a_json_array_of_entries(contract: str) -> None:
    abi = abi_for(contract)
    assert isinstance(abi, list) and abi, f"{contract} ABI is empty"
    assert all(isinstance(e, dict) and "type" in e for e in abi)


def test_v7_submit_functions_take_tx_list_root() -> None:
    """The exact defect: txListRoot went into the contract, not into the ABI.

    Asserted by POSITION, not just presence — ``submitBatch(merkleRoot,
    txListRoot, ...)`` and ``(merkleRoot, ..., txListRoot)`` are different
    functions, and web3 encodes positionally.
    """
    fns = _functions(abi_for("BatchRegistryV7"))
    for name in ("submitBatch", "submitBatchWithNonces"):
        names = [i["name"] for i in fns[name]]
        assert names[:4] == [
            "merkleRoot",
            "txListRoot",
            "bundle10",
            "bundle8",
        ], f"{name} parameters are {names}"


def test_v7_submit_with_nonces_still_ends_in_the_sender_arrays() -> None:
    fns = _functions(abi_for("BatchRegistryV7"))
    names = [i["name"] for i in fns["submitBatchWithNonces"]]
    assert names[-2:] == ["senders", "newNonces"]


def test_v5_submit_is_the_dual_group_shape_not_the_retired_single_proof_one() -> None:
    """Defect 2: the V5 ABI was a BatchRegistryV2 paste.

    V2 took one proof; V5 verifies BOTH V23 trace groups in one transaction.
    """
    fns = _functions(abi_for("BatchRegistryV5"))
    names = [i["name"] for i in fns["submitBatch"]]
    assert names == [
        "merkleRoot",
        "commitmentLog10",
        "proofLog10",
        "hintsLog10",
        "commitmentLog8",
        "proofLog8",
        "hintsLog8",
    ], names
    # The V2 paste carried `getCommitment`, which does not exist on V5.
    assert "getCommitment" not in fns
    assert {"getCommitmentsLog10", "getCommitmentsLog8"} <= set(fns)


# ── Every function the submitters call must exist in the ABI they load ────────

#: What each submitter class calls on its contract, read off testnet/submit.py.
#: Defect 3 was a submitter bound to an ABI that did not exist at all; this
#: pins the weaker but still load-bearing property that the ABI it IS bound to
#: contains every function it reaches for.
_CALLED: dict[str, tuple[str, ...]] = {
    "BatchRegistryV5": (
        "submitBatch",
        "submitBatchWithNonces",
        "isBatchFinalized",
        "senderNonces",
    ),
    "BatchRegistryV7": (
        "submitBatch",
        "submitBatchWithNonces",
        "isBatchFinalized",
        "batchCommitmentsLog10",
        "crossBoundRoot",
    ),
}


@pytest.mark.parametrize("contract,called", sorted(_CALLED.items()))
def test_every_function_the_submitter_calls_exists(
    contract: str, called: tuple[str, ...]
) -> None:
    fns = _functions(abi_for(contract))
    missing = [name for name in called if name not in fns]
    assert not missing, f"{contract} ABI lacks {missing}"


def test_submitters_are_bound_to_a_real_abi() -> None:
    """Defect 3 directly: importing the module must define both ABI names.

    ``_REGISTRY_V4_ABI`` was referenced from ``OnchainSubmitterV5.__init__``
    and defined nowhere, so this failed only when a submitter was constructed —
    i.e. only on a real submit.
    """
    import testnet.submit as submit

    for attr in ("_REGISTRY_V5_ABI", "_REGISTRY_V7_ABI"):
        abi = getattr(submit, attr)
        assert isinstance(abi, list) and abi, f"{attr} is not a populated ABI"


# ── The committed JSON is the artifact, not a hand edit ───────────────────────


@pytest.mark.parametrize("contract", CONTRACTS)
def test_abi_matches_compiled_artifact(contract: str) -> None:
    """Needs compiled contracts; CI's `contracts` job runs this as a hard gate."""
    if not artifact_path(contract).is_file():
        pytest.skip(
            f"{artifact_path(contract)} absent — run `npx hardhat compile` in contracts/"
        )
    reason = check(contract)
    assert reason is None, reason


@pytest.mark.parametrize("contract", CONTRACTS)
def test_committed_abi_is_canonically_formatted(contract: str) -> None:
    """Sorted keys and a trailing newline, so a reformat is not read as drift."""
    from testnet.abi._sync import committed_path

    text = committed_path(contract).read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"
