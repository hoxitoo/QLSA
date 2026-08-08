"""The witness-protocol registry — how the product layer selects a verifier.

Before this existed, `aggregator/batcher.py`, `aggregator/api.py` and both SDKs
each enumerated VFRI7/8/9/10 by hand, six fields per protocol per layer. When
VFRI11 became the default deployed stack nobody edited those four layers, so the
aggregator kept emitting proofs the default registry rejects BY DESIGN (a
different hash backend gives a different trace root and different FRI query
indices). Nothing failed — the aggregator simply stopped being able to talk to
the chain, silently.

These tests pin the two properties that stop that recurring: the default follows
the deployed stack, and an unknown protocol is a loud error rather than a
silently missing proof.
"""

import pytest

from aggregator.batcher import Batcher, BatchResult, GroupProof, WitnessProof
from aggregator.mempool import Mempool
from stark.prover import (
    DEFAULT_FRI_QUERIES,
    DEFAULT_WITNESS_PROTOCOL,
    DIRECT_PROTOCOLS,
    PROTOCOL_DEFAULT_QUERIES,
    WITNESS_PROTOCOLS,
    WitnessGroup,
    default_queries_for,
    prove_mldsa_sig_for_protocol,
)


def _wp(protocol: str) -> WitnessProof:
    return WitnessProof(
        protocol=protocol,
        log10=GroupProof(b"\x01" * 700, "a" * 32, b"\x02" * 16),
        log8=GroupProof(b"\x03" * 700, "b" * 32, b"\x04" * 16),
    )


# ── Registry ─────────────────────────────────────────────────────────────────

def test_default_protocol_is_what_the_deployed_stack_accepts() -> None:
    """The default must track testnet/e2e.py's default --stack.

    v7 (the default stack) wires QLSAVerifierVFRI11. A default of anything else
    means the aggregator's proofs cannot be submitted, which is the exact failure
    this registry exists to prevent.
    """
    assert DEFAULT_WITNESS_PROTOCOL == "vfri11"
    assert DEFAULT_WITNESS_PROTOCOL in WITNESS_PROTOCOLS


def test_registry_covers_every_protocol() -> None:
    assert set(WITNESS_PROTOCOLS) == set(DIRECT_PROTOCOLS) | {"recursive"}
    assert set(DIRECT_PROTOCOLS) == {"vfri7", "vfri8", "vfri9", "vfri10", "vfri11"}


def test_recursive_is_normalised_not_a_parallel_shape() -> None:
    """The recursive prover returns bundles; an adapter maps it to WitnessProof.

    Its outer proof takes the same three fields as a direct protocol's, and the
    inner publics that only BatchRegistryV7 needs live in `WitnessGroup.inner`.
    So the product layer stores and forwards every protocol identically, and only
    a submitter has to know which registry shape it is aiming at.
    """
    assert "recursive" in WITNESS_PROTOCOLS
    assert "recursive" not in DIRECT_PROTOCOLS


def test_only_the_recursive_protocol_carries_inner_publics() -> None:
    """`inner` is what distinguishes the two registry shapes downstream."""
    direct = WitnessGroup(b"p", "a" * 32, b"h")
    assert direct.inner is None
    rec = WitnessGroup(b"p", "a" * 32, b"h", {"inner_publics": {}, "last_layer_evals": []})
    assert rec.inner is not None
    assert set(rec.inner) == {"inner_publics", "last_layer_evals"}


def test_unknown_protocol_raises_with_the_supported_names() -> None:
    with pytest.raises(KeyError) as exc:
        prove_mldsa_sig_for_protocol(
            "vfri99", pk=b"", msg=b"", sig=b"", batch_merkle_root=b"\x00" * 32)
    msg = str(exc.value)
    assert "vfri99" in msg and "vfri11" in msg


# ── Batcher wiring ───────────────────────────────────────────────────────────

def test_batcher_defaults_to_the_deployed_protocol() -> None:
    assert Batcher(Mempool()).witness_protocols == (DEFAULT_WITNESS_PROTOCOL,)


def test_batcher_rejects_an_unknown_protocol_at_construction() -> None:
    """Fail at configuration time, not by quietly producing no proof."""
    with pytest.raises(ValueError, match="unknown witness protocol"):
        Batcher(Mempool(), witness_protocols=("vfri11", "nope"))


def test_batcher_accepts_an_explicit_protocol_set() -> None:
    b = Batcher(Mempool(), witness_protocols=("vfri10", "vfri11"))
    assert b.witness_protocols == ("vfri10", "vfri11")


# ── BatchResult views ────────────────────────────────────────────────────────

def test_result_reports_generated_protocols() -> None:
    r = BatchResult(batch=None)  # type: ignore[arg-type]
    assert r.witness_protocols == []
    assert r.has_witness is False

    r.witness_proofs["vfri11"] = _wp("vfri11")
    assert r.witness_protocols == ["vfri11"]
    assert r.has_protocol("vfri11") and not r.has_protocol("vfri10")
    assert r.has_witness is True


def test_deprecated_per_protocol_views_still_work() -> None:
    """aggregator/api.py and both SDKs read these names; they must keep working."""
    r = BatchResult(batch=None)  # type: ignore[arg-type]
    assert r.has_vfri11 is False
    assert r.vfri11_proof_log10 is None
    assert r.vfri11_commitment_log8 is None

    r.witness_proofs["vfri11"] = _wp("vfri11")
    assert r.has_vfri11 is True
    assert r.vfri11_proof_log10 == b"\x01" * 700
    assert r.vfri11_commitment_log10 == "a" * 32
    assert r.vfri11_hints_log8 == b"\x04" * 16
    # A protocol that was NOT generated reads as absent, not as another's data.
    assert r.has_vfri10 is False
    assert r.vfri10_proof_log10 is None


def test_witness_for_returns_the_pair_or_none() -> None:
    r = BatchResult(batch=None)  # type: ignore[arg-type]
    assert r.witness_for("vfri11") is None
    r.witness_proofs["vfri11"] = _wp("vfri11")
    w = r.witness_for("vfri11")
    assert w is not None
    # Both groups must be present: each is bound to the OTHER's trace root, so
    # a result carrying only one is not submittable.
    assert w.log10.proof and w.log8.proof
    assert w.protocol == "vfri11"


# ── API surface ──────────────────────────────────────────────────────────────

def test_api_exposes_the_protocol_on_every_batch_endpoint() -> None:
    """A client must be able to ask WHICH protocol a proof was generated under.

    That question could not previously be asked: the response enumerated
    VFRI7..VFRI10 as fixed keys, so when the default stack moved to VFRI11 the
    API reported four `false`s and no field said why. The four endpoints are
    checked together because they were four hand-written copies of the same
    block, and three of them were missed on the first pass of this change.
    """
    from fastapi.testclient import TestClient

    from aggregator.api import app
    from core.keys import derive_address, generate_keypair
    from core.signing import sign
    from core.transaction import Transaction

    with TestClient(app) as c:
        pk, sk = generate_keypair()
        addr = derive_address(pk)
        tx = Transaction(sender=addr, recipient=addr, amount=5, nonce=0, public_key=pk)
        tx.signature = sign(tx.to_bytes(), sk)
        r = c.post("/transactions", json={
            "sender": tx.sender, "recipient": tx.recipient, "amount": tx.amount,
            "nonce": tx.nonce, "public_key": tx.public_key.hex(),
            "signature": tx.signature.hex(),
        })
        assert r.json()["accepted"] is True

        flushed = c.post("/batch/flush").json()
        batch_id = flushed["batch_id"]

        bodies = [
            flushed,
            c.get(f"/batch/{batch_id}").json(),
            c.get(f"/batch/{batch_id}/witness").json(),
            c.get("/batches").json()["batches"][0],
        ]
        for body in bodies:
            # Present and correctly typed even with no witness proof — a field
            # that appears and disappears with the answer is unusable.
            assert isinstance(body.get("witness_protocols"), list)
            assert isinstance(body.get("witness"), dict)
            # The legacy keys must still be there for existing clients.
            for legacy in ("vfri7", "vfri8", "vfri9", "vfri10"):
                assert f"has_{legacy}" in body


def test_api_reports_which_registry_shape_a_proof_targets() -> None:
    """A client cannot infer the registry from the protocol name.

    Submitting a direct proof to BatchRegistryV7 (or the reverse) fails inside
    the transaction rather than at the boundary, so the response says which
    shape each proof is for.
    """
    from aggregator.api import _witness_fields
    from stark.prover import WitnessGroup, WitnessProof

    class _R:
        witness_protocols = ["vfri11", "recursive"]
        witness_proofs = {
            "vfri11": WitnessProof(
                "vfri11", WitnessGroup(b"a", "1" * 32, b"h"),
                WitnessGroup(b"b", "2" * 32, b"h")),
            "recursive": WitnessProof(
                "recursive",
                WitnessGroup(b"a", "3" * 32, b"h", {"inner_publics": {}, "last_layer_evals": []}),
                WitnessGroup(b"b", "4" * 32, b"h", {"inner_publics": {}, "last_layer_evals": []})),
        }

    f = _witness_fields(_R())
    assert f["witness"]["vfri11"]["registry"] == "direct"
    assert f["witness"]["recursive"]["registry"] == "recursive"
    # The legacy flat keys are frozen to the four protocols that predate
    # `witness_protocols`: newer ones appear under `witness` only, so an existing
    # client's response shape never changes under it.
    legacy = {k for k in f if k.startswith("has_vfri")}
    assert legacy == {"has_vfri7", "has_vfri8", "has_vfri9", "has_vfri10"}
    assert "has_recursive" not in f and "has_vfri11" not in f


# ── Query-count defaults ─────────────────────────────────────────────────────

def test_recursive_defaults_to_production_security() -> None:
    """The recursive route is pointless below production security.

    On-chain soundness is log_blowup(6) * n_queries + pow_bits(10). At ONE query
    the recursion costs MORE gas than verifying directly, for 16 bits — the one
    configuration it must never be entered by accident.

    This was a real regression: `prove_mldsa_sig_for_protocol` took
    `n_queries: int = 1` and always passed it, so the recursive prover's own
    default of 20 could never apply, and a caller who did not know to ask for 20
    silently paid for recursion and got 16 bits.
    """
    assert default_queries_for("recursive") == 20
    assert 6 * default_queries_for("recursive") + 10 == 130


def test_direct_protocols_default_to_one_query() -> None:
    for name in DIRECT_PROTOCOLS:
        assert default_queries_for(name) == DEFAULT_FRI_QUERIES == 1
        assert name not in PROTOCOL_DEFAULT_QUERIES


def test_batcher_leaves_the_query_count_to_the_protocol_by_default() -> None:
    """None must reach the registry, not be replaced by a shared default."""
    assert Batcher(Mempool()).n_fri_queries is None
    assert Batcher(Mempool(), n_fri_queries=20).n_fri_queries == 20
    with pytest.raises(ValueError, match=r"n_fri_queries must be in \[1, 64\]"):
        Batcher(Mempool(), n_fri_queries=0)
