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
    DEFAULT_WITNESS_PROTOCOL,
    WITNESS_PROTOCOLS,
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


def test_registry_covers_every_uniform_protocol() -> None:
    assert set(WITNESS_PROTOCOLS) == {"vfri7", "vfri8", "vfri9", "vfri10", "vfri11"}


def test_recursive_is_deliberately_absent() -> None:
    """prove_mldsa_sig_recursive_stark returns bundles, not hint triples.

    It is not substitutable through this registry, and pretending otherwise
    would produce an object whose fields the caller cannot use.
    """
    assert "recursive" not in WITNESS_PROTOCOLS


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
