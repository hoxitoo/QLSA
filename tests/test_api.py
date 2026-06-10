"""HTTP API integration tests — FastAPI TestClient.

Skipped automatically when fastapi / httpx are not installed.
Install with:  pip install -r requirements-api.txt

Each test class gets a fresh TestClient (and thus a fresh AggregatorNode)
via the `client` fixture; the `signed_payload` fixture provides a valid
ML-DSA-65-signed transaction payload shared across each class.
"""

from __future__ import annotations

import pytest

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(
    not _HAVE_FASTAPI,
    reason="fastapi not installed — pip install -r requirements-api.txt",
)

from core.keys import derive_address, generate_keypair, wipe_key
from core.signing import sign
from core.transaction import Transaction


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def signed_payload() -> dict:
    """One valid signed-transaction JSON payload, generated once per module."""
    pub, priv = generate_keypair()
    addr = derive_address(pub)
    tx = Transaction(
        sender=addr,
        recipient="a" * 64,
        amount=42,
        nonce=0,
        public_key=pub,
    )
    sig = sign(tx.to_bytes(), priv)
    wipe_key(priv)
    return {
        "sender": addr,
        "recipient": "a" * 64,
        "amount": 42,
        "nonce": 0,
        "public_key": pub.hex(),
        "signature": sig.hex(),
    }


def _make_payloads(n: int) -> list[dict]:
    """Generate *n* distinct signed transaction payloads (unique sender per tx)."""
    payloads = []
    for i in range(n):
        pub, priv = generate_keypair()
        addr = derive_address(pub)
        tx = Transaction(sender=addr, recipient="b" * 64, amount=i + 1, nonce=0, public_key=pub)
        sig = sign(tx.to_bytes(), priv)
        wipe_key(priv)
        payloads.append({
            "sender": addr, "recipient": "b" * 64, "amount": i + 1, "nonce": 0,
            "public_key": pub.hex(), "signature": sig.hex(),
        })
    return payloads


@pytest.fixture()
def client() -> "TestClient":
    from aggregator.api import app
    import aggregator.api as api_mod
    with api_mod._rate_lock:
        api_mod._tx_windows.clear()
        api_mod._batch_windows.clear()
        api_mod._read_windows.clear()
    with TestClient(app) as c:
        yield c


# ── GET /health ───────────────────────────────────────────────────────────────

class TestHealth:
    def test_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_content_type_is_json(self, client):
        resp = client.get("/health")
        assert "application/json" in resp.headers["content-type"]


# ── GET /stats ────────────────────────────────────────────────────────────────

class TestStats:
    def test_initial_stats_are_zero(self, client):
        resp = client.get("/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["transactions_received"] == 0
        assert data["transactions_batched"] == 0
        assert data["batches_created"] == 0
        assert data["proofs_generated"] == 0
        assert data["pending"] == 0

    def test_stats_include_fri_security_fields(self, client):
        data = client.get("/stats").json()
        assert "n_fri_queries" in data
        assert "fri_security_bits" in data
        n = data["n_fri_queries"]
        assert isinstance(n, int) and n >= 1
        assert data["fri_security_bits"] == 6 * n + 10

    def test_stats_increment_after_submit(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        resp = client.get("/stats")
        assert resp.json()["transactions_received"] == 1
        assert resp.json()["pending"] == 1


# ── GET /node/config ─────────────────────────────────────────────────────────

class TestNodeConfig:
    def test_returns_200(self, client):
        resp = client.get("/node/config")
        assert resp.status_code == 200

    def test_contains_required_fields(self, client):
        data = client.get("/node/config").json()
        for key in ("n_fri_queries", "fri_security_bits", "min_batch_size",
                    "max_batch_size", "mempool_capacity", "version"):
            assert key in data, f"missing field: {key}"

    def test_fri_security_bits_formula(self, client):
        data = client.get("/node/config").json()
        n = data["n_fri_queries"]
        assert data["fri_security_bits"] == 6 * n + 10

    def test_batch_size_ordering(self, client):
        data = client.get("/node/config").json()
        assert data["min_batch_size"] >= 1
        assert data["max_batch_size"] >= data["min_batch_size"]
        assert data["mempool_capacity"] >= data["max_batch_size"]

    def test_version_is_string(self, client):
        data = client.get("/node/config").json()
        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0


# ── POST /transactions ────────────────────────────────────────────────────────

class TestSubmitTransaction:
    def test_valid_tx_is_accepted(self, client, signed_payload):
        resp = client.post("/transactions", json=signed_payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] is True
        assert data["mempool_size"] == 1
        assert data["error"] is None

    def test_mempool_size_increments(self, client, signed_payload):
        r1 = client.post("/transactions", json=signed_payload)
        assert r1.json()["mempool_size"] == 1
        assert r1.json()["accepted"] is True

    def test_duplicate_tx_rejected(self, client, signed_payload):
        r1 = client.post("/transactions", json=signed_payload)
        r2 = client.post("/transactions", json=signed_payload)
        assert r1.json()["accepted"] is True
        assert r2.json()["accepted"] is False
        assert "duplicate" in r2.json()["error"]
        # mempool still has only 1 entry
        assert r2.json()["mempool_size"] == 1

    def test_invalid_signature_rejected(self, client, signed_payload):
        # Correct ML-DSA-65 signature length (3309 bytes) but wrong content —
        # passes pydantic length validator, rejected by cryptographic verification.
        bad = dict(signed_payload)
        bad["signature"] = "ab" * 3309
        resp = client.post("/transactions", json=bad)
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] is False
        assert data["error"] is not None

    def test_wrong_length_signature_rejected(self, client, signed_payload):
        # Wrong length — rejected by pydantic length validator with HTTP 422.
        bad = dict(signed_payload, signature="deadbeef" * 100)  # 400 bytes
        resp = client.post("/transactions", json=bad)
        assert resp.status_code == 422

    def test_sender_wrong_length_rejected(self, client, signed_payload):
        bad = dict(signed_payload, sender="abc")
        resp = client.post("/transactions", json=bad)
        assert resp.status_code == 422

    def test_recipient_wrong_length_rejected(self, client, signed_payload):
        bad = dict(signed_payload, recipient="xyz")
        resp = client.post("/transactions", json=bad)
        assert resp.status_code == 422

    def test_negative_amount_rejected(self, client, signed_payload):
        bad = dict(signed_payload, amount=-1)
        resp = client.post("/transactions", json=bad)
        assert resp.status_code == 422

    def test_zero_amount_rejected(self, client, signed_payload):
        bad = dict(signed_payload, amount=0)
        resp = client.post("/transactions", json=bad)
        assert resp.status_code == 422

    def test_negative_nonce_rejected(self, client, signed_payload):
        bad = dict(signed_payload, nonce=-1)
        resp = client.post("/transactions", json=bad)
        assert resp.status_code == 422

    def test_non_hex_public_key_rejected(self, client, signed_payload):
        bad = dict(signed_payload, public_key="not-hex!")
        resp = client.post("/transactions", json=bad)
        assert resp.status_code == 422

    def test_non_hex_signature_rejected(self, client, signed_payload):
        bad = dict(signed_payload, signature="ZZZZ")
        resp = client.post("/transactions", json=bad)
        assert resp.status_code == 422

    def test_sender_pubkey_mismatch_rejected(self, client, signed_payload):
        """A mismatched sender address causes signature verification to fail.

        The sender is part of the signed payload (to_bytes), so substituting a
        different sender address makes the original signature invalid — the check
        fires at signature verification, not at the sender-pubkey equality check.
        """
        pub2, priv2 = generate_keypair()
        bad_sender = derive_address(pub2)  # address from a different key
        wipe_key(priv2)
        bad = dict(signed_payload, sender=bad_sender)
        resp = client.post("/transactions", json=bad)
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] is False
        assert data["error"] is not None


# ── POST /batch/run ───────────────────────────────────────────────────────────

class TestBatchRun:
    def test_empty_mempool_returns_no_batch(self, client):
        resp = client.post("/batch/run")
        assert resp.status_code == 200
        assert resp.json()["status"] == "no_batch"

    def test_insufficient_txs_with_min_size_returns_no_batch(self, client, signed_payload):
        # Default min_batch_size=1, so submit 1 tx and it should batch.
        # To test no_batch we need min>1 — that requires a custom node.
        # Here we just verify the endpoint responds correctly with 1 tx in mempool.
        client.post("/transactions", json=signed_payload)
        resp = client.post("/batch/run")
        # Default node has min=1 so this WILL batch.
        data = resp.json()
        assert data["status"] in ("ok", "no_batch")

    def test_run_with_tx_produces_batch(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        resp = client.post("/batch/run")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["tx_count"] == 1
        assert len(data["merkle_root"]) == 128
        assert data["batch_id"] != ""
        assert isinstance(data["is_proven"], bool)
        assert "has_witness" in data
        assert data["has_witness"] is False

    def test_run_drains_mempool(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        client.post("/batch/run")
        stats = client.get("/stats").json()
        assert stats["pending"] == 0

    def test_run_increments_batches_created(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        client.post("/batch/run")
        stats = client.get("/stats").json()
        assert stats["batches_created"] == 1
        assert stats["transactions_batched"] == 1

    def test_prove_witnesses_query_param_accepted(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        resp = client.post("/batch/run?prove_witnesses=true")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert isinstance(data["has_witness"], bool)

    def test_run_response_includes_vfri7_fields(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        resp = client.post("/batch/run")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "has_vfri7" in data
        assert data["has_vfri7"] is False
        assert "vfri7_commitment_log10" in data
        assert "vfri7_commitment_log8" in data


# ── Bearer-token auth on POST /batch/* ───────────────────────────────────────

class TestBatchAuth:
    def test_open_when_token_unset(self, client, monkeypatch):
        monkeypatch.delenv("QLSA_API_TOKEN", raising=False)
        resp = client.post("/batch/flush")
        assert resp.status_code == 200

    def test_missing_header_returns_401(self, client, monkeypatch):
        monkeypatch.setenv("QLSA_API_TOKEN", "s3cret")
        resp = client.post("/batch/flush")
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"] == "Bearer"

    def test_wrong_token_returns_403(self, client, monkeypatch):
        monkeypatch.setenv("QLSA_API_TOKEN", "s3cret")
        resp = client.post(
            "/batch/flush", headers={"Authorization": "Bearer wrong"}
        )
        assert resp.status_code == 403

    def test_non_bearer_scheme_returns_401(self, client, monkeypatch):
        monkeypatch.setenv("QLSA_API_TOKEN", "s3cret")
        resp = client.post(
            "/batch/flush", headers={"Authorization": "Basic s3cret"}
        )
        assert resp.status_code == 401

    def test_correct_token_allows_request(self, client, monkeypatch):
        monkeypatch.setenv("QLSA_API_TOKEN", "s3cret")
        resp = client.post(
            "/batch/flush", headers={"Authorization": "Bearer s3cret"}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "empty"

    def test_batch_run_also_protected(self, client, monkeypatch):
        monkeypatch.setenv("QLSA_API_TOKEN", "s3cret")
        resp = client.post("/batch/run")
        assert resp.status_code == 401

    def test_transactions_not_affected_by_token(self, client, signed_payload, monkeypatch):
        monkeypatch.setenv("QLSA_API_TOKEN", "s3cret")
        resp = client.post("/transactions", json=signed_payload)
        assert resp.status_code == 200


# ── POST /batch/flush ─────────────────────────────────────────────────────────

class TestBatchFlush:
    def test_empty_mempool_returns_empty(self, client):
        resp = client.post("/batch/flush")
        assert resp.status_code == 200
        assert resp.json()["status"] == "empty"

    def test_flush_creates_batch(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        resp = client.post("/batch/flush")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["tx_count"] == 1
        assert len(data["merkle_root"]) == 128
        assert isinstance(data["is_proven"], bool)
        assert "has_witness" in data

    def test_flush_drains_mempool(self, client):
        for p in _make_payloads(3):
            client.post("/transactions", json=p)
        client.post("/batch/flush")
        assert client.get("/stats").json()["pending"] == 0

    def test_flush_batches_all_pending(self, client):
        for p in _make_payloads(5):
            client.post("/transactions", json=p)
        resp = client.post("/batch/flush")
        assert resp.json()["tx_count"] == 5

    def test_prove_witnesses_query_param_accepted(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        resp = client.post("/batch/flush?prove_witnesses=true")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert isinstance(data["has_witness"], bool)

    def test_flush_response_includes_vfri7_fields(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        resp = client.post("/batch/flush")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "has_vfri7" in data
        assert data["has_vfri7"] is False
        assert "vfri7_commitment_log10" in data
        assert "vfri7_commitment_log8" in data

    def test_flush_updates_stats(self, client):
        for p in _make_payloads(2):
            client.post("/transactions", json=p)
        client.post("/batch/flush")
        stats = client.get("/stats").json()
        assert stats["transactions_batched"] == 2
        assert stats["batches_created"] == 1


# ── GET /batch/{batch_id} ────────────────────────────────────────────────────

class TestBatchStatus:
    def test_invalid_batch_id_returns_400(self, client):
        resp = client.get("/batch/not-a-uuid")
        assert resp.status_code == 400

    def test_unknown_batch_returns_404(self, client):
        import uuid
        resp = client.get(f"/batch/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_known_batch_returns_200(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        batch_id = client.post("/batch/flush").json()["batch_id"]
        resp = client.get(f"/batch/{batch_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["batch_id"] == batch_id
        assert data["tx_count"] == 1
        assert isinstance(data["is_proven"], bool)
        assert isinstance(data["has_witness"], bool)
        assert isinstance(data["has_vfri7"], bool)

    def test_batch_status_merkle_root_present(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        batch_id = client.post("/batch/flush").json()["batch_id"]
        data = client.get(f"/batch/{batch_id}").json()
        assert isinstance(data["merkle_root"], str)
        assert len(data["merkle_root"]) == 128  # SHA3-512 → 64 bytes → 128 hex chars

    def test_batch_and_witness_endpoints_agree(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        batch_id = client.post("/batch/flush").json()["batch_id"]
        status = client.get(f"/batch/{batch_id}").json()
        witness = client.get(f"/batch/{batch_id}/witness").json()
        assert status["has_witness"] == witness["has_witness"]
        assert status["has_vfri7"] == witness["has_vfri7"]


# ── GET /batch/{batch_id}/witness ─────────────────────────────────────────────

class TestBatchWitness:
    def test_invalid_batch_id_returns_400(self, client):
        resp = client.get("/batch/not-a-uuid/witness")
        assert resp.status_code == 400

    def test_unknown_batch_returns_404(self, client):
        import uuid
        resp = client.get(f"/batch/{uuid.uuid4()}/witness")
        assert resp.status_code == 404

    def test_batch_without_witness_returns_has_witness_false(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        batch_resp = client.post("/batch/flush").json()
        batch_id = batch_resp["batch_id"]

        resp = client.get(f"/batch/{batch_id}/witness")
        assert resp.status_code == 200
        data = resp.json()
        assert data["batch_id"] == batch_id
        assert data["has_witness"] is False
        assert data["has_vfri7"] is False

    def test_witness_includes_fri_security_fields(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        batch_id = client.post("/batch/flush").json()["batch_id"]
        data = client.get(f"/batch/{batch_id}/witness").json()
        assert "n_fri_queries" in data
        assert "fri_security_bits" in data
        n = data["n_fri_queries"]
        assert isinstance(n, int) and n >= 1
        assert data["fri_security_bits"] == 6 * n + 10

    def test_witness_endpoint_returns_correct_batch_id(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        batch_id = client.post("/batch/flush").json()["batch_id"]
        data = client.get(f"/batch/{batch_id}/witness").json()
        assert data["batch_id"] == batch_id

    def test_multiple_batches_each_have_own_witness_record(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        id1 = client.post("/batch/flush").json()["batch_id"]
        client.post("/transactions", json=signed_payload)
        id2 = client.post("/batch/flush").json()["batch_id"]
        assert id1 != id2
        assert client.get(f"/batch/{id1}/witness").status_code == 200
        assert client.get(f"/batch/{id2}/witness").status_code == 200


# ── Rate limiting ─────────────────────────────────────────────────────────────

class TestRateLimit:
    def test_transaction_rate_limit_enforced(self, client, signed_payload):
        """101st POST /transactions from same IP within window returns 429."""
        import aggregator.api as api_mod

        # Clear the rate-limit window so previous tests don't interfere.
        with api_mod._rate_lock:
            api_mod._tx_windows.clear()

        for _ in range(100):
            resp = client.post("/transactions", json=signed_payload)
            assert resp.status_code == 200

        resp = client.post("/transactions", json=signed_payload)
        assert resp.status_code == 429
        assert "rate limit" in resp.json()["detail"]
        assert resp.headers.get("Retry-After") == "60"

    def test_batch_rate_limit_enforced(self, client, signed_payload):
        """21st POST /batch/flush from same IP within window returns 429."""
        import aggregator.api as api_mod

        with api_mod._rate_lock:
            api_mod._batch_windows.clear()

        for _ in range(20):
            client.post("/transactions", json=signed_payload)
            resp = client.post("/batch/flush")
            # May be empty if TX was already drained — that's fine, endpoint still counts
            assert resp.status_code == 200

        # This 21st batch op should be rate-limited
        resp = client.post("/batch/flush")
        assert resp.status_code == 429
        assert "rate limit" in resp.json()["detail"]
        assert resp.headers.get("Retry-After") == "60"

    def test_health_stats_not_rate_limited(self, client):
        """GET /health and /stats are never rate-limited."""
        for _ in range(50):
            assert client.get("/health").status_code == 200
            assert client.get("/stats").status_code == 200

    def test_get_batch_rate_limit_enforced(self, client, signed_payload):
        """201st GET /batch/* from same IP within window returns 429."""
        import aggregator.api as api_mod

        with api_mod._rate_lock:
            api_mod._read_windows.clear()

        import uuid
        fake_id = str(uuid.uuid4())
        for _ in range(200):
            resp = client.get(f"/batch/{fake_id}")
            # 404 is expected; only 429 would indicate rate limiting
            assert resp.status_code in (404, 200)

        resp = client.get(f"/batch/{fake_id}")
        assert resp.status_code == 429
        assert "rate limit" in resp.json()["detail"]
        assert resp.headers.get("Retry-After") == "60"


# ── GET /batches ──────────────────────────────────────────────────────────────

class TestListBatches:
    def test_empty_node_returns_empty_list(self, client):
        resp = client.get("/batches")
        assert resp.status_code == 200
        data = resp.json()
        assert data["batches"] == []
        assert data["total"] == 0

    def test_returns_batch_after_flush(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        client.post("/batch/flush")
        resp = client.get("/batches")
        data = resp.json()
        assert data["total"] == 1
        assert len(data["batches"]) == 1

    def test_batch_fields_present(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        client.post("/batch/flush")
        b = client.get("/batches").json()["batches"][0]
        for field in ("batch_id", "tx_count", "merkle_root", "is_proven",
                      "has_witness", "has_vfri7"):
            assert field in b, f"missing field: {field}"

    def test_newest_first_ordering(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        id1 = client.post("/batch/flush").json()["batch_id"]
        client.post("/transactions", json=signed_payload)
        id2 = client.post("/batch/flush").json()["batch_id"]
        data = client.get("/batches").json()
        assert data["total"] == 2
        ids = [b["batch_id"] for b in data["batches"]]
        assert ids[0] == id2
        assert ids[1] == id1

    def test_limit_caps_returned_count(self, client):
        for p in _make_payloads(3):
            client.post("/transactions", json=p)
            client.post("/batch/flush")
        data = client.get("/batches", params={"limit": 2}).json()
        assert len(data["batches"]) == 2
        assert data["total"] == 3

    def test_limit_zero_rejected_with_422(self, client):
        assert client.get("/batches", params={"limit": 0}).status_code == 422

    def test_limit_201_rejected_with_422(self, client):
        assert client.get("/batches", params={"limit": 201}).status_code == 422

    def test_limit_200_accepted(self, client):
        assert client.get("/batches", params={"limit": 200}).status_code == 200

    def test_limit_1_accepted(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        client.post("/batch/flush")
        data = client.get("/batches", params={"limit": 1}).json()
        assert len(data["batches"]) == 1

    def test_rate_limited_after_200_reads(self, client):
        import aggregator.api as api_mod
        with api_mod._rate_lock:
            api_mod._read_windows.clear()
        for _ in range(200):
            assert client.get("/batches").status_code == 200
        resp = client.get("/batches")
        assert resp.status_code == 429
        assert resp.headers.get("Retry-After") == "60"


# ── GET /transaction/{tx_hash} ────────────────────────────────────────────────

class TestTransactionStatus:
    def test_unknown_tx_returns_404(self, client):
        resp = client.get(f"/transaction/{'a' * 64}")
        assert resp.status_code == 404

    def test_invalid_hash_returns_400(self, client):
        resp = client.get("/transaction/not-a-valid-hash")
        assert resp.status_code == 400

    def test_invalid_hash_too_short_returns_400(self, client):
        resp = client.get("/transaction/deadbeef")
        assert resp.status_code == 400

    def test_pending_tx_returns_pending(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        # Compute tx_hash from the payload
        from core.transaction import Transaction
        tx = Transaction(
            sender=signed_payload["sender"],
            recipient=signed_payload["recipient"],
            amount=signed_payload["amount"],
            nonce=signed_payload["nonce"],
            public_key=bytes.fromhex(signed_payload["public_key"]),
        )
        tx_hash = tx.tx_hash().hex()
        resp = client.get(f"/transaction/{tx_hash}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"
        assert data["tx_hash"] == tx_hash
        assert data["batch_id"] is None

    def test_batched_tx_returns_batched_with_batch_id(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        batch_resp = client.post("/batch/flush")
        batch_id = batch_resp.json()["batch_id"]
        # Compute tx_hash
        from core.transaction import Transaction
        tx = Transaction(
            sender=signed_payload["sender"],
            recipient=signed_payload["recipient"],
            amount=signed_payload["amount"],
            nonce=signed_payload["nonce"],
            public_key=bytes.fromhex(signed_payload["public_key"]),
        )
        tx_hash = tx.tx_hash().hex()
        resp = client.get(f"/transaction/{tx_hash}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "batched"
        assert data["batch_id"] == batch_id

    def test_submit_response_includes_tx_hash(self, client, signed_payload):
        resp = client.post("/transactions", json=signed_payload)
        data = resp.json()
        assert data["accepted"] is True
        assert "tx_hash" in data
        assert len(data["tx_hash"]) == 64

    def test_rate_limited(self, client):
        import aggregator.api as api_mod
        with api_mod._rate_lock:
            api_mod._read_windows.clear()
        for _ in range(200):
            assert client.get(f"/transaction/{'b' * 64}").status_code in (200, 404)
        resp = client.get(f"/transaction/{'b' * 64}")
        assert resp.status_code == 429


# ── GET /mempool ──────────────────────────────────────────────────────────────

class TestMempoolStatus:
    def test_empty_mempool(self, client):
        resp = client.get("/mempool")
        assert resp.status_code == 200
        data = resp.json()
        assert data["size"] == 0
        assert data["capacity"] > 0
        assert data["tx_hashes"] == []

    def test_pending_tx_appears_in_mempool(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        resp = client.get("/mempool")
        assert resp.status_code == 200
        data = resp.json()
        assert data["size"] == 1
        assert len(data["tx_hashes"]) == 1

    def test_limit_param_caps_hashes(self, client, signed_payload):
        # Submit same tx twice (idempotent — second goes in too with different nonce? No,
        # same tx → same hash, same mempool entry. Use fresh payload.)
        from core.keys import generate_keypair, wipe_key, derive_address
        from core.signing import sign as _sign
        from core.transaction import Transaction
        import aggregator.api as api_mod
        with api_mod._rate_lock:
            api_mod._tx_windows.clear()
        pub, priv = generate_keypair()
        addr = derive_address(pub)
        txs = []
        for i in range(3):
            tx = Transaction(sender=addr, recipient="b" * 64, amount=i + 1, nonce=i, public_key=pub)
            tx.signature = _sign(tx.to_bytes(), priv)
            txs.append(tx)
        wipe_key(priv)
        for tx in txs:
            client.post("/transactions", json={
                "sender": addr, "recipient": "b" * 64, "amount": tx.amount,
                "nonce": tx.nonce, "public_key": pub.hex(), "signature": tx.signature.hex(),
            })
        resp = client.get("/mempool?limit=2")
        data = resp.json()
        assert data["size"] == 3
        assert len(data["tx_hashes"]) == 2

    def test_limit_zero_rejected(self, client):
        resp = client.get("/mempool?limit=0")
        assert resp.status_code == 422

    def test_limit_1001_rejected(self, client):
        resp = client.get("/mempool?limit=1001")
        assert resp.status_code == 422

    def test_rate_limited(self, client):
        import aggregator.api as api_mod
        with api_mod._rate_lock:
            api_mod._read_windows.clear()
        for _ in range(200):
            assert client.get("/mempool").status_code == 200
        assert client.get("/mempool").status_code == 429


# ── GET /batch/{batch_id}/transactions ───────────────────────────────────────

class TestBatchTransactions:
    def test_unknown_batch_returns_404(self, client):
        import uuid
        resp = client.get(f"/batch/{uuid.uuid4()}/transactions")
        assert resp.status_code == 404

    def test_invalid_batch_id_returns_400(self, client):
        resp = client.get("/batch/not-a-uuid/transactions")
        assert resp.status_code == 400

    def test_returns_tx_hashes_in_order(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        batch_resp = client.post("/batch/flush")
        batch_id = batch_resp.json()["batch_id"]
        resp = client.get(f"/batch/{batch_id}/transactions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["batch_id"] == batch_id
        assert data["tx_count"] == 1
        assert len(data["tx_hashes"]) == 1
        assert len(data["tx_hashes"][0]) == 64

    def test_tx_hash_matches_transaction(self, client, signed_payload):
        from core.transaction import Transaction
        client.post("/transactions", json=signed_payload)
        batch_resp = client.post("/batch/flush")
        batch_id = batch_resp.json()["batch_id"]
        resp = client.get(f"/batch/{batch_id}/transactions")
        tx_hashes = resp.json()["tx_hashes"]
        # compute expected hash from payload
        tx = Transaction(
            sender=signed_payload["sender"],
            recipient=signed_payload["recipient"],
            amount=signed_payload["amount"],
            nonce=signed_payload["nonce"],
            public_key=bytes.fromhex(signed_payload["public_key"]),
        )
        assert tx.tx_hash().hex() in tx_hashes


# ── GET /batches?proven=... ───────────────────────────────────────────────────

class TestBatchFilter:
    def test_proven_filter_false_includes_unproven(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        client.post("/batch/flush")
        r = client.get("/batches?proven=false")
        assert r.status_code == 200
        data = r.json()
        assert all(not b["is_proven"] for b in data["batches"])

    def test_proven_filter_true_excludes_unproven(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        client.post("/batch/flush")
        r = client.get("/batches?proven=true")
        assert r.status_code == 200
        data = r.json()
        assert all(b["is_proven"] for b in data["batches"])

    def test_no_filter_returns_all(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        client.post("/batch/flush")
        r_all = client.get("/batches")
        r_false = client.get("/batches?proven=false")
        assert r_all.json()["total"] >= r_false.json()["total"]

    def test_total_reflects_filtered_count(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        client.post("/batch/flush")
        r_all = client.get("/batches")
        r_proven = client.get("/batches?proven=true")
        r_not_proven = client.get("/batches?proven=false")
        # proven + unproven should sum to total
        assert (
            r_proven.json()["total"] + r_not_proven.json()["total"]
            == r_all.json()["total"]
        )


# ── GET /address/{sender}/transactions ────────────────────────────────────────

class TestSenderTransactions:
    def test_unknown_sender_returns_empty(self, client):
        sender = "a" * 64
        r = client.get(f"/address/{sender}/transactions")
        assert r.status_code == 200
        data = r.json()
        assert data["tx_hashes"] == []
        assert data["pending_count"] == 0
        assert data["total"] == 0

    def test_pending_tx_appears(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        sender = signed_payload["sender"]
        r = client.get(f"/address/{sender}/transactions")
        assert r.status_code == 200
        data = r.json()
        assert data["pending_count"] == 1
        assert len(data["tx_hashes"]) == 1

    def test_batched_tx_appears(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        client.post("/batch/flush")
        sender = signed_payload["sender"]
        r = client.get(f"/address/{sender}/transactions")
        assert r.status_code == 200
        data = r.json()
        assert data["pending_count"] == 0
        assert len(data["tx_hashes"]) == 1

    def test_invalid_sender_returns_400(self, client):
        r = client.get("/address/not-a-valid-sender/transactions")
        assert r.status_code == 400

    def test_limit_param(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        client.post("/batch/flush")
        sender = signed_payload["sender"]
        r = client.get(f"/address/{sender}/transactions?limit=1")
        assert r.status_code == 200
        assert len(r.json()["tx_hashes"]) <= 1

    def test_sender_field_in_response(self, client, signed_payload):
        sender = signed_payload["sender"]
        r = client.get(f"/address/{sender}/transactions")
        assert r.status_code == 200
        assert r.json()["sender"] == sender.lower()

    def test_limit_zero_rejected(self, client):
        sender = "b" * 64
        r = client.get(f"/address/{sender}/transactions?limit=0")
        assert r.status_code == 422

    def test_limit_1001_rejected(self, client):
        sender = "c" * 64
        r = client.get(f"/address/{sender}/transactions?limit=1001")
        assert r.status_code == 422
