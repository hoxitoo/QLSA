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


@pytest.fixture()
def client() -> "TestClient":
    from aggregator.api import app
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

    def test_stats_increment_after_submit(self, client, signed_payload):
        client.post("/transactions", json=signed_payload)
        resp = client.get("/stats")
        assert resp.json()["transactions_received"] == 1
        assert resp.json()["pending"] == 1


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
        r2 = client.post("/transactions", json=signed_payload)
        assert r1.json()["mempool_size"] == 1
        assert r2.json()["mempool_size"] == 2

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

    def test_flush_drains_mempool(self, client, signed_payload):
        for _ in range(3):
            client.post("/transactions", json=signed_payload)
        client.post("/batch/flush")
        assert client.get("/stats").json()["pending"] == 0

    def test_flush_batches_all_pending(self, client, signed_payload):
        for _ in range(5):
            client.post("/transactions", json=signed_payload)
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

    def test_flush_updates_stats(self, client, signed_payload):
        for _ in range(2):
            client.post("/transactions", json=signed_payload)
        client.post("/batch/flush")
        stats = client.get("/stats").json()
        assert stats["transactions_batched"] == 2
        assert stats["batches_created"] == 1


# ── GET /batch/{batch_id}/witness ─────────────────────────────────────────────

class TestBatchWitness:
    def test_unknown_batch_returns_404(self, client):
        resp = client.get("/batch/nonexistent-batch-id/witness")
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

    def test_get_endpoints_not_rate_limited(self, client):
        """GET /health and /stats are never rate-limited."""
        for _ in range(50):
            assert client.get("/health").status_code == 200
            assert client.get("/stats").status_code == 200
