#!/usr/bin/env python3
"""
QLSA Phase 6 — End-to-End Testnet Demo

Flow:
  1. Generate N ML-DSA-65 keypairs (ephemeral)
  2. Create and sign N transactions
  3. Build a Batch (Merkle tree, signature verification)
  4. Generate a Circle STARK proof via the Stwo prover
  5. Submit to BatchRegistryV2 on the configured testnet
  6. Verify on-chain finalization

Prerequisites:
  pip install -r requirements.txt -r requirements-api.txt -r requirements-testnet.txt
  cd stark_stwo && cargo +nightly-2025-07-01 build --release

Environment (.env):
  RPC_URL             — L2 RPC endpoint (e.g. Polygon zkEVM Cardona)
  DEPLOYER_PRIVATE_KEY — 0x-prefixed deployer private key
  REGISTRY_ADDRESS    — deployed BatchRegistryV2 address

Usage:
  python -m testnet.e2e [--txs N] [--dry-run]
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
import time
from pathlib import Path

# Load .env before any other imports that read env vars.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass  # python-dotenv is optional; env vars may already be set

from core.batch import create_batch
from core.keys import generate_keypair, derive_address, wipe_key
from core.signing import sign
from core.transaction import Transaction
from stark.prover import (
    prove_batch,
    prove_mldsa_sig_witness_stark,
    verify_mldsa_witness_stark,
    verify_mldsa_hash_check,
    NORM_BOUND,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("qlsa.e2e")


def _make_transactions(n: int) -> list[Transaction]:
    """Generate n signed transactions with fresh ML-DSA-65 keypairs."""
    txs: list[Transaction] = []
    for i in range(n):
        pk, sk = generate_keypair()
        addr_sender = derive_address(pk)
        addr_recipient = derive_address(pk)  # self-transfer for demo
        tx = Transaction(
            sender=addr_sender,
            recipient=addr_recipient,
            amount=1000 + i,
            nonce=i,
            public_key=pk,
        )
        tx.signature = sign(tx.to_bytes(), sk)
        wipe_key(sk)
        txs.append(tx)
        logger.info("  tx[%02d] sender=%s…", i, addr_sender[:16])
    return txs


def run(n_txs: int = 8, dry_run: bool = False) -> int:
    """Run the full E2E flow. Returns exit code (0 = success)."""
    logger.info("=== QLSA Phase 6 — E2E Testnet Demo ===")
    logger.info("Transactions: %d | Dry-run: %s", n_txs, dry_run)

    # ── Step 1: Check PyO3 extension ─────────────────────────────────────────
    try:
        import qlsa_stark_stwo  # noqa: F401
    except ImportError:
        logger.error(
            "PyO3 extension not installed. Build it with:\n"
            "  cd stark_stwo && maturin develop --features python --release"
        )
        return 1
    logger.info("STARK extension: OK")

    # ── Step 2: Generate keypairs + signed transactions ───────────────────────
    logger.info("Generating %d keypairs and signed transactions…", n_txs)
    t0 = time.monotonic()
    txs = _make_transactions(n_txs)
    logger.info("  done in %.2fs", time.monotonic() - t0)

    # ── Step 3: Create batch ──────────────────────────────────────────────────
    logger.info("Building batch (Merkle tree + signature verification)…")
    t0 = time.monotonic()
    batch = create_batch(txs)
    logger.info(
        "  batch_id=%s txs=%d merkle_root=%s… (%.2fs)",
        batch.batch_id[:8],
        len(batch.transactions),
        batch.merkle_root.hex()[:16],
        time.monotonic() - t0,
    )

    # ── Step 4: Generate batch STARK proof ───────────────────────────────────
    logger.info("Generating Circle STARK proof (Stwo, LOG_BLOWUP=4)…")
    t0 = time.monotonic()
    proof_result = prove_batch(batch)
    elapsed = time.monotonic() - t0
    logger.info(
        "  proof_size=%d bytes | commitment=%s | log_size=%d | onchain_commitment=%s (%.2fs)",
        len(proof_result.proof),
        proof_result.commitment,
        proof_result.log_size,
        proof_result.onchain_commitment,
        elapsed,
    )

    # ── Step 4.5: ML-DSA arithmetic witness proof (MVP-3+) ────────────────────
    # Prove the full Az → c·t₁ → sub → norm_check → UseHint pipeline for the
    # first transaction's signature. This demonstrates that the signer's
    # ML-DSA-65 verification logic is correct and committed to the batch.
    logger.info("Proving ML-DSA-65 arithmetic witness for tx[0]…")
    tx0 = txs[0]
    t0 = time.monotonic()
    try:
        witness_result = prove_mldsa_sig_witness_stark(
            pk=tx0.public_key,
            msg=tx0.to_bytes(),
            sig=tx0.signature,
        )
        elapsed_w = time.monotonic() - t0
        norm_ok   = all(mn < NORM_BOUND for mn in witness_result.max_norms)
        valid_w   = verify_mldsa_witness_stark(witness_result)
        hash_ok   = verify_mldsa_hash_check(tx0.public_key, tx0.to_bytes(), witness_result)
        logger.info(
            "  witness_proof=%d bytes | norms_ok=%s | stark_ok=%s | hash_ok=%s"
            " | onchain_commitment=%s (%.2fs)",
            len(witness_result.proof_bundle),
            norm_ok,
            valid_w,
            hash_ok,
            witness_result.onchain_commitment,
            elapsed_w,
        )
        if not valid_w or not hash_ok:
            logger.error("ML-DSA witness proof or hash check failed — aborting")
            return 1
    except RuntimeError as exc:
        logger.error("ML-DSA witness proof failed: %s", exc)
        return 1

    if dry_run:
        logger.info("[DRY-RUN] Skipping on-chain submission.")
        logger.info("To submit, set RPC_URL, DEPLOYER_PRIVATE_KEY, REGISTRY_ADDRESS in .env")
        logger.info("=== DRY-RUN COMPLETE ===")
        return 0


    # ── Step 5: Submit on-chain ───────────────────────────────────────────────
    try:
        from testnet.submit import OnchainSubmitter
        submitter = OnchainSubmitter.from_env()
    except KeyError as exc:
        logger.error("Missing env var: %s — run with --dry-run or set .env", exc)
        return 1
    except RuntimeError as exc:
        logger.error("Cannot connect to RPC: %s", exc)
        return 1

    # Build per-sender nonce list: highest nonce in this batch for each unique sender.
    sender_nonces: dict[bytes, int] = {}
    for tx in txs:
        sender_key = hashlib.sha3_256(tx.public_key).digest()
        if tx.nonce > sender_nonces.get(sender_key, -1):
            sender_nonces[sender_key] = tx.nonce

    logger.info("Submitting batch to BatchRegistryV2 (with nonce replay protection)…")
    t0 = time.monotonic()
    tx_hash = submitter.submit_batch_with_nonces(
        merkle_root=batch.merkle_root,
        onchain_commitment=proof_result.onchain_commitment,
        proof_bytes=proof_result.proof,
        senders=list(sender_nonces.keys()),
        new_nonces=list(sender_nonces.values()),
    )
    logger.info("  tx_hash=%s (%.2fs)", tx_hash, time.monotonic() - t0)

    # ── Step 6: Verify on-chain ───────────────────────────────────────────────
    logger.info("Waiting for confirmation and verifying finalization…")
    t0 = time.monotonic()
    finalized = submitter.wait_and_verify(tx_hash, batch.merkle_root)
    if not finalized:
        logger.error("Batch NOT finalized on-chain after tx confirmed — unexpected state")
        return 1

    logger.info("  finalized=True (%.2fs)", time.monotonic() - t0)
    logger.info("=== E2E COMPLETE — batch finalized on testnet ===")
    return 0


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="QLSA Phase 6 E2E demo")
    p.add_argument("--txs", type=int, default=8, help="Number of transactions (default: 8)")
    p.add_argument("--dry-run", action="store_true", help="Skip on-chain submission")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    sys.exit(run(n_txs=args.txs, dry_run=args.dry_run))
