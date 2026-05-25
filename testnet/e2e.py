#!/usr/bin/env python3
"""
QLSA Phase 6 — End-to-End Testnet Demo (MVP-5 VFRI7)

Flow:
  1. Generate N ML-DSA-65 keypairs (ephemeral)
  2. Create and sign N transactions
  3. Build a Batch (Merkle tree, signature verification)
  4. Generate VFRI7 cross-bound STARK proofs for tx[0] via Stwo prover
     (LOG=10 + LOG=8 groups bound to each other's trace commitments)
  5. Submit to BatchRegistryV4 on the configured testnet
  6. Verify on-chain finalization

Prerequisites:
  pip install -r requirements.txt -r requirements-api.txt -r requirements-testnet.txt
  cd stark_stwo && maturin develop --features python --release

Environment (.env):
  RPC_URL              — L2 RPC endpoint (e.g. Polygon zkEVM Cardona)
  DEPLOYER_PRIVATE_KEY — 0x-prefixed deployer private key
  REGISTRY_ADDRESS     — deployed BatchRegistryV4 address

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
    prove_mldsa_sig_vfri7_stark,
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

    # ── Step 4: Generate VFRI7 cross-bound ML-DSA V23 proofs for tx[0] ─────────
    # Prove the full V23 ML-DSA-65 arithmetic witness for tx[0]'s signature and
    # generate cross-bound VFRI7 hints for both LOG=10 (NttBatch+InttBatch, 1298 cols)
    # and LOG=8 (AzFull+Ct1Full+RangeQBatch+WPrime+NormCheck+UseHint, 2206 cols) groups.
    # The cross-bound roots bind each group's FRI query indices to the other group's
    # trace commitment, preventing adversarial proof mixing.
    logger.info("Generating VFRI7 cross-bound V23 ML-DSA STARK proofs for tx[0]…")
    tx0 = txs[0]
    batch_merkle_root = batch.merkle_root[:32]
    t0 = time.monotonic()
    try:
        vfri7_result = prove_mldsa_sig_vfri7_stark(
            pk=tx0.public_key,
            msg=tx0.to_bytes(),
            sig=tx0.signature,
            batch_merkle_root=batch_merkle_root,
            n_queries=1,
        )
        elapsed_v = time.monotonic() - t0
        logger.info(
            "  log10: proof=%d B commit=%s hints=%d B | "
            "log8: proof=%d B commit=%s hints=%d B (%.2fs)",
            len(vfri7_result.log10_proof),
            vfri7_result.log10_commitment,
            len(vfri7_result.log10_query_hints),
            len(vfri7_result.log8_proof),
            vfri7_result.log8_commitment,
            len(vfri7_result.log8_query_hints),
            elapsed_v,
        )
    except ValueError as exc:
        logger.error("ML-DSA signature invalid or witness extraction failed: %s", exc)
        return 1
    except RuntimeError as exc:
        logger.error("VFRI7 proof generation failed: %s", exc)
        return 1

    if dry_run:
        logger.info("[DRY-RUN] Skipping on-chain submission.")
        logger.info("To submit, set RPC_URL, DEPLOYER_PRIVATE_KEY, REGISTRY_ADDRESS in .env")
        logger.info("  REGISTRY_ADDRESS should point to a deployed BatchRegistryV4 contract.")
        logger.info("=== DRY-RUN COMPLETE ===")
        return 0

    # ── Step 5: Submit on-chain ───────────────────────────────────────────────
    try:
        from testnet.submit import OnchainSubmitterV4
        submitter = OnchainSubmitterV4.from_env()
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

    logger.info("Submitting batch to BatchRegistryV4 (VFRI7 cross-bound proofs + nonces)…")
    t0 = time.monotonic()
    tx_hash = submitter.submit_batch_with_nonces(
        merkle_root=batch_merkle_root,
        commitment_log10=vfri7_result.log10_commitment,
        proof_log10=vfri7_result.log10_proof,
        hints_log10=vfri7_result.log10_query_hints,
        commitment_log8=vfri7_result.log8_commitment,
        proof_log8=vfri7_result.log8_proof,
        hints_log8=vfri7_result.log8_query_hints,
        senders=list(sender_nonces.keys()),
        new_nonces=list(sender_nonces.values()),
    )
    logger.info("  tx_hash=%s (%.2fs)", tx_hash, time.monotonic() - t0)

    # ── Step 6: Verify on-chain ───────────────────────────────────────────────
    logger.info("Waiting for confirmation and verifying finalization…")
    t0 = time.monotonic()
    finalized = submitter.wait_and_verify(tx_hash, batch_merkle_root)
    if not finalized:
        logger.error("Batch NOT finalized on-chain after tx confirmed — unexpected state")
        return 1

    logger.info("  finalized=True (%.2fs)", time.monotonic() - t0)
    logger.info("=== E2E COMPLETE — batch finalized on testnet (VFRI7 cross-bound) ===")
    return 0


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="QLSA Phase 6 E2E demo")
    p.add_argument("--txs", type=int, default=8, help="Number of transactions (default: 8)")
    p.add_argument("--dry-run", action="store_true", help="Skip on-chain submission")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    sys.exit(run(n_txs=args.txs, dry_run=args.dry_run))
