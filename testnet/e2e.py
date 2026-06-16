#!/usr/bin/env python3
"""
QLSA — End-to-End Testnet Demo (MVP-6 VFRI10 / MVP-5 VFRI7)

Flow:
  1. Generate N ML-DSA-65 keypairs (ephemeral)
  2. Create and sign N transactions
  3. Build a Batch (Merkle tree, signature verification)
  4. Generate cross-bound STARK proofs for tx[0] via Stwo prover
     (LOG=10 + LOG=8 groups bound to each other's trace commitments)
  5. Submit to the on-chain registry on the configured testnet
  6. Verify on-chain finalization

Two contract stacks are supported via --stack:
  v6 (default): QLSAVerifierVFRI10 + BatchRegistryV6 — Poseidon2 t=4 backend,
                per-group split (submitGroup10 then submitGroup8WithNonces, each
                verify ≤16.7M gas).  Uses num_folds=6 for the gas budget.
  v4:           QLSAVerifierVFRI7 + BatchRegistryV4 — single submitBatch (MVP-5).

Prerequisites:
  pip install -r requirements.txt -r requirements-api.txt -r requirements-testnet.txt
  cd stark_stwo && maturin develop --features python --release

Environment (.env):
  RPC_URL              — L2 RPC endpoint (e.g. Polygon zkEVM Cardona)
  DEPLOYER_PRIVATE_KEY — 0x-prefixed deployer private key
  REGISTRY_ADDRESS     — deployed registry address (V6 for --stack v6, V4 for v4)

Usage:
  python -m testnet.e2e [--stack v6|v4] [--txs N] [--dry-run]
"""

from __future__ import annotations

import argparse

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
    prove_mldsa_sig_vfri10_stark,
)

# VFRI10 (BatchRegistryV6) requires num_folds=6 so each t=4 group verify() fits
# within the ~16.7M per-tx gas cap (num_folds=3 overruns the LOG=10 group alone).
_VFRI10_NUM_FOLDS = 6

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


def run(n_txs: int = 8, dry_run: bool = False, n_queries: int = 1, stack: str = "v6") -> int:
    """Run the full E2E flow. Returns exit code (0 = success)."""
    if stack not in ("v4", "v6"):
        logger.error("unknown --stack %r (expected 'v6' or 'v4')", stack)
        return 1
    # Security: log_blowup(6) × n_queries + pow_bits(10)
    # n=1 → 16-bit (demo); n=3 → 28-bit; n=20 → 130-bit (but ~300M gas — not feasible on mainnet).
    security_bits = 6 * n_queries + 10
    stack_label = ("VFRI10 + BatchRegistryV6 (t=4, per-group split)" if stack == "v6"
                   else "VFRI7 + BatchRegistryV4 (single submitBatch)")
    logger.info("=== QLSA — E2E Testnet Demo ===")
    logger.info("Stack: %s", stack_label)
    logger.info("Transactions: %d | Dry-run: %s | FRI queries: %d (%d-bit on-chain soundness)",
                n_txs, dry_run, n_queries, security_bits)

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

    # ── Step 4: Generate cross-bound ML-DSA V23 proofs for tx[0] ──────────────
    # Prove the full V23 ML-DSA-65 arithmetic witness for tx[0]'s signature and
    # generate cross-bound hints for both LOG=10 (NttBatch+InttBatch, 1298 cols)
    # and LOG=8 (AzFull+Ct1Full+RangeQBatch+WPrime+NormCheck+UseHint, 2206 cols).
    # The cross-bound roots bind each group's FRI query indices to the other
    # group's trace commitment, preventing adversarial proof mixing.
    proto = "VFRI10" if stack == "v6" else "VFRI7"
    logger.info("Generating %s cross-bound V23 ML-DSA STARK proofs for tx[0]…", proto)
    tx0 = txs[0]
    if tx0.signature is None:
        logger.error("tx[0] has no signature — _make_transactions failed to sign")
        return 1
    batch_merkle_root = batch.merkle_root[:32]
    t0 = time.monotonic()
    try:
        if stack == "v6":
            result = prove_mldsa_sig_vfri10_stark(
                pk=tx0.public_key,
                msg=tx0.to_bytes(),
                sig=tx0.signature,
                batch_merkle_root=batch_merkle_root,
                n_queries=n_queries,
                num_folds_log10=_VFRI10_NUM_FOLDS,
                num_folds_log8=_VFRI10_NUM_FOLDS,
            )
        else:
            result = prove_mldsa_sig_vfri7_stark(
                pk=tx0.public_key,
                msg=tx0.to_bytes(),
                sig=tx0.signature,
                batch_merkle_root=batch_merkle_root,
                n_queries=n_queries,
            )
        elapsed_v = time.monotonic() - t0
        logger.info(
            "  log10: proof=%d B commit=%s hints=%d B | "
            "log8: proof=%d B commit=%s hints=%d B (%.2fs)",
            len(result.log10_proof),
            result.log10_commitment,
            len(result.log10_query_hints),
            len(result.log8_proof),
            result.log8_commitment,
            len(result.log8_query_hints),
            elapsed_v,
        )
    except ValueError as exc:
        logger.error("ML-DSA signature invalid or witness extraction failed: %s", exc)
        return 1
    except RuntimeError as exc:
        logger.error("%s proof generation failed: %s", proto, exc)
        return 1

    registry_name = "BatchRegistryV6" if stack == "v6" else "BatchRegistryV4"
    if dry_run:
        logger.info("[DRY-RUN] Skipping on-chain submission.")
        logger.info("To submit, set RPC_URL, DEPLOYER_PRIVATE_KEY, REGISTRY_ADDRESS in .env")
        logger.info("  REGISTRY_ADDRESS should point to a deployed %s contract.", registry_name)
        logger.info("=== DRY-RUN COMPLETE ===")
        return 0

    # Build per-sender nonce list: highest nonce in this batch for each unique sender.
    # tx.sender is the hex-encoded SHA3-256 of the public key (32 bytes on-chain address).
    sender_nonces: dict[bytes, int] = {}
    for tx in txs:
        sender_key = bytes.fromhex(tx.sender)  # already == sha3_256(tx.public_key)
        if tx.nonce > sender_nonces.get(sender_key, -1):
            sender_nonces[sender_key] = tx.nonce

    if stack == "v6":
        return _submit_v6(result, batch_merkle_root, sender_nonces)
    return _submit_v4(result, batch_merkle_root, sender_nonces)


def _submit_v6(result, batch_merkle_root: bytes, sender_nonces: dict[bytes, int]) -> int:
    """Submit a VFRI10 cross-bound proof to BatchRegistryV6 (two-tx split)."""
    try:
        from testnet.submit import OnchainSubmitterV6
        submitter = OnchainSubmitterV6.from_env()
    except KeyError as exc:
        logger.error("Missing env var: %s — run with --dry-run or set .env", exc)
        return 1
    except RuntimeError as exc:
        logger.error("Cannot connect to RPC: %s", exc)
        return 1

    logger.info("Submitting to BatchRegistryV6 (per-group split: group10 then group8+nonces)…")
    t0 = time.monotonic()
    try:
        tx10, tx8 = submitter.finalize_batch(
            merkle_root=batch_merkle_root,
            vfri10_result=result,
            senders=list(sender_nonces.keys()),
            new_nonces=list(sender_nonces.values()),
        )
    except RuntimeError as exc:
        logger.error("on-chain submission failed: %s", exc)
        return 1
    logger.info("  group10 tx=%s group8 tx=%s (%.2fs)", tx10, tx8, time.monotonic() - t0)

    logger.info("Waiting for confirmation and verifying finalization…")
    t0 = time.monotonic()
    finalized = submitter.wait_and_verify(tx8, batch_merkle_root)
    if not finalized:
        logger.error("Batch NOT finalized on-chain after both groups confirmed — unexpected state")
        return 1
    logger.info("  finalized=True (%.2fs)", time.monotonic() - t0)
    logger.info("=== E2E COMPLETE — batch finalized on testnet (VFRI10 per-group split) ===")
    return 0


def _submit_v4(result, batch_merkle_root: bytes, sender_nonces: dict[bytes, int]) -> int:
    """Submit a VFRI7 cross-bound proof to BatchRegistryV4 (single submitBatch)."""
    try:
        from testnet.submit import OnchainSubmitterV4
        submitter = OnchainSubmitterV4.from_env()
    except KeyError as exc:
        logger.error("Missing env var: %s — run with --dry-run or set .env", exc)
        return 1
    except RuntimeError as exc:
        logger.error("Cannot connect to RPC: %s", exc)
        return 1

    logger.info("Submitting batch to BatchRegistryV4 (VFRI7 cross-bound proofs + nonces)…")
    t0 = time.monotonic()
    tx_hash = submitter.submit_batch_with_nonces(
        merkle_root=batch_merkle_root,
        commitment_log10=result.log10_commitment,
        proof_log10=result.log10_proof,
        hints_log10=result.log10_query_hints,
        commitment_log8=result.log8_commitment,
        proof_log8=result.log8_proof,
        hints_log8=result.log8_query_hints,
        senders=list(sender_nonces.keys()),
        new_nonces=list(sender_nonces.values()),
    )
    logger.info("  tx_hash=%s (%.2fs)", tx_hash, time.monotonic() - t0)

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
    p = argparse.ArgumentParser(description="QLSA E2E testnet demo")
    p.add_argument(
        "--stack", choices=["v6", "v4"], default="v6",
        help=(
            "Contract stack: v6 = QLSAVerifierVFRI10 + BatchRegistryV6 (default, "
            "Poseidon2 t=4, per-group split, num_folds=6); v4 = QLSAVerifierVFRI7 "
            "+ BatchRegistryV4 (MVP-5, single submitBatch)."
        ),
    )
    p.add_argument("--txs", type=int, default=8, help="Number of transactions (default: 8)")
    p.add_argument("--dry-run", action="store_true", help="Skip on-chain submission")
    p.add_argument(
        "--n-queries", type=int, default=1,
        metavar="N",
        help=(
            "FRI queries per proof group (default: 1 = 16-bit on-chain soundness, gas-safe). "
            "Security = 6×N+10 bits. n=3 → 28 bits; n=20 → 130 bits "
            "(WARNING: n≥4 may exceed 15M gas on mainnet)."
        ),
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    sys.exit(run(n_txs=args.txs, dry_run=args.dry_run, n_queries=args.n_queries, stack=args.stack))
