#!/usr/bin/env python3
"""
QLSA — End-to-End Testnet Demo (MVP-7 VFRI11 / MVP-6 VFRI10 / MVP-5 VFRI7)

Flow:
  1. Generate N ML-DSA-65 keypairs (ephemeral)
  2. Create and sign N transactions
  3. Build a Batch (Merkle tree, signature verification)
  4. Generate cross-bound STARK proofs for tx[0] via Stwo prover
     (LOG=10 + LOG=8 groups bound to each other's trace commitments)
  5. Submit to the on-chain registry on the configured testnet
  6. Verify on-chain finalization

Four contract stacks are supported via --stack:
  v8:           QLSAVerifierRecursive + BatchRegistryV7 — RECURSIVE proofs. The
                registry verifies, per V23 group, a STARK attesting the inner
                VFRI11 proof was verified. Defaults to n_queries=20, i.e. 130-bit
                on-chain soundness, at which DIRECT verification no longer fits a
                transaction at all; this route finalizes in one (~13.13M gas).
                Below ~2 queries v7 is cheaper — this is a soundness mechanism,
                not a gas optimisation. See docs/conclusions.md.
  v7 (default): QLSAVerifierVFRI11 + BatchRegistryV5 — Poseidon2 t=8 backend
                (4-word/124-bit Merkle nodes → node collision ~2^62 vs t=4's
                ~2^31), BOTH V23 groups verified in ONE atomic transaction
                (~6.06M gas measured).  Strongest available on-chain soundness,
                which is why it is the default.
  v6:           QLSAVerifierVFRI10 + BatchRegistryV6 — Poseidon2 t=4 backend,
                per-group split (submitGroup10 then submitGroup8WithNonces,
                ~2.15M + ~1.70M gas).  Choose it when a lower peak gas per
                transaction matters more than the stronger node bound.
  v4:           QLSAVerifierVFRI7 + BatchRegistryV4 — single submitBatch (MVP-5).

REGISTRY_ADDRESS must match the chosen stack's registry shape (v7 -> V5,
v6 -> V6).  A mismatch is detected and reported before anything is submitted.

Prerequisites:
  pip install -r requirements.txt -r requirements-api.txt -r requirements-testnet.txt
  cd stark_stwo && maturin develop --features python --release

Environment (.env):
  RPC_URL              — L2 RPC endpoint (e.g. Polygon zkEVM Cardona)
  DEPLOYER_PRIVATE_KEY — 0x-prefixed deployer private key
  REGISTRY_ADDRESS     — deployed registry address (V5 for --stack v7 (default),
                         V6 for v6, V4 for v4)

Usage:
  python -m testnet.e2e [--stack v8|v7] [--txs N] [--dry-run]
  bash testnet/deploy_v7.sh --network sepolia   # deploy the default stack
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
    gen_tree_recursive_bundles,
    prove_mldsa_sig_vfri11_stark,
)

# num_folds=6 keeps the last layer at 16/4 evaluations. It was originally forced
# by the per-tx gas cap (num_folds=3 overran the LOG=10 group alone); after the
# R4.8 Poseidon2 rewrite there is ample headroom, but 6 stays the tested default
# for the t=8 (VFRI11) stack.
#
# `_VFRI10_NUM_FOLDS` and `_V8_NUM_FOLDS` used to sit here too. The first went
# dead with the Ф1 narrowing (no VFRI10 prover remains); the second with the move
# to the aggregation tree, which derives each root's fold count from that root's
# OWN depth — the fix for the revert in a4742b5, where one fold count for both
# left the on-chain last-layer rebuild 32x too large.
_VFRI11_NUM_FOLDS = 6
# The v8 stack exists for production soundness: 20 queries is 130-bit
# (log_blowup(6)*20 + pow_bits(10)), the point at which direct verification stops
# fitting a transaction. Overridable with --n-queries for a faster demo run.
_V8_DEFAULT_QUERIES = 20

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


def build_sender_nonces(txs: list[Transaction]) -> dict[bytes, int]:
    """Map a batch's transactions to the on-chain per-sender nonce registry.

    Returns ``{sender_hash_32B: highest_onchain_nonce}`` — one entry per unique
    sender, carrying that sender's highest nonce in this batch.

    ``tx.sender`` is the hex-encoded SHA3-256 of the public key, which is exactly
    the 32-byte on-chain sender identifier.

    NOTE the +1. The registries (``BatchRegistryV4``/``V5``/``V6``) store 0 for a
    sender that has never been seen and enforce ``newNonce > stored``, so the
    smallest submittable nonce is 1. Transaction nonces are 0-based, so passing
    them through unchanged makes any batch containing a sender's very first
    transaction (nonce 0) revert with ``SenderNonceTooLow(provided=0, expected=1)``.
    Shifting by one maps the 0-based off-chain counter onto the 1-based on-chain
    replay counter while preserving strict monotonicity.
    """
    sender_nonces: dict[bytes, int] = {}
    for tx in txs:
        sender_key = bytes.fromhex(tx.sender)
        onchain_nonce = tx.nonce + 1
        if onchain_nonce > sender_nonces.get(sender_key, 0):
            sender_nonces[sender_key] = onchain_nonce
    return sender_nonces


def run(n_txs: int = 8, dry_run: bool = False, n_queries: int = 1, stack: str = "v7") -> int:
    """Run the full E2E flow. Returns exit code (0 = success)."""
    if stack not in ("v7", "v8"):
        logger.error("unknown --stack %r (expected 'v8' or 'v7')", stack)
        return 1
    if stack == "v8" and n_queries == 1:
        # The whole point of v8 is production soundness; 1 query would make it
        # strictly worse than v7. Only override this deliberately.
        n_queries = _V8_DEFAULT_QUERIES
        logger.info("--stack v8: raising n_queries to %d (130-bit)", n_queries)
    # Security: log_blowup(6) × n_queries + pow_bits(10)
    # n=1 → 16-bit (demo); n=3 → 28-bit; n=20 → 130-bit (but ~300M gas — not feasible on mainnet).
    security_bits = 6 * n_queries + 10
    stack_label = {
        "v8": "Recursive + BatchRegistryV7 (proof-of-verification, one tx)",
        "v7": "VFRI11 + BatchRegistryV5 (t=8, atomic dual verify, node ~2^62)",
    }[stack]
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
    proto = {"v8": "recursive", "v7": "VFRI11"}[stack]
    tx0 = txs[0]
    if tx0.signature is None:
        logger.error("tx[0] has no signature — _make_transactions failed to sign")
        return 1
    # The SHA3 transaction-list root. On the v7 (direct) path this IS the
    # on-chain `merkleRoot`. On the v8 (tree) path it is only `txListRoot`, and
    # the on-chain `merkleRoot` is R, which comes back from the prover below.
    tx_list_root = batch.merkle_root[:32]
    batch_merkle_root = tx_list_root
    t0 = time.monotonic()
    try:
        if stack == "v8":
            # ALL N signatures, not tx[0]. This is what the v8 stack exists for:
            # BatchRegistryV7 takes two cross-bound tree roots and finalizes the
            # whole batch in one transaction. Until 2026-10-04 this branch proved
            # tx[0] like the v7 one, so "N signatures in one proof" was true of
            # the Rust path and of a Solidity test, and of nothing that shipped.
            logger.info(
                "Generating recursive AGGREGATION TREE over all %d signatures…",
                len(txs),
            )
            unsigned = [i for i, t in enumerate(txs) if t.signature is None]
            if unsigned:
                logger.error("transactions %s have no signature", unsigned)
                return 1
            result = gen_tree_recursive_bundles(
                [(t.public_key, t.to_bytes(), t.signature) for t in txs],
                n_queries=n_queries,
            )
            # R, derived from the proofs' trace roots — NOT the SHA3 list root.
            batch_merkle_root = result.merkle_root
        elif stack == "v7":
            logger.info(
                "Generating %s cross-bound V23 ML-DSA STARK proofs for tx[0]…", proto
            )
            result = prove_mldsa_sig_vfri11_stark(
                pk=tx0.public_key,
                msg=tx0.to_bytes(),
                sig=tx0.signature,
                batch_merkle_root=batch_merkle_root,
                n_queries=n_queries,
                num_folds_log10=_VFRI11_NUM_FOLDS,
                num_folds_log8=_VFRI11_NUM_FOLDS,
            )
        elapsed_v = time.monotonic() - t0
        if stack == "v8":
            logger.info(
                "  log10: outer=%d B hints=%d B lastLayer=%d | "
                "log8: outer=%d B hints=%d B lastLayer=%d | %d-bit (%.2fs)",
                len(result.log10.outer_proof), len(result.log10.outer_hints),
                len(result.log10.last_layer_evals),
                len(result.log8.outer_proof), len(result.log8.outer_hints),
                len(result.log8.last_layer_evals),
                result.security_bits, elapsed_v,
            )
            # R's leading 16 bytes are zero BY CONSTRUCTION: it is a Poseidon2
            # t=8 node, four big-endian u32 words living in bytes[16..32]. The
            # usual `.hex()[:16]` prefix therefore prints all zeros for every
            # batch, which reads like a bug and distinguishes nothing. Show the
            # bytes that carry the value.
            logger.info(
                "  %d signatures aggregated | merkleRoot(R)=…%s txListRoot=%s…",
                result.leaf_count,
                batch_merkle_root[16:].hex(),
                tx_list_root.hex()[:16],
            )
        else:
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

    registry_name = {
        "v8": "BatchRegistryV7", "v7": "BatchRegistryV5",
    }[stack]
    if dry_run:
        logger.info("[DRY-RUN] Skipping on-chain submission.")
        logger.info("To submit, set RPC_URL, DEPLOYER_PRIVATE_KEY, REGISTRY_ADDRESS in .env")
        logger.info("  REGISTRY_ADDRESS should point to a deployed %s contract.", registry_name)
        logger.info("=== DRY-RUN COMPLETE ===")
        return 0

    sender_nonces = build_sender_nonces(txs)

    if stack == "v8":
        return _submit_v8(result, batch_merkle_root, sender_nonces, tx_list_root)
    return _submit_v7(result, batch_merkle_root, sender_nonces)


def _submit_v8(
    result,
    batch_merkle_root: bytes,
    sender_nonces: dict[bytes, int],
    tx_list_root: bytes,
) -> int:
    """Submit the aggregation tree's two roots to BatchRegistryV7 in ONE transaction.

    ``batch_merkle_root`` here is **R** — derived from the proofs — while
    ``tx_list_root`` is the SHA3 transaction-list commitment the registry
    records but cannot verify.
    """
    try:
        from testnet.submit import OnchainSubmitterV7
        submitter = OnchainSubmitterV7.from_env()
    except KeyError as exc:
        logger.error("Missing env var: %s — run with --dry-run or set .env", exc)
        return 1
    except RuntimeError as exc:
        logger.error("Cannot connect to RPC or wrong registry: %s", exc)
        return 1

    logger.info(
        "Submitting to BatchRegistryV7 (%d signatures via tree roots, "
        "%d-bit soundness)…",
        result.leaf_count, result.security_bits,
    )
    t0 = time.monotonic()
    try:
        tx_hash = submitter.submit_batch_with_nonces(
            merkle_root=batch_merkle_root,
            bundles=result,
            senders=list(sender_nonces.keys()),
            new_nonces=list(sender_nonces.values()),
            tx_list_root=tx_list_root,
        )
    except RuntimeError as exc:
        logger.error("on-chain submission failed: %s", exc)
        return 1
    logger.info("  tx_hash=%s (%.2fs)", tx_hash, time.monotonic() - t0)

    logger.info("Waiting for confirmation and verifying finalization…")
    t0 = time.monotonic()
    if not submitter.wait_and_verify(tx_hash, batch_merkle_root):
        logger.error("Batch NOT finalized on-chain after tx confirmed — unexpected state")
        return 1
    logger.info("  finalized=True (%.2fs)", time.monotonic() - t0)
    logger.info(
        "=== E2E COMPLETE — batch finalized via RECURSION at %d-bit soundness ===",
        result.security_bits,
    )
    return 0


def _submit_v7(result, batch_merkle_root: bytes, sender_nonces: dict[bytes, int]) -> int:
    """Submit a VFRI11 (t=8) cross-bound proof to BatchRegistryV5 in ONE transaction."""
    try:
        from testnet.submit import OnchainSubmitterV5
        submitter = OnchainSubmitterV5.from_env()
    except KeyError as exc:
        logger.error("Missing env var: %s — run with --dry-run or set .env", exc)
        return 1
    except RuntimeError as exc:
        logger.error("Cannot connect to RPC: %s", exc)
        return 1

    logger.info("Submitting batch to BatchRegistryV5 (VFRI11 t=8, atomic dual verify)…")
    t0 = time.monotonic()
    try:
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
    except RuntimeError as exc:
        logger.error("on-chain submission failed: %s", exc)
        return 1
    logger.info("  tx_hash=%s (%.2fs)", tx_hash, time.monotonic() - t0)

    logger.info("Waiting for confirmation and verifying finalization…")
    t0 = time.monotonic()
    finalized = submitter.wait_and_verify(tx_hash, batch_merkle_root)
    if not finalized:
        logger.error("Batch NOT finalized on-chain after tx confirmed — unexpected state")
        return 1
    logger.info("  finalized=True (%.2fs)", time.monotonic() - t0)
    logger.info("=== E2E COMPLETE — batch finalized on testnet (VFRI11 t=8, one tx) ===")
    return 0





def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="QLSA E2E testnet demo")
    p.add_argument(
        "--stack", choices=["v8", "v7", "v6", "v4"], default="v7",
        help=(
            "Contract stack: v7 = QLSAVerifierVFRI11 + BatchRegistryV5 (default; "
            "Poseidon2 t=8, atomic dual verify in one tx, node collision ~2^62 — "
            "strongest on-chain soundness); v6 = QLSAVerifierVFRI10 + "
            "BatchRegistryV6 (Poseidon2 t=4, per-group split, node ~2^31, lower "
            "peak gas per tx); v4 = QLSAVerifierVFRI7 + BatchRegistryV4 (MVP-5)."
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
    args = p.parse_args()
    if args.n_queries < 1:
        p.error("--n-queries must be >= 1 (security = 6×N+10 bits)")
    if args.txs < 1:
        p.error("--txs must be >= 1")
    return args


if __name__ == "__main__":
    args = _parse_args()
    sys.exit(run(n_txs=args.txs, dry_run=args.dry_run, n_queries=args.n_queries, stack=args.stack))
