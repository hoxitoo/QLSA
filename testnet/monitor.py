#!/usr/bin/env python3
"""
QLSA Testnet Monitor — polls BatchRegistryV2 for BatchFinalized events.

Usage:
  python -m testnet.monitor [--poll-interval 15]

Environment (.env):
  RPC_URL          — L2 RPC endpoint
  REGISTRY_ADDRESS — deployed BatchRegistryV2 address
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("qlsa.monitor")

_REGISTRY_ABI = json.loads("""
[
  {"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"indexed":true,"internalType":"bytes8","name":"commitment","type":"bytes8"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"}],"name":"BatchFinalized","type":"event"}
]
""")


def _connect() -> tuple[Web3, object]:
    rpc_url = os.environ["RPC_URL"]
    registry_address = os.environ["REGISTRY_ADDRESS"]

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    if not w3.is_connected():
        raise RuntimeError(f"Cannot connect to RPC: {rpc_url}")

    registry = w3.eth.contract(
        address=Web3.to_checksum_address(registry_address),
        abi=_REGISTRY_ABI,
    )
    logger.info("connected: chain=%d registry=%s", w3.eth.chain_id, registry_address)
    return w3, registry


def run(poll_interval_s: int = 15) -> None:
    w3, registry = _connect()

    from_block: int = w3.eth.block_number
    logger.info("watching BatchFinalized events from block %d (poll=%ds)…", from_block, poll_interval_s)
    logger.info("Press Ctrl-C to stop.")

    total_batches = 0
    while True:
        try:
            to_block = w3.eth.block_number
            if to_block >= from_block:
                events = registry.events.BatchFinalized.get_logs(  # type: ignore[attr-defined]
                    from_block=from_block,
                    to_block=to_block,
                )
                for ev in events:
                    total_batches += 1
                    args = ev["args"]
                    logger.info(
                        "[BatchFinalized #%d] root=%s… commitment=%s ts=%d block=%d",
                        total_batches,
                        args["merkleRoot"].hex()[:16],
                        args["commitment"].hex(),
                        args["timestamp"],
                        ev["blockNumber"],
                    )
                if to_block > from_block:
                    from_block = to_block + 1
        except KeyboardInterrupt:
            logger.info("stopped. total batches seen: %d", total_batches)
            break
        except Exception as exc:
            logger.warning("poll error (will retry): %s", exc)
        time.sleep(poll_interval_s)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="QLSA testnet event monitor")
    p.add_argument("--poll-interval", type=int, default=15, help="Seconds between polls (default: 15)")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    try:
        run(poll_interval_s=args.poll_interval)
    except KeyError as exc:
        logger.error("Missing env var: %s — set RPC_URL and REGISTRY_ADDRESS in .env", exc)
        sys.exit(1)
    except RuntimeError as exc:
        logger.error("%s", exc)
        sys.exit(1)
