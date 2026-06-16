"""
On-chain submission to BatchRegistryV2 via web3.py.

Usage:
    from testnet.submit import OnchainSubmitter
    sub = OnchainSubmitter.from_env()
    tx_hash = sub.submit_batch(merkle_root, onchain_commitment, proof_bytes)
    sub.wait_and_verify(tx_hash, merkle_root)
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

logger = logging.getLogger(__name__)


def _as_bytes32(b: bytes, name: str = "value") -> bytes:
    """Validate that *b* is at least 32 bytes and return the first 32 bytes."""
    if len(b) < 32:
        raise ValueError(f"{name} must be at least 32 bytes, got {len(b)}")
    return b[:32]


def _decode_commitment16(hex_str: str, name: str = "commitment") -> bytes:
    """Decode a 32-char hex string to 16 bytes; raises ValueError on bad input."""
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError as exc:
        raise ValueError(f"{name} is not valid hex: {exc}") from exc
    if len(raw) != 16:
        raise ValueError(f"{name} must be 32 hex chars (16 bytes), got {len(raw)} bytes")
    return raw


def _validate_senders(senders: list[bytes]) -> list[bytes]:
    """Validate that every sender hash is exactly 32 bytes."""
    for i, s in enumerate(senders):
        if len(s) != 32:
            raise ValueError(
                f"senders[{i}] must be exactly 32 bytes (SHA3-256 of public key), "
                f"got {len(s)}"
            )
    return list(senders)


def _trace_root(proof: bytes, name: str = "proof") -> bytes:
    """Extract the embedded Stwo trace root (proof[8:40]) used for cross-binding.

    Both BatchRegistryV4 and BatchRegistryV6 read the verifier's trace commitment
    from bytes [8:40] of the proof (proof[0:8] is the little-endian version marker).
    """
    if len(proof) < 40:
        raise ValueError(f"{name} must be at least 40 bytes, got {len(proof)}")
    return proof[8:40]


# Inline ABI — generated from contracts/artifacts/src/BatchRegistryV2.sol
_REGISTRY_ABI = json.loads("""
[
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"BatchAlreadyFinalized","type":"error"},
  {"inputs":[],"name":"InvalidMerkleRoot","type":"error"},
  {"inputs":[],"name":"InvalidProof","type":"error"},
  {"inputs":[],"name":"ZeroAddressVerifier","type":"error"},
  {"inputs":[{"internalType":"bytes32","name":"sender","type":"bytes32"},{"internalType":"uint64","name":"provided","type":"uint64"},{"internalType":"uint64","name":"expected","type":"uint64"}],"name":"SenderNonceTooLow","type":"error"},
  {"inputs":[],"name":"NoncesLengthMismatch","type":"error"},
  {"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"indexed":true,"internalType":"bytes16","name":"commitment","type":"bytes16"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"}],"name":"BatchFinalized","type":"event"},
  {"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"sender","type":"bytes32"},{"indexed":false,"internalType":"uint64","name":"newNonce","type":"uint64"}],"name":"NonceAdvanced","type":"event"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"isBatchFinalized","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"internalType":"bytes16","name":"commitment","type":"bytes16"},{"internalType":"bytes","name":"starkProof","type":"bytes"}],"name":"submitBatch","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"internalType":"bytes16","name":"commitment","type":"bytes16"},{"internalType":"bytes","name":"starkProof","type":"bytes"},{"internalType":"bytes32[]","name":"senders","type":"bytes32[]"},{"internalType":"uint64[]","name":"newNonces","type":"uint64[]"}],"name":"submitBatchWithNonces","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"getCommitment","outputs":[{"internalType":"bytes16","name":"","type":"bytes16"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"senderNonces","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"}
]
""")


class OnchainSubmitter:
    """Wraps web3 interaction with BatchRegistryV2."""

    def __init__(
        self,
        rpc_url: str,
        private_key: str,
        registry_address: str,
        gas_limit: int = 5_000_000,
        confirm_timeout_s: int = 120,
    ) -> None:
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        # POA chains (Polygon zkEVM Cardona) inject extra fields in block headers.
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        if not self.w3.is_connected():
            raise RuntimeError(f"Cannot connect to RPC: {rpc_url}")

        self.account = self.w3.eth.account.from_key(private_key)
        self.registry = self.w3.eth.contract(
            address=Web3.to_checksum_address(registry_address),
            abi=_REGISTRY_ABI,
        )
        self.gas_limit = gas_limit
        self.confirm_timeout_s = confirm_timeout_s
        logger.info("submitter ready: account=%s chain=%d", self.account.address, self.w3.eth.chain_id)

    @classmethod
    def from_env(cls) -> "OnchainSubmitter":
        """Construct from environment variables (loaded from .env by caller)."""
        rpc_url = os.environ["RPC_URL"]
        # PRIVATE_KEY is the canonical name; DEPLOYER_PRIVATE_KEY is the legacy alias.
        private_key = os.environ.get("PRIVATE_KEY") or os.environ["DEPLOYER_PRIVATE_KEY"]
        registry_address = os.environ["REGISTRY_ADDRESS"]
        return cls(rpc_url=rpc_url, private_key=private_key, registry_address=registry_address)

    def submit_batch(
        self,
        merkle_root: bytes,
        onchain_commitment: str,
        proof_bytes: bytes,
    ) -> str:
        """
        Call BatchRegistryV2.submitBatch() and return the transaction hash.

        Args:
            merkle_root:        First 32 bytes of the SHA3-512 Merkle root (bytes32).
            onchain_commitment: 32-char hex string (16 bytes) from ProofResult.onchain_commitment.
            proof_bytes:        Raw STARK proof bytes.

        Returns:
            Transaction hash as a hex string (0x-prefixed).
        """
        root_bytes32: bytes = _as_bytes32(merkle_root, "merkle_root")
        commitment_bytes16: bytes = _decode_commitment16(onchain_commitment, "onchain_commitment")

        nonce = self.w3.eth.get_transaction_count(self.account.address)
        gas_price = self.w3.eth.gas_price

        tx = self.registry.functions.submitBatch(
            root_bytes32,
            commitment_bytes16,
            proof_bytes,
        ).build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": self.gas_limit,
            "gasPrice": gas_price,
        })

        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        tx_hex = tx_hash.hex()
        logger.info("tx submitted: %s", tx_hex)
        return tx_hex

    def submit_batch_with_nonces(
        self,
        merkle_root: bytes,
        onchain_commitment: str,
        proof_bytes: bytes,
        senders: list[bytes],
        new_nonces: list[int],
    ) -> str:
        """Call BatchRegistryV2.submitBatchWithNonces() with replay protection.

        Args:
            merkle_root:        First 32 bytes of the SHA3-512 Merkle root.
            onchain_commitment: 32-char hex string (16 bytes).
            proof_bytes:        Raw STARK proof bytes.
            senders:            List of sender address hashes (bytes, 32 bytes each).
                                Each entry is SHA3-256(public_key) — the on-chain bytes32 sender.
            new_nonces:         Highest nonce for each sender in this batch (must exceed stored).

        Returns:
            Transaction hash as a hex string (0x-prefixed).
        """
        if len(senders) != len(new_nonces):
            raise ValueError("senders and new_nonces must have equal length")

        root_bytes32 = _as_bytes32(merkle_root, "merkle_root")
        commitment_bytes16 = _decode_commitment16(onchain_commitment, "onchain_commitment")
        senders_b32 = _validate_senders(senders)

        nonce = self.w3.eth.get_transaction_count(self.account.address)
        gas_price = self.w3.eth.gas_price

        tx = self.registry.functions.submitBatchWithNonces(
            root_bytes32,
            commitment_bytes16,
            proof_bytes,
            senders_b32,
            new_nonces,
        ).build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": self.gas_limit,
            "gasPrice": gas_price,
        })

        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        tx_hex = tx_hash.hex()
        logger.info("tx submitted (with nonces): %s", tx_hex)
        return tx_hex

    def get_sender_nonce(self, sender_hash: bytes) -> int:
        """Return the current on-chain nonce for a sender (bytes32 address hash)."""
        return int(self.registry.functions.senderNonces(_as_bytes32(sender_hash, "sender_hash")).call())

    def wait_and_verify_v4(self, tx_hash: str, merkle_root: bytes) -> bool:
        """Wait for confirmation then verify finalization on BatchRegistryV4."""
        return self.wait_and_verify(tx_hash, merkle_root)

    def wait_and_verify(self, tx_hash: str, merkle_root: bytes) -> bool:
        """
        Wait for transaction confirmation then verify on-chain finalization.

        Returns True when the batch is confirmed as finalized.
        Raises RuntimeError on timeout or revert.
        """
        logger.info("waiting for confirmation (timeout=%ds)…", self.confirm_timeout_s)
        deadline = time.monotonic() + self.confirm_timeout_s
        while time.monotonic() < deadline:
            receipt = None
            try:
                receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            except Exception as exc:
                if "not found" not in str(exc).lower():
                    raise
            if receipt is not None:
                if receipt["status"] == 0:
                    raise RuntimeError(f"tx reverted: {tx_hash}")
                break
            time.sleep(2)
        else:
            raise RuntimeError(f"tx not confirmed within {self.confirm_timeout_s}s: {tx_hash}")

        root_bytes32 = _as_bytes32(merkle_root, "merkle_root")
        finalized: bool = self.registry.functions.isBatchFinalized(root_bytes32).call()
        if finalized:
            commitment = self.registry.functions.getCommitment(root_bytes32).call()
            logger.info(
                "batch finalized on-chain: root=%s commitment=%s",
                root_bytes32.hex()[:16],
                commitment.hex(),
            )
        return finalized


# ── BatchRegistryV4 (dual VFRI7 proofs, cross-proof binding) ──────────────────

_REGISTRY_V4_ABI = json.loads("""
[
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"BatchAlreadyFinalized","type":"error"},
  {"inputs":[],"name":"InvalidMerkleRoot","type":"error"},
  {"inputs":[],"name":"Log10ProofInvalid","type":"error"},
  {"inputs":[],"name":"Log8ProofInvalid","type":"error"},
  {"inputs":[],"name":"ZeroAddressVerifier","type":"error"},
  {"inputs":[{"internalType":"bytes32","name":"sender","type":"bytes32"},{"internalType":"uint64","name":"provided","type":"uint64"},{"internalType":"uint64","name":"expected","type":"uint64"}],"name":"SenderNonceTooLow","type":"error"},
  {"inputs":[],"name":"NoncesLengthMismatch","type":"error"},
  {"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"indexed":true,"internalType":"bytes16","name":"commitmentLog10","type":"bytes16"},{"indexed":false,"internalType":"bytes16","name":"commitmentLog8","type":"bytes16"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"}],"name":"BatchFinalized","type":"event"},
  {"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"sender","type":"bytes32"},{"indexed":false,"internalType":"uint64","name":"newNonce","type":"uint64"}],"name":"NonceAdvanced","type":"event"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"isBatchFinalized","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"internalType":"bytes16","name":"commitmentLog10","type":"bytes16"},{"internalType":"bytes","name":"proofLog10","type":"bytes"},{"internalType":"bytes","name":"hintsLog10","type":"bytes"},{"internalType":"bytes16","name":"commitmentLog8","type":"bytes16"},{"internalType":"bytes","name":"proofLog8","type":"bytes"},{"internalType":"bytes","name":"hintsLog8","type":"bytes"}],"name":"submitBatch","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"internalType":"bytes16","name":"commitmentLog10","type":"bytes16"},{"internalType":"bytes","name":"proofLog10","type":"bytes"},{"internalType":"bytes","name":"hintsLog10","type":"bytes"},{"internalType":"bytes16","name":"commitmentLog8","type":"bytes16"},{"internalType":"bytes","name":"proofLog8","type":"bytes"},{"internalType":"bytes","name":"hintsLog8","type":"bytes"},{"internalType":"bytes32[]","name":"senders","type":"bytes32[]"},{"internalType":"uint64[]","name":"newNonces","type":"uint64[]"}],"name":"submitBatchWithNonces","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"batchCommitmentsLog10","outputs":[{"internalType":"bytes16","name":"","type":"bytes16"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"senderNonces","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"}
]
""")


class OnchainSubmitterV4:
    """Wraps web3 interaction with BatchRegistryV4 (dual VFRI7 proofs)."""

    def __init__(
        self,
        rpc_url: str,
        private_key: str,
        registry_address: str,
        gas_limit: int = 15_000_000,
        confirm_timeout_s: int = 120,
    ) -> None:
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        if not self.w3.is_connected():
            raise RuntimeError(f"Cannot connect to RPC: {rpc_url}")
        self.account = self.w3.eth.account.from_key(private_key)
        self.registry = self.w3.eth.contract(
            address=Web3.to_checksum_address(registry_address),
            abi=_REGISTRY_V4_ABI,
        )
        self.gas_limit = gas_limit
        self.confirm_timeout_s = confirm_timeout_s
        logger.info("submitterV4 ready: account=%s chain=%d", self.account.address, self.w3.eth.chain_id)

    @classmethod
    def from_env(cls) -> "OnchainSubmitterV4":
        """Construct from environment variables."""
        rpc_url = os.environ["RPC_URL"]
        private_key = os.environ.get("PRIVATE_KEY") or os.environ["DEPLOYER_PRIVATE_KEY"]
        registry_address = os.environ["REGISTRY_ADDRESS"]
        return cls(rpc_url=rpc_url, private_key=private_key, registry_address=registry_address)

    def submit_batch(
        self,
        merkle_root: bytes,
        commitment_log10: str,
        proof_log10: bytes,
        hints_log10: bytes,
        commitment_log8: str,
        proof_log8: bytes,
        hints_log8: bytes,
    ) -> str:
        """Call BatchRegistryV4.submitBatch() with both VFRI7 proof pairs.

        Args:
            merkle_root:      32-byte batch Merkle root.
            commitment_log10: 32-char hex of LOG=10 commitment (no 0x prefix).
            proof_log10:      Raw STARK proof bytes for LOG=10 group.
            hints_log10:      ABI-encoded VFRI7 query hints for LOG=10 group.
            commitment_log8:  32-char hex of LOG=8 commitment.
            proof_log8:       Raw STARK proof bytes for LOG=8 group.
            hints_log8:       ABI-encoded VFRI7 query hints for LOG=8 group.

        Returns:
            Transaction hash as a hex string (0x-prefixed).
        """
        root_b32  = _as_bytes32(merkle_root, "merkle_root")
        c10_b16   = _decode_commitment16(commitment_log10, "commitment_log10")
        c8_b16    = _decode_commitment16(commitment_log8, "commitment_log8")

        nonce     = self.w3.eth.get_transaction_count(self.account.address)
        gas_price = self.w3.eth.gas_price
        tx = self.registry.functions.submitBatch(
            root_b32, c10_b16, proof_log10, hints_log10,
            c8_b16,  proof_log8,  hints_log8,
        ).build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": self.gas_limit,
            "gasPrice": gas_price,
        })
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        tx_hex = tx_hash.hex()
        logger.info("V4 tx submitted: %s", tx_hex)
        return tx_hex

    def submit_batch_with_nonces(
        self,
        merkle_root: bytes,
        commitment_log10: str,
        proof_log10: bytes,
        hints_log10: bytes,
        commitment_log8: str,
        proof_log8: bytes,
        hints_log8: bytes,
        senders: list[bytes],
        new_nonces: list[int],
    ) -> str:
        """Call BatchRegistryV4.submitBatchWithNonces() with replay protection."""
        if len(senders) != len(new_nonces):
            raise ValueError("senders and new_nonces must have equal length")
        root_b32    = _as_bytes32(merkle_root, "merkle_root")
        c10_b16     = _decode_commitment16(commitment_log10, "commitment_log10")
        c8_b16      = _decode_commitment16(commitment_log8, "commitment_log8")
        senders_b32 = _validate_senders(senders)
        nonce      = self.w3.eth.get_transaction_count(self.account.address)
        gas_price  = self.w3.eth.gas_price
        tx = self.registry.functions.submitBatchWithNonces(
            root_b32, c10_b16, proof_log10, hints_log10,
            c8_b16,  proof_log8,  hints_log8,
            senders_b32, new_nonces,
        ).build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": self.gas_limit,
            "gasPrice": gas_price,
        })
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        tx_hex = tx_hash.hex()
        logger.info("V4 tx submitted (with nonces): %s", tx_hex)
        return tx_hex

    def wait_and_verify(self, tx_hash: str, merkle_root: bytes) -> bool:
        """Wait for confirmation then verify batch finalization on BatchRegistryV4."""
        logger.info("waiting for confirmation (timeout=%ds)…", self.confirm_timeout_s)
        deadline = time.monotonic() + self.confirm_timeout_s
        while time.monotonic() < deadline:
            receipt = None
            try:
                receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            except Exception as exc:
                if "not found" not in str(exc).lower():
                    raise
            if receipt is not None:
                if receipt["status"] == 0:
                    raise RuntimeError(f"tx reverted: {tx_hash}")
                break
            time.sleep(2)
        else:
            raise RuntimeError(f"tx not confirmed within {self.confirm_timeout_s}s: {tx_hash}")

        root_b32 = _as_bytes32(merkle_root, "merkle_root")
        finalized: bool = self.registry.functions.isBatchFinalized(root_b32).call()
        if finalized:
            c10 = self.registry.functions.batchCommitmentsLog10(root_b32).call()
            logger.info(
                "V4 batch finalized: root=%s commitmentLog10=%s",
                root_b32.hex()[:16],
                c10.hex(),
            )
        return finalized

    def get_sender_nonce(self, sender_hash: bytes) -> int:
        """Return the current on-chain nonce for a sender."""
        return int(self.registry.functions.senderNonces(_as_bytes32(sender_hash, "sender_hash")).call())


# ── BatchRegistryV6 (per-group split, dual VFRI10 proofs) ─────────────────────

# Inline ABI — generated from contracts/artifacts/src/BatchRegistryV6.sol
_REGISTRY_V6_ABI = json.loads("""
[
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"BatchAlreadyFinalized","type":"error"},
  {"inputs":[],"name":"InvalidMerkleRoot","type":"error"},
  {"inputs":[],"name":"Log10ProofInvalid","type":"error"},
  {"inputs":[],"name":"Log8ProofInvalid","type":"error"},
  {"inputs":[],"name":"NotReadyToFinalize","type":"error"},
  {"inputs":[],"name":"ZeroAddressVerifier","type":"error"},
  {"inputs":[{"internalType":"bytes32","name":"sender","type":"bytes32"},{"internalType":"uint64","name":"provided","type":"uint64"},{"internalType":"uint64","name":"expected","type":"uint64"}],"name":"SenderNonceTooLow","type":"error"},
  {"inputs":[],"name":"NoncesLengthMismatch","type":"error"},
  {"inputs":[],"name":"SenderCountExceedsLimit","type":"error"},
  {"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"indexed":false,"internalType":"uint8","name":"log","type":"uint8"},{"indexed":false,"internalType":"bytes16","name":"commitment","type":"bytes16"}],"name":"GroupVerified","type":"event"},
  {"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"indexed":true,"internalType":"bytes16","name":"commitmentLog10","type":"bytes16"},{"indexed":false,"internalType":"bytes16","name":"commitmentLog8","type":"bytes16"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"}],"name":"BatchFinalized","type":"event"},
  {"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"sender","type":"bytes32"},{"indexed":false,"internalType":"uint64","name":"newNonce","type":"uint64"}],"name":"NonceAdvanced","type":"event"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"isBatchFinalized","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"pendingGroups","outputs":[{"internalType":"bool","name":"has10","type":"bool"},{"internalType":"bool","name":"has8","type":"bool"},{"internalType":"bool","name":"readyToFinalize","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"internalType":"bytes32","name":"crossTraceRoot8","type":"bytes32"},{"internalType":"bytes16","name":"commitmentLog10","type":"bytes16"},{"internalType":"bytes","name":"proofLog10","type":"bytes"},{"internalType":"bytes","name":"hintsLog10","type":"bytes"}],"name":"submitGroup10","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"internalType":"bytes32","name":"crossTraceRoot10","type":"bytes32"},{"internalType":"bytes16","name":"commitmentLog8","type":"bytes16"},{"internalType":"bytes","name":"proofLog8","type":"bytes"},{"internalType":"bytes","name":"hintsLog8","type":"bytes"}],"name":"submitGroup8","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"internalType":"bytes32","name":"crossTraceRoot10","type":"bytes32"},{"internalType":"bytes16","name":"commitmentLog8","type":"bytes16"},{"internalType":"bytes","name":"proofLog8","type":"bytes"},{"internalType":"bytes","name":"hintsLog8","type":"bytes"},{"internalType":"bytes32[]","name":"senders","type":"bytes32[]"},{"internalType":"uint64[]","name":"newNonces","type":"uint64[]"}],"name":"submitGroup8WithNonces","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"getCommitmentsLog10","outputs":[{"internalType":"bytes16","name":"","type":"bytes16"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"senderNonces","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"}
]
""")


class OnchainSubmitterV6:
    """Wraps web3 interaction with BatchRegistryV6 (per-group split, dual VFRI10).

    BatchRegistryV6 verifies each V23 trace group in its OWN transaction so each
    t=4 ``verify()`` stays within the ~16.7M per-tx gas cap:

      1. ``submitGroup10(merkleRoot, traceRoot8, c10, proof10, hints10)``
      2. ``submitGroup8WithNonces(merkleRoot, traceRoot10, c8, proof8, hints8,
         senders, nonces)``  — finalizes once both groups are cross-consistent.

    The cross trace root passed to each call is the OTHER proof's embedded trace
    root (``proof[8:40]``), reproducing BatchRegistryV5's atomic cross-binding
    lazily across two transactions.
    """

    def __init__(
        self,
        rpc_url: str,
        private_key: str,
        registry_address: str,
        gas_limit: int = 16_700_000,
        confirm_timeout_s: int = 180,
    ) -> None:
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        if not self.w3.is_connected():
            raise RuntimeError(f"Cannot connect to RPC: {rpc_url}")
        self.account = self.w3.eth.account.from_key(private_key)
        self.registry = self.w3.eth.contract(
            address=Web3.to_checksum_address(registry_address),
            abi=_REGISTRY_V6_ABI,
        )
        self.gas_limit = gas_limit
        self.confirm_timeout_s = confirm_timeout_s
        logger.info("submitterV6 ready: account=%s chain=%d", self.account.address, self.w3.eth.chain_id)

    @classmethod
    def from_env(cls) -> "OnchainSubmitterV6":
        """Construct from environment variables."""
        rpc_url = os.environ["RPC_URL"]
        private_key = os.environ.get("PRIVATE_KEY") or os.environ["DEPLOYER_PRIVATE_KEY"]
        registry_address = os.environ["REGISTRY_ADDRESS"]
        return cls(rpc_url=rpc_url, private_key=private_key, registry_address=registry_address)

    def _send(self, fn) -> str:  # type: ignore[no-untyped-def]
        """Build, sign, and broadcast a contract call; return the tx hash hex."""
        nonce = self.w3.eth.get_transaction_count(self.account.address)
        gas_price = self.w3.eth.gas_price
        tx = fn.build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": self.gas_limit,
            "gasPrice": gas_price,
        })
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        return tx_hash.hex()

    def submit_group10(
        self,
        merkle_root: bytes,
        proof_log10: bytes,
        hints_log10: bytes,
        commitment_log10: str,
        cross_trace_root8: bytes,
    ) -> str:
        """Verify the LOG=10 group in its own tx; bound to the LOG=8 trace root."""
        tx_hex = self._send(self.registry.functions.submitGroup10(
            _as_bytes32(merkle_root, "merkle_root"),
            _as_bytes32(cross_trace_root8, "cross_trace_root8"),
            _decode_commitment16(commitment_log10, "commitment_log10"),
            proof_log10,
            hints_log10,
        ))
        logger.info("V6 submitGroup10: %s", tx_hex)
        return tx_hex

    def submit_group8_with_nonces(
        self,
        merkle_root: bytes,
        proof_log8: bytes,
        hints_log8: bytes,
        commitment_log8: str,
        cross_trace_root10: bytes,
        senders: list[bytes],
        new_nonces: list[int],
    ) -> str:
        """Verify the LOG=8 group and finalize with per-sender nonce enforcement.

        Requires LOG=10 to already be present and cross-consistent (call
        ``submit_group10`` first and wait for confirmation).
        """
        if len(senders) != len(new_nonces):
            raise ValueError("senders and new_nonces must have equal length")
        tx_hex = self._send(self.registry.functions.submitGroup8WithNonces(
            _as_bytes32(merkle_root, "merkle_root"),
            _as_bytes32(cross_trace_root10, "cross_trace_root10"),
            _decode_commitment16(commitment_log8, "commitment_log8"),
            proof_log8,
            hints_log8,
            _validate_senders(senders),
            new_nonces,
        ))
        logger.info("V6 submitGroup8WithNonces: %s", tx_hex)
        return tx_hex

    def finalize_batch(
        self,
        merkle_root: bytes,
        vfri10_result,  # type: ignore[no-untyped-def]
        senders: list[bytes],
        new_nonces: list[int],
    ) -> tuple[str, str]:
        """Run the full two-tx finalization from a FullV23VFRI10CrossBoundHintResult.

        Extracts each group's cross trace root from the OTHER proof's bytes [8:40],
        submits LOG=10, waits for confirmation, then submits LOG=8 with nonces.
        Returns ``(tx_hash10, tx_hash8)``.
        """
        root_b32 = _as_bytes32(merkle_root, "merkle_root")
        trace_root10 = _trace_root(vfri10_result.log10_proof, "log10_proof")
        trace_root8  = _trace_root(vfri10_result.log8_proof, "log8_proof")

        tx10 = self.submit_group10(
            merkle_root=root_b32,
            proof_log10=vfri10_result.log10_proof,
            hints_log10=vfri10_result.log10_query_hints,
            commitment_log10=vfri10_result.log10_commitment,
            cross_trace_root8=trace_root8,
        )
        if not self._wait_receipt(tx10):
            raise RuntimeError(f"submitGroup10 reverted: {tx10}")

        tx8 = self.submit_group8_with_nonces(
            merkle_root=root_b32,
            proof_log8=vfri10_result.log8_proof,
            hints_log8=vfri10_result.log8_query_hints,
            commitment_log8=vfri10_result.log8_commitment,
            cross_trace_root10=trace_root10,
            senders=senders,
            new_nonces=new_nonces,
        )
        return tx10, tx8

    def _wait_receipt(self, tx_hash: str) -> bool:
        """Wait for a single tx receipt; return True if status==1, raise on revert."""
        deadline = time.monotonic() + self.confirm_timeout_s
        while time.monotonic() < deadline:
            try:
                receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            except Exception as exc:
                if "not found" not in str(exc).lower():
                    raise
                receipt = None
            if receipt is not None:
                if receipt["status"] == 0:
                    raise RuntimeError(f"tx reverted: {tx_hash}")
                return True
            time.sleep(2)
        raise RuntimeError(f"tx not confirmed within {self.confirm_timeout_s}s: {tx_hash}")

    def wait_and_verify(self, tx_hash: str, merkle_root: bytes) -> bool:
        """Wait for the finalizing tx then verify on-chain finalization."""
        logger.info("waiting for confirmation (timeout=%ds)…", self.confirm_timeout_s)
        self._wait_receipt(tx_hash)
        root_b32 = _as_bytes32(merkle_root, "merkle_root")
        finalized: bool = self.registry.functions.isBatchFinalized(root_b32).call()
        if finalized:
            c10 = self.registry.functions.getCommitmentsLog10(root_b32).call()
            logger.info(
                "V6 batch finalized: root=%s commitmentLog10=%s",
                root_b32.hex()[:16],
                c10.hex(),
            )
        return finalized

    def pending_groups(self, merkle_root: bytes) -> tuple[bool, bool, bool]:
        """Return (has10, has8, readyToFinalize) for a not-yet-finalized batch."""
        has10, has8, ready = self.registry.functions.pendingGroups(
            _as_bytes32(merkle_root, "merkle_root")
        ).call()
        return bool(has10), bool(has8), bool(ready)

    def get_sender_nonce(self, sender_hash: bytes) -> int:
        """Return the current on-chain nonce for a sender."""
        return int(self.registry.functions.senderNonces(_as_bytes32(sender_hash, "sender_hash")).call())
