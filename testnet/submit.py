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

from eth_abi.exceptions import DecodingError
from web3 import Web3
from web3.exceptions import BadFunctionCallOutput, ContractLogicError
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


# ── Registry-kind detection ───────────────────────────────────────────────────
#
# The three stacks pair a prover protocol with a registry SHAPE:
#
#   --stack v4 / v7 -> BatchRegistryV4 / V5: submitBatch[WithNonces] (one tx)
#   --stack v6      -> BatchRegistryV6:      submitGroup10 + submitGroup8 (two txs)
#
# Pointing REGISTRY_ADDRESS at the wrong shape otherwise fails deep inside a
# transaction with an opaque error (calling a selector the contract does not
# implement), so probe it up front and say plainly what is mismatched.
#
# `pendingGroups(bytes32)` exists ONLY on BatchRegistryV6, which makes it an exact
# discriminator between the two shapes. V4 vs V5 cannot be told apart on-chain —
# their ABIs are byte-identical, only the wired verifier differs — but that
# mismatch surfaces legibly as Log10ProofInvalid from verify(), not as a decode
# failure, so it needs no probe.

_PER_GROUP = "per-group"          # BatchRegistryV6
_SINGLE_SUBMIT = "single-submit"  # BatchRegistryV4 / V5
_RECURSIVE = "recursive"          # BatchRegistryV7

# Only CONTRACT-level failures mean "this selector is not implemented".  A
# transport failure (dead RPC, timeout, rate limit) must NOT be read as an answer:
# swallowing it would silently classify a BatchRegistryV6 as V4/V5 and let a
# mismatched submission proceed.  Verified against a live node — a missing selector
# raises ContractLogicError, a dead endpoint raises requests.ConnectionError — so
# anything outside this tuple propagates to the caller.
_NO_SUCH_FUNCTION = (
    ContractLogicError,      # reverted / no such function
    BadFunctionCallOutput,   # empty or undecodable return data
    DecodingError,           # return data did not match the probe ABI
)

#: `crossBoundRoot(bytes32,bytes32)` exists ONLY on BatchRegistryV7, so it is an
#: exact discriminator for the recursive shape. Probed FIRST because a V7 also
#: lacks `pendingGroups`, which would otherwise misread it as V4/V5.
_CROSS_BOUND_ROOT_ABI = json.loads("""
[
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"internalType":"bytes32","name":"otherTraceRoot","type":"bytes32"}],"name":"crossBoundRoot","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"pure","type":"function"}
]
""")

_PENDING_GROUPS_ABI = json.loads("""
[
  {"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"pendingGroups","outputs":[{"internalType":"bool","name":"","type":"bool"},{"internalType":"bool","name":"","type":"bool"},{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}
]
""")


def detect_registry_kind(w3: Web3, registry_address: str) -> str:
    """Return ``_PER_GROUP`` or ``_SINGLE_SUBMIT`` for a deployed registry.

    Probes ``pendingGroups(bytes32)``, which only BatchRegistryV6 implements.
    Raises RuntimeError if there is no contract at the address at all — a far more
    common misconfiguration than a wrong registry version.
    """
    addr = Web3.to_checksum_address(registry_address)
    if w3.eth.get_code(addr) in (b"", b"0x"):
        raise RuntimeError(
            f"no contract deployed at REGISTRY_ADDRESS={addr} "
            "(wrong network, or the address was never deployed)"
        )
    # V7 first: it implements neither `pendingGroups` nor the V4/V5 flow, so
    # probing `pendingGroups` alone would misclassify it as single-submit.
    v7 = w3.eth.contract(address=addr, abi=_CROSS_BOUND_ROOT_ABI)
    try:
        v7.functions.crossBoundRoot(b"\x00" * 32, b"\x00" * 32).call()
        return _RECURSIVE
    except _NO_SUCH_FUNCTION as exc:
        logger.debug("crossBoundRoot probe rejected by %s: %s", addr, exc)

    probe = w3.eth.contract(address=addr, abi=_PENDING_GROUPS_ABI)
    try:
        probe.functions.pendingGroups(b"\x00" * 32).call()
    except _NO_SUCH_FUNCTION as exc:
        # Contract-level failure: the selector is not implemented (V4/V5).
        logger.debug("pendingGroups probe rejected by %s: %s", addr, exc)
        return _SINGLE_SUBMIT
    return _PER_GROUP


def require_registry_kind(
    w3: Web3, registry_address: str, expected_kind: str, expected_registry: str
) -> None:
    """Raise RuntimeError unless the deployed registry has the expected shape."""
    kind = detect_registry_kind(w3, registry_address)
    if kind != expected_kind:
        raise RuntimeError(
            f"REGISTRY_ADDRESS={registry_address} is a {kind} registry, but this "
            f"submitter expects {expected_kind} ({expected_registry}). Check --stack "
            "against the deployed contract: v4/v7 need BatchRegistryV4/V5, "
            "v6 needs BatchRegistryV6, v8 needs BatchRegistryV7."
        )




class OnchainSubmitterV5:
    """Wraps web3 interaction with BatchRegistryV5 (atomic dual VFRI11 / t=8).

    Was ``OnchainSubmitterV4`` with a thin ``V5`` subclass over it, because
    BatchRegistryV4 and V5 have byte-identical ABIs and only the wired verifier
    differed. V4 was retired with the rest of the legacy surface, so the two
    collapsed into one class named after the registry that still exists.

    Stack: ``QLSAVerifierVFRI11`` (Poseidon2 t=8 → 4-word/124-bit Merkle nodes,
    node collision ~2^62) behind ``BatchRegistryV5``, which verifies BOTH V23
    trace groups in ONE transaction with cross-proof binding computed on-chain:

      boundRoot10 = keccak256(merkleRoot | traceRoot8)
      boundRoot8  = keccak256(merkleRoot | traceRoot10)

    Measured cost of the atomic dual verify: ~6.06M gas, inside the 16,777,216
    (2^24, EIP-7825) per-tx cap.
    """

    #: Registry shape this submitter speaks; checked against the deployed contract.
    _EXPECTED_KIND = _SINGLE_SUBMIT
    _EXPECTED_REGISTRY = "BatchRegistryV5"
    #: Log prefix — subclasses override it so a v7 run does not log "V5".
    _LOG_TAG = "V5"

    def __init__(
        self,
        rpc_url: str,
        private_key: str,
        registry_address: str,
        gas_limit: int = 15_000_000,
        confirm_timeout_s: int = 120,
    ) -> None:
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        if not self.w3.is_connected():
            raise RuntimeError(f"Cannot connect to RPC: {rpc_url}")
        self.account = self.w3.eth.account.from_key(private_key)
        self.registry = self.w3.eth.contract(
            address=Web3.to_checksum_address(registry_address),
            abi=_REGISTRY_V4_ABI,
        )
        require_registry_kind(
            self.w3, registry_address, self._EXPECTED_KIND, self._EXPECTED_REGISTRY
        )
        self.gas_limit = gas_limit
        self.confirm_timeout_s = confirm_timeout_s
        logger.info(
            "submitter%s ready: account=%s chain=%d",
            self._LOG_TAG, self.account.address, self.w3.eth.chain_id,
        )



    @classmethod
    def from_env(cls) -> "OnchainSubmitterV5":
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
        logger.info("%s tx submitted: %s", self._LOG_TAG, tx_hex)
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
        logger.info("%s tx submitted (with nonces): %s", self._LOG_TAG, tx_hex)
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
                "%s batch finalized: root=%s commitmentLog10=%s",
                self._LOG_TAG,
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


_REGISTRY_V7_ABI = json.loads("""[{"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"BatchAlreadyFinalized","type":"error"},{"inputs":[],"name":"CrossBindingMismatch","type":"error"},{"inputs":[],"name":"InvalidMerkleRoot","type":"error"},{"inputs":[],"name":"Log10ProofInvalid","type":"error"},{"inputs":[],"name":"Log8ProofInvalid","type":"error"},{"inputs":[],"name":"NoncesLengthMismatch","type":"error"},{"inputs":[],"name":"SenderCountExceedsLimit","type":"error"},{"inputs":[{"internalType":"bytes32","name":"sender","type":"bytes32"},{"internalType":"uint64","name":"provided","type":"uint64"},{"internalType":"uint64","name":"expected","type":"uint64"}],"name":"SenderNonceTooLow","type":"error"},{"inputs":[],"name":"ZeroAddressVerifier","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"indexed":true,"internalType":"bytes16","name":"commitmentLog10","type":"bytes16"},{"indexed":false,"internalType":"bytes16","name":"commitmentLog8","type":"bytes16"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"}],"name":"BatchFinalized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"sender","type":"bytes32"},{"indexed":false,"internalType":"uint64","name":"newNonce","type":"uint64"}],"name":"NonceAdvanced","type":"event"},{"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"batchCommitmentsLog10","outputs":[{"internalType":"bytes16","name":"","type":"bytes16"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"batchCommitmentsLog8","outputs":[{"internalType":"bytes16","name":"","type":"bytes16"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"internalType":"bytes32","name":"otherTraceRoot","type":"bytes32"}],"name":"crossBoundRoot","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"}],"name":"isBatchFinalized","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"senderNonces","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"components":[{"components":[{"internalType":"bytes32","name":"traceRoot","type":"bytes32"},{"internalType":"uint128","name":"oodsComboPos","type":"uint128"},{"internalType":"uint128","name":"oodsComboNeg","type":"uint128"},{"internalType":"bytes32","name":"compRoot","type":"bytes32"},{"internalType":"bytes32[]","name":"friLayerRoots","type":"bytes32[]"},{"internalType":"bytes32","name":"batchRoot","type":"bytes32"},{"internalType":"uint256","name":"treeDepth","type":"uint256"},{"internalType":"uint256","name":"nQueries","type":"uint256"}],"internalType":"struct QLSAVerifierRecursive.InnerPublics","name":"inner","type":"tuple"},{"internalType":"bytes","name":"outerProof","type":"bytes"},{"internalType":"bytes16","name":"outerCommitment","type":"bytes16"},{"internalType":"bytes","name":"outerHints","type":"bytes"},{"internalType":"uint128[]","name":"lastLayerEvals","type":"uint128[]"}],"internalType":"struct BatchRegistryV7.RecursiveBundle","name":"bundle10","type":"tuple"},{"components":[{"components":[{"internalType":"bytes32","name":"traceRoot","type":"bytes32"},{"internalType":"uint128","name":"oodsComboPos","type":"uint128"},{"internalType":"uint128","name":"oodsComboNeg","type":"uint128"},{"internalType":"bytes32","name":"compRoot","type":"bytes32"},{"internalType":"bytes32[]","name":"friLayerRoots","type":"bytes32[]"},{"internalType":"bytes32","name":"batchRoot","type":"bytes32"},{"internalType":"uint256","name":"treeDepth","type":"uint256"},{"internalType":"uint256","name":"nQueries","type":"uint256"}],"internalType":"struct QLSAVerifierRecursive.InnerPublics","name":"inner","type":"tuple"},{"internalType":"bytes","name":"outerProof","type":"bytes"},{"internalType":"bytes16","name":"outerCommitment","type":"bytes16"},{"internalType":"bytes","name":"outerHints","type":"bytes"},{"internalType":"uint128[]","name":"lastLayerEvals","type":"uint128[]"}],"internalType":"struct BatchRegistryV7.RecursiveBundle","name":"bundle8","type":"tuple"}],"name":"submitBatch","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"components":[{"components":[{"internalType":"bytes32","name":"traceRoot","type":"bytes32"},{"internalType":"uint128","name":"oodsComboPos","type":"uint128"},{"internalType":"uint128","name":"oodsComboNeg","type":"uint128"},{"internalType":"bytes32","name":"compRoot","type":"bytes32"},{"internalType":"bytes32[]","name":"friLayerRoots","type":"bytes32[]"},{"internalType":"bytes32","name":"batchRoot","type":"bytes32"},{"internalType":"uint256","name":"treeDepth","type":"uint256"},{"internalType":"uint256","name":"nQueries","type":"uint256"}],"internalType":"struct QLSAVerifierRecursive.InnerPublics","name":"inner","type":"tuple"},{"internalType":"bytes","name":"outerProof","type":"bytes"},{"internalType":"bytes16","name":"outerCommitment","type":"bytes16"},{"internalType":"bytes","name":"outerHints","type":"bytes"},{"internalType":"uint128[]","name":"lastLayerEvals","type":"uint128[]"}],"internalType":"struct BatchRegistryV7.RecursiveBundle","name":"bundle10","type":"tuple"},{"components":[{"components":[{"internalType":"bytes32","name":"traceRoot","type":"bytes32"},{"internalType":"uint128","name":"oodsComboPos","type":"uint128"},{"internalType":"uint128","name":"oodsComboNeg","type":"uint128"},{"internalType":"bytes32","name":"compRoot","type":"bytes32"},{"internalType":"bytes32[]","name":"friLayerRoots","type":"bytes32[]"},{"internalType":"bytes32","name":"batchRoot","type":"bytes32"},{"internalType":"uint256","name":"treeDepth","type":"uint256"},{"internalType":"uint256","name":"nQueries","type":"uint256"}],"internalType":"struct QLSAVerifierRecursive.InnerPublics","name":"inner","type":"tuple"},{"internalType":"bytes","name":"outerProof","type":"bytes"},{"internalType":"bytes16","name":"outerCommitment","type":"bytes16"},{"internalType":"bytes","name":"outerHints","type":"bytes"},{"internalType":"uint128[]","name":"lastLayerEvals","type":"uint128[]"}],"internalType":"struct BatchRegistryV7.RecursiveBundle","name":"bundle8","type":"tuple"},{"internalType":"bytes32[]","name":"senders","type":"bytes32[]"},{"internalType":"uint64[]","name":"newNonces","type":"uint64[]"}],"name":"submitBatchWithNonces","outputs":[],"stateMutability":"nonpayable","type":"function"}]""")


class OnchainSubmitterV7:
    """Wraps web3 interaction with BatchRegistryV7 (RECURSIVE bundles, MVP-8).

    The registry verifies, per V23 trace group, a STARK attesting that the inner
    VFRI11 proof was verified — not the inner proof itself. Both groups finalize
    in ONE transaction.

    Use this stack for PRODUCTION soundness. At ``n_queries=20`` (130-bit) direct
    verification of a V23 group no longer fits an Ethereum transaction, while this
    route finalizes the whole batch in one (~13.13M gas measured). Below roughly 2
    queries the direct v7 stack is cheaper — see ``docs/conclusions.md``.
    """

    _EXPECTED_KIND = _RECURSIVE
    _EXPECTED_REGISTRY = "BatchRegistryV7"
    _LOG_TAG = "V7reg"

    def __init__(
        self,
        rpc_url: str,
        private_key: str,
        registry_address: str,
        gas_limit: int = 16_700_000,
        confirm_timeout_s: int = 180,
    ) -> None:
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        if not self.w3.is_connected():
            raise RuntimeError(f"Cannot connect to RPC: {rpc_url}")
        self.account = self.w3.eth.account.from_key(private_key)
        self.registry = self.w3.eth.contract(
            address=Web3.to_checksum_address(registry_address),
            abi=_REGISTRY_V7_ABI,
        )
        require_registry_kind(
            self.w3, registry_address, self._EXPECTED_KIND, self._EXPECTED_REGISTRY
        )
        self.gas_limit = gas_limit
        self.confirm_timeout_s = confirm_timeout_s
        logger.info(
            "submitter%s ready: account=%s chain=%d",
            self._LOG_TAG, self.account.address, self.w3.eth.chain_id,
        )
        logger.info("stack: recursive proofs (BatchRegistryV7), one atomic transaction")

    @classmethod
    def from_env(cls) -> "OnchainSubmitterV7":
        rpc_url = os.environ["RPC_URL"]
        private_key = os.environ.get("PRIVATE_KEY") or os.environ["DEPLOYER_PRIVATE_KEY"]
        registry_address = os.environ["REGISTRY_ADDRESS"]
        return cls(rpc_url=rpc_url, private_key=private_key, registry_address=registry_address)

    @staticmethod
    def _bundle_tuple(b) -> tuple:  # type: ignore[no-untyped-def]
        """Convert a ``stark.prover.RecursiveBundle`` into the ABI tuple.

        QM31 scalars arrive as decimal strings (they are u128) and roots as 0x-hex;
        web3 wants ints and bytes respectively.
        """
        inner = (
            bytes.fromhex(b.trace_root[2:]),
            int(b.oods_combo_pos),
            int(b.oods_combo_neg),
            bytes.fromhex(b.comp_root[2:]),
            [bytes.fromhex(r[2:]) for r in b.fri_layer_roots],
            bytes.fromhex(b.batch_root[2:]),
            int(b.tree_depth),
            int(b.n_queries),
        )
        return (
            inner,
            bytes(b.outer_proof),
            _decode_commitment16(b.outer_commitment, "outer_commitment"),
            bytes(b.outer_hints),
            [int(v) for v in b.last_layer_evals],
        )

    def _send(self, fn) -> str:  # type: ignore[no-untyped-def]
        # "pending" rather than the default "latest": the deploying account may
        # have transactions mined between the read and this send, and a stale
        # count fails with "nonce too low" before the call is even attempted.
        nonce = self.w3.eth.get_transaction_count(self.account.address, "pending")
        tx = fn.build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": self.gas_limit,
            "gasPrice": self.w3.eth.gas_price,
        })
        signed = self.account.sign_transaction(tx)
        return self.w3.eth.send_raw_transaction(signed.raw_transaction).hex()

    def submit_batch_with_nonces(
        self,
        merkle_root: bytes,
        bundles,  # stark.prover.V23RecursiveBundlesResult
        senders: list[bytes],
        new_nonces: list[int],
    ) -> str:
        """Finalize a batch from two cross-bound recursive bundles, with nonces.

        The registry recomputes the cross-binding itself and reverts with
        ``CrossBindingMismatch`` if either bundle was not produced against the
        other group's trace root — so a mismatched pair fails before any proof is
        verified.
        """
        if len(senders) != len(new_nonces):
            raise ValueError("senders and new_nonces must have equal length")
        tx_hex = self._send(self.registry.functions.submitBatchWithNonces(
            _as_bytes32(merkle_root, "merkle_root"),
            self._bundle_tuple(bundles.log10),
            self._bundle_tuple(bundles.log8),
            _validate_senders(senders),
            new_nonces,
        ))
        logger.info("%s submitBatchWithNonces: %s", self._LOG_TAG, tx_hex)
        return tx_hex

    def wait_and_verify(self, tx_hash: str, merkle_root: bytes) -> bool:
        """Wait for confirmation, then read back whether the batch is finalized."""
        logger.info("waiting for confirmation (timeout=%ds)…", self.confirm_timeout_s)
        h = tx_hash if tx_hash.startswith("0x") else "0x" + tx_hash
        receipt = self.w3.eth.wait_for_transaction_receipt(h, timeout=self.confirm_timeout_s)
        if receipt.status != 1:
            logger.error("%s transaction reverted: %s", self._LOG_TAG, tx_hash)
            return False
        root_b32 = _as_bytes32(merkle_root, "merkle_root")
        finalized: bool = self.registry.functions.isBatchFinalized(root_b32).call()
        if finalized:
            c10 = self.registry.functions.batchCommitmentsLog10(root_b32).call()
            logger.info(
                "%s batch finalized: root=%s commitmentLog10=%s gasUsed=%d",
                self._LOG_TAG, root_b32.hex()[:16], c10.hex(), receipt.gasUsed,
            )
        return finalized


