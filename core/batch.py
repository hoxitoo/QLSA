from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from core.keys import DEFAULT_ALGORITHM
from core.merkle import build_merkle_tree, get_merkle_root
from core.signing import verify
from core.transaction import Transaction


MAX_BATCH_SIZE = 3000
MIN_BATCH_SIZE = 1


class InvalidSignatureError(Exception):
    """Raised when a transaction's signature is missing or invalid."""


class BatchSizeError(Exception):
    """Raised when the number of transactions violates limits."""


@dataclass
class Batch:
    transactions: list[Transaction]
    merkle_root: bytes
    batch_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    # Set after calling stark.prover.prove_batch()
    stark_commitment: str | None = field(default=None, repr=False)

    def merkle_root_onchain(self) -> bytes:
        """First 32 bytes of the SHA3-512 Merkle root — use as bytes32 in Solidity.
        Python: batch.merkle_root_onchain()
        Solidity: BatchRegistry.submitBatch(merkleRoot, ...)
        """
        return self.merkle_root[:32]

    def stark_commitment_onchain(self) -> bytes:
        """Decode the hex stark_commitment to 8 raw bytes for Solidity bytes8.
        Raises ValueError if stark_commitment is not set.
        """
        if self.stark_commitment is None:
            raise ValueError("stark_commitment not set — call prove_batch() first")
        return bytes.fromhex(self.stark_commitment)


def create_batch(
    transactions: list[Transaction],
    algorithm: str = DEFAULT_ALGORITHM,
) -> Batch:
    """
    Validate all signatures, build a Merkle tree of tx hashes, return a Batch.
    Raises InvalidSignatureError on the first invalid/missing signature.
    Raises BatchSizeError if the list is empty or exceeds MAX_BATCH_SIZE.
    """
    n = len(transactions)
    if n < MIN_BATCH_SIZE:
        raise BatchSizeError(f"Batch must contain at least {MIN_BATCH_SIZE} transaction(s)")
    if n > MAX_BATCH_SIZE:
        raise BatchSizeError(f"Batch exceeds maximum size of {MAX_BATCH_SIZE} transactions")

    for i, tx in enumerate(transactions):
        if tx.signature is None:
            raise InvalidSignatureError(f"Transaction at index {i} is unsigned")
        ok = verify(tx.to_bytes(), tx.signature, tx.public_key, algorithm)
        if not ok:
            raise InvalidSignatureError(f"Invalid signature for transaction at index {i}")

    leaves = [tx.tx_hash() for tx in transactions]
    tree = build_merkle_tree(leaves)
    root = get_merkle_root(tree)

    return Batch(transactions=transactions, merkle_root=root)
