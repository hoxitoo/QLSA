from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field


@dataclass
class Transaction:
    sender: str       # hex address derived from public_key
    recipient: str    # hex address of the receiver
    amount: int       # non-negative integer (smallest unit)
    nonce: int        # per-sender sequence number
    public_key: bytes # revealed at signing time

    # Set after calling signing.sign()
    signature: bytes | None = field(default=None, repr=False)

    _UINT64_MAX = (1 << 64) - 1

    def __post_init__(self) -> None:
        if self.amount < 1:
            raise ValueError("amount must be positive (at least 1)")
        if self.amount > self._UINT64_MAX:
            raise ValueError("amount must fit in uint64")
        if self.nonce < 0:
            raise ValueError("nonce must be non-negative")
        if self.nonce > self._UINT64_MAX:
            raise ValueError("nonce must fit in uint64")
        if len(self.sender) != 64 or not _is_hex(self.sender):
            raise ValueError("sender must be a 64-char hex address")
        if len(self.recipient) != 64 or not _is_hex(self.recipient):
            raise ValueError("recipient must be a 64-char hex address")
        if not self.public_key:
            raise ValueError("public_key must not be empty")

    def to_bytes(self) -> bytes:
        """Deterministic serialization of the signable fields (no signature)."""
        sender_b = bytes.fromhex(self.sender)
        recipient_b = bytes.fromhex(self.recipient)
        amount_b = struct.pack(">Q", self.amount)   # 8 bytes, big-endian
        nonce_b = struct.pack(">Q", self.nonce)     # 8 bytes, big-endian
        pubkey_len = struct.pack(">I", len(self.public_key))
        return sender_b + recipient_b + amount_b + nonce_b + pubkey_len + self.public_key

    def tx_hash(self) -> bytes:
        """SHA3-256 of the signable serialization."""
        return hashlib.sha3_256(self.to_bytes()).digest()


def _is_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False
