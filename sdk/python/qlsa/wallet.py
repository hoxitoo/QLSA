from __future__ import annotations

from dataclasses import dataclass, field
from types import TracebackType

from core.keys import DEFAULT_ALGORITHM, derive_address, generate_keypair, wipe_key
from core.signing import sign
from core.transaction import Transaction


@dataclass
class Wallet:
    """Holds an ML-DSA keypair for signing transactions.

    Use as a context manager to guarantee key cleanup:

        with Wallet.generate() as w:
            tx = w.sign_transaction(tx)
        # private key is zeroed here
    """

    address: str
    public_key: bytes
    algorithm: str
    _private_key: bytearray = field(repr=False)

    @classmethod
    def generate(cls, algorithm: str = DEFAULT_ALGORITHM) -> Wallet:
        pub, priv = generate_keypair(algorithm)
        return cls(
            address=derive_address(pub),
            public_key=pub,
            algorithm=algorithm,
            _private_key=priv,
        )

    def sign_transaction(self, tx: Transaction) -> Transaction:
        """Sign *tx* in-place and return it."""
        tx.signature = sign(tx.to_bytes(), self._private_key)
        return tx

    def wipe(self) -> None:
        """Zero the private key. The wallet is unusable after this call."""
        wipe_key(self._private_key)

    def __enter__(self) -> Wallet:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.wipe()
