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

    After ``wipe()`` is called (or the context manager exits), further calls
    to ``sign_transaction()`` raise ``ValueError``.
    """

    address: str
    public_key: bytes
    algorithm: str
    _private_key: bytearray = field(repr=False)
    _wiped: bool = field(default=False, init=False, repr=False, compare=False)

    @classmethod
    def generate(cls, algorithm: str = DEFAULT_ALGORITHM) -> Wallet:
        pub, priv = generate_keypair(algorithm)
        return cls(
            address=derive_address(pub),
            public_key=pub,
            algorithm=algorithm,
            _private_key=priv,
        )

    @property
    def public_key_hex(self) -> str:
        """Hex-encoded public key (convenient for display and HTTP payloads)."""
        return self.public_key.hex()

    @property
    def is_wiped(self) -> bool:
        """True after ``wipe()`` has been called."""
        return self._wiped

    def sign_transaction(self, tx: Transaction) -> Transaction:
        """Sign *tx* in-place and return it.

        Raises ``ValueError`` if the private key has already been wiped.
        """
        if self._wiped:
            raise ValueError(
                "Wallet private key has been wiped — create a new Wallet.generate() "
                "to sign transactions"
            )
        tx.signature = sign(tx.to_bytes(), self._private_key, self.algorithm)
        return tx

    def wipe(self) -> None:
        """Zero the private key. The wallet is unusable after this call."""
        wipe_key(self._private_key)
        self._wiped = True

    def __enter__(self) -> Wallet:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.wipe()
