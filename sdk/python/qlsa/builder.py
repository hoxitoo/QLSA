from __future__ import annotations

from core.transaction import Transaction
from .wallet import Wallet

_SENTINEL = object()


class TransactionBuilder:
    """Builds signed transactions from a Wallet.

    Tracks a per-builder nonce counter so callers can omit ``nonce`` for
    sequential transactions:

        with Wallet.generate() as wallet:
            builder = TransactionBuilder(wallet)
            tx0 = builder.build(recipient="aa" * 32, amount=1)   # nonce=0
            tx1 = builder.build(recipient="bb" * 32, amount=2)   # nonce=1

    Pass an explicit ``nonce`` to override the counter without advancing it:

        tx = builder.build(recipient="cc" * 32, amount=3, nonce=42)
    """

    def __init__(self, wallet: Wallet, *, start_nonce: int = 0) -> None:
        self._wallet = wallet
        self._nonce = start_nonce

    def build(self, *, recipient: str, amount: int, nonce: object = _SENTINEL) -> Transaction:
        """Create and sign a transaction.

        If *nonce* is omitted the builder's internal counter is used and
        then incremented. Pass an explicit non-negative integer to pin the
        nonce without affecting the counter.
        """
        if nonce is _SENTINEL:
            effective_nonce = self._nonce
            self._nonce += 1
        else:
            if not isinstance(nonce, int) or nonce < 0:
                raise TypeError("nonce must be a non-negative integer")
            effective_nonce = nonce
        tx = Transaction(
            sender=self._wallet.address,
            recipient=recipient,
            amount=amount,
            nonce=effective_nonce,
            public_key=self._wallet.public_key,
        )
        return self._wallet.sign_transaction(tx)

    @property
    def next_nonce(self) -> int:
        """The nonce that will be used by the next auto-nonce call to build()."""
        return self._nonce
