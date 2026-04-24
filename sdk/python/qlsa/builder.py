from __future__ import annotations

from core.transaction import Transaction
from .wallet import Wallet


class TransactionBuilder:
    """Builds signed transactions from a Wallet.

    Example::

        with Wallet.generate() as wallet:
            builder = TransactionBuilder(wallet)
            tx = builder.build(recipient="aa" * 32, amount=100, nonce=0)
    """

    def __init__(self, wallet: Wallet) -> None:
        self._wallet = wallet

    def build(self, *, recipient: str, amount: int, nonce: int) -> Transaction:
        """Create and sign a transaction. Returns the signed Transaction."""
        tx = Transaction(
            sender=self._wallet.address,
            recipient=recipient,
            amount=amount,
            nonce=nonce,
            public_key=self._wallet.public_key,
        )
        return self._wallet.sign_transaction(tx)
