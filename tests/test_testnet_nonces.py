"""Tests for testnet/e2e.py's off-chain -> on-chain nonce mapping.

Regression coverage for a bug that only ever surfaced on a real submit: the
on-chain registries (BatchRegistryV4/V5/V6) store 0 for a sender that has never
been seen and enforce ``newNonce > stored``, so the smallest submittable nonce is
1.  Transaction nonces are 0-based, so passing them through unchanged made every
non-dry-run ``testnet.e2e`` submission revert with
``SenderNonceTooLow(provided=0, expected=1)`` for the sender of tx[0].
"""

from testnet.e2e import build_sender_nonces
from core.transaction import Transaction


def _tx(sender_hex: str, nonce: int) -> Transaction:
    """Minimal Transaction carrying only what build_sender_nonces reads."""
    return Transaction(
        sender=sender_hex,
        recipient=sender_hex,
        amount=1,
        nonce=nonce,
        public_key=b"\x00" * 1952,
    )


A = "aa" * 32
B = "bb" * 32


def test_shifts_zero_based_nonce_onto_the_one_based_registry() -> None:
    """A sender's first transaction (nonce 0) must submit as on-chain nonce 1."""
    got = build_sender_nonces([_tx(A, 0)])
    assert got == {bytes.fromhex(A): 1}


def test_never_emits_a_zero_nonce() -> None:
    """Zero is unsubmittable on-chain, so it must never appear in the output."""
    txs = [_tx(A, 0), _tx(B, 0)]
    assert 0 not in build_sender_nonces(txs).values()


def test_keeps_the_highest_nonce_per_sender() -> None:
    """One entry per unique sender, carrying that sender's highest nonce."""
    txs = [_tx(A, 0), _tx(A, 5), _tx(A, 2), _tx(B, 7)]
    assert build_sender_nonces(txs) == {
        bytes.fromhex(A): 6,   # 5 + 1
        bytes.fromhex(B): 8,   # 7 + 1
    }


def test_out_of_order_transactions_still_yield_the_maximum() -> None:
    """Order within the batch must not change the result."""
    ascending = build_sender_nonces([_tx(A, 1), _tx(A, 4)])
    descending = build_sender_nonces([_tx(A, 4), _tx(A, 1)])
    assert ascending == descending == {bytes.fromhex(A): 5}


def test_sender_keys_are_32_byte_identifiers() -> None:
    """Keys must be the raw 32-byte sender hash the contracts index by."""
    for key in build_sender_nonces([_tx(A, 0), _tx(B, 3)]):
        assert isinstance(key, bytes)
        assert len(key) == 32


def test_empty_batch_yields_no_nonces() -> None:
    assert build_sender_nonces([]) == {}


def test_mapping_is_strictly_monotonic_in_the_tx_nonce() -> None:
    """Distinct tx nonces must map to distinct, correctly ordered on-chain nonces.

    The registry rejects ``newNonce <= stored``, so a batch submitted after an
    earlier one must carry a strictly larger value for the same sender.
    """
    earlier = build_sender_nonces([_tx(A, 3)])[bytes.fromhex(A)]
    later = build_sender_nonces([_tx(A, 4)])[bytes.fromhex(A)]
    assert later > earlier
