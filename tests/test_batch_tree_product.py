"""Ф2.3: the PRODUCT proves every signature in the batch, not just ``tx[0]``.

This file exists because of a gap between what was reported and what shipped.
By 2026-10-04 the aggregation tree, the derived batch identifier R and a
measured 14,663,950-gas single-transaction submission all worked — in Rust, and
in a Solidity end-to-end test. ``aggregator/batcher.py`` meanwhile still called
``prove_mldsa_sig_for_protocol(..., pk=tx0.public_key, ...)``, and
``grep gen_tree_recursive_bundles aggregator/ testnet/ sdk/`` returned nothing.
So "N signatures in one proof" was a property of the Rust path, not of the
product, and Ф2 had been reported complete anyway.

The condition ROADMAP § Ф2.3 sets is deliberately a TEST rather than an
observation: *a batch of N transactions finalizes and ALL N carry a proof.*
Observation is what failed last time — the logs said "proofs for tx[0]" in
plain sight for weeks.

Proving a tree over N real ML-DSA-65 signatures costs roughly 40 s per
signature here, so these use the smallest N that can distinguish "all" from
"the first one": N=2. The one test that needs N=3 says why.
"""

from __future__ import annotations

import pytest

from aggregator.batcher import Batcher
from aggregator.mempool import Mempool
from core.keys import generate_keypair, wipe_key
from core.signing import sign
from core.transaction import Transaction

try:
    import qlsa_stark_stwo  # noqa: F401

    HAVE_EXT = True
except ImportError:
    HAVE_EXT = False

needs_ext = pytest.mark.skipif(not HAVE_EXT, reason="PyO3 extension not installed")


def _signed_txs(n: int) -> tuple[list[Transaction], list[bytes]]:
    """n signed transactions from n DIFFERENT keys, with their secret keys."""
    txs, privs = [], []
    for i in range(n):
        pk, sk = generate_keypair()
        tx = Transaction(
            sender="%064x" % (i + 1),
            recipient="%064x" % (i + 1000),
            amount=i + 1,
            nonce=i,
            public_key=pk,
        )
        tx.signature = sign(tx.to_bytes(), sk)
        txs.append(tx)
        privs.append(sk)
    return txs, privs


def _batch_with_tree(n: int) -> object:
    mp = Mempool()
    txs, privs = _signed_txs(n)
    for tx in txs:
        mp.add(tx)
    try:
        return Batcher(mp, min_batch_size=1).force_batch(prove_tree=True)
    finally:
        for sk in privs:
            wipe_key(sk)


# ── The Ф2.3 completion condition ─────────────────────────────────────────────


@needs_ext
def test_a_batch_of_n_yields_one_proof_covering_all_n() -> None:
    """THE test Ф2.3 is defined by.

    `tree_leaf_count == len(transactions)` is the whole claim: one pair of
    bundles, every member of the batch inside it. With the old tx[0] path this
    is None, because no tree is proved at all.
    """
    n = 2
    result = _batch_with_tree(n)

    assert result is not None
    assert len(result.batch.transactions) == n
    assert result.has_tree_proof, "the batch carries no tree proof"
    assert result.tree_leaf_count == n, (
        f"proof covers {result.tree_leaf_count} of {n} transactions"
    )


@needs_ext
def test_the_onchain_identifier_is_derived_not_the_transaction_list_hash() -> None:
    """V5 and V7 mean different things by `merkleRoot`; both are present here.

    R is derived from the proofs' trace roots and cannot be computed without the
    prover. The SHA3 list root still exists and goes on as `txListRoot`. A test
    that only checked "a root is present" would pass with the two swapped, which
    is the specific mistake this pair of fields invites.
    """
    result = _batch_with_tree(2)

    r = result.tree_merkle_root
    tx_list = result.tx_list_root

    assert isinstance(r, bytes) and len(r) == 32
    assert isinstance(tx_list, bytes) and len(tx_list) == 32
    assert r != tx_list
    # The pre-proof identity is still exactly the batch's Merkle root — the
    # mempool, the history index and _proof_retries depend on that.
    assert tx_list == result.batch.merkle_root[:32]
    # R must be non-zero: BatchRegistryV7 reverts with InvalidMerkleRoot on zero.
    # Its leading 16 bytes ARE zero (a Poseidon2 t=8 node is four u32 words in
    # bytes[16..32]), so a "first 8 bytes non-zero" check would fail wrongly.
    assert r != bytes(32)
    assert r[16:] != bytes(16)


@needs_ext
def test_the_bundles_go_straight_into_the_v7_submitter() -> None:
    """Shaped for the contract, checked against the submitter's own encoder."""
    from testnet.submit import OnchainSubmitterV7

    result = _batch_with_tree(2)

    for bundle in (result.tree_bundles.log10, result.tree_bundles.log8):
        inner, outer_proof, outer_commitment, outer_hints, last_layer = (
            OnchainSubmitterV7._bundle_tuple(bundle)
        )
        assert len(inner[0]) == 32  # traceRoot
        assert len(outer_proof) > 0
        assert len(outer_commitment) == 16
        assert len(last_layer) > 0

    # The two groups prove different halves of each V23 statement, so their
    # trace roots must differ — equal roots would mean one group was submitted
    # twice and half the arithmetic went unattested.
    assert (
        result.tree_bundles.log10.trace_root != result.tree_bundles.log8.trace_root
    )


@needs_ext
def test_the_two_bundles_are_cross_bound_to_each_other() -> None:
    """`BatchRegistryV7._finalize` recomputes this and reverts if it disagrees.

    boundRoot10 = keccak256(merkleRoot ‖ traceRoot8)
    boundRoot8  = keccak256(merkleRoot ‖ traceRoot10)

    Checked here against an independent keccak rather than against the
    contract, so the test fails if the prover's binding drifts from the rule
    the contract applies.
    """
    # eth_utils ships with web3, which testnet/ already requires — no new dep.
    from eth_utils import keccak

    result = _batch_with_tree(2)
    b10, b8 = result.tree_bundles.log10, result.tree_bundles.log8
    r = result.tree_merkle_root

    def bound(other_trace_root_hex: str) -> str:
        other = bytes.fromhex(other_trace_root_hex.removeprefix("0x"))
        return "0x" + keccak(r + other).hex()

    assert b10.batch_root == bound(b8.trace_root)
    assert b8.batch_root == bound(b10.trace_root)


# ── The tree is opt-in, and the direct path is unchanged ──────────────────────


def test_tree_is_not_proved_unless_asked() -> None:
    """`prove_tree` defaults off; cost grows with N, so it is never implicit."""
    mp = Mempool()
    txs, privs = _signed_txs(2)
    for tx in txs:
        mp.add(tx)
    result = Batcher(mp, min_batch_size=1).force_batch()
    for sk in privs:
        wipe_key(sk)

    assert result is not None
    assert result.has_tree_proof is False
    assert result.tree_leaf_count is None
    assert result.tree_merkle_root is None


def test_tx_list_root_and_merkle_root_onchain_are_the_same_value() -> None:
    """Two names for the pre-proof root, because two call sites mean it.

    Needs no extension: it is a property of the batch, not of a proof.
    """
    mp = Mempool()
    txs, privs = _signed_txs(2)
    for tx in txs:
        mp.add(tx)
    result = Batcher(mp, min_batch_size=1).force_batch()
    for sk in privs:
        wipe_key(sk)

    assert result.tx_list_root == result.merkle_root_onchain


@needs_ext
def test_a_three_transaction_batch_is_not_padded_to_four() -> None:
    """N=3 specifically: a ragged leaf count must not silently become a power of 2.

    Padding would make `tree_leaf_count` disagree with the batch size, and a
    padded leaf is a leaf an adversary could also supply.
    """
    result = _batch_with_tree(3)

    assert result.tree_leaf_count == 3
    assert len(result.batch.transactions) == 3
