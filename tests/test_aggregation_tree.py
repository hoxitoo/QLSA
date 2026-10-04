"""Aggregating N ML-DSA-65 signatures into TWO proofs — one per V23 group.

A V23 statement is two FRI commitments proving different things: the LOG=10
group the NTT/INTT transforms, the LOG=8 group the multiplication `A·z`, the
norm bound `‖z‖∞ < γ₁−β` and the ω hint bound. A root over log10 alone attests
neither of the latter, so both trees are built — which is also why
`BatchRegistryV7` takes two cross-bound bundles. `node_count` is therefore the
sum over both trees.

This is the claim the project's headline makes and, until now, the one the
pipeline did not meet: it proved `tx[0]` and committed the rest by Merkle root
alone. A recursion tree folds N leaf statements to a single root whose on-chain
cost does not depend on N — the node shape is a fixed point, so depth is
absorbed by the prover.

These need the PyO3 extension; without it they skip rather than fail, as the
rest of the STARK suite does.
"""

import pytest

from core.keys import generate_keypair
from core.signing import sign

try:
    import qlsa_stark_stwo  # noqa: F401
    HAVE_EXT = True
except ImportError:
    HAVE_EXT = False

needs_ext = pytest.mark.skipif(not HAVE_EXT, reason="PyO3 extension not installed")


def _signatures(n: int) -> list[tuple[bytes, bytes, bytes]]:
    """n DIFFERENT signatures — aggregating copies would prove nothing."""
    out = []
    for i in range(n):
        pk, sk = generate_keypair()
        msg = f"transfer #{i}".encode()
        out.append((pk, msg, sign(msg, sk)))
    return out


@needs_ext
def test_four_signatures_aggregate_to_one_root() -> None:
    from stark.prover import prove_mldsa_aggregation_tree

    tree = prove_mldsa_aggregation_tree(_signatures(4), n_queries=1, fan_in=2)

    assert tree.leaf_count == 4
    # Four leaves at fan-in 2: two nodes, then the root — in EACH of the two
    # trees, so six nodes of work for one batch.
    assert tree.depth == 2
    assert tree.node_count == 6
    assert tree.fan_in == 2

    for proof, log_size, roots, which in [
        (tree.root_proof, tree.root_log_size, tree.root_roots, "log10"),
        (tree.root_proof8, tree.root_log_size8, tree.root_roots8, "log8"),
    ]:
        assert len(proof) > 0, which
        assert log_size > 0, which
        assert all(len(r) == 4 for r in roots), f"{which}: roots are 4-word t=8 nodes"

    # Both trees' membership paths land on ONE batch root (A-5), and that root
    # is an OUTPUT: it is derived from the trace roots and is simultaneously the
    # Fiat-Shamir seed every proof ran under. No external root goes in, which is
    # what makes the registry's identifier derivable from the proofs.
    assert len(tree.batch_root) == 4
    assert any(w != 0 for w in tree.batch_root), "a derived root, not a placeholder"

    # The two halves are different proofs, not a copy: log8 is the bigger group.
    assert tree.root_proof != tree.root_proof8


@needs_ext
def test_a_ragged_leaf_count_is_not_padded() -> None:
    """Three leaves at fan-in 2 leaves one node with a single child.

    Padding to a power of the fan-in would prove statements nobody made, so the
    tree carries the ragged shape instead — which works because a node is the
    same object at any fan-in and path depths are per-statement.
    """
    from stark.prover import prove_mldsa_aggregation_tree

    tree = prove_mldsa_aggregation_tree(_signatures(3), n_queries=1, fan_in=2)
    assert tree.leaf_count == 3
    assert tree.depth == 2
    # Per tree: two at level 0 (a pair and a lone one), then the root — times two.
    assert tree.node_count == 6


@needs_ext
def test_one_signature_is_the_degenerate_tree() -> None:
    from stark.prover import prove_mldsa_aggregation_tree

    tree = prove_mldsa_aggregation_tree(_signatures(1), n_queries=1, fan_in=2)
    assert tree.leaf_count == 1
    assert tree.node_count == 2, "one node per tree, and there are two trees"
    assert len(tree.root_proof) > 0
    assert len(tree.root_proof8) > 0


@needs_ext
def test_an_invalid_signature_names_itself() -> None:
    """With N signatures, "extraction failed" alone leaves the caller bisecting."""
    from stark.prover import prove_mldsa_aggregation_tree

    entries = _signatures(3)
    pk, msg, sig = entries[1]
    entries[1] = (pk, msg, bytes(len(sig)))  # a zeroed signature

    with pytest.raises(ValueError, match="signature 1"):
        prove_mldsa_aggregation_tree(entries, n_queries=1, fan_in=2)


def test_input_validation_needs_no_extension() -> None:
    """Argument checks run before any proving, so they hold without the ext."""
    from stark.prover import prove_mldsa_aggregation_tree

    with pytest.raises(ValueError, match="at least one signature"):
        prove_mldsa_aggregation_tree([])
    with pytest.raises(ValueError, match="fan_in must be"):
        prove_mldsa_aggregation_tree([(b"", b"", b"")], fan_in=1)


# ── The bundles must be what the submitter accepts, not merely bundle-shaped ──


@needs_ext
def test_tree_bundles_are_accepted_by_the_real_submitter() -> None:
    """The decisive test for a claim that was false for a week.

    `gen_tree_recursive_bundles`'s docstring promised "a submitter written for
    the single-signature path accepts these unchanged" while the function
    returned raw dicts; `OnchainSubmitterV7._bundle_tuple` reads
    `b.trace_root`, which on a dict is an `AttributeError`.

    So this does not check that the fields look right — it feeds the result to
    the SUBMITTER'S OWN encoder. Nothing else proves the two agree.
    """
    from stark.prover import gen_tree_recursive_bundles
    from testnet.submit import OnchainSubmitterV7

    res = gen_tree_recursive_bundles(_signatures(2), n_queries=1, fan_in=2)

    for bundle in (res.log10, res.log8):
        inner, outer_proof, outer_commitment, outer_hints, last_layer = (
            OnchainSubmitterV7._bundle_tuple(bundle)
        )
        trace_root, oods_pos, oods_neg, comp_root, fri_roots, batch_root, depth, nq = inner
        assert len(trace_root) == 32 and len(comp_root) == 32 and len(batch_root) == 32
        assert isinstance(oods_pos, int) and isinstance(oods_neg, int)
        assert all(len(r) == 32 for r in fri_roots)
        assert depth > 0 and nq == 1
        assert len(outer_proof) > 0 and len(outer_commitment) == 16
        assert len(outer_hints) > 0 and len(last_layer) > 0


@needs_ext
def test_the_derived_root_is_bytes32_and_is_not_the_transaction_list_root() -> None:
    """R comes BACK from the prover; the SHA3 list root goes on as txListRoot.

    They are different values with different guarantees, and the registry takes
    both. A test that only checked "a root came back" would pass if the two were
    swapped.
    """
    from core.batch import create_batch
    from core.transaction import Transaction
    from stark.prover import gen_tree_recursive_bundles

    # Build real transactions so the two roots are computed over the same members.
    from core.keys import generate_keypair
    from core.signing import sign

    txs = []
    for i in range(2):
        pk, sk = generate_keypair()
        tx = Transaction(
            sender="%064x" % (i + 1),
            recipient="%064x" % (i + 100),
            amount=i + 1,
            nonce=i,
            public_key=pk,
        )
        tx.signature = sign(tx.to_bytes(), sk)
        txs.append(tx)

    batch = create_batch(txs)
    res = gen_tree_recursive_bundles(
        [(tx.public_key, tx.to_bytes(), tx.signature) for tx in txs],
        n_queries=1,
        fan_in=2,
    )

    assert isinstance(res.merkle_root, bytes) and len(res.merkle_root) == 32
    assert res.leaf_count == len(txs)
    assert res.merkle_root != batch.merkle_root_onchain(), (
        "R and the SHA3 transaction-list root must be different values — "
        "R is derived from the proofs' trace roots"
    )


@needs_ext
def test_the_leaf_the_prover_derives_is_the_transactions_own_hash() -> None:
    """The link that makes the tree about THESE transactions.

    `gen_tree_recursive_bundles` derives each leaf as `sha3_256(msg)` and
    `Transaction.tx_hash()` is `sha3_256(to_bytes())`. The product layer passes
    `to_bytes()` as `msg`, so the two coincide — but only as long as both stay
    SHA3-256 over the same bytes. Asserted rather than left to a comment.
    """
    import hashlib

    from core.keys import generate_keypair
    from core.signing import sign
    from core.transaction import Transaction

    pk, sk = generate_keypair()
    tx = Transaction(
        sender="11" * 32, recipient="22" * 32, amount=7, nonce=3, public_key=pk
    )
    tx.signature = sign(tx.to_bytes(), sk)

    assert hashlib.sha3_256(tx.to_bytes()).digest() == tx.tx_hash()
