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

ROOT = bytes(range(32))


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

    tree = prove_mldsa_aggregation_tree(_signatures(4), ROOT, n_queries=1, fan_in=2)

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

    # Both trees' membership paths land on ONE batch root (A-5).
    assert len(tree.batch_root) == 4

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

    tree = prove_mldsa_aggregation_tree(_signatures(3), ROOT, n_queries=1, fan_in=2)
    assert tree.leaf_count == 3
    assert tree.depth == 2
    # Per tree: two at level 0 (a pair and a lone one), then the root — times two.
    assert tree.node_count == 6


@needs_ext
def test_one_signature_is_the_degenerate_tree() -> None:
    from stark.prover import prove_mldsa_aggregation_tree

    tree = prove_mldsa_aggregation_tree(_signatures(1), ROOT, n_queries=1, fan_in=2)
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
        prove_mldsa_aggregation_tree(entries, ROOT, n_queries=1, fan_in=2)


def test_input_validation_needs_no_extension() -> None:
    """Argument checks run before any proving, so they hold without the ext."""
    from stark.prover import prove_mldsa_aggregation_tree

    with pytest.raises(ValueError, match="at least one signature"):
        prove_mldsa_aggregation_tree([], ROOT)
    with pytest.raises(ValueError, match="fan_in must be"):
        prove_mldsa_aggregation_tree([(b"", b"", b"")], ROOT, fan_in=1)
    with pytest.raises(ValueError, match="32 bytes"):
        prove_mldsa_aggregation_tree([(b"", b"", b"")], b"short")
