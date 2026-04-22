import pytest

from core.merkle import (
    build_merkle_tree,
    get_merkle_proof,
    get_merkle_root,
    verify_merkle_proof,
)


def _leaves(n: int) -> list[bytes]:
    return [f"leaf-{i}".encode() for i in range(n)]


def test_build_tree_single_leaf():
    tree = build_merkle_tree([b"only"])
    root = get_merkle_root(tree)
    assert isinstance(root, bytes)
    assert len(root) == 64  # SHA3-512 digest


def test_build_tree_empty_raises():
    with pytest.raises(ValueError, match="empty"):
        build_merkle_tree([])


@pytest.mark.parametrize("n", [1, 2, 3, 4, 7, 8, 100])
def test_root_is_bytes64(n):
    root = get_merkle_root(build_merkle_tree(_leaves(n)))
    assert len(root) == 64


def test_root_changes_when_leaf_changes():
    leaves = _leaves(8)
    root1 = get_merkle_root(build_merkle_tree(leaves))
    leaves[3] = b"modified"
    root2 = get_merkle_root(build_merkle_tree(leaves))
    assert root1 != root2


def test_root_is_deterministic():
    leaves = _leaves(16)
    r1 = get_merkle_root(build_merkle_tree(leaves))
    r2 = get_merkle_root(build_merkle_tree(leaves))
    assert r1 == r2


@pytest.mark.parametrize("n", [1, 2, 3, 4, 7, 8, 16, 100])
def test_proof_verify_all_indices(n):
    leaves = _leaves(n)
    tree = build_merkle_tree(leaves)
    root = get_merkle_root(tree)
    for i in range(n):
        proof = get_merkle_proof(tree, i)
        assert verify_merkle_proof(leaves[i], proof, root)


def test_proof_fails_for_wrong_leaf():
    leaves = _leaves(8)
    tree = build_merkle_tree(leaves)
    root = get_merkle_root(tree)
    proof = get_merkle_proof(tree, 0)
    assert not verify_merkle_proof(b"wrong-leaf", proof, root)


def test_proof_fails_for_wrong_root():
    leaves = _leaves(8)
    tree = build_merkle_tree(leaves)
    root = get_merkle_root(build_merkle_tree(_leaves(8)))
    proof = get_merkle_proof(tree, 0)
    # Use a different root
    bad_root = bytes(b ^ 0xFF for b in root)
    assert not verify_merkle_proof(leaves[0], proof, bad_root)
