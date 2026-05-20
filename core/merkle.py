import hashlib
import hmac


def _hash_leaf(data: bytes) -> bytes:
    # Domain-separate leaf hashes from internal node hashes
    return hashlib.sha3_512(b"\x00" + data).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha3_512(b"\x01" + left + right).digest()


def build_merkle_tree(leaves: list[bytes]) -> list[list[bytes]]:
    """
    Build a complete Merkle tree from raw leaf data.
    Returns a list of levels: tree[0] = leaf hashes, tree[-1] = [root].
    Odd-length levels duplicate the last element.
    """
    if not leaves:
        raise ValueError("Cannot build Merkle tree from empty list")

    current = [_hash_leaf(leaf) for leaf in leaves]
    tree = [current]

    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + [current[-1]]  # duplicate last for odd length
        next_level = [
            _hash_node(current[i], current[i + 1])
            for i in range(0, len(current), 2)
        ]
        tree.append(next_level)
        current = next_level

    return tree


def get_merkle_root(tree: list[list[bytes]]) -> bytes:
    return tree[-1][0]


def get_merkle_proof(tree: list[list[bytes]], index: int) -> list[tuple[bytes, str]]:
    """
    Return a proof for the leaf at `index`.
    Each element is (sibling_hash, side) where side is 'left' or 'right'.
    """
    n_leaves = len(tree[0])
    if index < 0 or index >= n_leaves:
        raise IndexError(
            f"leaf index {index} is out of range [0, {n_leaves})"
        )
    proof: list[tuple[bytes, str]] = []

    for level in tree[:-1]:
        # Pad level to even length (mirrors build_merkle_tree)
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        if index % 2 == 0:
            sibling_index = index + 1
            side = "right"
        else:
            sibling_index = index - 1
            side = "left"
        proof.append((level[sibling_index], side))
        index //= 2

    return proof


def verify_merkle_proof(
    leaf: bytes,
    proof: list[tuple[bytes, str]],
    root: bytes,
) -> bool:
    current = _hash_leaf(leaf)
    for sibling, side in proof:
        if side == "right":
            current = _hash_node(current, sibling)
        else:
            current = _hash_node(sibling, current)
    return hmac.compare_digest(current, root)
