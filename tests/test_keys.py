import pytest

from core.keys import (
    DEFAULT_ALGORITHM,
    SUPPORTED_ALGORITHMS,
    derive_address,
    deserialize_public_key,
    generate_keypair,
    serialize_public_key,
    wipe_key,
)


def test_generate_keypair_returns_bytes_and_bytearray():
    pub, priv = generate_keypair()
    assert isinstance(pub, bytes)
    assert isinstance(priv, bytearray)
    assert len(pub) > 0
    assert len(priv) > 0


def test_generate_keypair_default_algorithm():
    pub, priv = generate_keypair()
    wipe_key(priv)
    assert len(pub) > 0


@pytest.mark.parametrize("alg", SUPPORTED_ALGORITHMS)
def test_generate_keypair_all_algorithms(alg):
    pub, priv = generate_keypair(algorithm=alg)
    assert len(pub) > 0
    assert len(priv) > 0
    wipe_key(priv)


def test_generate_keypair_unsupported_algorithm():
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        generate_keypair(algorithm="ECDSA")


def test_keypairs_are_unique():
    pub1, priv1 = generate_keypair()
    pub2, priv2 = generate_keypair()
    assert pub1 != pub2
    assert bytes(priv1) != bytes(priv2)
    wipe_key(priv1)
    wipe_key(priv2)


def test_derive_address_is_64_hex_chars():
    pub, priv = generate_keypair()
    wipe_key(priv)
    addr = derive_address(pub)
    assert len(addr) == 64
    assert all(c in "0123456789abcdef" for c in addr)


def test_derive_address_is_deterministic():
    pub, priv = generate_keypair()
    wipe_key(priv)
    assert derive_address(pub) == derive_address(pub)


def test_derive_address_differs_for_different_keys():
    pub1, priv1 = generate_keypair()
    pub2, priv2 = generate_keypair()
    wipe_key(priv1)
    wipe_key(priv2)
    assert derive_address(pub1) != derive_address(pub2)


def test_serialize_deserialize_public_key():
    pub, priv = generate_keypair()
    wipe_key(priv)
    serialized = serialize_public_key(pub)
    assert isinstance(serialized, str)
    recovered = deserialize_public_key(serialized)
    assert recovered == pub


def test_wipe_key_zeros_memory():
    _, priv = generate_keypair()
    wipe_key(priv)
    assert all(b == 0 for b in priv)
