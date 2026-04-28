import pytest

from core.keys import generate_keypair, wipe_key
from core.signing import sign, verify


def _make_keypair():
    pub, priv = generate_keypair()
    return pub, priv


def test_sign_and_verify():
    pub, priv = _make_keypair()
    msg = b"hello world"
    sig = sign(msg, priv)
    assert verify(msg, sig, pub)
    wipe_key(priv)


def test_verify_wrong_message():
    pub, priv = _make_keypair()
    sig = sign(b"original", priv)
    assert not verify(b"tampered", sig, pub)
    wipe_key(priv)


def test_verify_wrong_public_key():
    pub1, priv1 = _make_keypair()
    pub2, priv2 = _make_keypair()
    sig = sign(b"message", priv1)
    assert not verify(b"message", sig, pub2)
    wipe_key(priv1)
    wipe_key(priv2)


def test_verify_tampered_signature():
    pub, priv = _make_keypair()
    sig = bytearray(sign(b"message", priv))
    sig[0] ^= 0xFF  # flip bits in first byte
    assert not verify(b"message", bytes(sig), pub)
    wipe_key(priv)


def test_sign_empty_message_raises():
    _, priv = _make_keypair()
    with pytest.raises(ValueError, match="empty"):
        sign(b"", priv)
    wipe_key(priv)


def test_verify_empty_inputs_returns_false():
    pub, priv = _make_keypair()
    sig = sign(b"msg", priv)
    assert not verify(b"", sig, pub)
    assert not verify(b"msg", b"", pub)
    assert not verify(b"msg", sig, b"")
    wipe_key(priv)


def test_sign_unsupported_algorithm():
    _, priv = _make_keypair()
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        sign(b"msg", priv, algorithm="ECDSA")
    wipe_key(priv)


def test_verify_unsupported_algorithm():
    pub, priv = _make_keypair()
    sig = sign(b"msg", priv)
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        verify(b"msg", sig, pub, algorithm="ECDSA")
    wipe_key(priv)


def test_cross_algorithm_verify_fails():
    """Signature produced with ML-DSA-44 must not verify under ML-DSA-65."""
    from core.keys import generate_keypair as gkp
    pub44, priv44 = gkp(algorithm="ML-DSA-44")
    pub65, priv65 = gkp(algorithm="ML-DSA-65")
    msg = b"cross-algorithm test"
    sig44 = sign(msg, priv44, algorithm="ML-DSA-44")
    # Verify with the wrong algorithm — should return False, not raise.
    result = verify(msg, sig44, pub44, algorithm="ML-DSA-65")
    assert result is False
    wipe_key(priv44)
    wipe_key(priv65)
