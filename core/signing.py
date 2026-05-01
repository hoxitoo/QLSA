import oqs

from core.keys import DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS


def sign(message: bytes, private_key: bytearray, algorithm: str = DEFAULT_ALGORITHM) -> bytes:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'")
    if not message:
        raise ValueError("message must not be empty")
    # NOTE: liboqs-python requires an immutable bytes copy of the key here.
    # This copy lives on the Python heap and cannot be zeroed by wipe_key.
    # Callers must treat the Wallet/signing scope as security-sensitive and
    # minimise the window between sign() and wipe_key().
    key_bytes = bytes(private_key)
    try:
        with oqs.Signature(algorithm, key_bytes) as sig:
            return bytes(sig.sign(message))
    finally:
        # Attempt best-effort in-place zeroing of the local reference.
        # CPython may or may not reuse this memory immediately.
        del key_bytes


def verify(
    message: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: str = DEFAULT_ALGORITHM,
) -> bool:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'")
    if not message or not signature or not public_key:
        return False
    with oqs.Signature(algorithm) as sig:
        return bool(sig.verify(message, signature, public_key))
