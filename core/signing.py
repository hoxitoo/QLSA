import oqs

from core.keys import DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS


def sign(message: bytes, private_key: bytearray, algorithm: str = DEFAULT_ALGORITHM) -> bytes:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'")
    if not message:
        raise ValueError("message must not be empty")
    with oqs.Signature(algorithm, bytes(private_key)) as sig:
        return bytes(sig.sign(message))


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
