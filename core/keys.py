import base64
import hashlib
import oqs


SUPPORTED_ALGORITHMS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
DEFAULT_ALGORITHM = "ML-DSA-65"


def generate_keypair(algorithm: str = DEFAULT_ALGORITHM) -> tuple[bytes, bytearray]:
    """Return (public_key, private_key). private_key is a mutable bytearray — zero it after use."""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from {SUPPORTED_ALGORITHMS}")
    with oqs.Signature(algorithm) as sig:
        public_key = sig.generate_keypair()
        private_key = bytearray(sig.export_secret_key())
    return public_key, private_key


def derive_address(public_key: bytes) -> str:
    """SHA3-256(pubkey) → lowercase hex string (address)."""
    return hashlib.sha3_256(public_key).hexdigest()


def wipe_key(private_key: bytearray) -> None:
    """Overwrite private key bytes with zeros."""
    for i in range(len(private_key)):
        private_key[i] = 0


def serialize_public_key(public_key: bytes) -> str:
    return base64.b64encode(public_key).decode("ascii")


def deserialize_public_key(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))
