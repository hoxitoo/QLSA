import base64
import hashlib
import oqs.oqs as oqs  # liboqs-python; oqs top-level is shadowed by the unrelated OQS package


SUPPORTED_ALGORITHMS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
DEFAULT_ALGORITHM = "ML-DSA-65"

# FIPS 204 §5.1 — public key byte lengths per parameter set
# ML-DSA-44: ρ(32) + t1(k=4, ceil(N·10/8)=1280) = 1312
# ML-DSA-65: ρ(32) + t1(k=6, ceil(N·10/8)=1920) = 1952
# ML-DSA-87: ρ(32) + t1(k=8, ceil(N·10/8)=2560) = 2592
_PUBKEY_SIZES: frozenset[int] = frozenset({1312, 1952, 2592})


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
    if len(public_key) not in _PUBKEY_SIZES:
        raise ValueError(
            f"public_key length {len(public_key)} is not a valid ML-DSA public key size. "
            f"Expected one of {sorted(_PUBKEY_SIZES)} bytes."
        )
    return hashlib.sha3_256(public_key).hexdigest()


def wipe_key(private_key: bytearray) -> None:
    """Overwrite private key bytes with zeros using volatile writes when possible.

    Tries the Rust `wipe_bytes` (zeroize crate, volatile_set — compiler-safe)
    first; falls back to a pure-Python loop if the extension is not installed.
    Either way, the *primary* key buffer is zeroed.  Python-side copies made
    by liboqs during signing cannot be guaranteed to be erased.
    """
    try:
        import qlsa_stark_stwo as _ext  # noqa: PLC0415
        _ext.wipe_bytes(private_key)
    except (ImportError, AttributeError):
        for i in range(len(private_key)):
            private_key[i] = 0


def serialize_public_key(public_key: bytes) -> str:
    return base64.b64encode(public_key).decode("ascii")


def deserialize_public_key(data: str) -> bytes:
    try:
        key = base64.b64decode(data.encode("ascii"))
    except Exception as exc:
        raise ValueError(f"deserialize_public_key: invalid base64 data: {exc}") from exc
    if len(key) not in _PUBKEY_SIZES:
        raise ValueError(
            f"deserialize_public_key: decoded length {len(key)} is not a valid "
            f"ML-DSA public key size. Expected one of {sorted(_PUBKEY_SIZES)} bytes."
        )
    return key
