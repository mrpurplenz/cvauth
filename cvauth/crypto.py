from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class CryptoScheme:
    """A named crypto scheme with the operations required by CVAuth.

    The scheme is intentionally registry-driven so alternative algorithms can be
    plugged in without changing the higher-level auth logic.
    """

    name: str
    generate_keypair: Callable[[], tuple[object, object]]
    serialize_private: Callable[[object], bytes]
    serialize_public: Callable[[object], bytes]
    load_private: Callable[[bytes], object]
    load_public: Callable[[bytes], object]
    sign: Callable[[bytes, object], bytes]
    verify: Callable[[bytes, bytes, object], bool]


def sign(payload: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """Generate an Ed25519 signature for a payload."""
    if isinstance(private_key, str):
        raise TypeError(
            "private_key is a string not a key. "
            "Did you forget to load or deserialize it?\n"
            f"Value: {repr(private_key[:200])}"
        )

    if not hasattr(private_key, "sign"):
        raise TypeError(
            f"private_key has no sign() method. Type: {type(private_key)}"
        )

    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError(
            f"payload must be bytes, got {type(payload)} "
            f"with contents beginning {repr(payload)[:200]}"
        )

    return private_key.sign(payload)


def verify(payload: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    """Verify an Ed25519 signature."""
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False


def _generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def _serialize_ed25519_private_key(priv: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _serialize_ed25519_public_key(pub: Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _load_ed25519_private_key(data: bytes) -> Ed25519PrivateKey:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Not an Ed25519 private key")
    return key


def _load_ed25519_public_key(data: bytes) -> Ed25519PublicKey:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Not an Ed25519 public key")
    return key


DEFAULT_SCHEME = "ed25519"
CRYPTO_SCHEMES: dict[str, CryptoScheme] = {}


def register_scheme(scheme: CryptoScheme) -> None:
    """Register a crypto scheme in the global registry."""
    CRYPTO_SCHEMES[scheme.name] = scheme


def available_schemes() -> tuple[str, ...]:
    """Return the registered scheme identifiers in registry order."""
    return tuple(CRYPTO_SCHEMES)


def get_scheme(name: str) -> CryptoScheme:
    """Return the registered scheme by identifier."""
    return CRYPTO_SCHEMES[name]


register_scheme(
    CryptoScheme(
        name=DEFAULT_SCHEME,
        generate_keypair=_generate_ed25519_keypair,
        serialize_private=_serialize_ed25519_private_key,
        serialize_public=_serialize_ed25519_public_key,
        load_private=_load_ed25519_private_key,
        load_public=_load_ed25519_public_key,
        sign=sign,
        verify=verify,
    )
)
