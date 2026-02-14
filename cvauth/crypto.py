# cvauth/crypto.py

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
def sign(payload: bytes, private_key: Ed25519PrivateKey) -> bytes:
    if isinstance(private_key, str):
        raise TypeError(
            "private_key is a string not a key. Did you forget to load or deserialize it?\n"
            f"Value: {repr(private_key[:200])}"
        )

    if not hasattr(private_key, "sign"):
        raise TypeError(
            f"private_key has no sign() method. Type: {type(private_key)}"
        )

    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError(
            f"payload must be bytes, got {type(payload)}"
            f" with contents beginning {repr(payload)[:200]}"
        )

    return private_key.sign(payload)


def verify(payload: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False
