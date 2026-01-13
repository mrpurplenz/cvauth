# cvauth/crypto.py

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

def sign(payload: bytes, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(payload)

def verify(payload: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False
