"""
cvauth.crypto
=============

Cryptographic primitives for CVAuth authentication.

This module provides a minimal wrapper around Ed25519 signing
and verification for use within the CVAuth protocol.

Design Goals
------------

- Use modern, secure defaults (Ed25519)
- Avoid implicit key loading or serialization
- Fail safely on misuse
- Keep cryptographic boundaries explicit

This module does NOT:

- Generate keys
- Store keys
- Serialize keys
- Manage trust models
- Perform certificate validation

It strictly performs detached signature operations.

Algorithm
---------

Ed25519 (RFC 8032) via the `cryptography` library:

- Deterministic signatures
- 64-byte signature output
- 32-byte public keys
- 32-byte private key seed

Security Model
--------------

The caller is responsible for:

- Ensuring payload integrity before signing
- Verifying signatures before trusting identity
- Managing public key distribution
- Preventing replay attacks (e.g., via nonces)

This module only signs and verifies raw byte payloads.
"""

from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class CryptoScheme:
    """The detached-signature operations provided by a crypto scheme."""

    name: str
    sign: Callable[[bytes, object], bytes]
    verify: Callable[[bytes, bytes, object], bool]


def sign(payload: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """
    Generate an Ed25519 signature for a payload.
    """
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
    """
    Verify an Ed25519 signature.
    """
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False


DEFAULT_SCHEME = "ed25519"
CRYPTO_SCHEMES: dict[str, CryptoScheme] = {
    DEFAULT_SCHEME: CryptoScheme(
        name=DEFAULT_SCHEME,
        sign=sign,
        verify=verify,
    )
}


def available_schemes() -> tuple[str, ...]:
    """Return the registered scheme identifiers in registry order."""
    return tuple(CRYPTO_SCHEMES)


def get_scheme(name: str) -> CryptoScheme:
    """Return the registered scheme by identifier."""
    return CRYPTO_SCHEMES[name]
