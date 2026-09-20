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

    Args:
        payload: Raw bytes to sign.
        private_key: Ed25519 private key instance.

    Returns:
        bytes: 64-byte detached signature.

    Raises:
        TypeError: If inputs are invalid or improperly constructed.

    Notes:
        - The payload must be exactly the bytes intended for verification.
        - No hashing is performed here (Ed25519 signs directly).
        - The caller is responsible for defining canonical payload structure.

    Example:
        >>> signature = sign(b"hello", private_key)
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

    Args:
        payload: Original signed payload bytes.
        signature: Ed25519 signature bytes.
        public_key: Ed25519 public key instance.

    Returns:
        bool: True if signature is valid, False otherwise.

    Security:
        Any verification failure returns False. Exceptions are intentionally
        suppressed to prevent leaking failure detail.
    """
    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False


# Stable identifier for the scheme currently used on the wire.  The registry
# is deliberately separate from packet encoding; adding entries here must not
# change signature byte handling.
DEFAULT_SCHEME = "ed25519"
CRYPTO_SCHEMES: dict[str, CryptoScheme] = {
    DEFAULT_SCHEME: CryptoScheme(
        name=DEFAULT_SCHEME,
        sign=sign,
        verify=verify,
    ),
}


def available_schemes() -> tuple[str, ...]:
    """Return the registered scheme identifiers in registry order."""
    return tuple(CRYPTO_SCHEMES)


def get_scheme(name: str) -> CryptoScheme:
    """Return a registered scheme by identifier.

    Raises:
        KeyError: If ``name`` is not registered.
    """
    return CRYPTO_SCHEMES[name]
