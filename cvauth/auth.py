"""
cvauth.auth
===========

High-level authentication orchestration for CVAuth.

This module binds together:

- Packet layer (CVPacket)
- Cryptographic primitives via the scheme registry in cvauth.crypto
- Public key lookup
- Authentication result classification
"""

import re
from enum import Enum
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol

from . import crypto
from .packet import CVPacket


class AuthType(Enum):
    """Authentication classification for display or policy decisions."""

    UNKNOWN = "UK"
    NOTSIGNED = "NS"
    VALID = "SV"
    KEYNOTFOUND = "NK"
    INVALID = "IV"


CALL_RE = re.compile(r"^([A-Z0-9]{1,6})(?:-(\d{1,2}))?$")


class InvalidStationError(ValueError):
    pass


def call_from_station(station: str) -> str:
    """Normalize and validate an AX.25 station identifier."""
    if not station or not isinstance(station, str):
        raise InvalidStationError("Station must be a non-empty string")

    station = station.strip().upper()
    match = CALL_RE.fullmatch(station)
    if not match:
        raise InvalidStationError(f"Invalid station format: {station}")

    callsign, ssid_str = match.groups()
    ssid = 0 if ssid_str is None else int(ssid_str)
    if not (0 <= ssid <= 15):
        raise InvalidStationError(f"SSID out of range: {ssid}")

    return callsign


class PublicKeyProvider(Protocol):
    """Interface for retrieving public keys by callsign."""

    def get_public_key(self, callsign: str) -> Optional[object]:
        ...


def ensure_bytes(payload) -> bytes:
    """Normalize payload into bytes for crypto operations."""
    if payload is None:
        raise ValueError("Payload is None")

    if isinstance(payload, bytes):
        return payload

    if isinstance(payload, bytearray):
        return bytes(payload)

    if isinstance(payload, str):
        return payload.encode("utf-8")

    raise TypeError(f"Unsupported payload type: {type(payload)}")


def generate_keypair(key_type: str = crypto.DEFAULT_SCHEME):
    """Generate a keypair for the requested scheme.

    The default scheme is the registered Ed25519 implementation.
    """
    scheme = crypto.get_scheme(key_type)
    return scheme.generate_keypair()


def generate_and_save_keypair(
    private_path: Path,
    public_path: Path,
    key_type: str = crypto.DEFAULT_SCHEME,
):
    """Generate and persist a keypair for the requested scheme."""
    scheme = crypto.get_scheme(key_type)
    priv, pub = scheme.generate_keypair()

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_path.write_bytes(scheme.serialize_private(priv))
    public_path.write_bytes(scheme.serialize_public(pub))

    return private_path, public_path


def serialize_private_key(priv: object, scheme_name: str = crypto.DEFAULT_SCHEME) -> bytes:
    """Serialize a private key using the named scheme."""
    return crypto.get_scheme(scheme_name).serialize_private(priv)


def serialize_public_key(pub: object, scheme_name: str = crypto.DEFAULT_SCHEME) -> bytes:
    """Serialize a public key using the named scheme."""
    return crypto.get_scheme(scheme_name).serialize_public(pub)


def load_private_key(path: Path, scheme_name: str = crypto.DEFAULT_SCHEME) -> object:
    """Load a private key from disk using the named scheme."""
    if path is None:
        raise ValueError("Private key path is None")
    if not path.exists():
        raise FileNotFoundError(f"Private key not found: {path}")

    scheme = crypto.get_scheme(scheme_name)
    return scheme.load_private(path.read_bytes())


def load_public_key(path: Path, scheme_name: str = crypto.DEFAULT_SCHEME) -> object:
    """Load a public key from disk using the named scheme."""
    if path is None:
        raise ValueError("Public key path is None")
    if not path.exists():
        raise FileNotFoundError(f"Public key not found: {path}")

    scheme = crypto.get_scheme(scheme_name)
    return scheme.load_public(path.read_bytes())


@dataclass
class AuthResult:
    auth_type: Optional[AuthType]
    signer: Optional[str]
    reason: Optional[str]


def sign_packet(
    packet: CVPacket,
    private_key: object,
    *,
    scheme_name: str = crypto.DEFAULT_SCHEME,
) -> None:
    """Sign a packet payload using the selected crypto scheme."""
    if packet.payload is None:
        raise ValueError("Cannot sign packet with no payload")

    scheme = crypto.get_scheme(scheme_name)
    packet.signature = scheme.sign(ensure_bytes(packet.payload), private_key)
    packet.signed = True


def verify_packet(
    packet: CVPacket,
    keyring: PublicKeyProvider,
    *,
    scheme_names: Optional[list[str]] = None,
) -> AuthResult:
    """Verify packet signatures using the configured scheme first,
    then fall back to any registered scheme.
    """
    if not packet.signed or packet.signature is None:
        return AuthResult(
            auth_type=AuthType.NOTSIGNED,
            signer=None,
            reason="Packet is not signed",
        )

    if not packet.from_call:
        return AuthResult(
            auth_type=AuthType.KEYNOTFOUND,
            signer=None,
            reason="No callsign available for key lookup",
        )

    public_key = keyring.get_public_key(call_from_station(packet.from_call))
    if public_key is None:
        return AuthResult(
            auth_type=AuthType.KEYNOTFOUND,
            signer=packet.from_call,
            reason=f"Public key for {call_from_station(packet.from_call)} not found",
        )

    ordered_names = list(scheme_names or [])
    if not ordered_names:
        ordered_names = [
            crypto.DEFAULT_SCHEME,
            *[name for name in crypto.available_schemes() if name != crypto.DEFAULT_SCHEME],
        ]

    for scheme_name in ordered_names:
        try:
            scheme = crypto.get_scheme(scheme_name)
            if scheme.verify(ensure_bytes(packet.payload), packet.signature, public_key):
                return AuthResult(
                    auth_type=AuthType.VALID,
                    signer=packet.from_call,
                    reason="Signature verified",
                )
        except Exception:
            continue

    return AuthResult(
        auth_type=AuthType.INVALID,
        signer=packet.from_call,
        reason="Signature verification failed",
    )
