"""
cvauth.auth
===========

High-level authentication orchestration for CVAuth.

This module binds together:

- Packet layer (CVPacket)
- Cryptographic primitives (Ed25519)
- Public key lookup
- Authentication result classification

Public API (v0.1)
-----------------

- sign_packet
- verify_packet
- generate_keypair
- generate_and_save_keypair
- load_private_key
- load_public_key
- AuthType
- AuthResult
- PublicKeyProvider

Design Philosophy
-----------------

This module defines authentication *policy*, not cryptographic primitives.

It is responsible for:

- Signing packet payloads
- Verifying packet signatures
- Mapping verification results to user-facing status codes
- Delegating public key lookup

It is NOT responsible for:

- Trust networks
- Key distribution
- Revocation
- Replay protection
- Transport-layer integrity

Signature Scope
---------------

Signatures cover:

    packet.payload (bytes)

They do NOT include:

    - AX.25 headers
    - Routing metadata
    - Compression flags
    - Magic bytes

The caller is responsible for ensuring the correct canonical
payload is signed.
"""
import re
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Protocol
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization

from .packet import CVPacket
from . import crypto


class AuthType(Enum):
    """
    Authentication classification for display or policy decisions.

    Values:
        UNKNOWN     : Authentication state not yet determined.
        NOTSIGNED   : Packet contains no signature.
        VALID       : Signature verified successfully.
        KEYNOTFOUND : No public key available for signer.
        INVALID     : Signature present but verification failed.
    """

    UNKNOWN     = "UK"
    NOTSIGNED   = "NS"
    VALID       = "SV"
    KEYNOTFOUND = "NK"
    INVALID     = "IV"
    
CALL_RE = re.compile(r'^([A-Z0-9]{1,6})(?:-(\d{1,2}))?$')

class InvalidStationError(ValueError):
    pass

def call_from_station(station: str) -> str:
    """
    Normalize and validate an AX.25 station identifier.

    Returns canonical form:
        CALLSIGN
        CALLSIGN-SSID (if SSID != 0)

    Raises:
        InvalidStationError if malformed
    """
    if not station or not isinstance(station, str):
        raise InvalidStationError("Station must be a non-empty string")

    station = station.strip().upper()

    match = CALL_RE.fullmatch(station)
    if not match:
        raise InvalidStationError(f"Invalid station format: {station}")

    callsign, ssid_str = match.groups()

    if ssid_str is None:
        ssid = 0
    else:
        ssid = int(ssid_str)
        if not (0 <= ssid <= 15):
            raise InvalidStationError(f"SSID out of range: {ssid}")

    # Canonical form: omit -0
    #if ssid == 0:
    #    return callsign
    #else:
    #    return f"{callsign}-{ssid}"  
    return callsign  


class PublicKeyProvider(Protocol):
    """
    Interface for retrieving public keys by callsign.

    Implementations may retrieve keys from:

    - Local filesystem
    - Network service
    - Web key server
    - In-memory keyring

    The authentication layer depends only on this abstraction.
    """

    def get_public_key(self, callsign: str) -> Optional[Ed25519PublicKey]:
        """
        Retrieve public key for given callsign.

        Args:
            callsign: AX.25 callsign identifier.

        Returns:
            Ed25519PublicKey if known, otherwise None.
        """
        ...




def ensure_bytes(payload) -> bytes:
    """
    Normalize payload into bytes.

    Accepts:
        - bytes
        - bytearray
        - str (UTF-8 encoded)

    Raises:
        ValueError: If payload is None.
        TypeError: If unsupported type.
    """
    if payload is None:
        raise ValueError("Payload is None")

    if isinstance(payload, bytes):
        return payload

    if isinstance(payload, bytearray):
        return bytes(payload)

    if isinstance(payload, str):
        return payload.encode("utf-8")

    raise TypeError(f"Unsupported payload type: {type(payload)}")


def generate_keypair(key_type: str):
    """
    Generate a cryptographic keypair.

    Args:
        key_type: Currently only "ed25519" supported.

    Returns:
        Tuple[Ed25519PrivateKey, Ed25519PublicKey]

    Raises:
        ValueError: If unsupported key type.
    """
    if key_type != "ed25519":
        raise ValueError(f"Unsupported key type: {key_type}")

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def generate_and_save_keypair(
    private_path: Path,
    public_path: Path,
    key_type="ed25519",
):
    """
    Generate keypair and save to disk in PEM format.

    Existing files are overwritten.

    Args:
        private_path: Destination path for private key.
        public_path: Destination path for public key.
        key_type: Currently only "ed25519".

    Returns:
        Tuple[Path, Path]: Paths written.
    """
    priv, pub = generate_keypair(key_type)

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_path.write_bytes(serialize_private_key(priv))
    public_path.write_bytes(serialize_public_key(pub))

    return private_path, public_path


def serialize_private_key(priv: Ed25519PrivateKey) -> bytes:
    """
    Serialize private key to PEM (PKCS8, unencrypted).
    """
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(pub: Ed25519PublicKey) -> bytes:
    """
    Serialize public key to PEM (SubjectPublicKeyInfo).
    """
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """
    Load Ed25519 private key from PEM file.

    Raises:
        FileNotFoundError
        TypeError if key is not Ed25519
    """
    if not path.exists():
        raise FileNotFoundError(f"Private key not found: {path}")

    key = serialization.load_pem_private_key(path.read_bytes(), password=None)

    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Not an Ed25519 private key")

    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    """
    Load Ed25519 public key from PEM file.

    Raises:
        TypeError if key is not Ed25519.
    """
    key = serialization.load_pem_public_key(path.read_bytes())

    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Not an Ed25519 public key")

    return key


@dataclass
class AuthResult:
    """
    Result of authentication attempt.

    Attributes:
        auth_type: Classification of result.
        signer: Callsign of signer if known.
        reason: Human-readable explanation.
    """

    auth_type: AuthType
    signer: Optional[str]
    reason: Optional[str]


def sign_packet(
    packet: CVPacket,
    private_key: Ed25519PrivateKey,
) -> None:
    """
    Sign packet payload and attach signature in-place.

    Args:
        packet: CVPacket to sign.
        private_key: Ed25519 private key.

    Raises:
        ValueError: If payload is missing.
    """
    if packet.payload is None:
        raise ValueError("Cannot sign packet with no payload")

    signature = crypto.sign(
        payload=ensure_bytes(packet.payload),
        private_key=private_key,
    )

    packet.signature = signature
    packet.signed = True


def verify_packet(
    packet: CVPacket,
    keyring: PublicKeyProvider,
) -> AuthResult:
    """
    Verify packet signature using provided keyring.

    Args:
        packet: CVPacket to verify.
        keyring: PublicKeyProvider implementation.

    Returns:
        AuthResult describing verification outcome.

    Verification Flow:
        1. If not signed → NOTSIGNED
        2. If no callsign → KEYNOTFOUND
        3. Lookup public key
        4. Verify signature
        5. Return VALID or INVALID
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

    ok = crypto.verify(
        payload=packet.payload,
        signature=packet.signature,
        public_key=public_key,
    )

    if ok:
        return AuthResult(
            auth_type=AuthType.VALID,
            signer=packet.from_call,
            reason="Signature verified",
        )

    return AuthResult(
        auth_type=AuthType.INVALID,
        signer=packet.from_call,
        reason="Signature verification failed",
    )
