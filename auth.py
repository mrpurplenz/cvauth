"""
Public API (v0.1)
- sign_packet
- verify_packet
- AuthType
- AuthResult
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional, Protocol
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from .packet import CVPacket
from . import crypto
from pathlib import Path

class AuthType(Enum):
    """
    Type used to identify the authentication 
    status for display in application.
    """
    UNKNOWN     = "UK"  # Unknown or not yet determined
    NOTSIGNED   = "NS"  # No signature present
    VALID       = "SV"  # Signature present and verified
    KEYNOTFOUND = "NK"  # No public key available
    INVALID     = "IV"  # Signature invalid


class PublicKeyProvider(Protocol):
    def get_public_key(self, callsign: str) -> Optional[Ed25519PublicKey]:
        ...


def generate_keypair(key_type: str):
    if key_type != "ed25519":
        raise ValueError(f"Unsupported key type: {key_type}")

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def serialize_private_key(priv) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def write_private_key(path: Path, priv: Ed25519PrivateKey) -> None:
    path.write_bytes(serialize_private_key(priv))


def write_public_key(path: Path, pub: Ed25519PublicKey) -> None:
    path.write_bytes(serialize_public_key(pub))

def load_private_key(path: Path) -> Ed25519PrivateKey:
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)

    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Not an Ed25519 private key")

    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)

    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Not an Ed25519 public key")

    return key



@dataclass
class AuthResult:
    auth_type: AuthType
    signer: Optional[str]
    reason: Optional[str]

def sign_packet(
    packet: CVPacket,
    private_key: Ed25519PrivateKey,
) -> None:
    """
    Sign the packet payload and attach the signature.
    """

    if packet.payload is None:
        raise ValueError("Cannot sign packet with no payload")

    signature = crypto.sign(
        payload=packet.payload,
        private_key=private_key,
    )

    packet.signature = signature
    packet.signed = True

def verify_packet(
    packet: CVPacket,
    keyring: PublicKeyProvider,
) -> AuthResult:

    # Not signed at all
    if not packet.signed or packet.signature is None:
        return AuthResult(
            auth_type=AuthType.NOTSIGNED,
            signer=None,
            reason="Packet is not signed",
        )

    # Signed, but we don't know who sent it
    if not packet.from_call:
        return AuthResult(
            auth_type=AuthType.KEYNOTFOUND,
            signer=None,
            reason="No callsign available to locate public key, callsign should be available from the ax25 packet",
        )

    # Look up public key
    public_key = keyring.get_public_key(packet.from_call)
    if public_key is None:
        return AuthResult(
            auth_type=AuthType.KEYNOTFOUND,
            signer=packet.from_call,
            reason="Public key not found",
        )

    # Verify signature
    try:
        ok = crypto.verify(
            payload=packet.payload,
            signature=packet.signature,
            public_key=public_key,
        )
    except Exception as e:
        return AuthResult(
            auth_type=AuthType.INVALID,
            signer=packet.from_call,
            reason=f"Verification error: {e}",
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
