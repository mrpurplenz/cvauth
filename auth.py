from enum import Enum
from dataclasses import dataclass
from typing import Optional, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .packet import CVPacket
from . import crypto


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


@dataclass
class AuthResult:
    auth_type: AuthType
    signer: Optional[str]
    reason: Optional[str]

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


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
            reason="No callsign available to locate public key",
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
