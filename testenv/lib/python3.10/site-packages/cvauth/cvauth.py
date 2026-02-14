"""
CVAuth – front-facing authentication context.

This object owns:
- the local private key (optional)
- access to a public key provider
- the policy for signing and verifying packets

All cryptographic primitives live elsewhere.
"""

from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from .packet import CVPacket
from .auth import (
    sign_packet,
    verify_packet,
    AuthResult,
    PublicKeyProvider,
)


class CVAuth:
    """
    Authentication context for signing and verifying CV packets.

    Typical usage:

        auth = CVAuth(
            callsign="ZL1ABC",
            private_key=my_private_key,
            keyring=my_keyring,
        )

        auth.sign(packet)
        result = auth.verify(packet)
    """

    def __init__(
        self,
        *,
        callsign: Optional[str] = None,
        private_key: Optional[Ed25519PrivateKey] = None,
        keyring: Optional[PublicKeyProvider] = None,
    ):
        self.callsign = callsign
        self.private_key = private_key
        self.keyring = keyring

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def can_sign(self) -> bool:
        """Return True if this context is capable of signing packets."""
        return self.private_key is not None and self.callsign is not None

    def sign(self, packet: CVPacket) -> bool:
        """
        Sign a packet in place.

        Returns True on success, False if signing is not possible.
        """
        if not self.can_sign():
            return False

        # Ensure packet has a sender
        packet.from_call = self.callsign

        sign_packet(packet, self.private_key)
        return True

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def can_verify(self) -> bool:
        """Return True if this context is capable of verifying packets."""
        return self.keyring is not None

    def verify(self, packet: CVPacket) -> AuthResult:
        """
        Verify a packet signature.

        Always returns an AuthResult describing the outcome.
        """
        if self.keyring is None:
            return AuthResult(
                auth_type=None,
                signer=None,
                reason="No public key provider configured",
            )

        return verify_packet(packet, self.keyring)
