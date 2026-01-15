"""
CVAuth public API.

This file defines the stable, supported interface.
Anything not imported here is internal and may change.
"""
__version__ = "0.1.0"

from .packet import CVPacket
from .auth import (
    sign_packet,
    verify_packet,
    AuthType,
    AuthResult,
    PublicKeyProvider,
)

__all__ = [
    "CVPacket",
    "sign_packet",
    "verify_packet",
    "AuthType",
    "AuthResult",
    "PublicKeyProvider",
]
