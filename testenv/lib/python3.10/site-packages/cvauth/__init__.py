"""
CVAuth public API.

This module defines the stable, supported interface of the CVAuth package.
Anything not imported here should be considered internal and subject to change.
"""

from .cvauth import CVAuth
from .packet import CVPacket
from .auth import (
    sign_packet,
    verify_packet,
    AuthType,
    AuthResult,
    PublicKeyProvider,
)

__all__ = [
    # Primary front-facing API
    "CVAuth",

    # Core data structures
    "CVPacket",

    # Authentication helpers (advanced / lower-level use)
    "sign_packet",
    "verify_packet",
    "AuthType",
    "AuthResult",
    "PublicKeyProvider",
]

__version__ = "0.1.0"

