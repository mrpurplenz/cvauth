
"""Credential loading for CVAuth.

Resolves key locations through CVAuthConfig, loads key material through
the crypto scheme registry, and returns typed credential records.
"""

from pathlib import Path
from typing import Optional

from . import crypto
from .auth import PublicKeyRecord, call_from_station
from .config import CVAuthConfig


class Keyring:
    """Load trusted public keys for remote stations."""

    def __init__(self, config: CVAuthConfig):
        self.config = config

    def get_public_key(
        self,
        callsign: str,
        scheme_name: str = crypto.DEFAULT_SCHEME,
    ) -> Optional[PublicKeyRecord]:
        """Load a station's public key for the requested scheme.

        Scheme-aware paths take precedence over legacy paths. Legacy
        callsign-only keys are treated as the default crypto scheme.
        """
        callsign = call_from_station(callsign)

        # Ask config.py to apply the agreed storage and fallback policy.
        key_path = self.config.resolve_trusted_key_path(
            callsign,
            scheme_name,
        )

        if key_path is None:
            return None

        # The storage convention identifies the scheme. The crypto
        # registry handles interpreting the file's contents.
        scheme = crypto.get_scheme(scheme_name)

        try:
            key = scheme.load_public(key_path.read_bytes())
        except OSError as exc:
            raise OSError(
                f"Unable to read public key for {callsign} "
                f"using scheme {scheme_name!r} at {key_path}"
            ) from exc
        except Exception as exc:
            raise ValueError(
                f"Unable to load public key for {callsign} "
                f"using scheme {scheme_name!r} at {key_path}"
            ) from exc

        return PublicKeyRecord(
            callsign=callsign,
            scheme_name=scheme_name,
            key=key,
        )
