
from pathlib import Path

import pytest

from cvauth import crypto
from cvauth.auth import PublicKeyRecord
from cvauth.config import (
    BehaviourConfig,
    ConfigLocationConfig,
    CryptoConfig,
    CVAuthConfig,
    IdentityConfig,
    KeysConfig,
)
from cvauth.keyring import Keyring


@pytest.fixture
def config(tmp_path: Path) -> CVAuthConfig:
    """Build a real configuration using an isolated temporary directory."""
    config_file = tmp_path / "cvauth.toml"

    return CVAuthConfig(
        identity=IdentityConfig(callsign="ZL2DRS", ssid="0"),
        keys=KeysConfig(
            private_key="keys/private.pem",
            public_key="keys/public.pem",
        ),
        crypto=CryptoConfig(scheme=crypto.DEFAULT_SCHEME),
        behaviour=BehaviourConfig(),
        config_location=ConfigLocationConfig(
            config_path=str(config_file),
        ),
    )


@pytest.fixture
def ed25519_public_bytes() -> bytes:
    """Generate a valid Ed25519 public key in the registered format."""
    scheme = crypto.get_scheme(crypto.DEFAULT_SCHEME)
    _, public_key = scheme.generate_keypair()
    return scheme.serialize_public(public_key)


def test_loads_legacy_ed25519_key(
    config: CVAuthConfig,
    ed25519_public_bytes: bytes,
) -> None:
    """Legacy trusted_keys/CALLSIGN.pem files remain supported."""
    key_path = config.config_dir / "trusted_keys" / "ZL1ABC.pem"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(ed25519_public_bytes)

    keyring = Keyring(config)
    record = keyring.get_public_key("ZL1ABC-7")

    assert isinstance(record, PublicKeyRecord)
    assert record.callsign == "ZL1ABC"
    assert record.scheme_name == crypto.DEFAULT_SCHEME
    assert record.key is not None


def test_scheme_specific_key_takes_precedence(
    config: CVAuthConfig,
    ed25519_public_bytes: bytes,
) -> None:
    """The scheme-specific file takes precedence over the legacy file."""
    legacy_path = config.config_dir / "trusted_keys" / "ZL1ABC.pem"
    scheme_path = (
        config.config_dir
        / "trusted_keys"
        / "ZL1ABC"
        / f"{crypto.DEFAULT_SCHEME}.pem"
    )

    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_bytes(b"not a valid key")

    scheme_path.parent.mkdir(parents=True)
    scheme_path.write_bytes(ed25519_public_bytes)

    record = Keyring(config).get_public_key("ZL1ABC")

    assert isinstance(record, PublicKeyRecord)
    assert record.callsign == "ZL1ABC"
    assert record.scheme_name == crypto.DEFAULT_SCHEME


def test_missing_key_returns_none(config: CVAuthConfig) -> None:
    """An unknown station has no trusted public-key record."""
    record = Keyring(config).get_public_key("ZL1ABC")

    assert record is None


def test_malformed_key_raises_value_error(
    config: CVAuthConfig,
) -> None:
    """A present but malformed key must not be treated as missing."""
    key_path = config.config_dir / "trusted_keys" / "ZL1ABC.pem"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(b"this is not a valid public key")

    with pytest.raises(ValueError, match="Unable to load public key"):
        Keyring(config).get_public_key("ZL1ABC")


def test_invalid_callsign_is_rejected(config: CVAuthConfig) -> None:
    """Station identifiers are validated before filesystem lookup."""
    with pytest.raises(ValueError):
        Keyring(config).get_public_key("NOT A VALID CALL")

def test_get_public_keys_returns_empty_list_when_none_exist(
    config: CVAuthConfig,
) -> None:
    """No trusted keys produces an empty list."""
    records = Keyring(config).get_public_keys("ZL1ABC")

    assert records == []


def test_get_public_keys_returns_legacy_default_scheme(
    config: CVAuthConfig,
    ed25519_public_bytes: bytes,
) -> None:
    """The multi-key API discovers legacy default-scheme keys."""
    key_path = config.config_dir / "trusted_keys" / "ZL1ABC.pem"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(ed25519_public_bytes)

    records = Keyring(config).get_public_keys("ZL1ABC")

    assert len(records) == 1
    assert records[0].callsign == "ZL1ABC"
    assert records[0].scheme_name == crypto.DEFAULT_SCHEME


def test_get_public_keys_returns_scheme_specific_key(
    config: CVAuthConfig,
    ed25519_public_bytes: bytes,
) -> None:
    """The multi-key API discovers scheme-specific keys."""
    key_path = (
        config.config_dir
        / "trusted_keys"
        / "ZL1ABC"
        / f"{crypto.DEFAULT_SCHEME}.pem"
    )
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(ed25519_public_bytes)

    records = Keyring(config).get_public_keys("ZL1ABC")

    assert len(records) == 1
    assert records[0].scheme_name == crypto.DEFAULT_SCHEME
