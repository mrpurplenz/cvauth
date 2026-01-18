from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib  # Python 3.11+
from typing import Optional

from platformdirs import user_config_dir


APP_NAME = "cvauth"
CONFIG_FILENAME = "cvauth.toml"


class ConfigError(RuntimeError):
    """Configuration is missing or invalid."""


def default_config_path() -> Path:
    """
    Return the default path for cvauth.toml.
    Does NOT create it.
    """
    config_dir = Path(user_config_dir(APP_NAME))
    return config_dir / CONFIG_FILENAME


@dataclass(frozen=True)
class IdentityConfig:
    callsign: str


@dataclass(frozen=True)
class KeysConfig:
    private_key: Optional[Path]
    public_key: Optional[Path]


@dataclass(frozen=True)
class BehaviourConfig:
    allow_unsigned: bool = True
    allow_invalid_signatures: bool = True


@dataclass(frozen=True)
class CVAuthConfig:
    identity: IdentityConfig
    keys: KeysConfig
    behaviour: BehaviourConfig
    base_path: Path  # directory containing cvauth.toml

    def resolve_path(self, path: Optional[Path]) -> Optional[Path]:
        if path is None:
            return None
        if path.is_absolute():
            return path
        return (self.base_path / path).resolve()


def load_config(path: Optional[Path] = None) -> CVAuthConfig:
    """
    Load CVAuth configuration.
    Raises ConfigError if missing or invalid.
    """
    if path is None:
        path = default_config_path()

    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        data = tomllib.loads(path.read_text())
    except Exception as e:
        raise ConfigError(f"Failed to parse config: {e}") from e

    try:
        identity = IdentityConfig(
            callsign=data["identity"]["callsign"]
        )

        keys_section = data.get("keys", {})
        keys = KeysConfig(
            private_key=Path(keys_section["private_key"]) if "private_key" in keys_section else None,
            public_key=Path(keys_section["public_key"]) if "public_key" in keys_section else None,
        )

        behaviour_section = data.get("behaviour", {})
        behaviour = BehaviourConfig(
            allow_unsigned=behaviour_section.get("allow_unsigned", True),
            allow_invalid_signatures=behaviour_section.get("allow_invalid_signatures", True),
        )

    except KeyError as e:
        raise ConfigError(f"Missing required config field: {e}") from e

    return CVAuthConfig(
        identity=identity,
        keys=keys,
        behaviour=behaviour,
        base_path=path.parent,
    )
