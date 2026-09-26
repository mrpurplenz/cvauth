from __future__ import annotations

import os
import sys
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python <=3.10

import tomli_w
from importlib.resources import files
from platformdirs import user_config_dir

APP_NAME = "cvauth"
CONFIG_FILENAME = "cvauth.toml"


class ConfigError(RuntimeError):
    """Configuration is missing or invalid."""


def user_config_path() -> Path:
    override = os.environ.get("CVAUTH_CONFIG_DIR")
    if override:
        return Path(override) / CONFIG_FILENAME
    return Path(user_config_dir(APP_NAME)) / CONFIG_FILENAME


def default_config_path() -> Path:
    return user_config_path()


def load_default_config() -> dict:
    """Load the bundled default TOML template as a dict."""
    try:
        text = Path(__file__).with_name(CONFIG_FILENAME).read_text()
    except FileNotFoundError:
        text = (files("cvauth") / CONFIG_FILENAME).read_text()
    return tomllib.loads(text)


@dataclass(frozen=True)
class IdentityConfig:
    callsign: str
    ssid: str


@dataclass(frozen=True)
class KeysConfig:
    private_key: Optional[str]
    public_key: Optional[str]


@dataclass(frozen=True)
class CryptoConfig:
    scheme: str


@dataclass(frozen=True)
class BehaviourConfig:
    allow_unsigned: bool = True
    allow_invalid_signatures: bool = True


@dataclass(frozen=True)
class ConfigLocationConfig:
    config_path: str


@dataclass(frozen=True)
class CVAuthConfig:
    identity: IdentityConfig
    keys: KeysConfig
    crypto: CryptoConfig
    behaviour: BehaviourConfig
    config_location: ConfigLocationConfig

    @property
    def config_dir(self) -> Path:
        return Path(self.config_location.config_path).parent

    def resolve_path(self, path: Optional[str]) -> Optional[Path]:
        if not path:
            return None
        p = Path(path)
        if p.is_absolute():
            return p
        return (self.config_dir / p).resolve()


def _merge_with_defaults(user_data: dict) -> dict:
    """Merge user config with defaults from template.

    For any missing top-level section or missing keys within a section,
    use the values from the bundled default TOML file.
    This ensures upgrades and new installs both use the template as truth.
    """
    defaults = load_default_config().get("cvauth", {})
    user_cvauth = user_data.get("cvauth", {})

    # Start with defaults, then overlay user values
    merged = {}
    for section in defaults.keys():
        if isinstance(defaults[section], dict):
            # Section is a nested dict: merge key-by-key
            merged[section] = {**defaults[section], **user_cvauth.get(section, {})}
        else:
            # Scalar value: use user value if present, else default
            merged[section] = user_cvauth.get(section, defaults[section])

    return {"cvauth": merged}


def ensure_config() -> Path:
    """Ensure the configuration file exists.

    Writes the template verbatim on first run.
    Existing files are left untouched (upgrade happens on load).
    """
    config_path = user_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    if not config_path.exists():
        default_config = load_default_config()
        default_config["cvauth"]["config_location"]["config_path"] = str(config_path)
        with config_path.open("wb") as f:
            tomli_w.dump(default_config, f)

    return config_path


def load_config(path: Optional[Path] = None) -> CVAuthConfig:
    """Load CVAuth configuration with automatic upgrade from template defaults.

    Path resolution rules:
      1. Explicit path argument (highest priority)
      2. config_location.config_path from file (if non-empty)
      3. default_config_path()

    Missing keys are backfilled from the bundled default TOML template,
    ensuring new settings are automatically added on upgrade.
    """
    load_path = path or default_config_path()

    if not load_path.exists():
        raise ConfigError(f"Config file not found: {load_path}")

    try:
        user_data = tomllib.loads(load_path.read_text())
    except Exception as e:
        raise ConfigError(f"Failed to parse config: {e}") from e

    # Merge user config with defaults from template
    merged_data = _merge_with_defaults(user_data)
    data = merged_data["cvauth"]

    identity_section = data.get("identity", {})
    keys_section = data.get("keys", {})
    crypto_section = data.get("crypto", {})
    behaviour_section = data.get("behaviour", {})
    config_location_section = data.get("config_location", {})

    identity = IdentityConfig(
        callsign=identity_section.get("callsign", ""),
        ssid=identity_section.get("ssid", ""),
    )

    keys = KeysConfig(
        private_key=keys_section.get("private_key"),
        public_key=keys_section.get("public_key"),
    )

    crypto = CryptoConfig(
        scheme=crypto_section.get("scheme", ""),
    )

    behaviour = BehaviourConfig(
        allow_unsigned=behaviour_section.get("allow_unsigned", True),
        allow_invalid_signatures=behaviour_section.get("allow_invalid_signatures", True),
    )

    raw_config_path = config_location_section.get("config_path")

    if path is not None:
        final_config_path = str(load_path)
    elif isinstance(raw_config_path, str) and raw_config_path.strip():
        final_config_path = str(Path(raw_config_path).expanduser().resolve())
    else:
        final_config_path = str(default_config_path())

    config_location = ConfigLocationConfig(config_path=final_config_path)

    return CVAuthConfig(
        identity=identity,
        keys=keys,
        crypto=crypto,
        behaviour=behaviour,
        config_location=config_location,
    )


def update_config_value(config: CVAuthConfig, attr_path: str, value) -> CVAuthConfig:
    """Update a config value and write back to disk.

    Args:
        config: Current CVAuthConfig instance
        attr_path: Dot-separated path like "identity.callsign" or "crypto.scheme"
        value: The value to set

    Returns:
        Updated CVAuthConfig with the change persisted to disk
    """
    parts = attr_path.split(".")
    if len(parts) != 2:
        raise ValueError("attr_path must be section.field")

    section, field = parts
    current = config

    if section == "identity":
        updated = replace(config.identity, **{field: value})
        current = replace(config, identity=updated)
    elif section == "keys":
        updated = replace(config.keys, **{field: value})
        current = replace(config, keys=updated)
    elif section == "crypto":
        updated = replace(config.crypto, **{field: value})
        current = replace(config, crypto=updated)
    elif section == "behaviour":
        updated = replace(config.behaviour, **{field: value})
        current = replace(config, behaviour=updated)
    elif section == "config_location":
        updated = replace(config.config_location, **{field: value})
        current = replace(config, config_location=updated)
    else:
        raise ValueError(f"Unknown config section: {section}")

    config_path = current.config_location.config_path
    config_dict = {"cvauth": asdict(current)}

    with Path(config_path).open("wb") as f:
        tomli_w.dump(config_dict, f)

    return current
