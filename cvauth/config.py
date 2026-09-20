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

from .crypto import DEFAULT_SCHEME, available_schemes

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
    scheme: str = DEFAULT_SCHEME


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
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    behaviour: BehaviourConfig = field(default_factory=BehaviourConfig)
    config_location: ConfigLocationConfig = field(default_factory=lambda: ConfigLocationConfig(config_path=""))

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


def ensure_config() -> Path:
    """Ensure the configuration file exists and contains required defaults.

    Existing files are upgraded in-place so older config files keep their values,
    while missing keys (such as the crypto scheme) are backfilled using the
    registered default scheme or an interactive prompt when available.
    """
    config_path = user_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    if not config_path.exists():
        default_config = load_default_config()
        default_config["cvauth"]["config_location"] = {"config_path": str(config_path)}
        if "crypto" not in default_config["cvauth"]:
            default_config["cvauth"]["crypto"] = {"scheme": DEFAULT_SCHEME}
        elif not default_config["cvauth"]["crypto"].get("scheme"):
            default_config["cvauth"]["crypto"]["scheme"] = DEFAULT_SCHEME
        with config_path.open("wb") as f:
            tomli_w.dump(default_config, f)
        return config_path

    data = tomllib.loads(config_path.read_text())
    if "cvauth" not in data:
        data["cvauth"] = {}

    cvauth = data["cvauth"]
    changed = False

    if "config_location" not in cvauth:
        cvauth["config_location"] = {}
    if "config_path" not in cvauth["config_location"] or not cvauth["config_location"]["config_path"]:
        cvauth["config_location"]["config_path"] = str(config_path)
        changed = True

    if "crypto" not in cvauth:
        cvauth["crypto"] = {}
    if "scheme" not in cvauth["crypto"] or not cvauth["crypto"]["scheme"]:
        scheme = DEFAULT_SCHEME
        if sys.stdin is not None and sys.stdin.isatty():
            try:
                from .config_utils import request_crypto_scheme

                scheme = request_crypto_scheme(default=scheme)
            except Exception:
                scheme = DEFAULT_SCHEME
        cvauth["crypto"]["scheme"] = scheme
        changed = True
    elif cvauth["crypto"]["scheme"] not in available_schemes():
        scheme = DEFAULT_SCHEME
        if sys.stdin is not None and sys.stdin.isatty():
            try:
                from .config_utils import request_crypto_scheme

                scheme = request_crypto_scheme(default=scheme)
            except Exception:
                scheme = DEFAULT_SCHEME
        cvauth["crypto"]["scheme"] = scheme
        changed = True

    if changed:
        with config_path.open("wb") as f:
            tomli_w.dump(data, f)

    return config_path


def load_config(path: Optional[Path] = None) -> CVAuthConfig:
    """Load CVAuth configuration."""
    load_path = path or default_config_path()

    if not load_path.exists():
        raise ConfigError(f"Config file not found: {load_path}")

    try:
        data = tomllib.loads(load_path.read_text())
    except Exception as e:
        raise ConfigError(f"Failed to parse config: {e}") from e

    if "cvauth" not in data:
        raise ConfigError("Missing [cvauth] section in config")

    data = data["cvauth"]

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
        scheme=crypto_section.get("scheme", DEFAULT_SCHEME),
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
    """Update a config value and write back to disk."""
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
