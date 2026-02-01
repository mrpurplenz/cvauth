#Depricated version
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python <=3.10
import tomli_w
from typing import Optional
import os
from platformdirs import user_config_dir
from importlib.resources import files


APP_NAME = "cvauth"
CONFIG_FILENAME = "cvauth.toml"
DEFAULT_CONFIG_TEMPLATE_PATH = Path(__file__).with_name(CONFIG_FILENAME)

def is_empty_val(p: Path | None) -> bool:
    return p is None or str(p) in ("", ".")


def set_attr_path(obj, path: str, value):
    """
    Set an attribute on a nested object using dotted-path notation.

    Example:
        set_attr_path(config, "identity.callsign", "ZL1ABC")
    """
    parts = path.split(".")
    target = obj

    for attr in parts[:-1]:
        target = getattr(target, attr)

    setattr(target, parts[-1], value)


def load_default_config() -> dict:
    try:
        return tomllib.loads(DEFAULT_CONFIG_TEMPLATE_PATH.read_text())
    except FileNotFoundError:
        # fallback for packaged installs
        from importlib.resources import files
        text = (files("cvauth") / CONFIG_FILENAME).read_text()
        return tomllib.loads(text)

class ConfigError(RuntimeError):
    """Configuration is missing or invalid."""

def user_config_path() -> Path:
    """
    Return the default path for cvauth.toml.
    Does NOT create it.
    """
    override = os.environ.get("CVAUTH_CONFIG_DIR")
    if override:
        return Path(override) / CONFIG_FILENAME

    config_dir = Path(user_config_dir(APP_NAME))
    print(config_dir)
    print("that was the user dir")
    return config_dir / CONFIG_FILENAME

def default_config_path() -> Path:
    override = os.environ.get("CVAUTH_CONFIG_DIR")
    if override:
        return Path(override) / CONFIG_FILENAME

    return Path(user_config_dir(APP_NAME)) / CONFIG_FILENAME

def get_config_path(path: Optional[Path] = None) -> Path:
    if path is not None:
        return path
    return default_config_path()


@dataclass(frozen=True)
class IdentityConfig:
    callsign: str
    ssid: int

@dataclass(frozen=True)
class KeysConfig:
    private_key: Optional[Path]
    public_key: Optional[Path]


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
    behaviour: BehaviourConfig
    config_location: ConfigLocationConfig  # full path to cvauth.toml

    @property
    def config_dir(self) -> Path:
        return self.config_path.parent

    def resolve_path(self, path: Optional[Path]) -> Optional[Path]:
        if path is None:
            return None
        if path.is_absolute():
            return path
        return (self.config_dir / path).resolve()


def ensure_config() -> Path:
    """
    Ensure that the default config directory and cvauth.toml exist.
    Returns the path to default cvauth.toml (NOT THE TEMPLATE)
    """
    config_path = user_config_path()
    config_dir = config_path.parent
    config_dir.mkdir(parents=True, exist_ok=True)

    if not config_path.exists():
        with config_path.open("wb") as f:
            default_config = load_default_config()
            #print(default_config)
            default_config.cvauth.config_location.config_path=str(config_path)
            tomli_w.dump(default_config, f)

    return config_path

def path_to_str(p):
    return str(p) if isinstance(p, Path) else p

def config_to_dict(config):
    return {
        "cvauth": {
            "identity": {
                "callsign": path_to_str(config.identity.callsign),
                "ssid": path_to_str(config.identity.ssid),
            },
            "keys": {
                "private_key": path_to_str(config.keys.private_key),
                "public_key": path_to_str(config.keys.public_key),
            },
            "behaviour": {
                "allow_unsigned": config.behaviour.allow_unsigned,
                "allow_invalid_signatures": config.behaviour.allow_invalid_signatures,
            },
            "config_location": {
                "config_path": config.config_location.config_path,
            },
        }
    }



from dataclasses import replace, asdict
import tomli_w

def update_config_value(config: CVAuthConfig, attr_path: str, value) -> CVAuthConfig:
    """
    Return a new CVAuthConfig object with the value at attr_path updated.
    Also writes the updated config back to disk.
    
    attr_path: e.g. "identity.callsign"
    """
    parts = attr_path.split(".")
    if parts[0] != "identity" and parts[0] != "keys" and parts[0] != "behaviour":
        raise ValueError(f"Unknown top-level section: {parts[0]}")

    current = config

    #hack to set current file location at first use of update
    if config.config_location.config_path is None:
        config_path = str(user_config_path())
        updated = replace(config.config_location, **{"config_path": str(user_config_path())})
        current = replace(config, config_location=updated)
    else:
        config_path = config.config_location.config_path
    print("config path below")
    print(config_path)
    print("config_path in config below")
    print(current.config_location.config_path)

    # Start with top-level dataclass
    if parts[0] == "identity":
        updated = replace(config.identity, **{parts[1]: value})
        current = replace(config, identity=updated)
    elif parts[0] == "keys":
        updated = replace(config.keys, **{parts[1]: value})
        current = replace(config, keys=updated)
    elif parts[0] == "behaviour":
        updated = replace(config.behaviour, **{parts[1]: value})
        current = replace(config, behaviour=updated)
    elif parts[0] == "config_location":
        updated = replace(config.config_location, **{parts[1]: value})
        current = replace(config, config_location=updated)


    # Write back to TOML
    config_dict = asdict(current)
    print("we will try to dump this")
    print(config_dict)
    current_path = config_dict["config_location"]["config_path"]

    if current_path is not None and current_path != "":
        config_path = config_dict["config_location"]["config_path"]

    with Path(config_path).open("wb") as f:
        tomli_w.dump({"cvauth": config_dict}, f)

    return current




def load_config(path: Optional[Path] = None) -> CVAuthConfig:
    """
    Load CVAuth configuration.
    Raises ConfigError if missing or invalid.
    """
    load_path = path or default_config_path()

    #if path is None:
    #    path = default_config_path()

    if not load_path.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        data = tomllib.loads(load_path.read_text())
    except Exception as e:
        raise ConfigError(f"Failed to parse config: {e}") from e

    # Accept both new and legacy layouts
    if "cvauth" in data:
        data = data["cvauth"]
    else:
        # legacy / flat config
        data = data
    #try:
    #    data = data["cvauth"]
    #except KeyError:
    #    raise ConfigError("Missing [cvauth] section in config")


    try:

        # --- identity -------------------------------------------------

        identity_section = data.get("identity", {})

        identity = IdentityConfig(
            callsign=identity_section.get("callsign"),
            ssid=identity_section.get("ssid"),
        )

        # --- keys -----------------------------------------------------

        keys_section = data.get("keys", {})

        keys = KeysConfig(
            private_key=keys_section.get("private_key"),
            public_key=keys_section.get("public_key"),
        )

        # --- behaviour ------------------------------------------------

        behaviour_section = data.get("behaviour", {})

        behaviour = BehaviourConfig(
            allow_unsigned=behaviour_section.get("allow_unsigned", True),
            allow_invalid_signatures=behaviour_section.get(
                "allow_invalid_signatures", True
            ),
        )

        # --- config location -----------------------------------------

        config_location_section = data.get("config_location", {})
        raw_config_path=config_location_section.get("config_path"),




    except KeyError as e:
        raise ConfigError(f"Missing required config field: {e}") from e

    # Resolve authoritative config_path
    if path is not None:
        final_config_path = load_path
    elif isinstance(raw_config_path, str) and raw_config_path.strip():
        final_config_path = Path(raw_config_path).expanduser().resolve()
    else:
        final_config_path = default_config_path()

    config_location = ConfigLocationConfig(
        config_path=str(final_config_path)
    )

    return CVAuthConfig(
        identity=identity,
        keys=keys,
        behaviour=behaviour,
        config_location=config_location,
    )


