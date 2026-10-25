# cvauth/cli.py

import argparse
from dataclasses import asdict

import tomli_w
import sys
from pathlib import Path

from . import crypto
from .utilities import call_from_station
from .config import ConfigError, default_config_path, ensure_config, load_config


def cmd_init(args: argparse.Namespace) -> None:
    """
    Initialise CVAuth configuration.
    Idempotent by design.
    """
    path = ensure_config()
    print(f"CVAuth config initialised at {path}")


def cmd_config(args: argparse.Namespace) -> None:
    """Read and display the current CVAuth configuration."""
    path = ensure_config()
    config = load_config(path)
    print(tomli_w.dumps({"cvauth": asdict(config)}), end="")

def identify_key_scheme(key_data: bytes) -> str | None:
    """Identify a likely public-key scheme from its file format."""
    stripped = key_data.strip()

    # Ed25519 public keys use PEM SubjectPublicKeyInfo format.
    if stripped.startswith(b"-----BEGIN PUBLIC KEY-----"):
        return "ed25519"

    # ChatterVox P-192 public keys are ASCII uncompressed points:
    # 04 followed by 96 hexadecimal characters.
    if (
        len(stripped) == 98
        and stripped.startswith(b"04")
        and all(c in b"0123456789abcdefABCDEF" for c in stripped)
    ):
        return "chattervox-p192"

    return None


def cmd_add(args: argparse.Namespace) -> None:
    """Import a public key into the trusted-key directory."""
    source = Path(args.path).expanduser()

    # Check configuration before doing anything that might create it.
    config_path = default_config_path()

    if not config_path.is_file():
        print(
            f"CVAuth configuration not found at {config_path}.\n"
            "Please run 'cvauth init' first.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    try:
        config = load_config(config_path)
    except (ConfigError, OSError, ValueError) as exc:
        print(f"Unable to load CVAuth configuration: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if not source.is_file():
        print(f"Key file not found: {source}", file=sys.stderr)
        raise SystemExit(1)

    try:
        key_data = source.read_bytes()
    except OSError as exc:
        print(f"Unable to read key file: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    # Suggest a scheme based on the key's format.
    detected_scheme = identify_key_scheme(key_data)
    schemes = crypto.available_schemes()

    print("\nAvailable key schemes:")
    for index, scheme_name in enumerate(schemes, start=1):
        marker = " (detected)" if scheme_name == detected_scheme else ""
        print(f"  {index}. {scheme_name}{marker}")

    while True:
        prompt = "Select scheme by number"
        if detected_scheme in schemes:
            default_number = schemes.index(detected_scheme) + 1
            prompt += f" [{default_number}]"
        else:
            default_number = None

        choice = input(f"{prompt}: ").strip()

        if not choice and default_number is not None:
            scheme_name = detected_scheme
            break

        try:
            selection = int(choice)
            if 1 <= selection <= len(schemes):
                scheme_name = schemes[selection - 1]
                break
        except ValueError:
            pass

        print("Please enter one of the listed numbers.")

    # Validate the key using the selected scheme's loader.
    try:
        crypto.get_scheme(scheme_name).load_public(key_data)
    except (ValueError, TypeError) as exc:
        print(
            f"The file is not a valid {scheme_name} public key: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    callsign_input = input("Callsign of trusted station: ").strip()

    try:
        callsign = call_from_station(callsign_input)
    except (ValueError, TypeError) as exc:
        print(f"Invalid callsign: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if not callsign:
        print("A callsign is required.", file=sys.stderr)
        raise SystemExit(1)

    # Resolve the configured destination for this callsign and scheme.
    destination = config.trusted_key_path(callsign, scheme_name)

    if destination.exists():
        answer = input(
            f"{destination} already exists. Overwrite it? [y/N]: "
        ).strip().lower()

        if answer not in ("y", "yes"):
            print("Import cancelled.")
            return

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(key_data)
    except OSError as exc:
        print(f"Unable to save trusted key: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(f"Trusted {scheme_name} key for {callsign} saved to:")
    print(destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cvauth",
        description="CVAuth configuration tool",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialise CVAuth configuration")
    p_init.set_defaults(func=cmd_init)

    p_config = sub.add_parser("config", help="Display the current configuration")
    p_config.set_defaults(func=cmd_config)

    args = parser.parse_args(argv)

    args.func(args)
    p_add = sub.add_parser("add",help="Add a trusted public key",)
    p_add.add_argument("path",help="Path to the public-key file",)
    p_add.set_defaults(func=cmd_add)
    return 0
