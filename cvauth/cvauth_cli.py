# cvauth/cli.py

import argparse
from dataclasses import asdict

import tomli_w

from .config import ensure_config, load_config


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
    return 0
