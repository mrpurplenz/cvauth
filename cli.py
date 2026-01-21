# cvauth/cli.py

import argparse
from .config import ensure_config


def cmd_init(args: argparse.Namespace) -> None:
    path = ensure_config()
    print(f"CVAuth config initialised at {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cvauth",
        description="CVAuth configuration and key management tool",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialise CVAuth configuration")
    p_init.set_defaults(func=cmd_init)

    # --- future commands ---
    # sub.add_parser("sign", help="Sign a payload")
    # sub.add_parser("verify", help="Verify a signed payload")

    args = parser.parse_args()
    args.func(args)

