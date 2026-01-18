# cvauth/cli.py

import argparse
from .config import ensure_config


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cvauth",
        description="CVAuth configuration and key management tool",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialise CVAuth configuration")

    args = parser.parse_args()

    if args.command == "init":
        path = ensure_config()
        print(f"CVAuth config initialised at {path}")
