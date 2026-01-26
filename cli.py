# cvauth/cli.py

import argparse
from pathlib import Path
import argparse
import sys

from .config import ensure_config, load_config
from .keys import generate_keypair, save_private_key, save_public_key


def cmd_genkey(args: argparse.Namespace) -> None:
    # Ensure config exists
    cfg_path = ensure_config()
    cfg = load_config(cfg_path)

    priv_path = Path(cfg["keys"]["private_key"])
    pub_path = Path(cfg["keys"]["public_key"])

    # Refuse overwrite unless --force
    if not args.force and (priv_path.exists() or pub_path.exists()):
        print("Error: key files already exist. Use --force to overwrite.", file=sys.stderr)
        raise SystemExit(1)

    # Generate keypair
    priv_key, pub_key = generate_keypair(cfg["crypto"]["algorithm"])

    # Ensure directories exist
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)

    # Save keys
    save_private_key(priv_path, priv_key)
    save_public_key(pub_path, pub_key)

    print(f"Generated keypair:")
    print(f"  Private key: {priv_path}")
    print(f"  Public key:  {pub_path}")


def cmd_init(args: argparse.Namespace) -> None:
    path = ensure_config()
    print(f"CVAuth config initialised at {path}")



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cvauth",
        description="CVAuth configuration and key management tool",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialise CVAuth configuration")
    p_init.set_defaults(func=cmd_init)

    p_gen = sub.add_parser("genkey", help="Generate signing keypair")
    p_gen.add_argument("--force", action="store_true", help="Overwrite existing keys")
    p_gen.set_defaults(func=cmd_genkey)


    # --- future commands ---
    # sub.add_parser("sign", help="Sign a payload")
    # sub.add_parser("verify", help="Verify a signed payload")

    args = parser.parse_args(argv)
    args.func(args)
    return 0

