# config_utils.py
import re
import sys

def valid_callsign(call) -> bool:

    _CALLSIGN_RE = re.compile(
        r"""
        ^                           # start
        [A-Z]                       # must start with letter
        [A-Z0-9]{0,5}               # up to 6 chars total
        (?:-(?:[0-9]|1[0-5]))?      # optional -SSID (0–15)
        $                           # end
        """,
        re.VERBOSE
    )
    if _CALLSIGN_RE.match(call):
        return True

    return False



CALLSIGN_RE = re.compile(r"^[A-Z0-9]{1,3}[0-9][A-Z0-9]{1,4}$")


def request_callsign(default: str | None = None) -> str:
    """
    Prompt the user for a station callsign.

    If default is provided, it is returned immediately.

    Raises:
        RuntimeError if interactive input is unavailable.
    """

    if default:
        return default.strip().upper()

    if not sys.stdin or not sys.stdin.isatty():
        raise RuntimeError(
            "Interactive input unavailable. "
            "Please supply a callsign via configuration or --callsign."
        )

    print("\nNo callsign is configured for this station.")
    print("Please enter the callsign this station should use.")
    print("Examples: ZL1ABC, VK3XYZ, N0CALL\n")

    while True:
        try:
            value = input("Callsign: ").strip().upper()
        except EOFError:
            raise RuntimeError("Cannot prompt for callsign (no stdin)")

        if not value:
            print("Callsign cannot be empty.")
            continue

        if not CALLSIGN_RE.match(value):
            print(f"'{value}' does not look like a valid callsign.")
            print("Try again (letters + number, no spaces).")
            continue

        confirm = input(f"Use callsign '{value}'? [Y/n]: ").strip().lower()
        if confirm in ("", "y", "yes"):
            return value


def request_ssid(default: int = 1) -> int:
    """
    Interactively request an AX.25 SSID from the user.
    Returns a validated integer between 0 and 15.
    """
    print("\nAX.25 SSID configuration")
    print("------------------------")
    print("The SSID distinguishes multiple stations using the same callsign.")
    print("Valid values are 0–15. Reflectors commonly use something like 1 or 10.\n")

    while True:
        raw = input(f"Enter SSID [0–15] (default: {default}): ").strip()

        if raw == "":
            return default

        try:
            ssid = int(raw)
        except ValueError:
            print("Invalid input. Please enter a number between 0 and 15.")
            continue

        if 0 <= ssid <= 15:
            return ssid

        print("SSID must be between 0 and 15.")


def request_keypair_paths(default_priv: str = "keys/private.pem",
                          default_pub: str = "keys/public.pem") -> tuple[str, str]:
    """
    Prompt the user for private/public key locations.
    Returns a tuple of (private_key_path, public_key_path).
    """
    if not hasattr(__builtins__, "input"):
        raise RuntimeError("Interactive input unavailable")

    print("\nNo keypair is configured for this station.")
    print("A private/public keypair is required for authentication.\n")

    # --- Private key -------------------------------------------------
    while True:
        try:
            value = input(f"Private key path [{default_priv}]: ").strip()
        except EOFError:
            raise RuntimeError("Cannot prompt for key path (no stdin)")

        if not value:
            value = default_priv

        confirm = input(f"Use private key path '{value}'? [Y/n]: ").strip().lower()
        if confirm in ("", "y", "yes"):
            private_key = value
            break

    # --- Public key --------------------------------------------------
    while True:
        try:
            value = input(f"Public key path [{default_pub}]: ").strip()
        except EOFError:
            raise RuntimeError("Cannot prompt for key path (no stdin)")

        if not value:
            value = default_pub

        confirm = input(f"Use public key path '{value}'? [Y/n]: ").strip().lower()
        if confirm in ("", "y", "yes"):
            public_key = value
            break

    return private_key, public_key
