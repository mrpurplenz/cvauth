#!/usr/bin/env python3
"""
CVAuth Reflector

Listens for AX.25 UI packets addressed to our callsign via Direwolf (AGWPE),
verifies CVAuth payloads, and emits a NEW CVAuth-signed response.

Architecture:

AGWPE socket
   ↓
pyham_pe Application
   ↓
_Monitor (queues decoded events)
   ↓
event loop (this file)
   ↓
CVAuth verification
   ↓
send_unproto()
"""

import queue
import signal
import sys
import time
from enum import Enum
from pathlib import Path
import pe.app
import pe.monitor

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python <=3.10
import tomli_w

from .config import ensure_config, load_config, update_config_value
from .auth import load_private_key, generate_and_save_keypair, ensure_bytes
from .auth import sign_packet, verify_packet, AuthType, AuthResult
from .packet import CVPacket
from .transport import connect_agwpe

import re


def update_config(update_data,config_path):
    """
    Update the existing CVAuth config file.
    Current config as understood by application is written.
    """
    #config_path = current_config.config_path
    with config_path.open("wb") as f:
        config_dict = tomllib.load(f)

    config_dict = config["cvauth"]["identity"]["ssid"] = ssid


    config = load_config(config_path)
    return config


def request_callsign() -> str:
    """
    Prompt the user for a station callsign.

    Returns:
        Uppercase callsign string.

    Raises:
        RuntimeError if stdin is not interactive.
    """
    CALLSIGN_RE = re.compile(r"^[A-Z0-9]{1,3}[0-9][A-Z0-9]{1,4}$")

    if not hasattr(__builtins__, "input"):
        raise RuntimeError("Interactive input unavailable")

    print()
    print("No callsign is configured for this CVAuth reflector.")
    print("Please enter the callsign this station should use.")
    print("Examples: ZL1ABC, VK3XYZ, N0CALL")
    print()

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

def request_ssid() -> int:
    """
    Interactively request an AX.25 SSID from the user.
    Returns a validated integer between 0 and 15.
    """
    print()
    print("AX.25 SSID configuration")
    print("------------------------")
    print("The SSID distinguishes multiple stations using the same callsign.")
    print("Valid values are 0–15. Reflectors commonly use something like 1 or 10.")
    print()

    while True:
        raw = input("Enter SSID [0–15] (default: 1): ").strip()

        if raw == "":
            return 1

        try:
            ssid = int(raw)
        except ValueError:
            print("Invalid input. Please enter a number between 0 and 15.")
            continue

        if 0 <= ssid <= 15:
            return ssid

        print("SSID must be between 0 and 15.")


def request_keypair_paths(config) -> tuple[str, str]:
    """
    Prompt the user for private/public key locations.
    Returns relative paths suitable for config storage.
    """
    if not hasattr(__builtins__, "input"):
        raise RuntimeError("Interactive input unavailable")

    default_priv = "keys/private.pem"
    default_pub = "keys/public.pem"

    print()
    print("No keypair is configured for this CVAuth reflector.")
    print("A private/public keypair is required for authentication.")
    print()

    # --- Private key -------------------------------------------------

    while True:
        try:
            value = input(
                f"Private key path [{default_priv}]: "
            ).strip()
        except EOFError:
            raise RuntimeError("Cannot prompt for key path (no stdin)")

        if not value:
            value = default_priv

        confirm = input(
            f"Use private key path '{value}'? [Y/n]: "
        ).strip().lower()

        if confirm in ("", "y", "yes"):
            private_key = value
            break

    # --- Public key --------------------------------------------------

    while True:
        try:
            value = input(
                f"Public key path [{default_pub}]: "
            ).strip()
        except EOFError:
            raise RuntimeError("Cannot prompt for key path (no stdin)")

        if not value:
            value = default_pub

        confirm = input(
            f"Use public key path '{value}'? [Y/n]: "
        ).strip().lower()

        if confirm in ("", "y", "yes"):
            public_key = value
            break

    return private_key, public_key



# =====================
# CONFIG
# =====================

AGWPE_HOST = "127.0.0.1"
AGWPE_PORT = 8000

LISTEN_CALLSIGN = "N0CALL"
TX_CALLSIGN = "N0CALL"
AX25_PORT = 0
VIA = []  # e.g. ["WIDE1-1", "WIDE2-1"]

def default_private_key_path(config) -> Path:
    return config.config_dir / "keys" / "private.pem"

def default_public_key_path(config) -> Path:
    return config.config_dir / "keys" / "public.pem"



# =====================
# MONITOR TYPES
# =====================

class MonitorType(Enum):
    UNPROTO_INFO = "UI"
    UNPROTO_TEXT = "UT"
    UNPROTO_BINARY = "UB"



class LocalKeyring:
    def __init__(self, state, public_key_dir: Path, callsign: str):
        self.state = state
        self.public_key_dir = public_key_dir
        #self.key_dir = public_key_path.parent

    def get_public_key(self, station: str):
        from cvauth.auth import load_public_key
        callsign = station2call(station.upper())
        if self.state.verbose:
            self.state.messages.append(f"looking for key at {self.public_key_dir}/{callsign}.pem")

        key_file = self.public_key_dir / f"{callsign}.pem"

        if key_file.exists():
            return load_public_key(key_file)

        return None



# =====================
# MONITOR IMPLEMENTATION
# =====================

class _Monitor(pe.monitor.Monitor):
    """
    Minimal monitor that pushes incoming UI frames into a queue.
    """

    def __init__(self):
        self._queue = queue.Queue()

    @property
    def event_queue(self):
        return self._queue

    def monitored_unproto(self, port, call_from, call_to, text, data):
        # Only care about UI frames addressed to us
        #if call_to != LISTEN_CALLSIGN:
        #    return

        self._queue.put((
            MonitorType.UNPROTO_INFO,
            port,
            call_from,
            call_to,
            text,
            data
        ))
        return

# =====================
# CVAUTH PLACEHOLDERS
# =====================


def verify_cvauth(received_payload: bytes, call_from: str, keyring: LocalKeyring):
    """
    Verify a CVAuth packet and return structured information.

    Returns dict:
      {
        "signed": bool,       		# True if the packet had a signature
        "valid": bool,        		# True if the signature is valid
        "signer": str|None,   		# Callsign of signer if known
        "call_from": str,               # Call sign of UI packer sender
        "sanitised_payload": bytes      # Internal payload of the CVAuth packet
      }
    """
    AUTH_DISPLAY = {
        AuthType.VALID:       "Signature verified",
        AuthType.NOTSIGNED:   "Not signed",
        AuthType.KEYNOTFOUND: "Public key not found",
        AuthType.INVALID:     "Invalid signature",
        AuthType.UNKNOWN:     "Unknown",
    }

    try:
        # Wrap the raw bytes into a CVPacket
        packet = CVPacket.decode(raw=received_payload, from_call=call_from)
    except Exception:
        # Not a CVAuth packet at all
        text = payload.decode("utf-8", "replace")
        return {
            "auth_status": AuthType.UNKNOWN,
            "authentic": "Unknown packet format",
            "reason": None,
            "signer": None,
            "call_from": call_from,
            "sanitised_payload": text.strip(),
        }

    # Use your auth module to verify the packet
    result = verify_packet(packet, keyring)
    print(packet)
    print(result)

    # Map AuthType to signed/valid
    signed = result.auth_type != AuthType.NOTSIGNED and result.auth_type != AuthType.UNKNOWN
    valid = result.auth_type == AuthType.VALID
    authenticity = AUTH_DISPLAY[result.auth_type]

    return {
        "auth_status": result.auth_type,
        "authentic": authenticity,
        "reason": result.reason if result.reason else None,
        "signer": result.signer if signed else None,
        "call_from": call_from,
        "sanitised_payload": packet.payload,
    }


def make_reflector_message(result, callsign, private_key):
    """
    Construct a *new* reflector-originated message.
    """
    if result["auth_status"] == AuthType.VALID:
        return (
            f"CVAuth reflector: An authenticated message was received from {result['signer']}"
            f" which was {result['sanitised_payload']}"
        )

    if result["auth_status"] == AuthType.NOTSIGNED:
        #return (
        #    f"CVAuth reflector: Received an UNSIGNED message from {result['call_from']} "
        #    f" as follows: {result['sanitised_payload']}"
        #)
        message_to_sign = (
            f"CVAuth reflector: Received an UNSIGNED message from {result['call_from']} "
            f" as follows: {result['sanitised_payload']} This message has been signed by me and returned to you, hense the bytes at the front of the message"
        )
        pkt = CVPacket(
            from_call=callsign,
            payload=ensure_bytes(message_to_sign),
        )
        sign_packet(pkt, private_key)
        return pkt.encode()

    if result["auth_status"] == AuthType.KEYNOTFOUND:
        return (
            f"CVAuth reflector: Key not found to authenticate the SIGNED message from {result['signer']} "
            f" as follows: {result['sanitised_payload']}"
        )

    if result["auth_status"] == AuthType.INVALID:
        return (
            f"CVAuth reflector: INVALID signature from "
            f"{result['signer']}"
        )

    if result["auth_status"] == AuthType.UNKNOWN:
        return (
            f"CVAuth reflector: Unknown authentication status for message from "
            f"{result['call_from']} as follows: {result['sanitised_payload']}"
        )


    return (
        f"CVAuth reflector: authenticated message from "
        f"{result['call_from']}: {result['message']}"
    )

# =====================
# MAIN LOOP
# =====================

class CVAuthReflector:
    def __init__(self):
        self.config = None
        self.private_key = None
        self.callsign = None
        self.ssid = None

        self.app = pe.app.Application()
        self.monitor = _Monitor()
        self.running = True


    def send_start_beacon(self):
        test_text = "CVAuth reflector heartbeat test"
        print(f"[INFO] Sending local test beacon: {test_text}")
        local_call = "N0CALL"
        self.app.send_unproto(
            AX25_PORT,
            local_call,
            "QST",  # send to self
            test_text.encode("utf-8"),
            VIA,
        )


    def send_beacon(self,text):
        test_text = "Authentication Reflector - Decode with cvauth from: https://github.com/mrpurplenz/cvauth "+text
        print(f"[INFO] Sending local test beacon: {test_text}")
        self.app.send_unproto(
            AX25_PORT,
            "ZL2DRS",
            "QST",  # send to all
            test_text.encode("utf-8"),
            VIA,
        )
        


    def handle_incoming_packet(self, src, dest, packet):
        if not packet.is_signed():
            # Sign the packet using the reflector's private key
            packet.sign(self.private_key, self.callsign)
            header = f"Message received from {src} was unsigned; signing as {self.callsign}: "
            payload = header + packet.payload
            self.send_unproto(dest, payload)

    def start(self):
        ###########
        #Configure
        ###########

        # Ensure the config exists and load it
        config_path = ensure_config()
        print(f"Loading config from {config_path}")
        config = load_config(config_path)


        # Ensure a station callsign exists
        callsign = config.identity.callsign
        if not callsign:
            callsign = request_callsign()

            #update the local loaded config with a write to the config file
            config = update_config_value(config, "identity.callsign", callsign)

            print(f"Using callsign: {config.identity.callsign}")


        # Determine station SSID
        ssid = config.identity.ssid
        if not ssid:
            ssid = request_ssid()

            #update the local loaded config with a write to the config file
            config = update_config_value(config, "identity.ssid", ssid)

            print(f"Using ssid: {config.identity.ssid}")
            print(f"Local station: {config.identity.callsign}-{config.identity.ssid}") 


        # --- Ensure private/public key paths exist in config -----------------

        private_key = config.keys.private_key
        public_key = config.keys.public_key

        if not private_key or not public_key:
            private_key, public_key = request_keypair_paths(config)

            config = update_config_value(
                config, "keys.private_key", private_key
            )
            config = update_config_value(
                config, "keys.public_key", public_key
            )

            print("Key paths configured:")
            print(f"  Private key: {config.keys.private_key}")
            print(f"  Public key : {config.keys.public_key}")


        # --- Ensure key files exist ------------------------------------------

        private_path = config.resolve_path(Path(config.keys.private_key))
        public_path = config.resolve_path(Path(config.keys.public_key))

        if not private_path.exists() or not public_path.exists():
            print()
            print("No keypair files found on disk.")
            print(f"Expected private key: {private_path}")
            print(f"Expected public key : {public_path}")
            print()

            confirm = input("Generate a new keypair now? [Y/n]: ").strip().lower()
            if confirm not in ("", "y", "yes"):
                raise RuntimeError("Cannot continue without a keypair")

            private_path.parent.mkdir(parents=True, exist_ok=True)
            public_path.parent.mkdir(parents=True, exist_ok=True)

            generate_and_save_keypair(
                private_path=private_path,
                public_path=public_path,
            )

            print("[+] Keypair generated successfully")

        # Load private key (now guaranteed to exist)
        self.private_key = load_private_key(private_path)

        # Extract identity
        self.callsign = config.identity.callsign

        # Extract SSID
        self.ssid = config.identity.ssid

        self.config = config

        self.keyring = LocalKeyring(None,
            public_key_dir=self.config.resolve_path(self.config.keys.public_key).parent,
            callsign=self.config.identity.callsign
        )

        # Start reflector
        print("[*] Starting CVAuth reflector")
        self.app.use_monitor(self.monitor)

        connect_agwpe(self.app, AGWPE_HOST, AGWPE_PORT)

        #try:
        #    self.app.start(AGWPE_HOST, AGWPE_PORT)

        #except ConnectionRefusedError:
        #    print(f"[!] Cannot connect to AGWPE server at {AGWPE_HOST}:{AGWPE_PORT}")
        #    print("[!] Is the port accessable and open and your TNC running? eg. direwolf")
        #    print("[!] Is AGWPE enabled on your TNC config? ie (for direwolf conf) ")
        #    print(f"[!] AGWPORT {AGWPE_PORT}")
        #    sys.exit(1)

        #except socket.gaierror:
        #    print(f"[!] Invalid AGWPE host: {AGWPE_HOST}")
        #    sys.exit(1)

        #except Exception as e:
        #    print(f"[!] Unexpected error connecting to AGWPE server: {e}")
        #    sys.exit(1)

        self.app.enable_monitoring = True

    def stop(self):
        print("[*] Stopping CVAuth reflector")
        self.running = False
        try:
            self.app.enable_monitoring = False
        except Exception:
            pass
        self.app.stop()

    def run(self):
        q = self.monitor.event_queue
        
        last_beacon = time.time()
        while self.running:
            now = time.time()
            
            BEACON_INTERVAL = 1800
            if now - last_beacon >= BEACON_INTERVAL:
                self.send_beacon("")
                last_beacon = now
                
            reflect = False    
            try:
                kind, port, call_from, call_to, text, received_payload = q.get(timeout=0.5)
                if self.config.identity.callsign == call_to:
                    reflect = True
                    print(f"LOCATED UI PACKET FOR {self.callsign}")
                    #print(f"[DEBUG] Raw event: kind={kind}, port={port}, from={call_from}, to={call_to}, text={text}, data_len={len(data) if data else 0}")
            except queue.Empty:
                continue


            #if kind != MonitorType.UNPROTO_INFO:
            #    continue

            print(f"[RX] {call_from} → {call_to}: {text}")
            if reflect:
                result = verify_cvauth(received_payload, call_from, self.keyring)
                print(result)
                reply_bytes = make_reflector_message(result, self.callsign, self.private_key)

                #code to see the packet I created
                #if result["auth_status"] == AuthType.NOTSIGNED:
                #    created_packet = CVPacket.decode(reply_bytes, from_call=self.callsign)
                #    print(created_packet)

                print(f"[TX] {reply_bytes}")

                self.app.send_unproto(
                    AX25_PORT,
                    call_to,
                    call_from,      # reply directly to sender
                   reply_bytes,
                    VIA,
                )

# =====================
# SIGNAL HANDLING
# =====================

def main():
    reflector = CVAuthReflector()

    def shutdown(signum, frame):
        reflector.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    reflector.start()
    #reflector.send_start_beacon()
    reflector.run()

if __name__ == "__main__":
    main()
