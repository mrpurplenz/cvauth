#!/usr/bin/env python3

###THIS PROGRAM IS IN DEVELOPEMENT####

import os
import pty
import time
import queue
import select
import signal
import re
from pathlib import Path
import pe.app
import pe.monitor

#from cvauth.verify import verify_cvauth
#from cvauth.auth_types import AuthType
#from cvauth.keyring import Keyring

from .config import ensure_config, load_config, update_config_value
from .auth import load_private_key, generate_and_save_keypair, ensure_bytes
from .auth import sign_packet, verify_packet, AuthType, AuthResult
from .packet import CVPacket
from .transport import connect_agwpe

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python <=3.10
import tomli_w




# =====================
# CONFIG
# =====================
#DIRECT CONFIG
AGWPE_HOST = "127.0.0.1"
AGWPE_PORT = 8000

LISTEN_CALLSIGN = "N0CALL"
TX_CALLSIGN = "N0CALL"
AX25_PORT = 0
VIA = []  # e.g. ["WIDE1-1", "WIDE2-1"]

PTY_SHELL = "bash"

#LOCAL CONFIG FUNCTIONS

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

class LocalKeyring:

    def __init__(self, key_dir: Path):
        self.key_dir = key_dir

    def get_public_key(self, callsign: str):

        key_path = self.key_dir / f"{callsign.upper()}.pub"

        if not key_path.exists():
            return None

        from cvauth.auth import load_public_key
        return load_public_key(key_path)
        
        
def sanitise_text(data: bytes) -> str:

    import unicodedata

    text = data.decode("utf-8", "strict")

    text = unicodedata.normalize("NFC", text)

    text = "".join(
        ch for ch in text
        if ch == "\n" or (32 <= ord(ch) <= 126)
    )

    return text  

#AUTHENTICATION FUNCTION
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

class UIMonitor(pe.monitor.Monitor):
    """
    Monitor that pushes UI frames into a queue
    """

    #def __init__(self, q):
    def __init__(self):
        self._queue = queue.Queue()
        #super().__init__()
        #self.q = q
        
    @property
    def event_queue(self):
        return self._queue

    #def on_receive_ui(self, port, call_from, call_to, data, via):
    #    self.q.put((port, call_from, call_to, data, via))
    
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


class CVAuthPTYServer:

    def __init__(self):

        self.config = None
        self.private_key = None
        self.callsign = None
        self.ssid = None
        
        #self.packet_queue = queue.Queue()
        #self.keyring = Keyring()

        #self.call_from = None
        
        self.app = pe.app.Application()
        self.monitor = UIMonitor()
        
        self.pty_fd = None
        self.pty_pid = None

    # ---------------------------------------------------------

    def start_pty(self):
        """
        Spawn a bash shell inside a pseudo terminal
        """

        pid, fd = pty.fork()

        if pid == 0:
            os.execvp(PTY_SHELL, [PTY_SHELL])

        self.pty_pid = pid
        self.pty_fd = fd

        print(f"PTY started pid={pid}")

    # ---------------------------------------------------------

    def start(self):

        #print("Loading keyring...")
        #self.keyring.load()

        #Gather config
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

        self.keyring = LocalKeyring(
            public_key_path=self.config.resolve_path(self.config.keys.public_key),
            callsign=self.config.identity.callsign
        )
        
        
        
        
        
        print("[*] Starting PTY...")
        self.start_pty()
         
        print("[*] Starting AGWPE server")
        
        self.app.use_monitor(self.monitor)
        connect_agwpe(self.app, AGWPE_HOST, AGWPE_PORT)
        self.app.enable_monitoring = True
        self.running = True
        
    def stop(self):
        print("[*] Stopping CVAuth pty")
        self.running = False
        try:
            self.app.enable_monitoring = False
        except Exception:
            pass
        self.app.stop() 

    # ---------------------------------------------------------

    def process_packet(self, port, call_from, call_to, data, via):

        if call_to != self.callsign:
            return

        try:
            received_payload = data

            result = verify_cvauth(
                received_payload,
                call_from,
                self.keyring
            )

            auth_status = result["auth_status"]

            if auth_status != AuthType.VALID:
                print(f"Rejected packet from {call_from} ({auth_status})")
                return

            payload = sanitise_text(result["sanitised_payload"])

            if isinstance(payload, bytes):
                payload = payload.decode("utf-8", "ignore")

            print(f"{call_from} → PTY: {payload}")

            self.call_from = call_from

            os.write(self.pty_fd, (payload + "\n").encode())

        except Exception as e:
            print("Packet processing error:", e)

    # ---------------------------------------------------------

    def process_pty_output(self):

        try:
            output = os.read(self.pty_fd, 1024)

            if not output:
                return

            if not self.call_from:
                return

            self.app.send_unproto(
                AX25_PORT,
                self.callsign,
                self.call_from,
                output,
                VIA
            )

        except OSError:
            pass

    # ---------------------------------------------------------

    def run(self):

        print("Server running.")
        q = self.monitor.event_queue
        
        while self.running:
            process_this = False
            try:
                kind, port, call_from, call_to, text, received_payload = q.get(timeout=0.5)
                if self.config.identity.callsign == call_to:
                    process_this = True
                    print(f"LOCATED UI PACKET FOR {self.callsign}")
                    #print(f"[DEBUG] Raw event: kind={kind}, port={port}, from={call_from}, to={call_to}, text={text}, data_len={len(data) if data else 0}")
            except queue.Empty:
                continue
            
            
            if process_this:
                self.process_packet(port, call_from, call_to, received_payload, [])


            # check PTY output

            r, _, _ = select.select([self.pty_fd], [], [], 0)

            if self.pty_fd in r:
                self.process_pty_output()

            time.sleep(0.01)

    # ---------------------------------------------------------

    def depr_stop(self):

        print("Stopping server")

        if self.pty_pid:
            try:
                os.kill(self.pty_pid, signal.SIGTERM)
            except Exception:
                pass

        if self.app:
            self.app.stop()


# -------------------------------------------------------------


def main():

    server = CVAuthPTYServer()

    def shutdown(signum, frame):
        server.stop()
        
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    try:
        server.start()
        server.run()

    except KeyboardInterrupt:
        print("\nStopping")

    finally:
        server.stop()


if __name__ == "__main__":
    main()
