#!/usr/bin/env python3

import queue
import time
import signal
from blessed import Terminal
import pe.app
import pe.monitor
from pathlib import Path
from .config import ensure_config, load_config, update_config_value, CVAuthConfig
from .config_utils import request_callsign, request_ssid, request_keypair_paths, valid_callsign
from .packet import CVPacket
from .auth import sign_packet, verify_packet, AuthType, AuthResult, ensure_bytes, load_private_key


# ====================
# CONFIGURE
# ====================

class LocalKeyring:
    def __init__(self, public_key_path: Path, callsign: str):
        self.public_key_path = public_key_path
        self.callsign = callsign

    def get_public_key(self, callsign: str):
        if callsign == self.callsign:
            from cvauth.auth import load_public_key
            return load_public_key(self.public_key_path)
        return None

# =====================
# MONITOR
# =====================

class UIMonitor(pe.monitor.Monitor):
    """
    Minimal monitor that pushes UI frames into a queue.
    """
    def __init__(self):
        self.queue = queue.Queue()

    def monitored_unproto(self, port, call_from, call_to, text, data):
        # Push raw data; no logic here
        self.queue.put({
            "from": call_from,
            "to": call_to,
            "text": text,
            "data": data,
        })


# =====================
# STATE
# =====================

class UIState:
    def __init__(self, config: CVAuthConfig=None, callsign="N0CALL", ssid=0, signing=False):
        self.running = True
        self.callsign = callsign
        self.ssid = ssid
        self.signing = signing
        self.messages = []      # list[str]
        self.input_buffer = ""
        self.config = None
        self.private_key_path = None
        self.public_key_path = None
        self.destination = "ALL"

# =====================
# RENDER
# =====================

def render(term: Terminal, state: UIState):
    height = term.height
    width = term.width

    HEADER_Y = 1
    PROMPT_Y = 1
    BODY_Y = height - HEADER_Y - PROMPT_Y

    # Clear screen
    print(term.home + term.clear)
    #print(term.home) #This line to drive the prompt line up the screen

    # ----- Header -----
    call_print=state.callsign
    ssid_print=state.ssid
    destination=state.destination or ""
    #call_print="ZL2DRS"
    #ssid_print="4"
    headerL = f" CVAuth chat by ZL2DRS | Station {call_print}-{ssid_print} | Dest [{str(destination)}] | Filter []"
    sign_text = "Signing ON" if state.signing else "signing OFF"
    pad_width = width -len(headerL)- len(sign_text)
    if pad_width < 1:
        pad_width = 1
    headerPAD = " " * pad_width

    # Now apply colours
    headerR = (
        term.green + sign_text if state.signing
        else term.red + sign_text
    )
    header = headerL + headerPAD + headerR

    print(
        term.move_yx(1, 0)
        + term.black_on_white
        + header.ljust(width)
        + term.normal
    )

    # ----- Message area -----
    visible_msgs = state.messages[-BODY_Y:]
    for i, msg in enumerate(visible_msgs):
        print(
            term.move_yx(1+HEADER_Y + i, 0)
            + msg[:width].ljust(width)
        )

    # ----- Prompt -----
    prompt = f"{state.callsign} > "
    print(
        term.move_yx(height+2, 0)
        + term.bold
        + prompt
        + term.normal
        + state.input_buffer
        + term.clear_eol
    )

    # Put cursor at end of input
    print(
        term.move_yx(height - 2, len(prompt) + len(state.input_buffer)),
        end="",
        flush=True,
    )


# =====================
# MAIN LOOP
# =====================

def run_tui(
    app: pe.app.Application,
    monitor: UIMonitor,
    state: UIState,
):
    term = Terminal()
    show_splash(term)
    with term.fullscreen(), term.cbreak():
        while state.running:
            # ---- Keyboard input (non-blocking) ----
            key = term.inkey(timeout=0)

            if key:
                if key.name == "KEY_ENTER":
                    line = state.input_buffer.strip()

                    if line:
                        if line.startswith("/"):
                            dispatch_command(line, state)
                        else:
                            send_message(line, state, app)

                    state.input_buffer = ""

                elif key.name == "KEY_BACKSPACE":
                    state.input_buffer = state.input_buffer[:-1]

                elif not key.is_sequence:
                    state.input_buffer += key

            # ---- Drain monitor queue ----
            while not monitor.queue.empty():
                evt = monitor.queue.get()
                payload = evt["data"]
                call_from = evt["from"]

                #pass the payload to authentication process
                result = verify_cvauth(payload, evt["from"], state.keyring)
                auth_status=(result["auth_status"])
                sanitised_payload = result["sanitised_payload"]
                try:
                    text = sanitised_payload.decode("utf-8", "replace")
                except Exception:
                    text = repr(sanitised_payload)

                msg_colour = term.white
                match auth_status:
                    case AuthType.UNKNOWN:
                        msg_colour = term.orange
                    case AuthType.NOTSIGNED:
                        msg_colour = term.yellow
                    case AuthType.VALID:
                        msg_colour = term.green
                    case AuthType.KEYNOTFOUND:
                        msg_colour = term.orange
                    case AuthType.INVALID:
                        msg_colour = term.red
                    case _:
                        msg_colour = term.orange

                state.messages.append(
                    msg_colour +
                    f"[RX] {evt['from']} → {evt['to']}: {text}"
                    + term.normal
                )

            # ---- Render ----
            render(term, state)

            # ---- Yield ----
            time.sleep(0.05)

# ====================
# COMMANDS
# ====================

def cmd_quit(args, state):
    state.running = False
    state.messages.append("[system] Exiting.")
    return True

def cmd_help(args, state):
    if not args:
        state.messages.append("[system] Available commands:")
        for name, meta in COMMANDS.items():
            state.messages.append(
                f"[system] /{name:<8} - {meta['help']}"
            )
        return True

    cmd = COMMANDS.get(args[0])
    if not cmd:
        state.messages.append(
            "f[error] No such command: /{args[0]}"
        )
        return True

    state.messages.append(f"[system] Usage: {cmd['usage']}")
    state.messages.append(f"[system] " + cmd["help"])
    return True

def cmd_sign(args, state):
    new_signing = not(state.signing)
    state.signing = new_signing
    state.messages.append(f"[system] Signing toggled to {new_signing}")
    return True

def cmd_filter(args, state):
    return True

def cmd_status(args, state):
    return True

def cmd_destination(args, state):
    dest = args[0].strip().upper()
    VALID_ADHOC_DESTINATIONS = {
    "CQ",
    "QST",
    "BEACON",
    "IDENT",
    "ALL",
    "APRS",
    "CVAUTH",   # your protocol
    }

    if not dest:
        return False

    if dest in VALID_ADHOC_DESTINATIONS:
        state.destination=dest
        return True

    if valid_callsign(dest):
        state.destination=dest
        return True

    state.messages.append(f"[system] Destination must be either a valid call sign with optional ssid or one of")
    for valid_destination in VALID_ADHOC_DESTINATIONS:
        state.messages.append(f"[system]     {valid_destination}")

    return False

def cmd_via(args, state):
    return True



COMMANDS = {
    "quit": {
        "handler": cmd_quit,
        "help": "Exit the application",
        "usage": "/quit"
    },
    "help": {
        "handler": cmd_help,
        "help": "Show help for commands",
        "usage": "/help [command]"
    },
    "sign": {
        "handler": cmd_sign,
        "help": "Enable or disable message signing",
        "usage": "/sign on|off|toggle|status"
    },
    "filter": {
        "handler": cmd_filter,
        "help": "Set destination callsign filter",
        "usage": "/filter STRING or /filter -"
    },
    "status": {
        "handler": cmd_status,
        "help": "Show current status",
        "usage": "/status"
    },
    "destination": {
        "handler": cmd_destination,
        "help": "Set the Unproto packet destination",
        "usage": "/destination CALLSIGN"
    },
    "via": {
        "handler": cmd_via,
        "help": "Set the via nodes to pass through",
        "usage": "/via NODE"
    }
}


#Helper to wrangle the commands
def dispatch_command(line, state):
    parts = line.lstrip("/").split()
    if not parts:
        return

    cmd_name = parts[0]
    args = parts[1:]

    cmd = COMMANDS.get(cmd_name)

    if not cmd:
        state.messages.append(
            (f"[system] error Unknown command: /{cmd_name}")
        )
        return

    try:
        cmd["handler"](args, state)
    except Exception as e:
        state.messages.append(
            (f"[system] error Command failed: {e}")
        )

#Depricated
def handle_command(line, state):
    """
    Handle slash-commands.
    Returns True if the command was handled.
    """
    cmd = line.strip()

    if cmd == "/quit":
        state.running = False
        state.messages.append("[system] Quitting.")
        return True

    state.messages.append(f"[error] Unknown command: {cmd}")
    return True
# ====================
# AUTHENTICATION
# ====================

def sign_outgoing(line, state):

    pkt = CVPacket(
        from_call=state.callsign,
        payload=ensure_bytes(line),
    )
    config = state.config
    private_key_path = config.keys.private_key
    private_key_Posix = Path(private_key_path)
    private_key_file = config.resolve_path(private_key_Posix)
    private_key_deserial = load_private_key(private_key_file)
    sign_packet(pkt, private_key_deserial)
    return pkt.encode()

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




# =====================
# TRANSMISSION
# =====================

def send_message(line, state, app):
    # Stub: later this will go through AX.25 / signing / etc
    state.messages.append(f"[local] {line}")

    AX25_PORT = 0  #NEEDS MOVING TO STATE AND ULTIMATELY TO CONFIG
    VIA = []  # e.g. ["WIDE1-1", "WIDE2-1"] NEEDS MOVING TO STATE AND BE MUTABLE BY COMMAND
    destination = state.destination or ""
    call_to = destination
    call_from = f"{state.callsign}-{state.ssid}"
    signing = state.signing
    if signing:
        reply_bytes = sign_outgoing(line, state)
    else:
        reply_bytes = line.encode('utf-8')

    app.send_unproto(
        AX25_PORT,
        call_from,
        call_to,
        reply_bytes,
        VIA,
    )


# =====================
# SPLASH
# =====================
def show_splash(term):
    splash = [
"       ________            _________                                                                     ",
"       \______ \_______   /   _____/__ _______ ___  __ ____   ______                                     ",
"        |    |  \_  __ \  \_____  \|  |  \__  \\\\  \/ // __ \ /  ___/                                     ",
"        |    `   \  | \/  /        \  |  // __ \\\\   /\  ___/ \___ \                                      ",
"       /_______  /__|    /_______  /____/(____  /\_/  \___  >____  >                                     ",
"               \/                \/           \/          \/     \/                                      ",
"_____________   ____     _____          __  .__              .__            __                           ",
"\_   ___ \   \ /   /    /  _  \  __ ___/  |_|  |__      ____ |  |__ _____ _/  |_   _____  ______ ______  ",
"/    \  \/\   Y   /    /  /_\  \|  |  \   __\  |  \   _/ ___\|  |  \\\\__  \\\\   __\  \__  \ \____ \\\\____ \ ",
"\     \____\     /    /    |    \  |  /|  | |   Y  \  \  \___|   Y  \/ __ \|  |     / __ \|  |_> >  |_> >",
" \______  / \___/     \____|__  /____/ |__| |___|  /   \___  >___|  (____  /__|    (____  /   __/|   __/ ",
"        \/                    \/                 \/        \/     \/     \/             \/|__|   |__|    ",
"",
"",
        "CV Auth a chattervox authenticated chat terminal",
        "by Dr Suavé - ZL2DRS",
        "Based on ChatterVox by Brannon Dorsey,    KC3LZO ",
"          and PyHam by Martin F N Cooper, KD6YAM",
"",
        "Press any key to continue"

    ]

    with term.fullscreen(), term.cbreak(), term.hidden_cursor():
        print(term.clear)
        #print(term.hide_cursor(), end='', flush=True)

        height = len(splash)
        width = max(len(line) for line in splash)

        start_y = (term.height - height) // 2
        start_x = (term.width - width) // 2

        for i, line in enumerate(splash):
            print(term.move_yx(start_y + i, start_x) + term.bold + line)

        # Wait for any key
        term.inkey()
        print(term.normal_cursor(), end='', flush=True)



# =====================
# ENTRY POINT
# =====================

def main():
    AGW_HOST = "127.0.0.1"
    AGW_PORT = 8000

    app = pe.app.Application()
    monitor = UIMonitor()
    app.use_monitor(monitor)

    #Initialise the state data
    state = UIState()

    #Fetch config and load to the state
    config_path = ensure_config()
    config = load_config(config_path)
    state.config = config

    #Callsign
    callsign = config.identity.callsign
    if not callsign:
        callsign = request_callsign()
        config = update_config_value(config, "identity.callsign", callsign)
    state.callsign = config.identity.callsign

    #SSID
    ssid = config.identity.ssid
    if not ssid:
        ssid = request_ssid()
        config = update_config_value(config, "identity.ssid", ssid)
    state.ssid = config.identity.ssid

    #Local key paths
    private_key_path = config.keys.private_key
    public_key_path = config.keys.public_key

    if not private_key_path or not public_key_path:
        private_key_path, public_key_path = request_keypair_paths(config)

        config = update_config_value(
            config, "keys.private_key", private_key_path
        )
        config = update_config_value(
            config, "keys.public_key", public_key_path
        )
    state.private_key_path = private_key_path
    state.public_key_path = public_key_path

    #Local key files
    private_posix = config.resolve_path(Path(config.keys.private_key))
    public_posix = config.resolve_path(Path(config.keys.public_key))

    if not private_posix.exists() or not public_posix.exists():
        print()
        print("No keypair files found on disk.")
        print(f"Expected private key: {private_path}")
        print(f"Expected public key : {public_path}")
        print()

        confirm = input("Generate a new keypair now? [Y/n]: ").strip().lower()
        if confirm not in ("", "y", "yes"):
            raise RuntimeError("Cannot continue without a keypair")

        private_posix.parent.mkdir(parents=True, exist_ok=True)
        public_posix.parent.mkdir(parents=True, exist_ok=True)

        generate_and_save_keypair(
            private_path=private_posix,
            public_path=public_posix,
        )


        # Load private key (now guaranteed to exist)
        state.private_key = load_private_key(private_posix)

    #public keys keyring
    state.keyring = LocalKeyring(
        public_key_path=config.resolve_path(config.keys.public_key),
        callsign=config.identity.callsign
    )


    def shutdown(signum, frame):
        state.running = False

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print("[*] Starting AGW connection")
    app.start(AGW_HOST, AGW_PORT)
    app.enable_monitoring = True

    try:
        run_tui(app, monitor, state)
    finally:
        print("[*] Stopping")
        app.enable_monitoring = False
        app.stop()


if __name__ == "__main__":
    main()
