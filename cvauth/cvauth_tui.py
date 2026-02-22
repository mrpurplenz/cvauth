#!/usr/bin/env python3

import queue
import time
import signal
from blessed import Terminal
import pe.app
import pe.monitor
import ax25.netrom
from pathlib import Path
from .config import ensure_config, load_config, update_config_value, CVAuthConfig
from .config_utils import request_callsign, request_ssid, request_keypair_paths, valid_callsign
from .packet import CVPacket
from .auth import sign_packet, verify_packet, AuthType, AuthResult, ensure_bytes, load_private_key, generate_and_save_keypair
from .transport import connect_agwpe
import os

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
        self.destination = "QST"
        self.verbose = False
        self.netrom_nodes = {}   # dict[str, dict] keyed by sender callsign
        self.node_data = {}
        self.app = None
        self.via = None
        self.scroll_offset = 0
        self.body_y = 0
# =====================
# RENDER
# =====================

def render(term: Terminal, state: UIState):
    print(term.home + term.clear)
    height = term.height
    width = term.width

    HEADER_Y = 1
    PROMPT_Y = 1
    BODY_Y = height - HEADER_Y - PROMPT_Y
    state.body_y = BODY_Y
    # Clear screen
    #print(term.home + term.clear)
    #print(term.home)
    #print(term.home) #This line to drive the prompt line up the screen

    # ----- Header -----
    call_print=state.callsign
    ssid_print=state.ssid
    destination=state.destination or ""
    display_filter = ""
    h_1 = f" CVAuth chat | Station ["
    h_2 = f"{call_print}-{ssid_print}"
    h_3 = f"] | Dest ["
    h_4 = f"{str(destination)}"
    h_5 = f"] | Filter ["
    h_6 = f"{display_filter}"
    h_7 = f"]"
    header_no_colour = h_1+h_2+h_3+h_4+h_5+h_6+h_7
    sign_text = "Signing ON" if state.signing else "signing OFF"
    pad_width = width -len(header_no_colour)- len(sign_text)
    if pad_width < 1:
        pad_width = 1
    headerPAD = " " * pad_width

    # Now apply colours
    header_BG = term.on_grey
    headerL = (
        header_BG + 
        h_1 +
        term.yellow +
        h_2 +
        header_BG + term.black +
        h_3 +
        term.yellow +
        h_4 +
        header_BG + term.black +
        h_5 +
        term.yellow +
        h_6 +
        header_BG + term.black +
        h_7
    )
    headerR = (
        header_BG + term.green + sign_text if state.signing
        else header_BG + term.red + sign_text
    )
    header = headerL + headerPAD + headerR

    print(
        term.move_yx(1, 0)
        + term.black_on_white
        + header.ljust(width)
        + term.normal
    )
    # ----- Message area -----
    total = len(state.messages)
    start = max(0, total - (state.body_y) - state.scroll_offset)
    end = start + state.body_y
    visible_msgs = state.messages[start:end]
    
    for i, msg in enumerate(visible_msgs):
        line_no = 1 + HEADER_Y + i

        print(
            term.move_yx(line_no, 0)
            + msg[:width].ljust(width)
        )
    
    print(
        term.move_yx(1, 0)
        + term.black_on_white
        + header.ljust(width)
        + term.normal
    ) 

    # ----- Prompt -----
    prompt = f"{state.callsign} > "
    print(
        term.move_yx(height-1, 0)
        + term.bold
        + prompt
        + term.normal
        + state.input_buffer
        + term.normal
        + term.clear_eol
    )

    # Put cursor at end of input
    print(
        term.move_yx(height - 2, len(prompt) + len(state.input_buffer)),
        end="",
        flush=True,
    )
    
def bytes_to_hex_escape(data: bytes) -> str:
    """
    Convert raw bytes to a fully escaped \\xHH string representation.

    This is a lossless, byte-accurate representation suitable for:
        - Debug logging
        - Terminal-safe display
        - Copy/paste into test cases

    Args:
        data (bytes): Raw byte sequence.

    Returns:
        str: String like '\\x04\\x7a\\x39...'
    """
    return ''.join(f'\\x{b:02x}' for b in data)  
    
def bytes_to_display_text(data: bytes) -> str:
    """
    Convert raw bytes to terminal-safe text.

    - Decodes UTF-8 safely
    - Replaces invalid sequences
    - Escapes control characters (except newline, tab)
    """
    text = data.decode("utf-8", errors="replace")

    sanitized = []
    for ch in text:
        if ch in ("\n", "\r", "\t"):
            sanitized.append(ch)
        elif ord(ch) < 32 or ord(ch) == 127:
            sanitized.append(f"\\x{ord(ch):02x}")
        else:
            sanitized.append(ch)

    return "".join(sanitized)

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
    #with term.fullscreen(), term.cbreak(), term.mouse_enabled():
    with term.fullscreen(), term.cbreak():
        print(term.home + term.clear)
        render(term, state)
        while state.running:
            dirty = False
            # ---- Keyboard input (non-blocking) ----
            key = term.inkey(timeout=0)
            if key:
                dirty = True
                
                if key.name and key.name.startswith("MOUSE_"):
                    
		    # Scroll up (wheel up)
                    if key.name == "MOUSE_SCROLL_UP":
                        #state.messages.extend(str(state.body_y))
                        #state.scroll_offset = min(
                        #    state.scroll_offset + 1,
                        #    max(0, len(state.messages) - state.body_y)
                        #)
                        state.scroll_offset = min(max(0, len(state.messages) - state.body_y),state.scroll_offset+1)
                    # Scroll down (wheel down)
                    elif key.name == "MOUSE_SCROLL_DOWN":
                        #state.messages.extend("MOUSE_SCROLL_DOWN")
                        #state.scroll_offset = max(
                	#    state.scroll_offset - 1,
                	#    0
                        #)
                        state.scroll_offset = max(0, state.scroll_offset-1)
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
                dirty = True
                evt = monitor.queue.get()
                payload = evt["data"]
                call_from = evt["from"]
                call_to = evt["to"]

                if is_netrom_nodes_packet(call_to, payload):
                    netrom_data = decode_netrom_nodes(payload)
                    if netrom_data:
                        #state.messages.extend("[system detected NET/ROM data]")
                        #state.node_data[call_from] = netrom_data  # overwrite per sender
                        update_netrom_nodes(state, netrom_data['sender'], netrom_data) #add and update per sender
                        formatted_lines = format_netrom_summary(netrom_data)
                        state.messages.extend(formatted_lines)


                        continue  # Skip CVAuth + text decode
        

                #pass the payload to authentication process
                result = verify_cvauth(evt["data"], evt["from"], state.keyring)
                auth_status=(result["auth_status"])
                sanitised_payload = result["sanitised_payload"]
                try:
                    #text = bytes_to_display_text(sanitised_payload)
                    #text = sanitised_payload.decode("utf-8", "replace")
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
                RXheader = "[RX]"
                if state.verbose:
                    state.messages.append(f"[packet received: ChatterVox Magic bytes set: {result['is_CV']}, ChatterVox version: {result['version']}, Signed: {result['signed']}, Compressed: {result['compressed']}")
                    state.messages.append(f"[received bytes from pyham_pe: {bytes_to_hex_escape(evt['data'])}]")
                    RXheader = f"[RX {result['reason']}]"
                state.messages.append(
                    msg_colour +
                    RXheader +
                    f" {evt['from']} → {evt['to']}: {text}"
                    + term.normal
                )

            # ---- Render ----
            if dirty:
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

def cmd_verbose(args, state):
    new_verbose = not(state.verbose)
    state.verbose = new_verbose
    state.messages.append(f"[system] Verbose validity reason toggled to {new_verbose}")
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


def cmd_netpoll(args, state):
    """
    /netpoll CALLSIGN
    Send a NET/ROM routing table poll to a node.
    """
    app = state.app
    if not args:
        state.messages.append("[system] Usage: /netpoll CALLSIGN")
        return False

    target = args[0].strip().upper()
    if not valid_callsign(target):
        state.messages.append(f"[system] Invalid callsign: {target}")
        return False

    # Construct an empty NET/ROM poll frame
    # PID 0xCF indicates a NET/ROM frame
    poll_bytes = b'\x01'  # Simple poll indicator; some implementations may want actual payload
    AX25_PORT = 0  # Use default, can later be mutable
    VIA = state.via or []  # Use current via path

    call_from = f"{state.callsign}-{state.ssid}"
    call_to = target

    state.messages.append(f"[TX] NET/ROM poll to {call_to} via {VIA if VIA else 'direct'}")

    # Send the unproto packet
    app.send_unproto(
        AX25_PORT,
        call_from,
        call_to,
        poll_bytes,
        VIA,
    )

    return True
    
def cmd_tables(args, state):

    if not hasattr(state, "netrom_nodes") or not state.netrom_nodes:
        state.messages.append("[system] No NET/ROM node data available.")
        return True

    # If sender argument provided
    if args:
        sender = args[0].upper()

        if sender not in state.netrom_nodes:
            state.messages.append(
                f"[error] No NET/ROM data for sender: {sender}"
            )
            return True

        sender_nodes = state.netrom_nodes[sender]

        netrom_data = {
            "sender": sender,
            "nodes": list(sender_nodes.values()),
            "count": len(sender_nodes),
        }

        formatted_lines = format_netrom_summary(netrom_data)
        state.messages.extend(formatted_lines)
        return True

    # No args → print all
    for sender in sorted(state.netrom_nodes.keys()):

        sender_nodes = state.netrom_nodes[sender]

        netrom_data = {
            "sender": sender,
            "nodes": list(sender_nodes.values()),
            "count": len(sender_nodes),
        }

        formatted_lines = format_netrom_summary(netrom_data)
        state.messages.extend(formatted_lines)

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
    "verbose": {
        "handler": cmd_verbose,
        "help": "Toggle verbose authenticity reason on receive",
        "usage": "/verbose on|off|toggle|status"
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
    },
    "tables": {
        "handler": cmd_tables,
        "help": "Reports the netrom table",
        "usage": "/tables [SENDER_CALLSIGN]"
    },
        "netpoll": {
        "handler": cmd_netpoll,
        "help": "Send a NET/ROM routing table poll to a node",
        "usage": "/netpoll CALLSIGN"
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
    return pkt

def verify_cvauth(received_payload: bytes, call_from: str, keyring: LocalKeyring):
    """
    Verify a CVAuth packet and return structured information.

    Returns dict:
      {
        "auth_status": AuthType,        # One of UK, NS, SV, NK, IV
        "is_CV": bool,                  # True if chattervox packet
        "version": int,                 # verson no. of CV protocol 0 if not CV
        "signed": bool,                 # True if signed bit set
        "compressed":bool,              # True if compressed bit set
        "authentic": bool,              # True if valid
        "reason": str,                  # String contianing the reason for the status
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
        #text = bytes_to_display_text(received_payload)
        text = received_payload
        return {
            "auth_status": AuthType.UNKNOWN,
            "authentic": False,
            "reason": "Unknown packet format",
            "signer": None,
            "call_from": call_from,
            "sanitised_payload": bytes_to_hex_escape(received_payload),
        }

    # Use your auth module to verify the packet
    result = verify_packet(packet, keyring)
    #print(packet)
    #print(result)

    # Map AuthType to signed/valid
    signed = result.auth_type != AuthType.NOTSIGNED and result.auth_type != AuthType.UNKNOWN
    valid = result.auth_type == AuthType.VALID
    authenticity = AUTH_DISPLAY[result.auth_type]

    return {
        "auth_status": result.auth_type,
        "is_CV": packet.magic,                  
        "version": packet.version,                
        "signed": packet.signed,                 
        "compressed":packet.compressed,              
        "authentic": authenticity,
        "reason": result.reason if result.reason else None,
        "signer": result.signer if signed else None,
        "call_from": call_from,
        "sanitised_payload": packet.payload,
    }

# =====================
# NET/ROM DETECTION + DECODER
# =====================

def is_netrom_nodes_packet(call_to: str, payload: bytes) -> bool:
    return (
        call_to.strip().upper() == "NODES"
        and payload
        and payload[0] == 0xFF
    )



def old_decode_ax25_callsign(addr: bytes) -> str:
    """
    Decode 7-byte shifted AX.25 callsign field.
    """
    call = ''.join(chr(b >> 1) for b in addr[:6]).strip()
    ssid = (addr[6] >> 1) & 0x0F
    return f"{call}-{ssid}" if ssid else call
    
def decode_ax25_callsign(addr: bytes) -> str:
    """
    Properly decode 7-byte NET/ROM callsign field.
    """

    if len(addr) != 7:
        return "?"

    # First 6 bytes = callsign characters
    call = ""
    for b in addr[:6]:
        c = (b >> 1) & 0x7F
        if c != 0x20:  # ignore padding spaces
            call += chr(c)

    # 7th byte = SSID + flags
    ssid = (addr[6] >> 1) & 0x0F

    if ssid:
        return f"{call}-{ssid}"
    return call

    


def decode_netrom_nodes(payload: bytes):
    import ax25.netrom

    try:
        rb = ax25.netrom.RoutingBroadcast.unpack(payload)
    except Exception:
        return None

    nodes = []
    for d in rb.destinations:  # d is a Destination object
        nodes.append({
            "callsign": d.callsign,
            "alias": d.mnemonic,
            "via": d.best_neighbor,
            "quality": d.best_quality,
        })

    return {
        "sender": rb.sender,
        "nodes": nodes,
        "count": len(nodes),
    }



def depr_decode_netrom_nodes(sender: str, payload: bytes) -> dict:
    """
    Decode NET/ROM NODES broadcast into structured dict.
    """

    nodes = {}

    try:
        count = payload[0]
        offset = 1

        for _ in range(count):
            if offset + 21 > len(payload):
                break

            dest_call = decode_ax25_callsign(payload[offset:offset+7])
            offset += 7

            alias = payload[offset:offset+6].decode("ascii", "replace").strip()
            offset += 6

            best_neighbor = decode_ax25_callsign(payload[offset:offset+7])
            offset += 7

            quality = payload[offset]
            offset += 1

            nodes[dest_call] = {
                "alias": alias,
                "best_neighbor": best_neighbor,
                "quality": quality,
            }

    except Exception:
        return {}

    return {
        "sender": sender,
        "node_count": len(nodes),
        "nodes": nodes,
    }
def format_netrom_summary(netrom_data, term=None):
    """
    Format NET/ROM RoutingBroadcast data into a sorted, colored terminal table.

    Args:
        netrom_data: dict returned by decode_netrom_nodes()
        term: blessed.Terminal instance for color (optional)

    Returns:
        list[str]: formatted lines for display in messages
    """
    if term is None:
        class DummyTerm:
            bold = normal = white = cyan = yellow = green = magenta = red = ""
        term = DummyTerm()

    lines = []
    sender = netrom_data.get("sender", "UNKNOWN")
    node_count = netrom_data.get("count", 0)
    nodes = netrom_data.get("nodes", [])

    # Sort by quality descending
    nodes = sorted(nodes, key=lambda n: n.get("quality", 0), reverse=True)

    width = 64  # adjust for spacing

    # Top border
    lines.append(term.bold + "┌" + "─" * (width - 2) + "┐" + term.normal)

    # Title
    title = f"NET/ROM Routing Broadcast from {sender} — {node_count} nodes"
    lines.append(term.bold + "│" + title.center(width - 2) + "│" + term.normal)

    # Header separator
    lines.append(term.bold + "├" + "─" * (width - 2) + "┤" + term.normal)

    # Column headers
    header = f"{'DESTINATION':<12} {'ALIAS':<12} {'VIA':<12} {'QUAL':>5}"
    lines.append(term.bold + "│ " + header.ljust(width - 4) + " │" + term.normal)

    # Header-bottom separator
    lines.append(term.bold + "├" + "─" * (width - 2) + "┤" + term.normal)

    # Table rows
    for n in nodes:
        dest = str(n.get("callsign", ""))[:12]
        alias = str(n.get("alias", ""))[:12]
        via = str(n.get("via", ""))[:12]
        qual = n.get("quality", 0)

        # Color based on quality
        if qual >= 128:
            color = term.green + term.bold
        elif qual >= 120:
            color = term.green
        elif qual >= 110:
            color = term.yellow
        else:
            color = term.magenta + term.bold

        line = f"{dest:<12} {alias:<12} {via:<12} {str(qual):>5}"
        lines.append(term.bold + "│ " + line.ljust(width - 4) + " │" + term.normal)
        

    # Bottom border
    lines.append(term.bold + "└" + "─" * (width - 2) + "┘" + term.normal)

    return lines

def old_format_netrom_summary(netrom_data, term=None):
    """
    Format NET/ROM RoutingBroadcast data into a professional terminal table.

    Args:
        netrom_data: dict returned by decode_netrom_nodes()
        term: blessed.Terminal instance for color (optional)

    Returns:
        list[str]: formatted lines for display in messages
    """
    if term is None:
        class DummyTerm:
            bold = normal = white = cyan = yellow = green = magenta = ""
        term = DummyTerm()

    lines = []
    sender = netrom_data.get("sender", "UNKNOWN")
    node_count = netrom_data.get("count", 0)
    nodes = netrom_data.get("nodes", [])

    # Table width
    width = 60

    # Top border
    lines.append(term.bold + "┌" + "─" * (width - 2) + "┐" + term.normal)

    # Title
    title = f"NET/ROM Routing Broadcast from {sender} — {node_count} nodes"
    lines.append(term.bold + "│" + title.center(width - 2) + "│" + term.normal)

    # Header separator
    lines.append(term.bold + "├" + "─" * (width - 2) + "┤" + term.normal)

    # Column headers
    header = f"{'DESTINATION':<12} {'ALIAS':<12} {'VIA':<12} {'QUAL':>4}"
    lines.append(term.bold + "│ " + header.ljust(width - 4) + " │" + term.normal)

    # Header-bottom separator
    lines.append(term.bold + "├" + "─" * (width - 2) + "┤" + term.normal)

    # Table rows
    for n in nodes:
        dest = str(n.get("callsign", ""))[:12]
        alias = str(n.get("alias", ""))[:12]
        via = str(n.get("via", ""))[:12]
        qual = str(n.get("quality", ""))

        # Optional coloring
        color = term.green if n.get("quality", 0) > 110 else term.yellow
        line = f"│ {dest:<12} {alias:<12} {via:<12} {qual:>4} │"
        lines.append(color + line + term.normal)

    # Bottom border
    lines.append(term.bold + "└" + "─" * (width - 2) + "┘" + term.normal)

    return lines

def update_netrom_nodes(state, sender, netrom_data):
    """
    Merge decoded NET/ROM nodes into state.netrom_nodes
    without overwriting previous entries.
    """

    if not netrom_data or "nodes" not in netrom_data:
        return False

    # Ensure top-level container exists
    if not hasattr(state, "netrom_nodes"):
        state.netrom_nodes = {}

    # Ensure sender entry exists
    if sender not in state.netrom_nodes:
        state.netrom_nodes[sender] = {}

    sender_table = state.netrom_nodes[sender]

    updated = False

    for node in netrom_data["nodes"]:
        callsign = node["callsign"]

        existing = sender_table.get(callsign)

        if not existing:
            # New node
            sender_table[callsign] = node.copy()
            updated = True
            continue

        # Update only if something changed
        if (
            existing.get("alias") != node.get("alias") or
            existing.get("via") != node.get("via") or
            existing.get("quality") != node.get("quality")
        ):
            sender_table[callsign] = node.copy()
            updated = True

    return updated



# =====================
# TRANSMISSION
# =====================

def send_message(line, state, app):
    # Stub: later this will go through AX.25 / signing / etc
    state.messages.append(f"[TX] {line}")

    AX25_PORT = 0  #NEEDS MOVING TO STATE AND ULTIMATELY TO CONFIG
    VIA = []  # e.g. ["WIDE1-1", "WIDE2-1"] NEEDS MOVING TO STATE AND BE MUTABLE BY COMMAND
    destination = state.destination or ""
    call_to = destination
    call_from = f"{state.callsign}-{state.ssid}"
    signing = state.signing
    if signing:
        signed_packet = sign_outgoing(line, state)
        reply_bytes = sign_outgoing(line, state).encode()
        if state.verbose:
            state.messages.append(f"[packet sent: ChatterVox Magic bytes set: {signed_packet.magic}, ChatterVox version: {signed_packet.version}, Signed: {signed_packet.signed}, Compressed: {signed_packet.compressed}]")
            state.messages.append(f"[packet bytes: {reply_bytes}, payload bytes:  {signed_packet.payload}")
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
" ________            _________                                  ",
" \______ \_______   /   _____/__ _______ ___  __ ____   ______  ",
"  |    |  \_  __ \  \_____  \|  |  \__  \\\\  \/ // __ \ /  ___/",
"  |    `   \  | \/  /        \  |  // __ \\\\   /\  ___/ \___ \ ",
" /_______  /__|    /_______  /____/(____  /\_/  \___  >____  >  ",
"         \/                \/           \/          \/     \/   ",
"_____________   ____     _____          __  .__      ",
"\_   ___ \   \ /   /    /  _  \  __ ___/  |_|  |__   ",
"/    \  \/\   Y   /    /  /_\  \|  |  \   __\  |  \  ",
"\     \____\     /    /    |    \  |  /|  | |   Y  \ ",
" \______  / \___/     \____|__  /____/ |__| |___|  / ",
"        \/                    \/                 \/  ",
"       .__            __                           ",
"  ____ |  |__ _____ _/  |_   _____  ______ ______  ",
"_/ ___\|  |  \\\\__  \\\\   __\  \__  \ \____ \\\\____ \ ",
"\  \___|   Y  \/ __ \|  |     / __ \|  |_> >  |_> >",
" \___  >___|  (____  /__|    (____  /   __/|   __/ ",
"     \/     \/     \/             \/|__|   |__|    ",
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
    state.app = app

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
        print(f"Expected private key: {str(config.keys.private_key)}")
        print(f"Expected public key : {str(config.keys.public_key)}")
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
    connect_agwpe(app, AGW_HOST, AGW_PORT)
    #app.start(AGW_HOST, AGW_PORT)

    app.enable_monitoring = True

    try:
        run_tui(app, monitor, state)
    finally:
        print("[*] Stopping")
        app.enable_monitoring = False
        app.stop()


if __name__ == "__main__":
    main()
