#!/usr/bin/env python3

import queue
import time
import signal
from blessed import Terminal
from textwrap import wrap
import pe.app
import pe.monitor
import ax25.netrom
from pathlib import Path
from .config import ensure_config, load_config, update_config_value, CVAuthConfig, user_config_path
from .config_utils import request_callsign, request_ssid, request_keypair_paths, request_crypto_scheme, valid_callsign
from .utilities import station2call
from .packet import CVPacket
from .auth import sign_packet, verify_packet, AuthType, AuthResult, ensure_bytes, load_private_key, generate_and_save_keypair
from .transport import connect_agwpe
import os

# ====================
# CONFIGURE
# ====================

class LocalKeyring:
    def __init__(self, state, public_key_dir: Path, callsign: str):
        self.state = state
        self.public_key_dir = public_key_dir

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
# MONITOR
# =====================

class UIMonitor(pe.monitor.Monitor):
    """Minimal monitor that pushes UI frames into a queue."""
    def __init__(self):
        self.queue = queue.Queue()

    def monitored_unproto(self, port, call_from, call_to, text, data):
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
        self.messages = []
        self.input_buffer = ""
        self.config = None
        self.private_key_path = None
        self.public_key_path = None
        self.destination = "QST"
        self.verbose = False
        self.netrom_nodes = {}
        self.node_data = {}
        self.app = None
        self.via = None
        self.scroll_offset = 0
        self.body_y = 0
        self.disp_height = 0
        self.disp_width = 0
        
# =====================
# RENDER
# =====================
def get_wrapped_lines(messages, width):
    wrapped = []
    for msg in messages:
        wrapped.extend(wrap(msg, width))
    return wrapped

def render(term: Terminal, state: UIState):
    print(term.home + term.clear ,end="")
    height = term.height
    width = term.width

    HEADER_Y = 1
    PROMPT_Y = 1
    BODY_Y = height - HEADER_Y - PROMPT_Y
    state.body_y = BODY_Y

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

    header_BG = term.on_bright_blue
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

    print(term.move_yx(0, 0) + term.black_on_white + header.ljust(width) + term.normal)

    wrapped = get_wrapped_lines(state.messages,width)
    total = len(wrapped)
    body_height = state.body_y

    max_scroll = max(0, total - body_height)
    state.scroll_offset = min(state.scroll_offset, max_scroll)
    state.scroll_offset = max(0, state.scroll_offset)

    start = total - body_height - state.scroll_offset
    start = max(0, start)
    end = start + body_height

    visible_msgs = wrapped[start:end]
    for i, msg in enumerate(visible_msgs):
        line_no = HEADER_Y + i
        print(term.move_yx(line_no, 0) + msg[:width].ljust(width))

    print(term.move_yx(0, 0) + term.black_on_white + header.ljust(width) + term.normal)

    prompt = f"{state.callsign} > "
    line = prompt + state.input_buffer
    print(term.move_yx(height - 1, 0) + term.clear_eol + term.bold + line + term.normal, end="", flush=True)
    print(term.move_yx(height - 1, len(line)), end="", flush=True)
    
    
# The remainder of the TUI implementation is unchanged.
