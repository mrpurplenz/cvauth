#!/usr/bin/env python3
import queue
import signal
import time

from blessed import Terminal
import pe.app
import pe.monitor

from cvauth.config import ensure_config, load_config
from cvauth.auth import verify_packet, AuthType
from cvauth.packet import CVPacket
from cvauth.cvauth_reflector import LocalKeyring   # reuse yours


# =====================
# AGWPE CONFIG
# =====================

AGWPE_HOST = "127.0.0.1"
AGWPE_PORT = 8000
AX25_PORT  = 0
VIA = []


# =====================
# MONITOR
# =====================

class _Monitor(pe.monitor.Monitor):
    def __init__(self):
        self._queue = queue.Queue()

    @property
    def event_queue(self):
        return self._queue

    def monitored_unproto(self, port, call_from, call_to, text, data):
        self._queue.put((call_from, call_to, data))


# =====================
# UI CLASSIFICATION
# =====================

AUTH_TO_UI = {
    AuthType.VALID:       "recv_verified",
    AuthType.NOTSIGNED:   "recv_unsigned",
    AuthType.KEYNOTFOUND: "recv_signed_nopub",
    AuthType.INVALID:     "recv_signed_failed_verification",
    AuthType.UNKNOWN:     "warn",
}

# =====================
# FUNCTIONS
# =====================

def render_terminal(signing_enabled, message_stack, log_stack, term, sessionmanager):
    current_peer = sessionmanager.active_peer
    peer_list = sessionmanager.list_peers()
    message_colour_map = {
        "info": term.cyan,
        "error": term.red,
        "warn": term.yellow,
        "send_signed": term.green,
        "send_unsigned": term.white,
        "recv_unsigned": term.yellow,
        "recv_signed_nopub": term.orange,
        "recv_signed_failed_verification": term.red,
        "recv_verified": term.green,
        "system": term.magenta
    }

    log_colour_map = {
        "unconnected_not_signing": term.orange,
        "unconnected_signing": term.yellow,
        "connected_not_signing": term.orange,
        "connected_signing": term.green
    }

    CURRENT_TERM_WIDTH  = term.width
    CURRENT_TERM_HEIGHT = term.height

    # Define fixed zone heights (Y = number of rows, X = terminal width)
    HEADER_Y       = 1
    SEPARATOR_Y    = 1
    LOG_Y          = 6  # Lines reserved for the input log
    PROMPT_Y       = 1

    # Terminal width (constant across zones)
    HEADER_X       = CURRENT_TERM_WIDTH
    SEPARATOR_X    = CURRENT_TERM_WIDTH
    LOG_X          = CURRENT_TERM_WIDTH
    PROMPT_X       = CURRENT_TERM_WIDTH

    # Dynamically compute available height for messages
    MESSAGES_Y     = CURRENT_TERM_HEIGHT - (HEADER_Y + SEPARATOR_Y + LOG_Y + PROMPT_Y)
    MESSAGES_X     = CURRENT_TERM_WIDTH

    HEADER_START_Y     = 0
    MESSAGE_START_Y    = HEADER_START_Y + HEADER_Y
    SEPARATOR_START_Y  = MESSAGE_START_Y + MESSAGES_Y
    LOG_START_Y        = SEPARATOR_START_Y + SEPARATOR_Y
    PROMPT_START_Y     = LOG_START_Y + LOG_Y

    def draw_header(current_peer = None, signing_enabled = True):
        peer_label = current_peer or ' -------- '
        signing_colour = term.red
        sign_string = "OFF"
        if signing_enabled:
            signing_colour = term.green
            sign_string = "ON"
        author_string = "| AXAuth by ZL2DRS | Signing "
        header_text_len = len(peer_label + author_string + sign_string)
        print(term.move_yx(0,0) + term.on_white + term.black + peer_label + author_string + signing_colour + sign_string + term.clear_eol)

    def draw_message_stack(message_stack,MESSAGES_X,MESSAGES_Y):
        print(term.move_yx(0, 0))
        visible_rows = []

        # First, wrap each message into lines that fit terminal width
        for msgt in message_stack:
            status, text = msgt
            #prefix = f"{callsign}: "
            ansi_colour = message_colour_map[status]

            # Wrap text (taking prefix into account for first line)
            wrapped_lines = wrap(text, width=MESSAGES_X)
            if not wrapped_lines:
                wrapped_lines = [""]

            # Build first and subsequent lines
            first_line = ansi_colour +  wrapped_lines[0]
            other_lines = [ansi_colour + line for line in wrapped_lines[1:]]

            #Restack the now-wrapped messages
            visible_rows.extend([first_line] + other_lines)

        # Trim to fit available space
        rows_to_draw = visible_rows[-MESSAGES_Y:]

        # Now render the lines on screen
        for i, line in enumerate(rows_to_draw):
            print(term.move_yx(MESSAGE_START_Y + i, 0) + term.normal + term.clear_eol + line.ljust(MESSAGES_X))

    def draw_log_stack(log_stack):
        print(term.move_yx(0, 0))

        num_log_lines = min(len(log_stack), LOG_Y)
        num_blank_lines = LOG_Y - num_log_lines  # Always ≥ 0

        # Clear and print blank lines first
        for i in range(num_blank_lines):
            print(term.move_yx(LOG_START_Y + i, 0) + term.clear_eol)

        # Now print the most recent log lines, bottom-aligned
        recent_logs = log_stack[-num_log_lines:]
        for i, logt in enumerate(recent_logs):
            ansi_colour = log_colour_map.get(logt[0], term.normal)
            line_y = LOG_START_Y + num_blank_lines + i
            print(term.move_yx(line_y, 0) + term.clear_eol + ansi_colour + logt[1].ljust(MESSAGES_X))

    def draw_separator(active_session="IDLE", sessions=None):
        if sessions is None:
            sessions = ["IDLE"]  # Default unproto session

        max_sessions = 6
        session_display = []
        sep_len=0
        for session in sessions[:max_sessions]:
            session_text = f" {session} "
            sep_len += len(session_text)
            if session == active_session:
                # Black on green for active
                session_display.append(term.black_on_green + session_text + term.normal)
            else:
                # Black on white for inactive
                session_display.append(term.black_on_white + session_text + term.normal)

        status_bar = " ".join(session_display)

        import re
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        visible_len = sep_len
        #visible_len = len(ansi_escape.sub('', status_bar))
        padding_needed = SEPARATOR_X - visible_len
        status_bar += term.black_on_white  (' ' * max(0, padding_needed))

        # Print the bar (black/green or black/white) and then revert to white-on-black
        print(term.move_yx(SEPARATOR_START_Y, 0) + term.normal + status_bar + term.normal)

    def draw_prompt(current_peer,signing_enabled):
        print(term.move_yx(0,0))
        prompt = f"{current_peer or 'unproto'}> "
        if current_peer:
            if signing_enabled:
                prompt_status = "connected_signing"
            else:
                prompt_status = "connected_not_signing"
        else:
            if signing_enabled:
                prompt_status = "unconnected_signing"
            else:
                prompt_status = "unconnected_not_signing"
        ansi_colour = log_colour_map.get(prompt_status, term.normal)
        print(term.move_yx(PROMPT_START_Y, 0)  + ansi_colour + prompt, end='', flush=True)
        # Move cursor to after prompt
        print(term.move_yx(PROMPT_START_Y, len(prompt)), end='', flush=True)
        return len(prompt)

    #Conduct rendering in turn
    draw_header(current_peer, signing_enabled)
    #draw_message_stack(message_stack)
    draw_message_stack(message_stack,MESSAGES_X,MESSAGES_Y)
    draw_separator()
    draw_log_stack(log_stack)
    prompt_len = draw_prompt(current_peer,signing_enabled)

    return prompt_len, PROMPT_START_Y


# =====================
# MAIN APP
# =====================

class CVAuthMonitorTUI:
    def __init__(self):
        self.term = Terminal()
        self.running = True

        self.message_stack = []
        self.log_stack = []

        self.app = pe.app.Application()
        self.monitor = _Monitor()

        self.callsign = None
        self.ssid = None
        self.keyring = None

    # ---------------------

    def start(self):
        config_path = ensure_config()
        config = load_config(config_path)

        self.callsign = config.identity.callsign
        self.ssid = config.identity.ssid

        self.keyring = LocalKeyring(
            public_key_path=config.resolve_path(config.keys.public_key),
            callsign=self.callsign,
        )

        self.app.use_monitor(self.monitor)
        self.app.start(AGWPE_HOST, AGWPE_PORT)
        self.app.enable_monitoring = True

    # ---------------------

    def stop(self):
        self.running = False
        try:
            self.app.enable_monitoring = False
        except Exception:
            pass
        self.app.stop()

    # ---------------------

    def classify_and_format(self, call_from, call_to, raw_payload):
        try:
            pkt = CVPacket.decode(raw=raw_payload, from_call=call_from)
            result = verify_packet(pkt, self.keyring)
            status = AUTH_TO_UI[result.auth_type]
            payload = pkt.payload.decode("utf-8", "replace")
            auth_text = result.auth_type.name.replace("_", " ").title()
        except Exception:
            status = "warn"
            payload = raw_payload.decode("utf-8", "replace")
            auth_text = "Unknown format"

        line = f"{call_from} → {call_to} | {auth_text} | {payload}"
        return status, line

    # ---------------------

    def run(self):
        q = self.monitor.event_queue

        with self.term.fullscreen(), self.term.cbreak():
            print(self.term.clear)
            print(self.term.hide_cursor(), end="", flush=True)

            while self.running:
                # Drain queue
                while not q.empty():
                    call_from, call_to, raw = q.get()
                    status, line = self.classify_and_format(call_from, call_to, raw)
                    self.message_stack.append((status, line))

                # Render
                render_terminal(
                    signing_enabled=False,
                    message_stack=self.message_stack,
                    log_stack=self.log_stack,
                    term=self.term,
                    sessionmanager=None,
                )

                time.sleep(0.05)


# =====================
# ENTRY POINT
# =====================

def main():
    tui = CVAuthMonitorTUI()

    def shutdown(signum, frame):
        tui.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    tui.start()
    tui.run()


if __name__ == "__main__":
    main()
