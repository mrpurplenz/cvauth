#!/usr/bin/env python3

import queue
import time
import signal

from blessed import Terminal
import pe.app
import pe.monitor


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
    def __init__(self, callsign="N0CALL", ssid=0, signing=False):
        self.running = True
        self.callsign = callsign
        self.ssid = ssid
        self.signing = signing
        self.messages = []      # list[str]
        self.input_buffer = ""


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
    #call_print="ZL2DRS"
    #ssid_print="4"
    headerL = f" CVAuth chat by ZL2DRS | Station {call_print}-{ssid_print} | Dest [] | Filter []"
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
        term.move_yx(height - 1, 0)
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
                            handle_command(line, state)
                        else:
                            send_message(line, state)

                    state.input_buffer = ""

                elif key.name == "KEY_BACKSPACE":
                    state.input_buffer = state.input_buffer[:-1]

                elif not key.is_sequence:
                    state.input_buffer += key

            # ---- Drain monitor queue ----
            while not monitor.queue.empty():
                evt = monitor.queue.get()
                payload = evt["data"]

                #pass the payload to authentication process

                try:
                    text = payload.decode("utf-8", "replace")
                except Exception:
                    text = repr(payload)

                state.messages.append(
                    f"[RX] {evt['from']} → {evt['to']}: {text}"
                )

            # ---- Render ----
            render(term, state)

            # ---- Yield ----
            time.sleep(0.05)

# ====================
# COMMANDS
# ====================

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

# =====================
# TRANSMISSION
# =====================

def send_message(line, state):
    # Stub: later this will go through AX.25 / signing / etc
    state.messages.append(f"[local] {line}")


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

    #ensuring config file, loading config, and user interactionm to fill missing config values should go here
    #then config should be loaded into the state for use elsewhere

    state = UIState(callsign="ZL2DRS", ssid=1)

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
