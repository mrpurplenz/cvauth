#!/usr/bin/env python3

import os
import pty
import time
import queue
import select
import signal

import pe.app
import pe.monitor

from cvauth.verify import verify_cvauth
from cvauth.auth_types import AuthType
from cvauth.keyring import Keyring


AX25_PORT = "1"
VIA = ""
PTY_SHELL = "bash"


class UIMonitor(pe.monitor.Monitor):
    """
    Monitor that pushes UI frames into a queue
    """

    def __init__(self, q):
        super().__init__()
        self.q = q

    def on_receive_ui(self, port, call_from, call_to, data, via):
        self.q.put((port, call_from, call_to, data, via))


class CVAuthPTYServer:

    def __init__(self, callsign):

        self.callsign = callsign
        self.packet_queue = queue.Queue()
        self.keyring = Keyring()

        self.call_from = None

        self.app = None
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

        print("Loading keyring...")
        self.keyring.load()

        print("Starting PTY...")
        self.start_pty()

        print("Starting AGWPE app...")

        self.app = pe.app.Application()

        monitor = UIMonitor(self.packet_queue)

        self.app.use_monitor(monitor)

        self.app.start()

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

            payload = result["sanitised_payload"]

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

        while True:

            # process incoming packets

            try:
                port, call_from, call_to, data, via = \
                    self.packet_queue.get_nowait()

                self.process_packet(port, call_from, call_to, data, via)

            except queue.Empty:
                pass

            # check PTY output

            r, _, _ = select.select([self.pty_fd], [], [], 0)

            if self.pty_fd in r:
                self.process_pty_output()

            time.sleep(0.01)

    # ---------------------------------------------------------

    def stop(self):

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

    callsign = os.environ.get("CALLSIGN", "N0CALL")

    server = CVAuthPTYServer(callsign)

    try:
        server.start()
        server.run()

    except KeyboardInterrupt:
        print("\nStopping")

    finally:
        server.stop()


if __name__ == "__main__":
    main()
