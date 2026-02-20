"""
cvauth.transport
================

Transport-layer helpers for connecting CVAuth applications to
underlying packet radio engines (e.g., AGWPE-compatible TNCs such as
Direwolf).

This module centralizes connection logic so that all CVAuth applications
(TUI, reflector, node, etc.) share consistent error handling and
transport behavior.

Future extensions may include:
    - Native Linux AX.25 socket transport
    - FX.25 transport
    - TCP loopback transport for testing
"""

from __future__ import annotations

import socket
import sys
from typing import Any


class TransportConnectionError(Exception):
    """Raised when a transport connection cannot be established."""


def connect_agwpe(
    app: Any,
    host: str,
    port: int,
    *,
    exit_on_fail: bool = True,
) -> None:
    """Connect an AGWPE-compatible application to a TNC server.

    This helper wraps ``app.start(host, port)`` with standardized
    error handling and user-friendly diagnostics. It is intended
    for use by all CVAuth applications that connect to an AGWPE
    engine (e.g., Direwolf).

    Args:
        app: An object providing a ``start(host, port)`` method.
            Typically an instance of ``pe.app.App`` or compatible.
        host (str): Hostname or IP address of the AGWPE server.
        port (int): TCP port number where the AGWPE server is listening.
        exit_on_fail (bool, optional): If True, prints a diagnostic
            message and exits the program with status 1 on failure.
            If False, raises ``TransportConnectionError`` instead.
            Defaults to True.

    Raises:
        TransportConnectionError: If ``exit_on_fail`` is False and
            the connection attempt fails.
    """
    try:
        app.start(host, port)

    except ConnectionRefusedError:
        message = (
            f"[!] Cannot connect to AGWPE server at {host}:{port}\n"
            "[!] Is the port accessible and your TNC running? (e.g. direwolf)\n"
            "[!] Is AGWPE enabled in your TNC configuration?\n"
            f"[!] Example (direwolf.conf): AGWPORT {port}"
        )
        _handle_failure(message, exit_on_fail)

    except socket.gaierror:
        message = (
            f"[!] Invalid AGWPE host: {host}\n"
            "[!] Check your configuration file."
        )
        _handle_failure(message, exit_on_fail)

    except OSError as e:
        message = (
            f"[!] OS error while connecting to AGWPE server: {e}\n"
            f"[!] Host: {host}, Port: {port}"
        )
        _handle_failure(message, exit_on_fail)

    except Exception as e:
        message = (
            "[!] Unexpected error while connecting to AGWPE server:\n"
            f"[!] {e}"
        )
        _handle_failure(message, exit_on_fail)


def _handle_failure(message: str, exit_on_fail: bool) -> None:
    """Handle transport connection failures.

    Args:
        message (str): Human-readable diagnostic message.
        exit_on_fail (bool): Whether to exit the program or raise.
    """
    print(message)

    if exit_on_fail:
        sys.exit(1)

    raise TransportConnectionError(message)
