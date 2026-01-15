# CVAuth

CVAuth is a reference Python implementation of the Chattervox
authentication and signature protocol for AX.25 packet data.

It provides reusable logic for:
- Signing AX.25 packets using Chattervox-compatible signatures
- Verifying signed packets and extracting authenticated payloads
- Managing local and trusted public keys in a standard location
- Providing both a Python API and a command-line interface

CVAuth is designed to be used by multiple AX.25 applications,
including Paracon, and future clients and servers.

## Project goals

- Be the canonical Python implementation of Chattervox authentication
- Be easy to audit and reason about
- Be usable as a library or a CLI tool
- Avoid application-specific assumptions
- Minimize forked or duplicated implementations

## Non-goals

- User interfaces (GUI/TUI)
- AX.25 socket or radio handling
- Connection management
- Encryption (signing only)

## Status

This project is in early development.
The initial focus is on defining clean APIs and extracting
existing, working code from my Paracon-auth fork into a standalone library.

## Public API

CVAuth guarantees stability for the following symbols:

```python
from cvauth import (
    CVPacket,
    sign_packet,
    verify_packet,
    AuthType,
    AuthResult,
    PublicKeyProvider,
)

## Roadmap

- [*] Define public API surface
- [ ] Define config and key layout
- [ ] Extract signing and verification logic
- [ ] Implement CLI wrapper
- [ ] Add unit tests
- [ ] Publish to PyPI

## License

MIT
