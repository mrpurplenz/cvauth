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

## Basis

CVAuth is based on the ChatterVox protocol by Brannon Dorsey,    KC3LZO
and the code based on the awgoe server api PyHamPe by Martin F N Cooper, KD6YAM


## Project goals

- Be the canonical Python implementation of Chattervox authentication
- Be easy to audit and reason about
- Be usable as a library or a CLI tool or light weight tui
- Avoid application-specific assumptions
- Minimize forked or duplicated implementations

## Non-goals

- AX.25 socket or radio handling
- uses pyham_pe to interface with an existing agwpe server such as direwolf
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
```

## Installation

CVAuth can be installed directly from GitHub. It is recommended to install inside a Python virtual environment.

---

### Option 1 — Install Directly from GitHub (Recommended)

Install the latest version:

```bash
cd ~
mkdir cvauth
python -m venv cvenv
source cvenv/bin/activate
pip install git+https://github.com/mrpurplenz/cvauth.git

```

### Option 2 — Clone a developement version (Recommended for contributors)


### Option 3 - Wait until a pypi pip install candidate is generated (no plans yet) 


## Roadmap

- [x] Define public API surface
- [x] Define config and key layout
- [x] Extract signing and verification logic
- [x] Implement CLI wrapper
- [x] Add unit tests
- [x] Add a simple reflector
- [x] Add a light weight terminal user interface
- [ ] Publish to PyPI

## License

MIT
