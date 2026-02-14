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
Example programs are installed with the api

## Basis

CVAuth is based on the [ChatterVox protocol](https://github.com/brannondorsey/chattervox) by Brannon Dorsey, KC3LZO
and the code based on the AGWPE server api [pyham_pe](https://github.com/mfncooper/pyham_pe) by Martin F N Cooper, KD6YAM


## Project goals

- Be the canonical Python implementation of Chattervox authentication
- Be easy to audit and reason about
- Be usable as a library or a CLI tool or light weight tui
- Avoid application-specific assumptions
- Minimize forked or duplicated implementations

## Non-goals

- AX.25 socket or radio handling
- handle tnc or direwolf connectivity
- Connection management - ONLY chattervox protocol support which excludes connected frames for now
- Encryption (signing only)

## Status

This project is now at initial release
The focus is on defining clean APIs and maybe 
fulfilling my personal goals for an authenticated chat terminal.

Other uses may be built using the example programs:
cvauth_tui.py
cvauth_reflector.py
cvauth_cli.py

for example I might build an authenticated radio chess program one day...
or someone else could using my api and example code.

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
Preparation
You need to install and have a working direwolf version
A great resource for that can be found here
[The modern ham - Ultimate Direwolf Installation guide for packet radio - Windows and Linux}(https://youtu.be/iDQd1SoGgQE?si=fIfgTmMcmtIlO6qF)



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
At the moment cvauth-tui defaults to AX25_PORT = 0, VIA=[], AGW_HOST = "127.0.0.1", AGW_PORT = 8000
So it wont work without these and I havn't moved them to the config yet.

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
