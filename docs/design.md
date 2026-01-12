# CVAuth Design Notes

## Purpose

CVAuth exists to provide a single, shared implementation of the
Chattervox authentication protocol for AX.25 packet data.

The goal is interoperability and correctness, not feature richness.

## Scope

CVAuth operates on raw packet bytes and produces raw packet bytes.
It does not manage sockets, connections, or user interfaces.

## Key concepts

- AX.25 payload (unsigned)
- Chattervox signed packet (binary)
- Local signing keys
- Trusted external public keys
- Verified vs unverified payloads

## Consumers

Expected consumers include:
- Paracon
- AXAuthNode
- Python-based AX.25 clients
- CLI-based packet tooling

## Design principles

- Explicit over implicit
- Stable packet formats
- Minimal public API
- No hidden network access
- Configuration via standard filesystem locations
