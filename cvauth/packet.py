"""
cvauth.packet
=============

Packet encoding and decoding for the CVAuth authentication protocol.

This module defines the wire format used to transport authenticated
payloads over AX.25 connections.

The protocol provides:

- Magic header detection
- Versioned packet format
- Optional payload compression (zlib)
- Optional digital signature attachment
- Transparent decoding of signed/compressed frames

This layer is intentionally cryptography-agnostic. Signature generation
and verification are handled elsewhere. This module only transports
signature bytes.

Wire Format (Version 1)
-----------------------

All multi-byte values are big-endian.

+------------+---------+------------------------------------------+
| Offset     | Size    | Description                              |
+============+=========+==========================================+
| 0x00       | 2 bytes | Magic header (0x7a39)                    |
| 0x02       | 1 byte  | Protocol version                         |
| 0x03       | 1 byte  | Flags                                    |
|            |         |   bit 1 → Signed flag                    |
|            |         |   bit 0 → Compression flag               |
| 0x04       | 1 byte  | [optional] Signature length (if signed) |
| 0x05       | N bytes | [optional] Signature                     |
| ...        | M bytes | Payload (raw or zlib-compressed)         |
+------------+---------+------------------------------------------+

If the magic header is not present, the payload is treated as a raw,
unauthenticated message.

This design allows CVAuth to coexist with legacy AX.25 traffic.
"""

from dataclasses import dataclass
from typing import Optional, ClassVar
import zlib

MAGIC_BYTES: ClassVar[bytes] = b"\x7a\x39"
"""
Protocol magic header used to identify CVAuth packets.
"""

PROTOCOL_VERSION: ClassVar[int] = 1
"""
Current protocol version.
"""


@dataclass
class CVPacket:
    """
    Represents a single CVAuth protocol packet.

    A CVPacket encapsulates:

    - An optional sender callsign
    - A payload (bytes)
    - Optional compression
    - Optional digital signature
    - Encoded raw wire representation

    This class is responsible for:

    - Encoding structured data into wire format
    - Decoding raw AX.25 payloads into structured objects

    It does NOT:

    - Perform signature verification
    - Perform key lookup
    - Enforce authentication policy

    Attributes:
        from_call: Optional AX.25 callsign of sender.
        payload: Message payload as bytes.
        version: Protocol version number.
        signed: True if packet includes a signature.
        compressed: True if payload was compressed.
        signature: Optional signature bytes.
        raw: Raw wire-format packet bytes (if encoded or decoded).
    """

    from_call: Optional[str] = None
    payload: bytes = None
    version: int = PROTOCOL_VERSION
    signed: bool = False
    compressed: bool = False
    signature: Optional[bytes] = None
    raw: Optional[bytes] = None

    def __post_init__(self) -> None:
        """
        Validate payload type after initialization.

        Raises:
            TypeError: If payload is not bytes-like.
        """
        if self.payload is None:
            return

        if isinstance(self.payload, (bytes, bytearray, memoryview)):
            self.payload = bytes(self.payload)
        else:
            raise TypeError(
                f"CVPacket.payload must be bytes, not {type(self.payload).__name__}"
            )

    def encode(self) -> bytes:
        """
        Encode this packet into CVAuth wire format.

        Compression is automatically applied if it reduces payload size.
        Signature presence determines the signed flag.

        Returns:
            bytes: Encoded packet ready for AX.25 transmission.

        Raises:
            ValueError: If signature is invalid or too long.

        Notes:
            - Compression uses zlib.
            - Signature length is limited to 255 bytes.
            - `self.raw` is updated with the encoded result.
        """
        bytes_payload = self.payload
        compressed_payload = zlib.compress(bytes_payload)

        # Determine whether compression is beneficial
        if len(compressed_payload) < len(self.payload):
            self.compressed = True
            payload_to_encode = compressed_payload
        else:
            self.compressed = False
            payload_to_encode = self.payload

        # Signature presence defines signed state
        self.signed = self.signature is not None

        flags = (int(self.signed) << 1) | int(self.compressed)
        flags_byte = flags.to_bytes(1, "big")

        out = bytearray()
        out += MAGIC_BYTES
        out += self.version.to_bytes(1, "big")
        out += flags_byte

        if self.signed:
            if self.signature is None:
                raise ValueError("signed=True but no signature present")
            if len(self.signature) > 255:
                raise ValueError("Signature too long (max 255 bytes)")
            out += len(self.signature).to_bytes(1, "big")
            out += self.signature

        out += payload_to_encode

        self.raw = bytes(out)
        return self.raw

    @classmethod
    def decode(cls, raw: bytes, from_call: Optional[str] = None) -> "CVPacket":
        """
        Decode raw AX.25 payload into a CVPacket.

        If the magic header is absent, the packet is treated as
        unauthenticated raw payload.

        Args:
            raw: Raw AX.25 payload bytes.
            from_call: Optional callsign of sender.

        Returns:
            CVPacket: Parsed packet object.

        Raises:
            ValueError: If packet structure is invalid.
            zlib.error: If compressed payload cannot be decompressed.

        Security:
            This method does NOT verify signatures.
            Signature validation must be performed separately.
        """
        if raw[:2] != MAGIC_BYTES:
            return cls(from_call=from_call, payload=raw, raw=raw)

        if len(raw) < 4:
            raise ValueError("Packet too short to be CVPacket")

        version = raw[2]
        flags = raw[3]

        signed = bool(flags & 0b10)
        compressed = bool(flags & 0b01)

        idx = 4
        signature = None

        if signed:
            if idx >= len(raw):
                raise ValueError("Missing signature length field")
            sig_len = raw[idx]
            idx += 1

            if idx + sig_len > len(raw):
                raise ValueError("Invalid signature length")

            signature = raw[idx:idx + sig_len]
            idx += sig_len

        payload = raw[idx:]

        if compressed:
            payload = zlib.decompress(payload)

        return cls(
            from_call=from_call,
            payload=payload,
            version=version,
            signed=signed,
            compressed=compressed,
            signature=signature,
            raw=raw,
        )
