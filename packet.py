# cvauth/packet.py

from enum import Enum
from dataclasses import dataclass
from typing import Optional, ClassVar
import zlib



MAGIC_BYTES: ClassVar[bytes] = b"\x7a\x39"
PROTOCOL_VERSION: ClassVar[int] = 1

class AuthFlag(Enum):
    NOT_PRESENT = 0
    PRESENT = 1

@dataclass
class CVPacket:
    """
    Represents a Chattervox packet object.
    """
    from_call: Optional[str]
    payload: bytes = None
        
    version: int = PROTOCOL_VERSION
    signed: bool = False
    compressed: bool = False
    signature: Optional[bytes] = None

    raw: Optional[bytes] = None
    
    def encode(self) -> bytes:
        """
        Encode this packet into an AX.25 payload.
        if you want the non encoded packet just request CVPacket.payload
        """

        
        # compression
        compressed_payload = zlib.compress(self.payload)
        if len(compressed_payload) < len(self.payload):
            self.compressed = True
        else:
            self.compressed = False

        # flags byte
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
                raise ValueError("Signature too long")
            out += len(self.signature).to_bytes(1, "big")
            out += self.signature
        if self.compressed:
            out += compressed_payload
        else:
            out += self.payload

        self.raw = bytes(out)
        return self.raw

    @classmethod
    def decode(cls, raw: bytes, from_call: Optional[str] = None) -> "CVPacket":
        """
        Decode an AX.25 payload into a CVPacket.
        No verification.
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
            sig_len = raw[idx]
            idx += 1
            if idx + sig_len > len(raw):
                raise ValueError("Invalid signature length")
            signature = raw[idx:idx + sig_len]
            idx += sig_len

        payload = raw[idx:]

        if compressed:
            payload = zlib.decompress(payload)

        pkt = cls(
            from_call=from_call,
            payload=payload,
            version=version,
            signed=signed,
            compressed=compressed,
            signature=signature,
            raw=raw,
        )
        return pkt
