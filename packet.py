# cvauth/packet.py

from enum import Enum
from dataclasses import dataclass
from typing import Optional

# Magic bytes used to identify a Chattervox packet
MAGIC_BYTES = b'\x7a\x39'     #A constant two-byte value used to identify chattervox packets.

class AuthFlag(Enum):
    NOT_PRESENT = 0
    PRESENT = 1

@dataclass
class CVPacket:
    """
    Represents a Chattervox packet object.

    Attributes:
        #Packet data
        version (integer): Version number (1 to 255) 
        signed (bool): Message is signed
        compressed (bool): Message is compressed
        signature_length (integer):  Length of signature
        signature (bytes): Digital signature
        message_payload (bytes): byte form of message only

        #Meta data
        from_call (string): packet sender callsign (excluding SSID)

    """


    signature: Optional[bytes] = None
    raw: Optional[bytes] = None
        #Packet data
        self.version_number: Optional[int]       = 1
        self.version_byte                        = version_number.to_bytes(1, byteorder='big', signed=False)
        self.signed: Optional[bool]              = False
        self.compressed: Optional[bool]          = False
        self.base64_encoded:  Optional[bool]     = False
        self.signature_length: Optional[int]     = 0
        self.signature: Optional[bytes]          = None
        self.message_payload: Optional[bytes]    = None
        self.encoded_packet: Optional[bytes]     = None

        #Meta data
        self.from_call: Optional[str]            = None #NEEDS TO BE CALL NOT STATION as it matches a pub key
  
  def encode(self) -> bytes:
    """Return AX.25 payload bytes"""
    return self.encoded_packet

  @classmethod
  def decode(cls, raw: bytes, from_call: Optional[str] = None) -> "CVPacket":
    """Parse AX.25 payload bytes into a CVPacket"""
    pkt = CVPacket()
    return pkt

  def assemble(self, sign: bool = False) -> bytes:
      """
      Assemble the packet payload into bytes for AX.25 transmission.
  
      Args:
          sign (bool): If True, generate a signature using local private key.
  
      Returns:
          bytes: Complete payload including header, optional signature, and message.
  
      Payload layout:
          - [0x0000] 16 bits  Magic Header b'x7a39'
          - [0x0002] 8 bits   Version Byte b'x01' for version 1
          - [0x0003] 6 bits   Reserved/Unused
          - [0x0003] 1 bit    Digital Signature Flag 
          - [0x0003] 1 bit    Compression Flag
          - [0x0004] [opt] 8 bits Signature Length
          - [0x0005] [opt] Signature (Signature Length bytes) base64 encoded
          - [rest]   Message (raw or compressed bytes) base64 encoded
  
      """
      packet_payload = b''
  
      # --- Fixed header ---
      header = MAGIC_BYTES  # magic header
      version_byte = self.version_byte
      version_number = int.from_bytes(version_byte, byteorder='big', signed=False)
  
      # --- Message section ---
      #if self.compressed:
      #    raise NotImplementedError("Compression not yet implemented.")
      message_section, self.compressed = compress_message(self.message_payload)
      #message_section = self.message_payload
  
      # --- Flags ---
      # Construct one byte: 6 unused bits, then signature flag, then compression flag
      sig_flag = 1 if self.signed else 0
      comp_flag = 1 if self.compressed else 0
      flags = ((0 << 2) | (sig_flag << 1) | comp_flag)  # put bits in order
      flags_byte = flags.to_bytes(1, "big")
  
      # --- Signature section ---
      signature_section = b""
      if self.signed:
          if self.private_key:
              raw_signature = self.private_key.sign(self.message_payload)
              if version_number == 2:
                  # Encode to base64 for safe transport
                  self.signature = base64.b64encode(raw_signature)
              else:
                  self.signature = raw_signature
          sig_len = len(self.signature)
          if sig_len > 255:
              raise ValueError("Signature length exceeds 255 bytes.")
          signature_section += sig_len.to_bytes(1, "big")  # length
          signature_section += self.signature             # raw bytes
          self.signature_length = sig_len
          self.auth_type = AuthType.KEYNOTFOUND
          self._verify_signature(self.from_call)
      else:
          self.auth_type = AuthType.NOTSIGNED #UNSIGNED
  
  
  
      # --- Final assembly ---
      packet_payload = header + version_byte + flags_byte + signature_section + message_section
      self.packet_payload = packet_payload
      return self.packet_payload
  
  def disassemble(self, packet_payload: bytes, from_call: Optional[str] = None) -> Tuple[bytes, AuthType]:
      """
      Parse incoming packet payload bytes, populate the packet data
      and determine authentication status. Does not decode message content.
  
      Args:
          packet_payload (bytes): Raw payload from AX.25 frame.
          sender_call (str, optional): AX.25 source callsign for signature verification.
  
      Returns:
          Tuple[bytes, AuthType]: Sanitized payload bytes and authentication status.
  
      Raises:
          TypeError: If the packet is invalid or too short.
      """
  
      if not isinstance(packet_payload, (bytes, bytearray)):
          raise TypeError("Data must be bytes or bytearray")
  
      if len(packet_payload) < 2:
          raise TypeError("Invalid packet: too few bytes")
  
      self.from_call = from_call
  
      if packet_payload[:2] != MAGIC_BYTES:
          #This is not a chattervox payload.
          self.packet_payload     = packet_payload
          self.message_payload    = packet_payload
          self.auth_type          = AuthType.UNKNOWN
          return self.packet_payload, self.auth_type
      else:
          # Parse header
          self.version_number = packet_payload[2]
          self.version_byte   = version_number.to_bytes(1, byteorder='big', signed=False)
          flags_byte          = packet_payload[3]
          self.signed         = (flags_byte & 0b10) != 0   # second least significant bit
          self.compressed     = (flags_byte & 0b01) != 0   # least significant bit
  
          idx = 4
          if self.signed:
              self.signature_length = packet_payload[4]
              self.signature = packet_payload[5:5 + self.signature_length]
              idx = 5 + self.signature_length
              
              raw_message_payload = packet_payload[idx:]
              self.message_payload = decompress_message(
                  raw_message_payload,
                  self.compressed,
                  self.version_number
                  )
              self.auth_type = self._verify_signature(from_call)
          else:
              self.signature          = None
              self.signature_length   = 0
              self.message_payload    = packet_payload
              self.auth_type          = AuthType.NOTSIGNED
          self.packet_payload = packet_payload
  
      # Return raw payload bytes and authentication status
      return self.message_payload, self.auth_type
