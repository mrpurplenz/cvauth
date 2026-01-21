from cvauth.packet import CVPacket
from cvauth.auth import sign_packet, verify_packet, AuthType
from cvauth.crypto import sign, verify

class DictKeyring:
    def __init__(self, mapping):
        self.mapping = mapping

    def get_public_key(self, callsign):
        return self.mapping.get(callsign)

import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cvauth.packet import CVPacket
from cvauth.auth import sign_packet, verify_packet, AuthType


class TestAuthRoundTrip(unittest.TestCase):

    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.callsign = "ZL1TEST"
        self.payload = b"Hello AX.25"

        self.keyring = DictKeyring({
            self.callsign: self.public_key
        })

    def test_signed_packet_verifies(self):
        pkt = CVPacket(
            from_call=self.callsign,
            payload=self.payload,
        )

        sign_packet(pkt, self.private_key)

        self.assertTrue(pkt.signed)
        self.assertIsNotNone(pkt.signature)

        result = verify_packet(pkt, self.keyring)

        self.assertEqual(result.auth_type, AuthType.VALID)
        self.assertEqual(result.signer, self.callsign)

    def test_encode_decode_verify(self):
        pkt = CVPacket(
            from_call=self.callsign,
            payload=self.payload,
        )

        sign_packet(pkt, self.private_key)
        raw = pkt.encode()

        decoded = CVPacket.decode(raw, from_call=self.callsign)
        result = verify_packet(decoded, self.keyring)

        self.assertEqual(result.auth_type, AuthType.VALID)

    def test_wrong_key_fails(self):
        other_key = Ed25519PrivateKey.generate()
        other_pub = other_key.public_key()

        pkt = CVPacket(from_call=self.callsign, payload=self.payload)
        sign_packet(pkt, other_key)

        result = verify_packet(pkt, self.keyring)
        self.assertEqual(result.auth_type, AuthType.INVALID)

    def test_missing_key(self):
        pkt = CVPacket(from_call=self.callsign, payload=self.payload)
        sign_packet(pkt, self.private_key)

        empty_keyring = DictKeyring({})
        result = verify_packet(pkt, empty_keyring)

        self.assertEqual(result.auth_type, AuthType.KEYNOTFOUND)



