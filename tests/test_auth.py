import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cvauth.packet import CVPacket
from cvauth.auth import sign_packet, verify_packet, AuthType
from cvauth.crypto import sign, verify

class DictKeyring:
    def __init__(self, mapping):
        self.mapping = mapping

    def get_public_key(self, callsign):
        return self.mapping.get(callsign)


class TestAuthRoundTrip(unittest.TestCase):

    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.callsign = "ZL1TEST"
        self.payload = b"Hello AX.25. This will want to be able to compress 000000000000000000000"

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

    def test_signed_packet_roundtrip(self):
        # Arrange
        payload = self.payload
        private_key = self.private_key
        public_key = self.public_key
        test_from_call = self.callsign

        # Act: create and sign
        pkt = CVPacket(from_call=test_from_call, payload=payload)
        sign_packet(pkt,private_key)

        encoded = pkt.encode()

        # Act: decode and verify
        decoded = CVPacket.decode(encoded,from_call = test_from_call)
        keyring = self.keyring
        verification_result = verify_packet(decoded, keyring)

        assert verification_result.signer == test_from_call, \
            f"Expected signer {test_from_call} but got {verification_result.signer}. Reason: {verification_result.reason}"


        assert verification_result.auth_type == AuthType.VALID, \
            f"Expected VALID but got {verification_result.auth_type}. Reason: {verification_result.reason}"


        # Assert payload integrity
        assert decoded.payload == payload

