import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cvauth.packet import CVPacket
from cvauth.auth import sign_packet, verify_packet, AuthType, PublicKeyRecord
from cvauth.crypto import DEFAULT_SCHEME, CHATTERVOX_SCHEME, sign, verify, get_scheme
from cvauth.config import ensure_config
import os
import zlib
import tempfile
try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python <=3.10
import tomli_w


class depr_DictKeyring:
    def __init__(self, mapping):
        self.mapping = mapping

    def get_public_key(self, callsign):
        return self.mapping.get(callsign)

class depr_DictKeyring:
    def __init__(self, mapping):
        self.mapping = mapping

    def get_public_keys(self, callsign):
        value = self.mapping.get(callsign)

        if value is None:
            return []

        if isinstance(value, list):
            return value

        if isinstance(value, PublicKeyRecord):
            return [value]

        # Allow existing Ed25519 test fixtures to remain simple.
        return [
            PublicKeyRecord(
                callsign=callsign,
                scheme_name="ed25519",
                key=value,
            )
        ]

class DictKeyring:
    def __init__(self, mapping):
        self.mapping = mapping

    def get_public_keys(self, callsign):
        value = self.mapping.get(callsign, [])

        # Allow tests to provide either one record or a list of records.
        if value is None:
            return []
        if isinstance(value, PublicKeyRecord):
            return [value]
        return list(value)

class TestAuthRoundTrip(unittest.TestCase):

    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.callsign = "ZL1TST"
        self.payload = b"Hello AX.25. This will want to be able to compress 000000000000000000000"

        #self.keyring = DictKeyring({
        #    self.callsign: self.public_key
        #})
        self.keyring = DictKeyring({
            self.callsign: PublicKeyRecord(
                callsign=self.callsign,
                scheme_name=DEFAULT_SCHEME,
                key=self.public_key,
            )
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
        pkt = CVPacket(from_call=self.callsign, payload=self.payload)
        sign_packet(pkt, self.private_key)

        encoded = pkt.encode()
        decoded = CVPacket.decode(encoded, from_call=self.callsign)
        verification_result = verify_packet(decoded, self.keyring)

        self.assertEqual(verification_result.signer, self.callsign)
        self.assertEqual(verification_result.auth_type, AuthType.VALID)
        self.assertEqual(decoded.payload, self.payload)


class TestCompression(unittest.TestCase):

    def test_roundtrip_compression(self):
        original = b"Hello AX.25 world. " * 10
        compressed = zlib.compress(original)
        decompressed = zlib.decompress(compressed)

        self.assertEqual(decompressed, original)

    def test_packet_compression_roundtrip(self):
        payload = b"AX.25 payload that needs compressing" * 200
        pkt = CVPacket(from_call="ZL1TST", payload=payload)
        encoded = pkt.encode()
        decoded = CVPacket.decode(encoded)

        self.assertTrue(pkt.compressed, "packet payload was not compressed")
        self.assertEqual(decoded.payload, payload)


class TestConfig(unittest.TestCase):

    def test_config_is_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["CVAUTH_CONFIG_DIR"] = tmp

            path = ensure_config()

            self.assertTrue(path.exists())
            self.assertEqual(path.name, "cvauth.toml")

    def test_config_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["CVAUTH_CONFIG_DIR"] = tmp

            path1 = ensure_config()
            mtime1 = path1.stat().st_mtime

            path2 = ensure_config()
            mtime2 = path2.stat().st_mtime

            self.assertEqual(path1, path2)
            self.assertEqual(mtime1, mtime2)

    def test_config_contents_have_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["CVAUTH_CONFIG_DIR"] = tmp

            path = ensure_config()
            text = path.read_text()
            data = tomllib.loads(text)

            self.assertIn("cvauth", data)
            self.assertIn("identity", data["cvauth"])
            self.assertEqual(data["cvauth"]["identity"]["callsign"], "")

class TestMultiSchemeAuth(unittest.TestCase):
    def setUp(self):
        self.callsign = "ZL1MUL"
        self.payload = b"CVAuth multi-scheme authentication test"

        self.ed_scheme = get_scheme(DEFAULT_SCHEME)
        self.p192_scheme = get_scheme(CHATTERVOX_SCHEME)

        self.ed_private, self.ed_public = self.ed_scheme.generate_keypair()
        self.p192_private, self.p192_public = self.p192_scheme.generate_keypair()

    def make_keyring(self, *records):
        return DictKeyring({self.callsign: list(records)})

    def test_ed25519_signature_validates_with_ed25519_record(self):
        packet = CVPacket(from_call=self.callsign, payload=self.payload)
        sign_packet(
            packet,
            self.ed_private,
            scheme_name=DEFAULT_SCHEME,
        )

        keyring = self.make_keyring(
            PublicKeyRecord(self.callsign, DEFAULT_SCHEME, self.ed_public)
        )

        result = verify_packet(packet, keyring)
        self.assertEqual(result.auth_type, AuthType.VALID)

    def test_p192_signature_validates_with_p192_record(self):
        packet = CVPacket(from_call=self.callsign, payload=self.payload)
        sign_packet(
            packet,
            self.p192_private,
            scheme_name=CHATTERVOX_SCHEME,
        )

        keyring = self.make_keyring(
            PublicKeyRecord(self.callsign, CHATTERVOX_SCHEME, self.p192_public)
        )

        result = verify_packet(packet, keyring)
        self.assertEqual(result.auth_type, AuthType.VALID)

    def test_second_trusted_key_can_validate_signature(self):
        packet = CVPacket(from_call=self.callsign, payload=self.payload)
        sign_packet(
            packet,
            self.p192_private,
            scheme_name=CHATTERVOX_SCHEME,
        )

        # Ed25519 is checked first and must fail. P-192 must then succeed.
        keyring = self.make_keyring(
            PublicKeyRecord(self.callsign, DEFAULT_SCHEME, self.ed_public),
            PublicKeyRecord(self.callsign, CHATTERVOX_SCHEME, self.p192_public),
        )

        result = verify_packet(packet, keyring)
        self.assertEqual(result.auth_type, AuthType.VALID)
        self.assertIn(CHATTERVOX_SCHEME, result.reason)

    def test_invalid_signature_with_multiple_keys(self):
        packet = CVPacket(from_call=self.callsign, payload=self.payload)
        packet.signature = b"not a valid signature"
        packet.signed = True

        keyring = self.make_keyring(
            PublicKeyRecord(self.callsign, DEFAULT_SCHEME, self.ed_public),
            PublicKeyRecord(self.callsign, CHATTERVOX_SCHEME, self.p192_public),
        )

        result = verify_packet(packet, keyring)
        self.assertEqual(result.auth_type, AuthType.INVALID)

    def test_no_trusted_keys_returns_keynotfound(self):
        packet = CVPacket(from_call=self.callsign, payload=self.payload)
        sign_packet(packet, self.ed_private)

        result = verify_packet(packet, DictKeyring({}))
        self.assertEqual(result.auth_type, AuthType.KEYNOTFOUND)

    def test_payload_tampering_fails_for_p192(self):
        packet = CVPacket(from_call=self.callsign, payload=self.payload)
        sign_packet(
            packet,
            self.p192_private,
            scheme_name=CHATTERVOX_SCHEME,
        )
        packet.payload = b"tampered payload"

        keyring = self.make_keyring(
            PublicKeyRecord(self.callsign, CHATTERVOX_SCHEME, self.p192_public)
        )

        result = verify_packet(packet, keyring)
        self.assertEqual(result.auth_type, AuthType.INVALID)


