import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cvauth.crypto import (
    DEFAULT_SCHEME,
    CHATTERVOX_SCHEME,
    CryptoScheme,
    available_schemes,
    get_scheme,
    register_scheme,
)


class TestCryptoRegistry(unittest.TestCase):
    def test_current_scheme_is_registered(self):
        self.assertIn(DEFAULT_SCHEME, available_schemes())
        self.assertIs(get_scheme(DEFAULT_SCHEME).sign, get_scheme(DEFAULT_SCHEME).sign)
        self.assertIs(get_scheme(DEFAULT_SCHEME).verify, get_scheme(DEFAULT_SCHEME).verify)

    def test_registered_scheme_preserves_current_operations(self):
        scheme = get_scheme(DEFAULT_SCHEME)
        private_key = Ed25519PrivateKey.generate()
        payload = b"registry test"
        signature = scheme.sign(payload, private_key)

        self.assertTrue(scheme.verify(payload, signature, private_key.public_key()))
        self.assertFalse(
            scheme.verify(b"different payload", signature, private_key.public_key())
        )

    def test_default_scheme_serializes_and_loads_key_material(self):
        scheme = get_scheme(DEFAULT_SCHEME)
        private_key, public_key = scheme.generate_keypair()

        private_bytes = scheme.serialize_private(private_key)
        public_bytes = scheme.serialize_public(public_key)

        loaded_private = scheme.load_private(private_bytes)
        loaded_public = scheme.load_public(public_bytes)

        payload = b"serialize round-trip"
        signature = scheme.sign(payload, loaded_private)

        self.assertTrue(scheme.verify(payload, signature, loaded_public))

    def test_custom_scheme_can_be_registered(self):
        name = "test-scheme"
        scheme = get_scheme(DEFAULT_SCHEME)

        custom = CryptoScheme(
            name=name,
            description=scheme.description,
            generate_keypair=scheme.generate_keypair,
            serialize_private=scheme.serialize_private,
            serialize_public=scheme.serialize_public,
            load_private=scheme.load_private,
            load_public=scheme.load_public,
            sign=scheme.sign,
            verify=scheme.verify,
        )

        register_scheme(custom)

        self.assertIn(name, available_schemes())
        self.assertIs(get_scheme(name), custom)

        private_key = Ed25519PrivateKey.generate()
        payload = b"custom scheme"
        signature = get_scheme(name).sign(payload, private_key)

        self.assertTrue(get_scheme(name).verify(payload, signature, private_key.public_key()))

    def test_unknown_scheme_raises_key_error(self):
        with self.assertRaises(KeyError):
            get_scheme("does-not-exist")

class TestChattervoxP192(unittest.TestCase):
    def setUp(self):
        self.scheme = get_scheme(CHATTERVOX_SCHEME)
        self.payload = b"ChatterVox P-192 cryptographic test"

    def test_scheme_is_registered(self):
        self.assertIn(CHATTERVOX_SCHEME, available_schemes())

    def test_generate_and_sign(self):
        private_key, public_key = self.scheme.generate_keypair()

        signature = self.scheme.sign(self.payload, private_key)

        self.assertTrue(
            self.scheme.verify(self.payload, signature, public_key)
        )

    def test_modified_payload_fails_verification(self):
        private_key, public_key = self.scheme.generate_keypair()
        signature = self.scheme.sign(self.payload, private_key)

        self.assertFalse(
            self.scheme.verify(b"modified payload", signature, public_key)
        )

    def test_wrong_public_key_fails_verification(self):
        private_key, _ = self.scheme.generate_keypair()
        _, other_public_key = self.scheme.generate_keypair()
        signature = self.scheme.sign(self.payload, private_key)

        self.assertFalse(
            self.scheme.verify(self.payload, signature, other_public_key)
        )

    def test_key_serialization_round_trip(self):
        private_key, public_key = self.scheme.generate_keypair()

        private_bytes = self.scheme.serialize_private(private_key)
        public_bytes = self.scheme.serialize_public(public_key)

        self.assertEqual(len(private_bytes), 48)
        self.assertEqual(len(public_bytes), 98)
        self.assertTrue(public_bytes.startswith(b"04"))

        loaded_private = self.scheme.load_private(private_bytes)
        loaded_public = self.scheme.load_public(public_bytes)

        signature = self.scheme.sign(self.payload, loaded_private)

        self.assertTrue(
            self.scheme.verify(self.payload, signature, loaded_public)
        )

    def test_malformed_private_key_is_rejected(self):
        with self.assertRaises(TypeError):
            self.scheme.load_private(b"not-a-valid-key")

    def test_invalid_private_scalar_is_rejected(self):
        with self.assertRaises(TypeError):
            self.scheme.load_private(b"0" * 48)
