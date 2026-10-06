import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cvauth.crypto import (
    DEFAULT_SCHEME,
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
