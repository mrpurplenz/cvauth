import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cvauth.crypto import (
    DEFAULT_SCHEME,
    available_schemes,
    get_scheme,
)


class TestCryptoRegistry(unittest.TestCase):
    def test_current_scheme_is_registered(self):
        self.assertEqual(available_schemes(), (DEFAULT_SCHEME,))
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

    def test_unknown_scheme_raises_key_error(self):
        with self.assertRaises(KeyError):
            get_scheme("does-not-exist")
