# cvauth/tests/test_public_api.py

import unittest

class TestPublicAPI(unittest.TestCase):

    def test_public_api_imports(self):
        from cvauth import (
            CVPacket,
            sign_packet,
            verify_packet,
            AuthType,
            AuthResult,
            PublicKeyProvider,
            __version__,
        )

        self.assertIsNotNone(CVPacket)
        self.assertIsNotNone(sign_packet)
        self.assertIsNotNone(verify_packet)
        self.assertIsNotNone(AuthType)
        self.assertIsNotNone(AuthResult)
        self.assertIsNotNone(PublicKeyProvider)
        self.assertIsInstance(__version__, str)
