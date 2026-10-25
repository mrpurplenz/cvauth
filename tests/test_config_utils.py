import unittest
from unittest.mock import patch

from cvauth.config_utils import request_crypto_scheme
from cvauth.crypto import available_schemes


class TestConfigUtils(unittest.TestCase):
    def test_request_crypto_scheme_default(self):
        schemes = available_schemes()
        with patch("builtins.input", return_value=""):
            self.assertEqual(request_crypto_scheme(), schemes[0])

    def test_request_crypto_scheme_by_number(self):
        schemes = available_schemes()
        with patch("builtins.input", return_value="1"):
            self.assertEqual(request_crypto_scheme(), schemes[0])

    def test_request_crypto_scheme_by_name(self):
        schemes = available_schemes()
        with patch("builtins.input", return_value=schemes[0]):
            self.assertEqual(request_crypto_scheme(), schemes[0])

    def test_request_crypto_scheme_retries_on_invalid_choice(self):
        schemes = available_schemes()
        with patch("builtins.input", side_effect=["99", ""]):
            self.assertEqual(request_crypto_scheme(), schemes[0])
