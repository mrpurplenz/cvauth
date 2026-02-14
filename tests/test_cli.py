# cvauth/tests/test_cli.py

import os
import tempfile
from pathlib import Path
from io import StringIO
from unittest import TestCase
from unittest.mock import patch

from cvauth.cli import main
from cvauth.config import default_config_path

class TestCLIInit(TestCase):
    def test_init_creates_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["CVAUTH_CONFIG_DIR"] = tmp

            exit_code = main(["init"])

            self.assertEqual(exit_code, 0)

            cfg = default_config_path()
            self.assertTrue(cfg.exists())

    def test_init_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["CVAUTH_CONFIG_DIR"] = tmp

            main(["init"])
            cfg = default_config_path()
            text1 = cfg.read_text()

            main(["init"])
            text2 = cfg.read_text()

            self.assertEqual(text1, text2)


    def test_unknown_command_fails(self):
        with self.assertRaises(SystemExit) as cm:
            main(["doesnotexist"])

        self.assertNotEqual(cm.exception.code, 0)
