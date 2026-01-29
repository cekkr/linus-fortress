import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


CLI_PATH = Path(__file__).resolve().parents[1] / "fortress-cli.py"


def load_cli_module(temp_home: str):
    module_name = f"fortress_cli_test_{os.getpid()}"
    spec = importlib.util.spec_from_file_location(module_name, str(CLI_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, module_name


class CliCryptoTests(unittest.TestCase):
    def test_keypair_roundtrip_encrypt_decrypt(self) -> None:
        passphrase = "KeyPass-123_ABC"
        secret = "example-secret-42"
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["FORTRESS_HOME"] = tmpdir
            os.environ.pop("FORTRESS_PASSPHRASE", None)
            module, name = load_cli_module(tmpdir)
            try:
                module.generate_rsa_keypair(bits=2048, passphrase=passphrase)
                public_key = module.load_public_key()
                private_key = module.load_private_key(passphrase)
                ciphertext = module.encrypt_secret(secret, public_key)
                plaintext = module.decrypt_secret(ciphertext, private_key)
                self.assertEqual(secret, plaintext)
            finally:
                sys.modules.pop(name, None)
                os.environ.pop("FORTRESS_HOME", None)
