"""Skenario CLI U01, U14 dan verifikasi eksternal dengan OpenSSL 3."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from sleman.formats import load_bundle
from sleman.profiles import SUPPORTED_PROFILES


class SigningTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def cli(self, *args, expected=0):
        result = subprocess.run([sys.executable, "-m", "sleman", *args],
                                cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, expected, result.stderr)
        return result.stdout

    def check_openssl(self, profile, message, signature):
        command = ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                   "-inkey", profile + ".pub.pem", "-in", "manifest", "-sigfile", "sig"]
        if profile != "ed25519":
            command += ["-digest", "sha256"]
        if profile == "rsa-pss-sha256":
            for opt in ("rsa_padding_mode:pss", "rsa_pss_saltlen:32", "rsa_mgf1_md:sha256"):
                command += ["-pkeyopt", opt]
        if profile == "ecdsa-p256-sha256":
            signature = encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                             int.from_bytes(signature[32:], "big"))
        (self.root / "manifest").write_bytes(message)
        (self.root / "sig").write_bytes(signature)
        subprocess.run(command, cwd=self.root, check=True, capture_output=True)

    def test_u01_u14_and_openssl(self):
        release = ["--package", "demo", "--version", "1.0"]
        for profile in SUPPORTED_PROFILES:
            keyid = self.cli("keygen", "--algorithm", profile, "--out", profile).strip()
            self.cli("trust", "add", "--key", profile + ".pub.pem", "--package", "demo",
                     "--store", "trust.json")
            for name, payload in [("text.txt", b"rilis\r\n"), ("binary.bin", bytes(range(256))),
                                  ("empty.bin", b"")]:
                with self.subTest(profile=profile, name=name):
                    (self.root / name).write_bytes(payload)
                    pairs = []
                    for index in range(2):
                        output = f"{profile}-{name}-{index}.json"
                        self.cli("sign", "--file", name, *release, "--key", profile + ".key.pem",
                                 "--out", output)
                        status = self.cli("verify", "--file", name, *release, "--bundle", output,
                                          "--trust-store", "trust.json", "--json")
                        self.assertEqual(json.loads(status)["status"], "OK")
                        pairs.append(load_bundle((self.root / output).read_bytes()))
                    (message, sig), (other, sig2) = pairs
                    manifest = json.loads(message)
                    self.assertEqual(keyid, "keyid: " + manifest["keyid"])
                    self.assertEqual(manifest["artifact"], {"name": name, "size": len(payload),
                                     "sha256": hashlib.sha256(payload).hexdigest()})
                    self.assertEqual(message, other)
                    self.assertEqual(sig == sig2, profile != "rsa-pss-sha256")
                    self.assertEqual(len(sig), 384 if profile == "rsa-pss-sha256" else 64)
                    self.check_openssl(profile, message, sig)

    def test_profile_and_signature_rejections(self):
        from cryptography.hazmat.primitives import serialization as ser
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from sleman import crypto_backend as crypto
        from sleman.errors import FormatError

        for key in (ec.generate_private_key(ec.SECP384R1()), rsa.generate_private_key(65537, 2048)):
            with self.assertRaises(FormatError):
                crypto.validate_public_key(key.public_key().public_bytes(ser.Encoding.PEM, crypto.SPKI))
            with self.assertRaises(FormatError):
                crypto.load_private_key(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                         ser.NoEncryption()))
        for profile in SUPPORTED_PROFILES:
            fixture = Path(__file__).parent / "fixtures" / f"test-only-{profile}.key.pem"
            key = crypto.load_private_key(fixture.read_bytes())
            signature = crypto.sign_message(key, b"manifest")
            self.assertFalse(crypto.verify_signature(profile, key.public_key(), b"changed", signature))
            self.assertFalse(crypto.verify_signature(profile, key.public_key(), b"manifest", signature[:-1]))

    def test_existing_public_key_preserved(self):
        public = self.root / "publisher.pub.pem"
        public.write_bytes(b"existing")
        self.cli("keygen", "--algorithm", "ed25519", "--out", "publisher", expected=2)
        self.assertEqual(public.read_bytes(), b"existing")
        self.assertFalse((self.root / "publisher.key.pem").exists())
