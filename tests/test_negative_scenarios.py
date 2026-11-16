"""Skenario negatif U02-U13"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sleman.formats import serialize_manifest_canonical

PACKAGE = "demo-app"
VERSION = "1.0.0"


class NegativeScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.artifact = self.root / "app.txt"
        self.artifact.write_bytes(b"release artifact\n")
        self.keyid = self.cli(
            "keygen", "--algorithm", "ed25519", "--out", "publisher"
        ).strip()
        self.cli(
            "trust",
            "add",
            "--key",
            "publisher.pub.pem",
            "--package",
            PACKAGE,
            "--store",
            "trust.json",
        )

    def cli(self, *args: str, expected: int = 0) -> str:
        result = subprocess.run(
            [sys.executable, "-m", "sleman", *args],
            cwd=self.root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        return result.stdout

    def sign(self, artifact: str = "app.txt", *, key: str = "publisher.key.pem",
             output: str = "release.json") -> None:
        self.cli(
            "sign",
            "--file",
            artifact,
            "--package",
            PACKAGE,
            "--version",
            VERSION,
            "--key",
            key,
            "--out",
            output,
        )

    def verify(self, *, artifact: str = "app.txt", bundle: str = "release.json",
               trust: str = "trust.json", version: str = VERSION,
               expected: int = 0) -> dict:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "sleman",
                "verify",
                "--file",
                artifact,
                "--bundle",
                bundle,
                "--trust-store",
                trust,
                "--package",
                PACKAGE,
                "--version",
                version,
                "--json",
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        return json.loads(result.stdout)

    def test_u02_one_artifact_byte_changed_same_size(self) -> None:
        self.sign()
        data = bytearray(self.artifact.read_bytes())
        data[0] ^= 1
        self.artifact.write_bytes(data)
        self.assertEqual(self.verify(expected=1)["status"], "ARTIFACT_MISMATCH")

    def test_u03_artifact_size_changed(self) -> None:
        self.sign()
        self.artifact.write_bytes(self.artifact.read_bytes() + b"x")
        self.assertEqual(self.verify(expected=1)["status"], "ARTIFACT_MISMATCH")

    def test_u04_manifest_changed_with_old_signature(self) -> None:
        self.sign()
        bundle_path = self.root / "release.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        manifest = json.loads(base64.b64decode(bundle["manifest_b64"]))
        manifest["version"] = "1.0.1"
        bundle["manifest_b64"] = base64.b64encode(
            serialize_manifest_canonical(manifest)
        ).decode("ascii")
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        self.assertEqual(self.verify(expected=1)["status"], "INVALID_SIGNATURE")

    def test_u05_one_signature_bit_changed(self) -> None:
        self.sign()
        bundle_path = self.root / "release.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        signature = bytearray(base64.b64decode(bundle["signature_b64"]))
        signature[0] ^= 1
        bundle["signature_b64"] = base64.b64encode(signature).decode("ascii")
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        self.assertEqual(self.verify(expected=1)["status"], "INVALID_SIGNATURE")

    def test_u06_empty_trust_store(self) -> None:
        self.sign()
        (self.root / "empty.json").write_text(
            '{"schema":"minisign-trust/v1","keys":[]}\n', encoding="utf-8"
        )
        self.assertEqual(
            self.verify(trust="empty.json", expected=1)["status"],
            "KEY_NOT_TRUSTED",
        )

    def test_u07_key_only_allowed_for_other_package(self) -> None:
        self.sign()
        self.cli(
            "trust",
            "add",
            "--key",
            "publisher.pub.pem",
            "--package",
            "other-app",
            "--store",
            "other-trust.json",
        )
        self.assertEqual(
            self.verify(trust="other-trust.json", expected=1)["status"],
            "KEY_NOT_TRUSTED",
        )

    def test_u08_expected_version_differs(self) -> None:
        self.sign()
        self.assertEqual(
            self.verify(version="2.0.0", expected=1)["status"],
            "METADATA_MISMATCH",
        )

    def test_u09_artifact_name_changed(self) -> None:
        self.sign()
        renamed = self.root / "other.txt"
        renamed.write_bytes(self.artifact.read_bytes())
        self.assertEqual(
            self.verify(artifact="other.txt", expected=1)["status"],
            "METADATA_MISMATCH",
        )

    def test_u10_malformed_inputs(self) -> None:
        self.sign()
        bundle_path = self.root / "release.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        original = bundle_path.read_bytes()

        cases = {
            "duplicate": b'{"schema":"minisign-bundle/v1",' + original[1:],
            "base64": json.dumps({**bundle, "manifest_b64": "AAAA==="}).encode(),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                bad = self.root / f"bad-{name}.json"
                bad.write_bytes(data)
                self.assertEqual(
                    self.verify(bundle=bad.name, expected=1)["status"],
                    "FORMAT_ERROR",
                )

        manifest = json.loads(base64.b64decode(bundle["manifest_b64"]))
        wrong_type = {**manifest, "artifact": {**manifest["artifact"], "size": "16"}}
        wrong_bundle = self.root / "bad-type.json"
        wrong_bundle.write_text(
            json.dumps(
                {
                    "schema": "minisign-bundle/v1",
                    "manifest_b64": base64.b64encode(
                        json.dumps(wrong_type, separators=(",", ":")).encode()
                    ).decode("ascii"),
                    "signature_b64": bundle["signature_b64"],
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(
            self.verify(bundle=wrong_bundle.name, expected=1)["status"],
            "FORMAT_ERROR",
        )

        large_manifest = {**manifest, "algorithm": "a" * 20_000}
        large_bundle = self.root / "bad-large.json"
        large_bundle.write_text(
            json.dumps(
                {
                    "schema": "minisign-bundle/v1",
                    "manifest_b64": base64.b64encode(
                        json.dumps(large_manifest, separators=(",", ":")).encode()
                    ).decode("ascii"),
                    "signature_b64": bundle["signature_b64"],
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(
            self.verify(bundle=large_bundle.name, expected=1)["status"],
            "FORMAT_ERROR",
        )

        (self.root / "bad-trust.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(
            self.verify(trust="bad-trust.json", expected=1)["status"],
            "FORMAT_ERROR",
        )

    def test_u11_unknown_algorithm(self) -> None:
        self.sign()
        bundle_path = self.root / "release.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        manifest = json.loads(base64.b64decode(bundle["manifest_b64"]))
        manifest["algorithm"] = "unknown-profile"
        bundle["manifest_b64"] = base64.b64encode(
            serialize_manifest_canonical(manifest)
        ).decode("ascii")
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        self.assertEqual(
            self.verify(expected=1)["status"],
            "UNSUPPORTED_ALGORITHM",
        )

    def test_u12_untrusted_key_same_profile(self) -> None:
        self.cli("keygen", "--algorithm", "ed25519", "--out", "second")
        self.sign(key="second.key.pem")
        self.assertEqual(
            self.verify(expected=1)["status"],
            "KEY_NOT_TRUSTED",
        )

    def test_u13_bundle_whitespace_and_field_order(self) -> None:
        self.sign()
        bundle_path = self.root / "release.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        reordered = {key: bundle[key] for key in reversed(list(bundle))}
        bundle_path.write_text(json.dumps(reordered, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(self.verify()["status"], "OK")


if __name__ == "__main__":
    unittest.main()
