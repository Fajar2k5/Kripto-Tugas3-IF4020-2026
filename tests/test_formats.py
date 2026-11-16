from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path
from typing import Any

from sleman.errors import FormatError
from sleman.formats import (
    MAX_BUNDLE_BYTES,
    MAX_MANIFEST_BYTES,
    load_bundle,
    load_manifest,
    serialize_manifest_canonical,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MANIFEST_PATH = FIXTURES / "bundles" / "demo-app.manifest.json"
BUNDLE_PATH = FIXTURES / "bundles" / "demo-app.ed25519.json"


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_bytes())


def _bundle() -> dict[str, Any]:
    return json.loads(BUNDLE_PATH.read_bytes())


class ManifestStrictParserTests(unittest.TestCase):
    def test_valid_fixture_is_loaded(self) -> None:
        manifest = load_manifest(MANIFEST_PATH.read_bytes())
        self.assertEqual(manifest["package"], "demo-app")
        self.assertEqual(manifest["artifact"]["size"], 16)

    def test_valid_fixture_serializes_to_original_bytes(self) -> None:
        manifest = _manifest()
        self.assertEqual(
            serialize_manifest_canonical(manifest),
            MANIFEST_PATH.read_bytes(),
        )

    def test_unknown_algorithm_is_structurally_valid(self) -> None:
        manifest = _manifest()
        manifest["algorithm"] = "unknown-profile"
        raw = _json_bytes(manifest)
        self.assertEqual(load_manifest(raw)["algorithm"], "unknown-profile")

    def test_manifest_must_be_canonical(self) -> None:
        raw = MANIFEST_PATH.read_bytes()
        manifest = _manifest()
        reordered = {key: manifest[key] for key in reversed(list(manifest))}
        variants = {
            "spasi": raw.replace(b",", b", "),
            "newline": raw + b"\n",
            "urutan field": _json_bytes(reordered),
            "escape unicode": raw.replace(
                b'"algorithm":"ed25519"',
                b'"algorithm":"\\u0065d25519"',
            ),
        }
        for name, candidate in variants.items():
            with self.subTest(name=name), self.assertRaises(FormatError):
                load_manifest(candidate)

    def test_duplicate_fields_are_rejected(self) -> None:
        raw = MANIFEST_PATH.read_bytes()
        top_level_duplicate = b'{"schema":"minisign-manifest/v1",' + raw[1:]
        nested_duplicate = raw.replace(
            b'"artifact":{"name":',
            b'"artifact":{"name":"duplicate","name":',
        )
        for name, candidate in {
            "top level": top_level_duplicate,
            "artifact": nested_duplicate,
        }.items():
            with self.subTest(name=name), self.assertRaises(FormatError):
                load_manifest(candidate)

    def test_missing_extra_and_null_fields_are_rejected(self) -> None:
        missing = _manifest()
        del missing["algorithm"]

        extra = _manifest()
        extra["unknown"] = True

        null = _manifest()
        null["package"] = None

        for name, manifest in {
            "hilang": missing,
            "tambahan": extra,
            "null": null,
        }.items():
            with self.subTest(name=name), self.assertRaises(FormatError):
                load_manifest(_json_bytes(manifest))

    def test_wrong_types_are_rejected(self) -> None:
        cases = {
            "schema": ("schema", 1),
            "package": ("package", []),
            "version": ("version", True),
            "algorithm": ("algorithm", {}),
            "keyid": ("keyid", 0),
            "artifact": ("artifact", []),
        }
        for name, (field, value) in cases.items():
            manifest = _manifest()
            manifest[field] = value
            with self.subTest(name=name), self.assertRaises(FormatError):
                load_manifest(_json_bytes(manifest))

    def test_invalid_field_patterns_are_rejected(self) -> None:
        cases = {
            "package uppercase": ("package", "Demo-app"),
            "package kosong": ("package", ""),
            "version slash": ("version", "1.0/0"),
            "keyid uppercase": ("keyid", "A" * 64),
            "keyid pendek": ("keyid", "a" * 63),
        }
        for name, (field, value) in cases.items():
            manifest = _manifest()
            manifest[field] = value
            with self.subTest(name=name), self.assertRaises(FormatError):
                load_manifest(_json_bytes(manifest))

    def test_artifact_size_boundaries(self) -> None:
        accepted = [0, 9007199254740991]
        for size in accepted:
            manifest = _manifest()
            manifest["artifact"]["size"] = size
            with self.subTest(size=size):
                self.assertEqual(
                    load_manifest(_json_bytes(manifest))["artifact"]["size"],
                    size,
                )

        rejected = [-1, 9007199254740992, True, 1.0, "16"]
        for size in rejected:
            manifest = _manifest()
            manifest["artifact"]["size"] = size
            with self.subTest(size=size), self.assertRaises(FormatError):
                load_manifest(_json_bytes(manifest))

    def test_artifact_name_and_hash_patterns(self) -> None:
        cases = {
            "name slash": ("name", "dir/hello.txt"),
            "name kosong": ("name", ""),
            "sha uppercase": ("sha256", "A" * 64),
            "sha pendek": ("sha256", "a" * 63),
        }
        for name, (field, value) in cases.items():
            manifest = _manifest()
            manifest["artifact"][field] = value
            with self.subTest(name=name), self.assertRaises(FormatError):
                load_manifest(_json_bytes(manifest))

    def test_algorithm_must_be_printable_ascii(self) -> None:
        manifest = _manifest()
        manifest["algorithm"] = "ed25519\n"
        with self.assertRaises(FormatError):
            load_manifest(_json_bytes(manifest))

    def test_invalid_encoding_and_json_are_rejected(self) -> None:
        raw = MANIFEST_PATH.read_bytes()
        nan_manifest = raw.replace(b'"size":16', b'"size":NaN')
        cases = {
            "bom": b"\xef\xbb\xbf" + raw,
            "utf8 invalid": b"\xff" + raw,
            "trailing data": raw + b"x",
            "nan": nan_manifest,
        }
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaises(FormatError):
                load_manifest(candidate)

    def test_manifest_size_limit(self) -> None:
        manifest = _manifest()
        manifest["algorithm"] = "a" * MAX_MANIFEST_BYTES
        with self.assertRaises(FormatError):
            load_manifest(_json_bytes(manifest))


class BundleStrictParserTests(unittest.TestCase):
    def test_valid_fixture_is_loaded(self) -> None:
        manifest, signature = load_bundle(BUNDLE_PATH.read_bytes())
        self.assertEqual(manifest, MANIFEST_PATH.read_bytes())
        self.assertEqual(signature, bytes(64))

    def test_bundle_whitespace_and_field_order_are_free(self) -> None:
        bundle = _bundle()
        reordered = {key: bundle[key] for key in reversed(list(bundle))}
        encoded = json.dumps(reordered, indent=2).encode("utf-8") + b"\n"
        manifest, signature = load_bundle(encoded)
        self.assertEqual(manifest, MANIFEST_PATH.read_bytes())
        self.assertEqual(signature, bytes(64))

    def test_bundle_rejects_duplicate_fields(self) -> None:
        raw = BUNDLE_PATH.read_bytes()
        duplicate = b'{"schema":"minisign-bundle/v1",' + raw[1:]
        with self.assertRaises(FormatError):
            load_bundle(duplicate)

    def test_bundle_rejects_missing_extra_null_and_wrong_type(self) -> None:
        bundle = _bundle()
        variants = {
            "hilang": {key: value for key, value in bundle.items() if key != "schema"},
            "tambahan": {**bundle, "extra": True},
            "null": {**bundle, "signature_b64": None},
            "schema": {**bundle, "schema": "wrong"},
            "wrong type": {**bundle, "manifest_b64": []},
        }
        for name, candidate in variants.items():
            with self.subTest(name=name), self.assertRaises(FormatError):
                load_bundle(_json_bytes(candidate))

    def test_bundle_rejects_invalid_base64(self) -> None:
        bundle = _bundle()
        valid_manifest = bundle["manifest_b64"]
        variants = {
            "whitespace": " " + valid_manifest,
            "tanpa padding": valid_manifest.rstrip("="),
            "padding salah": "AAAA===",
            "alfabet salah": "-" * 4,
        }
        for field in ("manifest_b64", "signature_b64"):
            for name, value in variants.items():
                candidate = {**bundle, field: value}
                with self.subTest(field=field, name=name), self.assertRaises(FormatError):
                    load_bundle(_json_bytes(candidate))

        empty_manifest = {**bundle, "manifest_b64": ""}
        with self.assertRaises(FormatError):
            load_bundle(_json_bytes(empty_manifest))

    def test_empty_signature_is_structurally_valid(self) -> None:
        bundle = {**_bundle(), "signature_b64": ""}
        manifest, signature = load_bundle(_json_bytes(bundle))
        self.assertEqual(manifest, MANIFEST_PATH.read_bytes())
        self.assertEqual(signature, b"")

    def test_bundle_rejects_noncanonical_manifest(self) -> None:
        manifest = MANIFEST_PATH.read_bytes().replace(b",", b", ")
        bundle = _bundle()
        bundle["manifest_b64"] = base64.b64encode(manifest).decode("ascii")
        with self.assertRaises(FormatError):
            load_bundle(_json_bytes(bundle))

    def test_bundle_rejects_oversized_manifest(self) -> None:
        bundle = _bundle()
        oversized = b"x" * (MAX_MANIFEST_BYTES + 1)
        bundle["manifest_b64"] = base64.b64encode(oversized).decode("ascii")
        with self.assertRaises(FormatError):
            load_bundle(_json_bytes(bundle))

    def test_bundle_size_limit(self) -> None:
        with self.assertRaises(FormatError):
            load_bundle(b" " * (MAX_BUNDLE_BYTES + 1))

    def test_bundle_rejects_invalid_json(self) -> None:
        for candidate in (b"", b"{", b"\xef\xbb\xbf{}", b"\xff{}"):
            with self.subTest(candidate=candidate), self.assertRaises(FormatError):
                load_bundle(candidate)


if __name__ == "__main__":
    unittest.main()
