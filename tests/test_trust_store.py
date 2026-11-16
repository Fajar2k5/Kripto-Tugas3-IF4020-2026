from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sleman.errors import FormatError
from sleman.trust_store import (
    TrustKeyNotFoundError,
    add_trust,
    list_trust,
    load_trust_store,
    remove_trust,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PUBLIC_KEY_PATH = FIXTURES / "keys" / "ed25519-test.pub.pem"
TRUST_PATH = FIXTURES / "trust" / "demo-app.trust.json"
EMPTY_TRUST_PATH = FIXTURES / "trust" / "empty.trust.json"


class FakeBackend:
    """Backend pengujian; bukan implementasi kriptografi."""

    def __init__(self) -> None:
        self.keys: dict[bytes, tuple[str, bytes]] = {}

    def register(
        self, pem: str, profile: str = "ed25519", der: bytes | None = None
    ) -> tuple[bytes, str, bytes]:
        pem_bytes = pem.encode("utf-8")
        spki_der = der if der is not None else b"test-der:" + pem_bytes
        self.keys[pem_bytes] = (profile, spki_der)
        return pem_bytes, profile, spki_der

    def validate_public_key(self, public_key_pem: bytes) -> tuple[object, str, bytes]:
        try:
            profile, spki_der = self.keys[public_key_pem]
        except KeyError as exc:
            raise ValueError("kunci uji tidak dikenal") from exc
        return object(), profile, spki_der

    def fingerprint(self, spki_der: bytes) -> str:
        return hashlib.sha256(spki_der).hexdigest()


def _fixture_backend() -> FakeBackend:
    backend = FakeBackend()
    pem = PUBLIC_KEY_PATH.read_text(encoding="ascii")
    lines = pem.splitlines()
    spki_der = base64.b64decode("".join(lines[1:-1]), validate=True)
    backend.register(pem, "ed25519", spki_der)
    return backend


def _fake_pem(label: str) -> str:
    body = base64.b64encode(("test-key:" + label).encode("utf-8")).decode("ascii")
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"


def _store() -> dict[str, object]:
    return json.loads(TRUST_PATH.read_text(encoding="utf-8"))


def _write(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


class TrustStoreValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = _fixture_backend()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "trust.json"

    def _assert_rejected(self, candidate: object) -> None:
        _write(self.path, candidate)
        with self.assertRaises(FormatError):
            load_trust_store(self.path, backend=self.backend)

    def test_valid_fixture(self) -> None:
        store = load_trust_store(TRUST_PATH, backend=self.backend)
        self.assertEqual(store["schema"], "minisign-trust/v1")
        self.assertEqual(store["keys"][0]["packages"], ["demo-app"])

    def test_empty_store_is_valid(self) -> None:
        store = load_trust_store(EMPTY_TRUST_PATH, backend=FakeBackend())
        self.assertEqual(store, {"schema": "minisign-trust/v1", "keys": []})

    def test_missing_file(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_trust_store(self.path, backend=self.backend)

    def test_missing_extra_null_and_wrong_types(self) -> None:
        base = _store()
        variants = {
            "schema hilang": {key: value for key, value in base.items() if key != "schema"},
            "field tambahan": {**base, "extra": True},
            "null": {**base, "keys": None},
            "keys bukan array": {**base, "keys": {}},
            "entry bukan object": {**base, "keys": [None]},
        }
        for name, candidate in variants.items():
            with self.subTest(name=name):
                self._assert_rejected(candidate)

    def test_entry_fields_are_strict(self) -> None:
        base = _store()
        entry = copy.deepcopy(base["keys"][0])
        cases = {
            "field entry tambahan": {**entry, "extra": True},
            "public_key_pem bukan string": {**entry, "public_key_pem": 1},
            "packages bukan array": {**entry, "packages": "demo-app"},
            "packages kosong": {**entry, "packages": []},
            "packages duplikat": {**entry, "packages": ["demo-app", "demo-app"]},
            "packages wildcard": {**entry, "packages": ["*"]},
            "packages uppercase": {**entry, "packages": ["Demo-app"]},
            "keyid uppercase": {**entry, "keyid": "A" * 64},
        }
        for name, altered_entry in cases.items():
            with self.subTest(name=name):
                self._assert_rejected({**base, "keys": [altered_entry]})

    def test_duplicate_keyids_are_rejected(self) -> None:
        base = _store()
        self._assert_rejected({**base, "keys": [base["keys"][0], base["keys"][0]]})

    def test_unknown_algorithm_is_rejected(self) -> None:
        base = _store()
        entry = {**copy.deepcopy(base["keys"][0]), "algorithm": "unknown-profile"}
        self._assert_rejected({**base, "keys": [entry]})

    def test_profile_must_match_key(self) -> None:
        base = _store()
        pem = PUBLIC_KEY_PATH.read_text(encoding="ascii")
        lines = pem.splitlines()
        spki_der = base64.b64decode("".join(lines[1:-1]), validate=True)
        backend = FakeBackend()
        backend.register(pem, "rsa-pss-sha256", spki_der)
        _write(self.path, base)
        with self.assertRaises(FormatError):
            load_trust_store(self.path, backend=backend)

    def test_fingerprint_must_match_key(self) -> None:
        base = _store()
        entry = {**copy.deepcopy(base["keys"][0]), "keyid": "b" * 64}
        self._assert_rejected({**base, "keys": [entry]})

    def test_invalid_public_key_is_rejected(self) -> None:
        base = _store()
        entry = {**copy.deepcopy(base["keys"][0]), "public_key_pem": "not a pem"}
        self._assert_rejected({**base, "keys": [entry]})

    def test_duplicate_json_fields_are_rejected(self) -> None:
        raw = TRUST_PATH.read_text(encoding="utf-8")
        duplicate_top_level = raw.replace(
            '"keys": [', '"keys": [], "keys": [', 1
        )
        keyid = _store()["keys"][0]["keyid"]
        duplicate_entry = raw.replace(
            f'"keyid": "{keyid}"',
            f'"keyid": "{keyid}", "keyid": "{keyid}"',
            1,
        )
        for name, candidate in {
            "top level": duplicate_top_level,
            "entry": duplicate_entry,
        }.items():
            with self.subTest(name=name):
                self.path.write_text(candidate, encoding="utf-8")
                with self.assertRaises(FormatError):
                    load_trust_store(self.path, backend=self.backend)

    def test_trust_store_whitespace_is_allowed(self) -> None:
        raw = TRUST_PATH.read_text(encoding="utf-8")
        self.path.write_text("\n" + raw + "\n", encoding="utf-8")
        store = load_trust_store(self.path, backend=self.backend)
        self.assertEqual(len(store["keys"]), 1)


class TrustStoreManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FakeBackend()
        self.pem_text, _, self.spki_der = self.backend.register(_fake_pem("one"))
        self.keyid = self.backend.fingerprint(self.spki_der)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "trust.json"

    def test_add_creates_store(self) -> None:
        entry = add_trust(
            self.path,
            self.pem_text,
            "demo-app",
            backend=self.backend,
        )
        self.assertEqual(entry["keyid"], self.keyid)
        self.assertEqual(entry["algorithm"], "ed25519")
        self.assertEqual(entry["packages"], ["demo-app"])

        store = load_trust_store(self.path, backend=self.backend)
        self.assertEqual(store["keys"], [entry])

    def test_add_is_idempotent(self) -> None:
        add_trust(self.path, self.pem_text, "demo-app", backend=self.backend)
        before = self.path.read_bytes()
        add_trust(self.path, self.pem_text, "demo-app", backend=self.backend)
        self.assertEqual(self.path.read_bytes(), before)

    def test_add_merges_package_on_same_key(self) -> None:
        add_trust(self.path, self.pem_text, "demo-app", backend=self.backend)
        add_trust(self.path, self.pem_text, "other-app", backend=self.backend)
        store = load_trust_store(self.path, backend=self.backend)
        self.assertEqual(store["keys"][0]["packages"], ["demo-app", "other-app"])

    def test_add_second_key(self) -> None:
        add_trust(self.path, self.pem_text, "demo-app", backend=self.backend)
        second_pem, _, _ = self.backend.register(_fake_pem("two"))
        add_trust(self.path, second_pem, "demo-app", backend=self.backend)
        self.assertEqual(len(list_trust(self.path, backend=self.backend)), 2)

    def test_list_returns_entries(self) -> None:
        add_trust(self.path, self.pem_text, "demo-app", backend=self.backend)
        entries = list_trust(self.path, backend=self.backend)
        self.assertEqual(entries[0]["packages"], ["demo-app"])

    def test_remove_key(self) -> None:
        add_trust(self.path, self.pem_text, "demo-app", backend=self.backend)
        remove_trust(self.path, self.keyid, backend=self.backend)
        self.assertEqual(list_trust(self.path, backend=self.backend), [])

    def test_remove_missing_keyid(self) -> None:
        add_trust(self.path, self.pem_text, "demo-app", backend=self.backend)
        with self.assertRaises(TrustKeyNotFoundError):
            remove_trust(self.path, "a" * 64, backend=self.backend)

    def test_invalid_store_is_not_overwritten(self) -> None:
        self.path.write_text("{not json", encoding="utf-8")
        before = self.path.read_bytes()
        with self.assertRaises(FormatError):
            add_trust(self.path, self.pem_text, "demo-app", backend=self.backend)
        self.assertEqual(self.path.read_bytes(), before)

    def test_atomic_write_failure_preserves_old_store(self) -> None:
        add_trust(self.path, self.pem_text, "demo-app", backend=self.backend)
        before = self.path.read_bytes()
        with patch("sleman.trust_store.os.replace", side_effect=OSError("gagal")):
            with self.assertRaises(OSError):
                add_trust(
                    self.path,
                    self.pem_text,
                    "other-app",
                    backend=self.backend,
                )
        self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_package_is_rejected(self) -> None:
        with self.assertRaises(FormatError):
            add_trust(self.path, self.pem_text, "Demo-app", backend=self.backend)
        self.assertFalse(self.path.exists())

    def test_unknown_key_is_rejected(self) -> None:
        with self.assertRaises(FormatError):
            add_trust(
                self.path,
                _fake_pem("unknown").encode("utf-8"),
                "demo-app",
                backend=self.backend,
            )
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
