"""Validasi dan pengelolaan trust store."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Protocol, cast

from . import crypto_backend
from .errors import FormatError
from .formats import parse_json_object
from .profiles import SUPPORTED_PROFILES

_TRUST_SCHEMA = "minisign-trust/v1"
_TRUST_FIELDS = frozenset({"schema", "keys"})
_ENTRY_FIELDS = frozenset({"keyid", "algorithm", "public_key_pem", "packages"})
_PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}", re.ASCII)
_HEX64_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)


class CryptoBackend(Protocol):
    """Operasi kriptografi minimum yang dibutuhkan trust store."""

    def validate_public_key(self, public_key_pem: bytes) -> tuple[Any, str, bytes]:
        ...

    def fingerprint(self, spki_der: bytes) -> str:
        ...


class TrustKeyNotFoundError(ValueError):
    """Keyid tidak ditemukan di trust store."""


def _get_backend(backend: CryptoBackend | None) -> CryptoBackend:
    return cast(CryptoBackend, crypto_backend) if backend is None else backend


def _require_exact_fields(
    value: dict[str, Any], expected: frozenset[str], label: str
) -> None:
    actual = set(value)
    missing = expected - actual
    extra = actual - expected
    if missing:
        raise FormatError(f"{label} tidak memiliki field: {', '.join(sorted(missing))}")
    if extra:
        raise FormatError(f"{label} memiliki field tambahan: {', '.join(sorted(extra))}")


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise FormatError(f"{label} harus berupa string")
    return value


def _require_pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    text = _require_string(value, label)
    if pattern.fullmatch(text) is None:
        raise FormatError(f"{label} tidak sesuai pola")
    return text


def _inspect_key(
    public_key_pem: bytes, backend: CryptoBackend
) -> tuple[str, str, str]:
    try:
        result = backend.validate_public_key(public_key_pem)
    except (ValueError, TypeError) as exc:
        raise FormatError("public_key_pem bukan kunci publik yang valid") from exc

    if not isinstance(result, tuple) or len(result) != 3:
        raise FormatError("backend mengembalikan hasil validasi kunci yang invalid")
    _key_object, profile, spki_der = result
    if not isinstance(profile, str) or profile not in SUPPORTED_PROFILES:
        raise FormatError("profil algoritma kunci tidak didukung")
    if not isinstance(spki_der, bytes):
        raise FormatError("DER SPKI kunci tidak valid")

    try:
        keyid = backend.fingerprint(spki_der)
    except (ValueError, TypeError) as exc:
        raise FormatError("fingerprint kunci tidak dapat dihitung") from exc
    if not isinstance(keyid, str) or _HEX64_RE.fullmatch(keyid) is None:
        raise FormatError("fingerprint kunci tidak valid")

    try:
        pem_text = public_key_pem.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FormatError("public_key_pem harus berupa teks UTF-8") from exc

    return keyid, profile, pem_text


def _validate_store(
    store: dict[str, Any], backend: CryptoBackend
) -> dict[str, Any]:
    _require_exact_fields(store, _TRUST_FIELDS, "trust store")

    if _require_string(store["schema"], "trust store.schema") != _TRUST_SCHEMA:
        raise FormatError("trust store.schema tidak dikenal")

    keys = store["keys"]
    if not isinstance(keys, list):
        raise FormatError("trust store.keys harus berupa array")

    seen_keyids: set[str] = set()
    normalized_entries: list[dict[str, Any]] = []

    for index, raw_entry in enumerate(keys):
        label = f"trust store.keys[{index}]"
        if not isinstance(raw_entry, dict):
            raise FormatError(f"{label} harus berupa objek")
        _require_exact_fields(raw_entry, _ENTRY_FIELDS, label)

        keyid = _require_pattern(raw_entry["keyid"], _HEX64_RE, f"{label}.keyid")
        if keyid in seen_keyids:
            raise FormatError(f"{label}.keyid duplikat")
        seen_keyids.add(keyid)

        algorithm = _require_string(raw_entry["algorithm"], f"{label}.algorithm")
        if algorithm not in SUPPORTED_PROFILES:
            raise FormatError(f"{label}.algorithm tidak didukung")

        pem_text = _require_string(
            raw_entry["public_key_pem"], f"{label}.public_key_pem"
        )
        try:
            computed_keyid, detected_profile, stored_pem = _inspect_key(
                pem_text.encode("utf-8"), backend
            )
        except FormatError as exc:
            raise FormatError(f"{label}: {exc}") from exc

        if detected_profile != algorithm:
            raise FormatError(f"{label}.algorithm tidak cocok dengan kunci")
        if computed_keyid != keyid:
            raise FormatError(f"{label}.keyid tidak cocok dengan fingerprint kunci")

        raw_packages = raw_entry["packages"]
        if not isinstance(raw_packages, list) or not raw_packages:
            raise FormatError(f"{label}.packages harus berupa array tidak kosong")
        packages: list[str] = []
        for package_index, raw_package in enumerate(raw_packages):
            packages.append(
                _require_pattern(
                    raw_package,
                    _PACKAGE_RE,
                    f"{label}.packages[{package_index}]",
                )
            )
        if len(set(packages)) != len(packages):
            raise FormatError(f"{label}.packages memuat duplikat")

        normalized_entries.append(
            {
                "keyid": keyid,
                "algorithm": algorithm,
                "public_key_pem": stored_pem,
                "packages": packages,
            }
        )

    return {"schema": _TRUST_SCHEMA, "keys": normalized_entries}


def _serialize_store(store: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            {
                "schema": store["schema"],
                "keys": [
                    {
                        "keyid": entry["keyid"],
                        "algorithm": entry["algorithm"],
                        "public_key_pem": entry["public_key_pem"],
                        "packages": list(entry["packages"]),
                    }
                    for entry in store["keys"]
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _write_store(path: Path, store: dict[str, Any]) -> None:
    payload = _serialize_store(store)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _copy_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "keyid": entry["keyid"],
        "algorithm": entry["algorithm"],
        "public_key_pem": entry["public_key_pem"],
        "packages": list(entry["packages"]),
    }


def load_trust_store(
    path: Path, *, backend: CryptoBackend | None = None
) -> dict[str, Any]:
    """Baca dan validasi trust store"""

    path = Path(path)
    store = parse_json_object(
        path.read_bytes(),
        max_bytes=None,
        label="trust store",
    )
    return _validate_store(store, _get_backend(backend))


def add_trust(
    path: Path,
    public_key_pem: bytes,
    package: str,
    *,
    backend: CryptoBackend | None = None,
) -> dict[str, Any]:
    """Tambahkan izin package untuk sebuah kunci publik"""

    path = Path(path)
    package = _require_pattern(package, _PACKAGE_RE, "package")
    backend = _get_backend(backend)
    keyid, profile, pem_text = _inspect_key(public_key_pem, backend)

    if path.exists():
        store = load_trust_store(path, backend=backend)
    else:
        store = {"schema": _TRUST_SCHEMA, "keys": []}

    entry = next(
        (candidate for candidate in store["keys"] if candidate["keyid"] == keyid),
        None,
    )
    if entry is None:
        entry = {
            "keyid": keyid,
            "algorithm": profile,
            "public_key_pem": pem_text,
            "packages": [package],
        }
        store["keys"].append(entry)
        _write_store(path, store)
    elif package not in entry["packages"]:
        entry["packages"].append(package)
        _write_store(path, store)

    return _copy_entry(entry)


def list_trust(
    path: Path, *, backend: CryptoBackend | None = None
) -> list[dict[str, Any]]:
    """Tampilkan entri fingerprint, profil, dan package yang diizinkan"""

    store = load_trust_store(path, backend=backend)
    return [_copy_entry(entry) for entry in store["keys"]]


def remove_trust(
    path: Path,
    keyid: str,
    *,
    backend: CryptoBackend | None = None,
) -> None:
    """Hapus entri kunci berdasarkan keyid"""

    path = Path(path)
    store = load_trust_store(path, backend=backend)
    for index, entry in enumerate(store["keys"]):
        if entry["keyid"] == keyid:
            del store["keys"][index]
            _write_store(path, store)
            return
    raise TrustKeyNotFoundError(f"keyid tidak ditemukan: {keyid}")


__all__ = [
    "CryptoBackend",
    "TrustKeyNotFoundError",
    "add_trust",
    "list_trust",
    "load_trust_store",
    "remove_trust",
]
