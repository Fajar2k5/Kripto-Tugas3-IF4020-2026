"""Parser strict untuk bundle dan manifest."""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from typing import Any

from .errors import FormatError

MAX_MANIFEST_BYTES = 16 * 1024
MAX_BUNDLE_BYTES = 64 * 1024
MAX_ARTIFACT_SIZE = 9007199254740991

_MANIFEST_SCHEMA = "minisign-manifest/v1"
_BUNDLE_SCHEMA = "minisign-bundle/v1"
_MANIFEST_FIELDS = frozenset(
    {"schema", "package", "version", "algorithm", "keyid", "artifact"}
)
_ARTIFACT_FIELDS = frozenset({"name", "size", "sha256"})
_BUNDLE_FIELDS = frozenset({"schema", "manifest_b64", "signature_b64"})

_PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}", re.ASCII)
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", re.ASCII)
_ARTIFACT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", re.ASCII)
_HEX64_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)


def _reject_constant(value: str) -> None:
    raise FormatError(f"nilai JSON tidak standar: {value}")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FormatError(f"field duplikat: {key}")
        result[key] = value
    return result


def parse_json_object(data: bytes, *, max_bytes: int, label: str) -> dict[str, Any]:
    """Parse satu objek JSON dengan batas ukuran."""

    if not isinstance(data, bytes):
        raise FormatError(f"{label} harus berupa byte")
    if len(data) > max_bytes:
        raise FormatError(f"{label} melebihi batas {max_bytes} byte")
    if data.startswith(b"\xef\xbb\xbf"):
        raise FormatError(f"{label} tidak boleh memakai BOM")

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FormatError(f"{label} bukan UTF-8 yang valid") from exc

    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except FormatError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise FormatError(f"{label} bukan JSON yang valid: {exc}") from exc

    if not isinstance(value, dict):
        raise FormatError(f"{label} harus berupa objek JSON")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], label: str
) -> None:
    actual = set(value)
    missing = expected - actual
    extra = actual - expected
    if missing:
        raise FormatError(f"{label} kehilangan field: {', '.join(sorted(missing))}")
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


def _validate_manifest(manifest: Mapping[str, Any]) -> None:
    _require_exact_fields(manifest, _MANIFEST_FIELDS, "manifest")

    if _require_string(manifest["schema"], "manifest.schema") != _MANIFEST_SCHEMA:
        raise FormatError("manifest.schema tidak dikenal")

    _require_pattern(manifest["package"], _PACKAGE_RE, "manifest.package")
    _require_pattern(manifest["version"], _VERSION_RE, "manifest.version")

    algorithm = _require_string(manifest["algorithm"], "manifest.algorithm")
    if not all(0x20 <= ord(char) <= 0x7E for char in algorithm):
        raise FormatError("manifest.algorithm harus berupa ASCII yang dapat dicetak")

    _require_pattern(manifest["keyid"], _HEX64_RE, "manifest.keyid")

    artifact = manifest["artifact"]
    if not isinstance(artifact, dict):
        raise FormatError("manifest.artifact harus berupa objek")
    _require_exact_fields(artifact, _ARTIFACT_FIELDS, "manifest.artifact")

    _require_pattern(
        artifact["name"], _ARTIFACT_NAME_RE, "manifest.artifact.name"
    )

    size = artifact["size"]
    if type(size) is not int:
        raise FormatError("manifest.artifact.size harus berupa integer")
    if not 0 <= size <= MAX_ARTIFACT_SIZE:
        raise FormatError("manifest.artifact.size di luar rentang")

    _require_pattern(artifact["sha256"], _HEX64_RE, "manifest.artifact.sha256")


def _serialize_manifest(manifest: Mapping[str, Any]) -> bytes:
    ordered: dict[str, Any] = {
        "schema": manifest["schema"],
        "package": manifest["package"],
        "version": manifest["version"],
        "algorithm": manifest["algorithm"],
        "keyid": manifest["keyid"],
        "artifact": {
            "name": manifest["artifact"]["name"],
            "size": manifest["artifact"]["size"],
            "sha256": manifest["artifact"]["sha256"],
        },
    }
    try:
        encoded = json.dumps(
            ordered,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise FormatError("manifest tidak dapat di-serialize") from exc
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise FormatError(f"manifest melebihi batas {MAX_MANIFEST_BYTES} byte")
    return encoded


def serialize_manifest_canonical(manifest: Mapping[str, Any]) -> bytes:
    """Serialisasi manifest sesuai urutan dan aturan canonical."""

    _validate_manifest(manifest)
    return _serialize_manifest(manifest)


def load_manifest(data: bytes) -> Mapping[str, Any]:
    """Parse, validasi, dan periksa canonical serialization manifest."""

    manifest = parse_json_object(
        data,
        max_bytes=MAX_MANIFEST_BYTES,
        label="manifest",
    )
    _validate_manifest(manifest)

    if _serialize_manifest(manifest) != data:
        raise FormatError("manifest tidak menggunakan canonical serialization")

    return manifest


def _decode_base64(value: str, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FormatError(f"{label} bukan Base64 yang valid") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise FormatError(f"{label} bukan Base64 canonical")
    return decoded


def load_bundle(data: bytes) -> tuple[bytes, bytes]:
    """Parse bundle dan kembalikan byte manifest serta byte signature."""

    bundle = parse_json_object(
        data,
        max_bytes=MAX_BUNDLE_BYTES,
        label="bundle",
    )
    _require_exact_fields(bundle, _BUNDLE_FIELDS, "bundle")

    if _require_string(bundle["schema"], "bundle.schema") != _BUNDLE_SCHEMA:
        raise FormatError("bundle.schema tidak dikenal")

    manifest_b64 = _require_string(bundle["manifest_b64"], "bundle.manifest_b64")
    signature_b64 = _require_string(bundle["signature_b64"], "bundle.signature_b64")

    manifest = _decode_base64(manifest_b64, "bundle.manifest_b64")
    signature = _decode_base64(signature_b64, "bundle.signature_b64")

    if len(manifest) > MAX_MANIFEST_BYTES:
        raise FormatError(f"manifest melebihi batas {MAX_MANIFEST_BYTES} byte")
    load_manifest(manifest)

    return manifest, signature


__all__ = [
    "MAX_ARTIFACT_SIZE",
    "MAX_BUNDLE_BYTES",
    "MAX_MANIFEST_BYTES",
    "load_bundle",
    "load_manifest",
    "parse_json_object",
    "serialize_manifest_canonical",
]
