from collections.abc import Mapping
from typing import Any

MAX_MANIFEST_BYTES = 16 * 1024
MAX_BUNDLE_BYTES = 64 * 1024


def load_bundle(data: bytes) -> tuple[bytes, bytes]:
    """Kembalikan byte manifest asli dan byte signature dari bundle."""

    raise NotImplementedError("strict bundle parser belum dibuat")


def load_manifest(data: bytes) -> Mapping[str, Any]:
    """Parse dan validasi manifest, lalu kembalikan nilai terstruktur.
    """

    raise NotImplementedError("strict manifest parser belum dibuat")


def serialize_manifest_canonical(manifest: Mapping[str, Any]) -> bytes:
    """Serialisasi manifest sesuai aturan canonical."""

    raise NotImplementedError("canonical serializer belum dibuat")


__all__ = [
    "MAX_BUNDLE_BYTES",
    "MAX_MANIFEST_BYTES",
    "load_bundle",
    "load_manifest",
    "serialize_manifest_canonical",
]
