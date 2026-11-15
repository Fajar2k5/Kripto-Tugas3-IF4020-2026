"""Alur verifikasi release dan hasilnya."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from . import crypto_backend
from .errors import EXIT_CODES, FormatError, VerificationStatus
from .formats import load_bundle, load_manifest
from .profiles import SUPPORTED_PROFILES
from .trust_store import CryptoBackend, parse_trust_store

_SIGNATURE_LENGTHS = {
    "rsa-pss-sha256": 384,
    "ecdsa-p256-sha256": 64,
    "ed25519": 64,
}


class VerificationBackend(CryptoBackend, Protocol):
    """Interface backend kriptografi untuk verifikasi"""

    def verify_signature(
        self,
        profile: str,
        public_key_object: Any,
        message: bytes,
        signature: bytes,
    ) -> bool:
        ...


@dataclass(frozen=True)
class VerificationResult:
    """Hasil verifikasi"""

    status: VerificationStatus
    message: str
    algorithm: str | None = None
    keyid: str | None = None
    package: str | None = None
    version: str | None = None

    @property
    def valid(self) -> bool:
        return self.status is VerificationStatus.OK

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.status]

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "status": self.status.value,
            "message": self.message,
            "algorithm": self.algorithm,
            "keyid": self.keyid,
            "package": self.package,
            "version": self.version,
        }


def _get_backend(backend: VerificationBackend | None) -> VerificationBackend:
    return cast(VerificationBackend, crypto_backend) if backend is None else backend


def _result(
    status: VerificationStatus,
    message: str,
    manifest: dict[str, Any] | None = None,
) -> VerificationResult:
    if manifest is None:
        return VerificationResult(status=status, message=message)
    return VerificationResult(
        status=status,
        message=message,
        algorithm=manifest["algorithm"],
        keyid=manifest["keyid"],
        package=manifest["package"],
        version=manifest["version"],
    )


def verify_release(
    *,
    artifact_path: Path,
    bundle_path: Path,
    trust_store_path: Path,
    expected_package: str,
    expected_version: str,
    backend: VerificationBackend | None = None,
) -> VerificationResult:
    """Verifikasi artefak terhadap bundle dan trust store."""

    artifact_path = Path(artifact_path)
    bundle_path = Path(bundle_path)
    trust_store_path = Path(trust_store_path)
    backend = _get_backend(backend)

    try:
        artifact_bytes = artifact_path.read_bytes()
        bundle_bytes = bundle_path.read_bytes()
        trust_store_bytes = trust_store_path.read_bytes()
    except OSError as exc:
        return _result(
            VerificationStatus.INPUT_ERROR,
            f"berkas masukan tidak dapat dibaca: {exc}",
        )

    try:
        manifest_bytes, signature = load_bundle(bundle_bytes)
        manifest = load_manifest(manifest_bytes)
    except FormatError as exc:
        return _result(
            VerificationStatus.FORMAT_ERROR,
            f"bundle/manifest tidak valid: {exc}",
        )

    try:
        trust_store = parse_trust_store(trust_store_bytes, backend=backend)
    except FormatError as exc:
        return _result(
            VerificationStatus.FORMAT_ERROR,
            f"trust store tidak valid: {exc}",
            dict(manifest),
        )

    algorithm = manifest["algorithm"]
    if algorithm not in SUPPORTED_PROFILES:
        return _result(
            VerificationStatus.UNSUPPORTED_ALGORITHM,
            "profil algoritma kriptografi tidak didukung",
            dict(manifest),
        )

    entry = next(
        (
            candidate
            for candidate in trust_store["keys"]
            if candidate["keyid"] == manifest["keyid"]
        ),
        None,
    )
    if entry is None:
        return _result(
            VerificationStatus.KEY_NOT_TRUSTED,
            "keyid tidak ditemukan di trust store",
            dict(manifest),
        )
    if entry["algorithm"] != algorithm:
        return _result(
            VerificationStatus.KEY_NOT_TRUSTED,
            "profil kunci tidak cocok dengan manifest",
            dict(manifest),
        )
    if expected_package not in entry["packages"]:
        return _result(
            VerificationStatus.KEY_NOT_TRUSTED,
            "kunci tidak diizinkan untuk package yang diminta",
            dict(manifest),
        )

    try:
        public_key, detected_profile, _spki_der = backend.validate_public_key(
            entry["public_key_pem"].encode("utf-8")
        )
    except (ValueError, TypeError) as exc:
        return _result(
            VerificationStatus.FORMAT_ERROR,
            f"kunci trust store tidak valid: {exc}",
            dict(manifest),
        )
    if detected_profile != algorithm:
        return _result(
            VerificationStatus.FORMAT_ERROR,
            "profil kunci trust store tidak sesuai",
            dict(manifest),
        )

    if len(signature) != _SIGNATURE_LENGTHS[algorithm]:
        return _result(
            VerificationStatus.INVALID_SIGNATURE,
            "panjang signature tidak sesuai",
            dict(manifest),
        )

    try:
        signature_valid = backend.verify_signature(
            algorithm,
            public_key,
            manifest_bytes,
            signature,
        )
    except (ValueError, TypeError):
        signature_valid = False
    if not signature_valid:
        return _result(
            VerificationStatus.INVALID_SIGNATURE,
            "signature tidak valid",
            dict(manifest),
        )

    if (
        manifest["package"] != expected_package
        or manifest["version"] != expected_version
        or manifest["artifact"]["name"] != artifact_path.name
    ):
        return _result(
            VerificationStatus.METADATA_MISMATCH,
            "metadata manifest tidak cocok dengan masukan",
            dict(manifest),
        )

    if (
        manifest["artifact"]["size"] != len(artifact_bytes)
        or manifest["artifact"]["sha256"] != hashlib.sha256(artifact_bytes).hexdigest()
    ):
        return _result(
            VerificationStatus.ARTIFACT_MISMATCH,
            "ukuran atau hash artefak tidak cocok",
            dict(manifest),
        )

    return _result(
        VerificationStatus.OK,
        "Tanda tangan dan artefak valid.",
        dict(manifest),
    )


__all__ = ["VerificationBackend", "VerificationResult", "verify_release"]
