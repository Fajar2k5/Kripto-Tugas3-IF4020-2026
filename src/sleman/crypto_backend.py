from typing import Any


def validate_public_key(public_key_pem: bytes) -> tuple[Any, str, bytes]:
    """Validasi kunci publik SPKI PEM dan kembalikan objek kunci/profil/DER.

    Hasil tuple: ``(public_key_object, profile, spki_der)``.
    """

    raise NotImplementedError("backend kriptografi belum tersedia")


def fingerprint(spki_der: bytes) -> str:
    """Kembalikan SHA-256 DER SPKI sebagai 64 karakter heksadesimal lowercase."""

    raise NotImplementedError("backend kriptografi belum tersedia")


def verify_signature(
    profile: str,
    public_key_object: Any,
    message: bytes,
    signature: bytes,
) -> bool:
    """Verifikasi signature atas byte pesan dengan profil yang diberikan.

    ``False`` berarti signature tidak valid, termasuk panjang/encoding yang
    salah. Kesalahan memuat kunci ditangani oleh ``validate_public_key``.
    """

    raise NotImplementedError("backend kriptografi belum tersedia")


__all__ = ["fingerprint", "validate_public_key", "verify_signature"]
