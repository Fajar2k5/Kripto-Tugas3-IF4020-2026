from collections.abc import Mapping
from pathlib import Path
from typing import Any


def load_trust_store(path: Path) -> Mapping[str, Any]:
    """Baca dan validasi trust store"""

    raise NotImplementedError("strict trust store parser belum dibuat")


def add_trust(path: Path, public_key_pem: bytes, package: str) -> Mapping[str, Any]:
    """Tambahkan izin package untuk sebuah kunci publik"""

    raise NotImplementedError("trust add belum dibuat")


def list_trust(path: Path) -> list[Mapping[str, Any]]:
    """Tampilkan entri fingerprint, profil, dan package yang diizinkan"""

    raise NotImplementedError("trust list belum dibuat")


def remove_trust(path: Path, keyid: str) -> None:
    """Hapus entri kunci berdasarkan keyid"""

    raise NotImplementedError("trust remove belum dibuat")


__all__ = ["add_trust", "list_trust", "load_trust_store", "remove_trust"]
