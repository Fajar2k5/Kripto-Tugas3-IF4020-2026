from pathlib import Path
from typing import Any


def verify_release(
    *,
    artifact_path: Path,
    bundle_path: Path,
    trust_store_path: Path,
    expected_package: str,
    expected_version: str,
) -> Any:
    """Verifikasi artefak terhadap bundle dan trust store.

    Hasil akhir harus memakai ``VerificationStatus`` dan ``EXIT_CODES`` dari
    :mod:`sleman.errors`.
    """

    raise NotImplementedError("alur verify belum dibuat")


__all__ = ["verify_release"]
