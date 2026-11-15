"""Sleman: Penandatanganan dan verifikasi software release"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sleman")
except PackageNotFoundError:
    # Dipakai saat menjalankan dari checkout tanpa instalasi package.
    __version__ = "0.1.0"

__all__ = ["__version__"]
