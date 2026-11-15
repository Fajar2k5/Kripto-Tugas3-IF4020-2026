"""Daftar status dan exit code"""

from enum import StrEnum


class VerificationStatus(StrEnum):
    """Status hasil verify"""

    INPUT_ERROR = "INPUT_ERROR"
    FORMAT_ERROR = "FORMAT_ERROR"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    KEY_NOT_TRUSTED = "KEY_NOT_TRUSTED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    METADATA_MISMATCH = "METADATA_MISMATCH"
    ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"
    OK = "OK"


class FormatError(ValueError):
    """Input tidak sesuai format."""


EXIT_CODES: dict[VerificationStatus, int] = {
    VerificationStatus.OK: 0,
    VerificationStatus.INPUT_ERROR: 2,
    VerificationStatus.FORMAT_ERROR: 1,
    VerificationStatus.UNSUPPORTED_ALGORITHM: 1,
    VerificationStatus.KEY_NOT_TRUSTED: 1,
    VerificationStatus.INVALID_SIGNATURE: 1,
    VerificationStatus.METADATA_MISMATCH: 1,
    VerificationStatus.ARTIFACT_MISMATCH: 1,
}

__all__ = ["EXIT_CODES", "FormatError", "VerificationStatus"]
