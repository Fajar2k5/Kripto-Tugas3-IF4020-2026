"""Entry point CLI Sleman"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .errors import FormatError, VerificationStatus
from .profiles import SUPPORTED_PROFILES
from .signing import keygen, sign_release
from .trust_store import (
    TrustKeyNotFoundError,
    add_trust,
    list_trust,
    remove_trust,
)
from .verification import (
    VerificationBackend,
    VerificationResult,
    verify_release,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sleman",
        description=(
            "Menandatangani dan memverifikasi software release menggunakan "
            "manifest, bundle, dan trust store."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="Generate pasangan kunci.")
    keygen.add_argument("--algorithm", required=True, choices=SUPPORTED_PROFILES)
    keygen.add_argument("--out", required=True)

    sign = subparsers.add_parser("sign", help="Tandatangani artefak.")
    sign.add_argument("--file", required=True)
    sign.add_argument("--package", required=True)
    sign.add_argument("--version", required=True)
    sign.add_argument("--key", required=True)
    sign.add_argument("--out", required=True)

    verify = subparsers.add_parser("verify", help="Verifikasi artefak.")
    verify.add_argument("--file", required=True)
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--trust-store", required=True)
    verify.add_argument("--package", required=True)
    verify.add_argument("--version", required=True)
    verify.add_argument("--json", action="store_true", dest="json_output")

    trust = subparsers.add_parser("trust", help="Kelola trust store.")
    trust_subparsers = trust.add_subparsers(dest="trust_command", required=True)

    trust_add = trust_subparsers.add_parser("add", help="Tambahkan izin package.")
    trust_add.add_argument("--key", required=True)
    trust_add.add_argument("--package", required=True)
    trust_add.add_argument("--store", required=True)

    trust_list = trust_subparsers.add_parser("list", help="Tampilkan trust store.")
    trust_list.add_argument("--store", required=True)

    trust_remove = trust_subparsers.add_parser("remove", help="Hapus entri kunci.")
    trust_remove.add_argument("--keyid", required=True)
    trust_remove.add_argument("--store", required=True)

    return parser


def _verify_command(
    args: argparse.Namespace,
    backend: VerificationBackend | None,
) -> int:
    try:
        result = verify_release(
            artifact_path=Path(args.file),
            bundle_path=Path(args.bundle),
            trust_store_path=Path(args.trust_store),
            expected_package=args.package,
            expected_version=args.version,
            backend=backend,
        )
    except NotImplementedError:
        result = VerificationResult(
            status=VerificationStatus.INPUT_ERROR,
            message="backend kriptografi belum tersedia",
        )

    if args.json_output:
        print(
            json.dumps(
                result.as_dict(),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        if not result.valid:
            print(f"{result.status.value}: {result.message}", file=sys.stderr)
    else:
        print(f"{result.status.value}: {result.message}")
        if result.algorithm is not None:
            print(f"algorithm: {result.algorithm}")
            print(f"keyid: {result.keyid}")
            print(f"package: {result.package}")
            print(f"version: {result.version}")

    return result.exit_code


def _trust_command(
    args: argparse.Namespace,
    backend: VerificationBackend | None,
) -> int:
    command = f"trust {args.trust_command}"
    try:
        if args.trust_command == "add":
            try:
                public_key = Path(args.key).read_bytes()
            except OSError as exc:
                raise OSError(f"kunci tidak dapat dibaca: {exc}") from exc
            entry = add_trust(
                Path(args.store),
                public_key,
                args.package,
                backend=backend,
            )
            print(f"keyid: {entry['keyid']}")
            print(f"algorithm: {entry['algorithm']}")
            print(f"packages: {', '.join(entry['packages'])}")
        elif args.trust_command == "list":
            entries = list_trust(Path(args.store), backend=backend)
            for entry in entries:
                print(
                    f"{entry['keyid']} {entry['algorithm']} "
                    f"{', '.join(entry['packages'])}"
                )
        else:
            remove_trust(Path(args.store), args.keyid, backend=backend)
            print(f"keyid dihapus: {args.keyid}")
    except NotImplementedError:
        print(f"sleman {command}: backend kriptografi belum tersedia", file=sys.stderr)
        return 2
    except (OSError, FormatError, TrustKeyNotFoundError) as exc:
        print(f"sleman {command}: {exc}", file=sys.stderr)
        return 2
    return 0


def _is_verify_json(argv: Sequence[str]) -> bool:
    return bool(argv) and argv[0] == "verify" and "--json" in argv


def main(
    argv: Sequence[str] | None = None,
    backend: VerificationBackend | None = None,
) -> int:
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)

    try:
        args = parser.parse_args(arguments)
    except SystemExit as exc:
        if exc.code == 0:
            raise
        if _is_verify_json(arguments):
            result = VerificationResult(
                status=VerificationStatus.INPUT_ERROR,
                message="pemakaian perintah tidak valid",
            )
            print(
                json.dumps(
                    result.as_dict(),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
            print(f"{result.status.value}: {result.message}", file=sys.stderr)
        return 2

    if args.command == "verify":
        return _verify_command(args, backend)
    if args.command == "trust":
        return _trust_command(args, backend)
    try:
        if args.command == "keygen":
            print(f"keyid: {keygen(args.algorithm, Path(args.out))}")
        else:
            sign_release(Path(args.file), args.package, args.version, Path(args.key), Path(args.out))
    except (OSError, FormatError) as exc:
        print(f"sleman {args.command}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
