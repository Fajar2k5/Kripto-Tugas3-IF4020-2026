"""Entry point CLI Sleman"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .profiles import SUPPORTED_PROFILES


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

    for command_parser in (
        keygen,
        sign,
        verify,
        trust_add,
        trust_list,
        trust_remove,
    ):
        command_parser.set_defaults(handler=_command_not_implemented)

    return parser


def _command_not_implemented(args: argparse.Namespace) -> int:
    command = "trust " + args.trust_command if args.command == "trust" else args.command
    print(
        f"sleman {command}: placeholder",
        file=sys.stderr,
    )
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = args.handler
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
