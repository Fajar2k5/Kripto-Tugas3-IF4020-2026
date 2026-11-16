from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from sleman.cli import main


class CliContractTests(unittest.TestCase):
    def test_version_is_available(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertRegex(stdout.getvalue(), r"^sleman \d+\.\d+\.\d+\n$")

    def test_help_is_available(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("verify", stdout.getvalue())

    def test_missing_argument_with_json_returns_input_error(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main(["verify", "--file", "hello.txt", "--json"])
        self.assertEqual(exit_code, 2)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "INPUT_ERROR")
        self.assertIn("INPUT_ERROR", stderr.getvalue())

    def test_trust_list_missing_store_reports_error(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            exit_code = main(["trust", "list", "--store", "missing-trust.json"])
        self.assertEqual(exit_code, 2)
        self.assertIn("sleman trust list", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
