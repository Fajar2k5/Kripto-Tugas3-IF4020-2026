#!/usr/bin/env python3
"""Benchmark verifikasi kriptografis dan verify end-to-end CLI."""

from __future__ import annotations

import json
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from time import perf_counter_ns

import cryptography

from benchmark_hash import (
    DEFAULT_SIZES,
    _artifact,
    _environment,
    _percentile_nearest_rank,
)
from sleman import crypto_backend as crypto
from sleman.formats import load_bundle
from sleman.profiles import SUPPORTED_PROFILES
from sleman.signing import keygen, sign_release
from sleman.trust_store import add_trust


def measure(operation, count: int, warmup: int) -> dict:
    for _ in range(warmup):
        operation()
    samples = []
    for _ in range(count):
        start = perf_counter_ns()
        operation()
        samples.append(perf_counter_ns() - start)
    return {
        "samples_ns": samples,
        "median_ms": statistics.median(samples) / 1e6,
        "p95_ms": _percentile_nearest_rank(samples, 0.95) / 1e6,
    }


def run(root: Path) -> dict:
    trust_path = root / "trust.json"
    results = {}

    for profile in SUPPORTED_PROFILES:
        keygen(profile, root / profile)
        key_path = root / f"{profile}.key.pem"
        public_pem = root / f"{profile}.pub.pem"
        add_trust(trust_path, public_pem.read_bytes(), "demo", backend=crypto)
        public_key, detected_profile, _ = crypto.validate_public_key(public_pem.read_bytes())
        assert detected_profile == profile

        profile_result = {"artifacts": []}
        for size in DEFAULT_SIZES:
            artifact = root / f"artifact-{size}.bin"
            artifact.write_bytes(_artifact(size))
            bundle_path = root / f"{profile}-{size}.json"
            sign_release(artifact, "demo", "1.0", key_path, bundle_path)
            manifest, signature = load_bundle(bundle_path.read_bytes())

            primitive = measure(
                lambda: crypto.verify_signature(
                    profile, public_key, manifest, signature
                ),
                30,
                5,
            )

            command = [
                sys.executable,
                "-m",
                "sleman",
                "verify",
                "--file",
                str(artifact),
                "--bundle",
                str(bundle_path),
                "--trust-store",
                str(trust_path),
                "--package",
                "demo",
                "--version",
                "1.0",
                "--json",
            ]
            cli = measure(
                lambda: subprocess.run(
                    command,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                ),
                30,
                5,
            )

            profile_result["artifacts"].append(
                {
                    "size_bytes": size,
                    "verify": primitive,
                    "cli_verify": cli,
                }
            )
        results[profile] = profile_result

    return results


if __name__ == "__main__":
    environment = _environment()
    environment.pop("executable", None)
    environment["cryptography"] = cryptography.__version__
    with tempfile.TemporaryDirectory() as temp:
        result = run(Path(temp))
    output = Path(__file__).parent / "results" / "verify.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "benchmark": "verify",
                "method": {
                    "verify": "crypto_backend.verify_signature atas manifest",
                    "cli_verify": "subprocess sleman verify --json, termasuk proses Python, I/O, parsing, hashing, dan output",
                    "samples": 30,
                    "warmup": 5,
                    "timer": "time.perf_counter_ns",
                },
                "environment": environment,
                "profiles": result,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(output)
