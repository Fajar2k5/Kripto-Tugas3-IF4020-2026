"""Pengukuran keygen dan sign untuk artefak yang sama dengan benchmark hash."""

import hashlib
import json
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from time import perf_counter_ns

import cryptography
from cryptography.hazmat.primitives import serialization as ser
from benchmark_hash import DEFAULT_SIZES, _artifact, _environment, _percentile_nearest_rank
from sleman import crypto_backend as crypto
from sleman.formats import load_bundle
from sleman.profiles import SUPPORTED_PROFILES
from sleman.signing import keygen, make_manifest


def measure(operation, count, warmup):
    for _ in range(warmup):
        operation()
    samples = []
    for _ in range(count):
        start = perf_counter_ns()
        operation()
        samples.append(perf_counter_ns() - start)
    return {"samples_ns": samples, "median_ms": statistics.median(samples) / 1e6,
            "p95_ms": _percentile_nearest_rank(samples, .95) / 1e6}


def run(root):
    results = {}
    for profile in SUPPORTED_PROFILES:
        generation = measure(lambda: crypto.generate_key(profile), 5, 0)
        keygen(profile, root / profile)
        path = root / (profile + ".key.pem")
        key = crypto.load_private_key(path.read_bytes())
        results[profile] = {
            "keygen": generation,
            "private_der_bytes": len(key.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8,
                                                       ser.NoEncryption())),
            "public_der_bytes": len(key.public_key().public_bytes(ser.Encoding.DER, crypto.SPKI)),
            "artifacts": [],
        }
        for size in DEFAULT_SIZES:
            artifact = root / f"artifact-{size}.bin"
            payload = _artifact(size)
            artifact.write_bytes(payload)
            manifest = make_manifest(key, artifact, "demo", "1.0")
            output = root / f"{profile}-{size}.json"
            command = [sys.executable, "-m", "sleman", "sign", "--file", str(artifact),
                       "--key", str(path), "--out", str(output), "--package", "demo",
                       "--version", "1.0"]
            signing = measure(lambda: crypto.sign_message(key, manifest), 30, 5)
            sequence = iter(range(35))
            def run_cli():
                command[command.index("--out") + 1] = str(root / f"{profile}-{size}-{next(sequence)}.json")
                subprocess.run(command, check=True)

            cli = measure(run_cli, 30, 5)
            output = root / f"{profile}-{size}-34.json"
            stored, sig = load_bundle(output.read_bytes())
            assert stored == manifest and crypto.verify_signature(profile, key.public_key(), stored, sig)
            results[profile]["artifacts"].append({
                "size_bytes": size, "sha256": hashlib.sha256(payload).hexdigest(),
                "sign": signing, "cli_sign": cli, "signature_bytes": len(sig),
                "bundle_bytes": output.stat().st_size,
            })
    return results


if __name__ == "__main__":
    env = _environment()
    env.pop("executable")
    env["cryptography"] = cryptography.__version__
    with tempfile.TemporaryDirectory() as temp:
        result = run(Path(temp))
    output = Path(__file__).parent / "results" / "sign.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps({"environment": env, "profiles": result}, indent=2) + "\n")
    print(output)
