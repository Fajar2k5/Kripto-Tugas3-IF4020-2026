#!/usr/bin/env python3
"""Benchmark waktu SHA-256 untuk artefak"""


from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_SIZES = (1024, 1024 * 1024, 16 * 1024 * 1024)
DEFAULT_SAMPLES = 30
DEFAULT_WARMUP = 5


def _percentile_nearest_rank(values: list[int], percentile: float) -> int:
    if not values:
        raise ValueError("values tidak boleh kosong")
    if not 0 < percentile <= 1:
        raise ValueError("percentile harus di antara 0 dan 1")
    ordered = sorted(values)
    index = math.ceil(percentile * len(ordered)) - 1
    return ordered[max(0, index)]


def _artifact(size: int) -> bytes:
    if size < 0:
        raise ValueError("ukuran artefak tidak boleh negatif")
    pattern = b"IF4020-Sleman-hash-benchmark\n"
    repeats, remainder = divmod(size, len(pattern))
    return pattern * repeats + pattern[:remainder]


def _measure(payload: bytes, samples: int, warmup: int) -> list[int]:
    for _ in range(warmup):
        hashlib.sha256(payload).digest()

    durations: list[int] = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        hashlib.sha256(payload).digest()
        durations.append(time.perf_counter_ns() - start)
    return durations


def _cpu_model() -> str | None:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return None


def _environment() -> dict[str, Any]:
    uname = platform.uname()
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "system": uname.system,
        "release": uname.release,
        "machine": uname.machine,
        "processor": uname.processor,
        "cpu_model": _cpu_model(),
        "cpu_count": os.cpu_count(),
        "python": sys.version,
        "executable": sys.executable,
    }


def run(
    sizes: tuple[int, ...],
    samples: int,
    warmup: int,
) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    for size in sizes:
        payload = _artifact(size)
        digest = hashlib.sha256(payload).hexdigest()
        durations = _measure(payload, samples, warmup)
        artifacts.append(
            {
                "size_bytes": size,
                "sha256": digest,
                "samples_ns": durations,
                "sample_count": len(durations),
                "warmup_count": warmup,
                "median_ns": statistics.median(durations),
                "p95_ns": _percentile_nearest_rank(durations, 0.95),
                "median_ms": statistics.median(durations) / 1_000_000,
                "p95_ms": _percentile_nearest_rank(durations, 0.95) / 1_000_000,
            }
        )

    return {
        "benchmark": "hash-artifact",
        "method": {
            "timer": "time.perf_counter_ns",
            "hash": "SHA-256",
            "measurement": "hashing in-memory artifact bytes; I/O excluded",
            "percentile": "nearest-rank: ceil(p * n), posisi 1-based",
            "samples": samples,
            "warmup": warmup,
        },
        "environment": _environment(),
        "artifacts": artifacts,
    }


def _summary(result: dict[str, Any]) -> str:
    lines = ["Benchmark SHA-256 artefak"]
    for artifact in result["artifacts"]:
        lines.append(
            f"  {artifact['size_bytes']:>10} byte: "
            f"median={artifact['median_ms']:.3f} ms, "
            f"P95={artifact['p95_ms']:.3f} ms"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes",
        nargs="+",
        type=int,
        default=list(DEFAULT_SIZES),
        help="Ukuran artefak dalam byte.",
    )
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/results/hash-artifact.json"),
    )
    args = parser.parse_args(argv)

    if args.samples <= 0:
        parser.error("--samples harus lebih dari 0")
    if args.warmup < 0:
        parser.error("--warmup tidak boleh negatif")
    if any(size < 0 for size in args.sizes):
        parser.error("--sizes tidak boleh negatif")

    result = run(tuple(args.sizes), args.samples, args.warmup)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(_summary(result))
    print(f"Raw data: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
