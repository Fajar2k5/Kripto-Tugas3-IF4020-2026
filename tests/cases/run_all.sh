#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
mkdir -p tests/cases/results
uv run pytest -v "$@" | tee tests/cases/results/latest.txt
