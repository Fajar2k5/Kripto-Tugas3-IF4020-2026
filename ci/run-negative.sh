#!/usr/bin/env bash
set -euo pipefail

: "${SLEMAN_IMAGE:?SLEMAN_IMAGE belum diset}"
: "${SLEMAN_DEMO_KEY_ED25519:?secret kunci demo ed25519 belum diset}"

root="$(pwd)"
out="$root/ci-out/negative"
temp_root="${RUNNER_TEMP:-$root/ci-out/tmp}"
mkdir -p "$temp_root" "$root/dist"
rm -rf "$out"
mkdir -p "$out/c01-sign" "$out/c02" "$out/c03" "$out/c04"

key_file="$temp_root/sleman-negative-signing.pem"
umask 077
printf '%s\n' "$SLEMAN_DEMO_KEY_ED25519" > "$key_file"
chmod 600 "$key_file"
trap 'rm -f "$key_file"' EXIT

printf 'Sleman consumer demo artifact\n' > "$root/dist/demo-app.txt"
printf 'image=%s\n' "$SLEMAN_IMAGE" > "$out/image.txt"

docker run --rm --network none \
  --user "$(id -u):$(id -g)" \
  -v "$root/dist:/input:ro" \
  -v "$out/c01-sign:/output" \
  -v "$key_file:/run/signing.key.pem:ro" \
  "$SLEMAN_IMAGE" sign \
  --file /input/demo-app.txt \
  --package demo-app \
  --version 1.0.0 \
  --key /run/signing.key.pem \
  --out /output/release.json

mkdir -p "$out/c02-input"
cp "$root/dist/demo-app.txt" "$out/c02-input/demo-app.txt"
python3 - "$out/c02-input/demo-app.txt" <<'PY'
import sys

path = sys.argv[1]
with open(path, "rb") as stream:
    data = bytearray(stream.read())
data[0] ^= 1
with open(path, "wb") as stream:
    stream.write(data)
PY

verify_expect() {
  local expected_code="$1"
  local expected_status="$2"
  local label="$3"
  local input_dir="$4"
  local trust_file="$5"
  local output_dir="$6"
  local artifact_path="$7"

  mkdir -p "$output_dir"
  set +e
  docker run --rm --network none \
    --user "$(id -u):$(id -g)" \
    -v "$input_dir:/input:ro" \
    -v "$out/c01-sign:/output:ro" \
    -v "$trust_file:/trust.json:ro" \
    "$SLEMAN_IMAGE" verify \
    --file "/input/$artifact_path" \
    --bundle /output/release.json \
    --trust-store /trust.json \
    --package demo-app \
    --version 1.0.0 \
    --json > "$output_dir/verification.json" 2> "$output_dir/stderr.txt"
  local code=$?
  set -e

  if [ "$code" -ne "$expected_code" ]; then
    echo "$label: exit code $code, diharapkan $expected_code" >&2
    exit 1
  fi

  python3 - "$output_dir/verification.json" "$expected_status" "$label" <<'PY'
import json
import sys

path, expected, label = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as stream:
    result = json.load(stream)
if result.get("valid") is not False or result.get("status") != expected:
    raise SystemExit(f"{label}: hasil tidak sesuai: {result}")
print(f"{label}: {expected}")
PY
}

verify_expect 1 ARTIFACT_MISMATCH "C02" \
  "$out/c02-input" "$root/ci/trust/ed25519.json" "$out/c02" "demo-app.txt"
verify_expect 1 KEY_NOT_TRUSTED "C03" \
  "$root/dist" "$root/ci/trust/empty.json" "$out/c03" "demo-app.txt"
verify_expect 2 INPUT_ERROR "C04" \
  "$root/dist" "$root/ci/trust/ed25519.json" "$out/c04" "missing.txt"

if find "$out" -name published.txt -print -quit | grep -q .; then
  echo "penanda publikasi tidak boleh ada pada skenario negatif" >&2
  exit 1
fi

echo "C02-C04: penolakan sesuai harapan; tidak ada penanda publikasi"
