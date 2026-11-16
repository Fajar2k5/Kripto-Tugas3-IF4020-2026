#!/usr/bin/env bash
set -euo pipefail

profile="${1:?profil diperlukan}"
: "${SLEMAN_IMAGE:?SLEMAN_IMAGE belum diset}"

case "$profile" in
  rsa-pss-sha256) key_value="${SLEMAN_DEMO_KEY_RSA_PSS_SHA256:-}" ;;
  ecdsa-p256-sha256) key_value="${SLEMAN_DEMO_KEY_ECDSA_P256_SHA256:-}" ;;
  ed25519) key_value="${SLEMAN_DEMO_KEY_ED25519:-}" ;;
  *) echo "profil tidak dikenal: $profile" >&2; exit 2 ;;
esac
: "${key_value:?secret kunci demo untuk $profile belum diset}"

root="$(pwd)"
out="$root/ci-out/$profile"
temp_root="${RUNNER_TEMP:-$root/ci-out/tmp}"
mkdir -p "$temp_root" "$root/dist" "$out"
rm -rf "$out"
mkdir -p "$out"

key_file="$temp_root/sleman-signing-$profile.pem"
umask 077
printf '%s\n' "$key_value" > "$key_file"
chmod 600 "$key_file"
trap 'rm -f "$key_file"' EXIT

printf 'Sleman consumer demo artifact\n' > "$root/dist/demo-app.txt"
printf 'image=%s\n' "$SLEMAN_IMAGE" > "$out/image.txt"

docker run --rm --network none \
  --user "$(id -u):$(id -g)" \
  -v "$root/dist:/input:ro" \
  -v "$out:/output" \
  -v "$key_file:/run/signing.key.pem:ro" \
  "$SLEMAN_IMAGE" sign \
  --file /input/demo-app.txt \
  --package demo-app \
  --version 1.0.0 \
  --key /run/signing.key.pem \
  --out /output/release.json

if ! docker run --rm --network none \
  --user "$(id -u):$(id -g)" \
  -v "$root/dist:/input:ro" \
  -v "$out:/output:ro" \
  -v "$root/ci/trust/$profile.json:/trust.json:ro" \
  "$SLEMAN_IMAGE" verify \
  --file /input/demo-app.txt \
  --bundle /output/release.json \
  --trust-store /trust.json \
  --package demo-app \
  --version 1.0.0 \
  --json > "$out/verification.json" 2> "$out/stderr.txt"; then
  echo "C01 verify gagal untuk $profile" >&2
  if [ -f "$out/stderr.txt" ]; then
    cat "$out/stderr.txt" >&2
  fi
  exit 1
fi

python3 - "$out/verification.json" "$profile" <<'PY'
import json
import sys

path, profile = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as stream:
    result = json.load(stream)
if result.get("valid") is not True or result.get("status") != "OK":
    raise SystemExit(f"hasil verify tidak OK: {result}")
if result.get("algorithm") != profile:
    raise SystemExit(f"profil tidak cocok: {result}")
print(f"C01 {profile}: OK")
PY

printf 'published version 1.0.0\n' > "$out/published.txt"
