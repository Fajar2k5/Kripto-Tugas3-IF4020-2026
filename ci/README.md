# Consumer CI/CD

Workflow [`.github/workflows/consumer-release-gate.yml`](../.github/workflows/consumer-release-gate.yml)
menjalankan C01-C05 menggunakan image rilis Sleman.

## Image yang dipakai

```text
ghcr.io/orvin14/kripto-tugas3-if4020-2026@sha256:6635e7dbf5b757ba0c8c491adbeca8b7bacf668361c0590d4b3cce18f26c3404
```

Referensi dikunci dengan digest, bukan versi/tag.

## Trust store

Trust store berada di `ci/trust/`:

| Profil | File | Fingerprint |
|---|---|---|
| RSA-PSS | `ci/trust/rsa-pss-sha256.json` | `8d8cad304fcba64ef0caeed38d72b5946e7c929d591221d9f2885bd04e791b85` |
| ECDSA P-256 | `ci/trust/ecdsa-p256-sha256.json` | `6114a1cc8fe59aec81ae7bc4bf80e2607f283e0367e20f740365369eb729815e` |
| Ed25519 | `ci/trust/ed25519.json` | `fd6c035ed72207d17423c48df58b83afc1e39760d93c1e45fec110707a15a374` |
| Kosong | `ci/trust/empty.json` | — |

Semua trust store mengizinkan package `demo-app`.

## Secret yang diperlukan

```text
SLEMAN_DEMO_KEY_RSA_PSS_SHA256
SLEMAN_DEMO_KEY_ECDSA_P256_SHA256
SLEMAN_DEMO_KEY_ED25519
```

Jika kunci dirotasi, buat trust store baru dari public key yang sesuai dengan:

```sh
uv run sleman trust add --key path/to/new.pub.pem --package demo-app \
  --store ci/trust/<profil>.json
```

## Menjalankan workflow

1. Tambahkan ketiga secret melalui GitHub repository settings.
2. Buka Actions → **Consumer release gate C01-C05** → **Run workflow**.
3. Unduh artifact `c01-*`, `c02-c04-negative`, dan `c05-container` sebagai bukti.

Workflow hanya dipicu manual agar tidak menandatangani release pada setiap push. Jika
ingin dijalankan otomatis, tambahkan trigger setelah secret dan kebijakan repository
disiapkan.

## Cakupan skenario

| Job | Skenario |
|---|---|
| `c01` | Tiga profil: sign → verify → `published.txt` hanya jika verify OK |
| `negative` | C02 artefak diubah, C03 trust store kosong, C04 artefak hilang |
| `c05` | UID/GID runner, tanpa TTY, `--network none` |

Skenario negatif tidak memakai `continue-on-error` atau `|| true`. Script menangkap exit
code, membandingkannya dengan nilai yang diharapkan, lalu memeriksa status JSON. Workflow
baru berhasil jika penolakan benar-benar terjadi dan tidak ada `published.txt`.

## Menjalankan lokal

Private key dapat diberikan lewat environment variable, misalnya:

```sh
export SLEMAN_IMAGE='ghcr.io/orvin14/kripto-tugas3-if4020-2026@sha256:6635e7dbf5b757ba0c8c491adbeca8b7bacf668361c0590d4b3cce18f26c3404'
export SLEMAN_DEMO_KEY_ED25519="$(cat /path/ke/ed25519.key.pem)"
bash ci/run-c01.sh ed25519
bash ci/run-negative.sh
```

Keluaran berada di `ci-out/`.
