# Sleman

Sleman menandatangani artefak rilis dan memverifikasinya terhadap paket, versi, dan kunci penerbit dalam trust store lokal. CLI memerlukan Python 3.12+ dan pyca/cryptography. OpenSSL CLI digunakan untuk pengujian.

## Menjalankan CLI

Dari direktori repositori, jalankan contoh berikut sekali di direktori output yang kosong. File README dipakai sebagai artefak untuk contoh.

```sh
uv sync --locked
uv run sleman keygen --algorithm ed25519 --out keys/publisher
uv run sleman trust add --key keys/publisher.pub.pem --package contoh-app --store trust.json
uv run sleman sign --file README.md --package contoh-app --version 1.0.0 --key keys/publisher.key.pem --out release.json
uv run sleman verify --file README.md --bundle release.json --trust-store trust.json --package contoh-app --version 1.0.0 --json
uv run sleman trust list --store trust.json
uv run sleman trust remove --keyid <fingerprint-dari-keygen> --store trust.json
```

Kunci publik memakai SPKI PEM. Fingerprint adalah SHA-256 DER SPKI ditulis dalam 64 digit heksadesimal.

## Implementasi penandatanganan

`sign` membaca berkas sebagai byte dalam potongan 1 MiB. Selama pembacaan, Sleman menghitung ukuran dan SHA-256. Nama artefak berasal dari basename. Serializer memvalidasi metadata dan menghasilkan JSON UTF-8 dalam urutan `schema, package, version, algorithm, keyid, artifact`, dengan urutan `name, size, sha256` untuk artefak. Sleman menandatangani byte manifest tersebut. Bundle menyimpan schema, manifest, dan tanda tangan dalam dua field Base64 standar berpading sesuai kebutuhan. Batas manifest 16 KiB dan bundle 64 KiB. Keluaran yang sudah ada menghasilkan exit code 2.

| Profil | Pembangkitan dan operasi pyca/cryptography | Encoding tanda tangan |
|---|---|---|
| rsa-pss-sha256 | `rsa.generate_private_key(65537, 3072)`, PSS dengan SHA-256, MGF1-SHA-256, salt acak 32 byte | 384 byte |
| ecdsa-p256-sha256 | `ec.generate_private_key(SECP256R1())`, ECDSA SHA-256 dengan nonce deterministik RFC 6979 | Pasangan DER dari library dikonversi ke dua integer big-endian masing-masing 32 byte |
| ed25519 | `Ed25519PrivateKey.generate()`, PureEdDSA atas byte manifest langsung | 64 byte |

RSA dan ECDSA menghitung hash manifest di dalam operasi tanda tangan. Verifier menerima kembali byte manifest asli dan memakai parameter yang sama. Dokumentasi tersedia untuk [RSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/), [ECDSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/), dan [Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).

## Pengujian dan benchmark

```sh
make test
uv run pytest -q
make benchmark-hash
uv run python benchmarks/benchmark_sign.py
make benchmark-verify
```

CLI membuat pasangan kunci sementara untuk pengujian dan memeriksa exit code serta status JSON.

| Uji | Masukan dan hasil yang diharapkan | Hasil lokal |
|---|---|---|
| U01 | Teks dengan CRLF, byte 0–255, berkas kosong × 3 algoritma kriptografi. Ukuran dan hash cocok, verifikasi OK | 9 kombinasi PASS |
| U14 | Dua penandatanganan per kombinasi U01. RSA berbeda karena salt acak. ECDSA RFC 6979 dan Ed25519 identik untuk pesan dan kunci yang sama | Pola sesuai untuk 9 pasangan, 18 bundle berstatus OK |
| Interoperabilitas | OpenSSL 3.4.0 `pkeyutl -verify -rawin` membaca SPKI dan manifest dari bundle. ECDSA dikembalikan ke DER, RSA memakai parameter PSS eksplisit | 9 tanda tangan diterima |
| U02–U13 | Manipulasi artefak, manifest, signature, trust store, format, dan algoritma | Semua status sesuai; |

Keygen mengukur 5 pembangkitan di memori. Setiap pengukuran sign/verify memakai 5 pemanasan dan 30 sampel. Waktu primitif mencakup operasi kriptografi atas manifest. Waktu CLI mencakup proses Python baru, baca kunci dan artefak, hashing, parsing, verifikasi, serta keluaran. P95 memakai nearest-rank pada posisi `ceil(0.95 × n)`. Data mentah ada di `benchmarks/results/`.

## Container linux/amd64

```sh
docker build --platform linux/amd64 -t sleman:0.1.0 .
docker run --rm --network none --user "$(id -u):$(id -g)" sleman:0.1.0 --version
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" -v "$PWD/keys:/work/keys:ro" sleman:0.1.0 \
  sign --file README.md --package contoh-app --version 1.0.0 --key keys/publisher.key.pem --out container-release.json
```

### Menggunakan image GHCR untuk menandatangani aplikasi

Image Sleman adalah program penandatangan. Jalankan perintah berikut dari root repositori aplikasi yang berisi artefak. Contoh kode PowerShell dengan artefak hasil build berada di `dist/aplikasi.zip`.

```powershell
$image = "ghcr.io/orvin14/kripto-tugas3-if4020-2026@sha256:6635e7dbf5b757ba0c8c491adbeca8b7bacf668361c0590d4b3cce18f26c3404"
docker pull $image

# Buat pasangan kunci di folder terpisah dari artefak aplikasi.
New-Item -ItemType Directory -Force signing-keys | Out-Null
docker run --rm -v "${PWD}/signing-keys:/keys" $image `
  keygen --algorithm ed25519 --out /keys/publisher

# Daftarkan kunci publik dan izinkan kunci tersebut menandatangani paket aplikasi.
docker run --rm `
  -v "${PWD}:/work" `
  -v "${PWD}/signing-keys:/keys:ro" `
  -w /work $image `
  trust add --key /keys/publisher.pub.pem --package aplikasi --store /work/trust.json

# Tandatangani artefak hasil build. Bundle ditulis kembali ke repositori aplikasi.
docker run --rm `
  -v "${PWD}:/work" `
  -v "${PWD}/signing-keys:/keys:ro" `
  -w /work $image `
  sign --file /work/dist/aplikasi.zip --package aplikasi --version 1.0.0 `
  --key /keys/publisher.key.pem --out /work/dist/release.json

# Verifikasi bundle memakai artefak, nama paket, versi, dan trust store yang sama.
docker run --rm -v "${PWD}:/work:ro" -w /work $image `
  verify --file /work/dist/aplikasi.zip --bundle /work/dist/release.json `
  --trust-store /work/trust.json --package aplikasi --version 1.0.0 --json
```

Jika verifikasi berhasil, status JSON adalah `OK` dan exit code proses adalah `0`. Untuk menguji integritas, ubah artefak setelah ditandatangani lalu ulangi `verify`. Verifikasi seharusnya gagal dengan status `ARTIFACT_MISMATCH`.

Workflow [release-image](.github/workflows/release-image.yml) membangun image dari tag Git yang cocok dengan versi program (untuk 0.1.0, `v0.1.0`), menguji entrypoint, lalu mengirim image ke GHCR. Digest tercatat pada ringkasan run. Digest `0.1.0` yang dipakai workflow CI pada 16 November 2026 adalah: `sha256:6635e7dbf5b757ba0c8c491adbeca8b7bacf668361c0590d4b3cce18f26c3404`.

## Consumer CI/CD

Workflow [consumer-release-gate](.github/workflows/consumer-release-gate.yml) adalah workflow CI. Workflow ini menarik image rilis berdasarkan digest, menjalankan `sign` dan `verify`, lalu hanya membuat penanda publikasi setelah verifikasi berhasil. Skenario C01 dijalankan untuk tiga profil algoritma; C02-C04 memakai Ed25519; C05 memeriksa UID/GID runner, tanpa TTY, dan `--network none`.

Trust store demo berada di `ci/trust/`. Kunci privat demo tidak disimpan di repo dan dimasukkan ke secret:

```text
SLEMAN_DEMO_KEY_RSA_PSS_SHA256
SLEMAN_DEMO_KEY_ECDSA_P256_SHA256
SLEMAN_DEMO_KEY_ED25519
```

Detail setup, fingerprint, dan cara menjalankan ada di [`ci/README.md`](ci/README.md). Run C01-C05 yang berhasil: <https://github.com/Fajar2k5/Kripto-Tugas3-IF4020-2026/actions/runs/43824440894>.
