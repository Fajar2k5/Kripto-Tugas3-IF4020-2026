# Sleman

Sleman menandatangani artefak rilis dan memverifikasinya terhadap paket, versi, dan kunci penerbit dalam trust store lokal. CLI memerlukan Python 3.12+ dan pyca/cryptography (50.0.2 dalam `uv.lock`). OpenSSL CLI 3.x diperlukan untuk uji interoperabilitas saja.

## Menjalankan CLI

Dari direktori repositori, jalankan contoh berikut sekali di direktori keluaran yang bersih. README itu sendiri dipakai sebagai artefak contoh.

```sh
uv sync --locked
uv run sleman keygen --algorithm ed25519 --out keys/publisher
uv run sleman trust add --key keys/publisher.pub.pem --package contoh-app --store trust.json
uv run sleman sign --file README.md --package contoh-app --version 1.0.0 --key keys/publisher.key.pem --out release.json
uv run sleman verify --file README.md --bundle release.json --trust-store trust.json --package contoh-app --version 1.0.0 --json
uv run sleman trust list --store trust.json
uv run sleman trust remove --keyid <fingerprint-dari-keygen> --store trust.json
```

`keygen` mencetak fingerprint dan membuat berkas baru dengan prefiks pilihan. Gunakan prefiks baru untuk rotasi kunci. Simpan kunci privat PKCS8 PEM tanpa enkripsi di lokasi dengan akses terbatas. Pada POSIX, Sleman meminta mode 0600 saat membuatnya. Kunci publik memakai SPKI PEM. Fingerprint adalah SHA-256 atas DER SPKI, ditulis sebagai 64 digit heksadesimal kecil.

## Implementasi penandatanganan

`sign` membaca berkas sebagai byte dalam potongan 1 MiB. Selama pembacaan, Sleman menghitung ukuran dan SHA-256. Nama artefak berasal dari basename. Serializer bersama memvalidasi metadata dan menghasilkan JSON UTF-8 ringkas dalam urutan `schema, package, version, algorithm, keyid, artifact`, dengan urutan `name, size, sha256` untuk artefak. Sleman menandatangani byte manifest tersebut. Bundle menyimpan schema, manifest, dan tanda tangan dalam dua field Base64 standar berpading sesuai kebutuhan. Batas manifest 16 KiB dan bundle 64 KiB. Keluaran yang sudah ada menghasilkan exit code 2.

| Profil | Pembangkitan dan operasi pyca/cryptography | Encoding tanda tangan |
|---|---|---|
| rsa-pss-sha256 | `rsa.generate_private_key(65537, 3072)`, PSS dengan SHA-256, MGF1-SHA-256, salt acak 32 byte | 384 byte |
| ecdsa-p256-sha256 | `ec.generate_private_key(SECP256R1())`, ECDSA SHA-256 dengan nonce deterministik RFC 6979 | Pasangan DER dari pustaka dikonversi ke dua integer big-endian masing-masing 32 byte |
| ed25519 | `Ed25519PrivateKey.generate()`, PureEdDSA atas byte manifest langsung | 64 byte |

Ketiga generator memakai sumber acak pustaka. RSA dan ECDSA menghitung hash manifest di dalam operasi tanda tangan. Verifier menerima kembali byte manifest asli dan memakai parameter yang sama. Dokumentasi pustaka tersedia untuk [RSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/), [ECDSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/), dan [Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).

## Pengujian dan benchmark

```sh
uv run python -m unittest discover -s tests -v
uv run python benchmarks/benchmark_sign.py
```

Skenario CLI membuat pasangan kunci sementara dan memeriksa exit code serta status JSON. Pasangan kunci contoh dalam `tests/fixtures/test-only-*` hanya untuk reproduksi latihan. Seluruh kunci privat pada direktori fixture bersifat publik.

| Uji | Masukan dan hasil yang diharapkan | Hasil lokal |
|---|---|---|
| U01 | Teks dengan CRLF, byte 0–255, berkas kosong × 3 profil. Ukuran dan hash cocok, verifikasi OK | 9 kombinasi lulus |
| U14 | Dua penandatanganan per kombinasi U01. RSA berbeda karena salt acak. ECDSA RFC 6979 dan Ed25519 identik untuk pesan dan kunci yang sama | Pola sesuai untuk 9 pasangan, 18 bundle berstatus OK |
| Interoperabilitas | OpenSSL 3.4.0 `pkeyutl -verify -rawin` membaca SPKI dan manifest dari bundle. ECDSA dikembalikan ke DER, RSA memakai parameter PSS eksplisit | 9 tanda tangan diterima |
| Konflik keygen | Hanya berkas kunci publik tujuan sudah ada. Exit 2, isi lama tetap, kunci privat parsial dibersihkan | Lulus |

Benchmark memakai artefak identik dengan benchmark hash tim (1 KiB, 1 MiB, 16 MiB). Keygen mengukur 5 pembangkitan di memori. Setiap pengukuran sign memakai 5 pemanasan dan 30 sampel. Waktu primitif mencakup operasi kriptografi atas manifest. Waktu CLI mencakup proses Python baru, baca kunci dan artefak, hashing, penandatanganan, serta tulis bundle. P95 memakai nearest-rank pada posisi `ceil(0.95 × n)`. Data mentah, lingkungan, ukuran kunci DER dan bundle tersedia di [hasil benchmark](benchmarks/results/sign.json).

## Container linux/amd64

```sh
docker build --platform linux/amd64 -t sleman:0.1.0 .
docker run --rm --network none --user "$(id -u):$(id -g)" sleman:0.1.0 --version
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" -v "$PWD/keys:/work/keys:ro" sleman:0.1.0 \
  sign --file README.md --package contoh-app --version 1.0.0 --key keys/publisher.key.pem --out container-release.json
```

### Menggunakan image GHCR untuk menandatangani aplikasi

Image Sleman adalah program penandatangan. Jalankan perintah berikut dari root repositori aplikasi yang berisi artefak. Contoh PowerShell ini menganggap artefak hasil build berada di `dist/aplikasi.zip`, dan image sudah dipublikasikan sebagai package publik. Ganti nama owner atau image bila package Anda berbeda.

```powershell
$image = "ghcr.io/orvin14/kripto-tugas3-if4020-2026:0.1.0"
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

Simpan `signing-keys/publisher.key.pem` dengan akses terbatas dan jangan commit atau bagikan kunci privat tersebut. Folder kunci dipasang read-only saat `sign`. Pastikan `dist/aplikasi.zip` sudah dibuat sebelum menjalankan contoh. Pull image publik tidak memerlukan login. Untuk package privat, lakukan `docker login ghcr.io -u <username>` dan masukkan GitHub Personal Access Token ketika Docker meminta password.

Workflow [release-image](.github/workflows/release-image.yml) membangun image dari tag Git yang cocok dengan versi program (untuk 0.1.0, `v0.1.0`), menguji entrypoint, lalu mengirim image ke GHCR. Digest tercatat pada ringkasan run. Untuk rilis publik, pemilik package perlu mengaktifkan visibilitas publik dan memastikan pull anonim berhasil. Gunakan referensi `ghcr.io/<owner>/<repo>@sha256:<digest>` pada runner. Publikasi dan digest latihan ini belum terverifikasi.
