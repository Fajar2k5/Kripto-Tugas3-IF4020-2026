Referensi API
=============

API Python Sleman dipakai untuk memuat bundle, memvalidasi manifest, mengelola trust
store, dan menjalankan verifikasi. Modul publik menerima byte atau ``pathlib.Path`` dan
mengembalikan struktur Python biasa. Kesalahan format dilempar sebagai
``sleman.errors.FormatError``.

Overview
--------

- ``sleman.formats``: parser dan serializer manifest/bundle.
- ``sleman.trust_store``: baca, tambah, daftar, dan hapus kunci tepercaya.
- ``sleman.verification``: alur verifikasi dan objek hasil.
- ``sleman.errors``: status verifikasi dan error format.
- ``sleman.profiles``: nama profil algoritma.
- ``sleman.signing`` dan ``sleman.crypto_backend``: penandatanganan dan operasi
  kriptografi.

Fungsi publik
-------------

.. list-table::
   :header-rows: 1
   :widths: 24 34 28 20

   * - Fungsi
     - Input
     - Output
     - Keterangan
   * - ``load_bundle(data)``
     - ``data: bytes``
     - ``tuple[bytes, bytes]``
     - Mengembalikan byte manifest asli dan signature.
   * - ``load_manifest(data)``
     - ``data: bytes``
     - ``Mapping[str, Any]``
     - Manifest tervalidasi; ukuran maksimum 16 KiB.
   * - ``serialize_manifest_canonical(manifest)``
     - ``manifest: Mapping[str, Any]``
     - ``bytes``
     - Serialisasi canonical UTF-8.
   * - ``parse_json_object(data, *, max_bytes, label)``
     - ``data: bytes``, ``max_bytes: int | None``, ``label: str``
     - ``dict[str, Any]``
     - Parser JSON strict dengan deteksi field duplikat.
   * - ``parse_trust_store(data, *, backend=None)``
     - ``data: bytes``, ``backend: CryptoBackend | None``
     - ``dict[str, Any]``
     - Trust store tervalidasi tanpa membaca file.
   * - ``load_trust_store(path, *, backend=None)``
     - ``path: Path``, ``backend: CryptoBackend | None``
     - ``dict[str, Any]``
     - Membaca dan memvalidasi trust store.
   * - ``add_trust(path, public_key_pem, package, *, backend=None)``
     - ``path: Path``, ``public_key_pem: bytes``, ``package: str``
     - ``dict[str, Any]``
     - Menambah izin package; idempoten.
   * - ``list_trust(path, *, backend=None)``
     - ``path: Path``, ``backend: CryptoBackend | None``
     - ``list[dict[str, Any]]``
     - Daftar entri trust store.
   * - ``remove_trust(path, keyid, *, backend=None)``
     - ``path: Path``, ``keyid: str``
     - ``None``
     - Menghapus entri; error jika keyid tidak ada.
   * - ``verify_release(**)``
     - Parameter bernama pada tabel berikut
     - ``VerificationResult``
     - Menjalankan urutan pemeriksaan verifikasi.

Parameter ``verify_release``
----------------------------

.. list-table::
   :header-rows: 1
   :widths: 24 20 56

   * - Parameter
     - Tipe
     - Keterangan
   * - ``artifact_path``
     - ``Path``
     - Berkas artefak yang dibaca sebagai byte tanpa normalisasi.
   * - ``bundle_path``
     - ``Path``
     - Berkas bundle JSON.
   * - ``trust_store_path``
     - ``Path``
     - Berkas trust store JSON.
   * - ``expected_package``
     - ``str``
     - Nama package yang diharapkan pengguna.
   * - ``expected_version``
     - ``str``
     - Versi yang diharapkan pengguna.
   * - ``backend``
     - ``VerificationBackend | None``
     - Opsional; default memakai ``sleman.crypto_backend``.

Nilai balik ``VerificationResult``:

.. list-table::
   :header-rows: 1
   :widths: 24 18 58

   * - Atribut
     - Tipe
     - Keterangan
   * - ``status``
     - ``VerificationStatus``
     - Status akhir pemeriksaan.
   * - ``message``
     - ``str``
     - Penjelasan singkat.
   * - ``algorithm``
     - ``str | None``
     - Profil algoritma dari manifest, jika terbaca.
   * - ``keyid``
     - ``str | None``
     - Fingerprint dari manifest, jika terbaca.
   * - ``package``
     - ``str | None``
     - Package dari manifest, jika terbaca.
   * - ``version``
     - ``str | None``
     - Versi dari manifest, jika terbaca.
   * - ``valid``
     - ``bool``
     - ``True`` hanya jika status ``OK``.
   * - ``exit_code``
     - ``int``
     - 0 untuk ``OK``, 1 untuk penolakan, 2 untuk ``INPUT_ERROR``.

Contoh penggunaan
-----------------

Membaca bundle dan manifest:

.. code-block:: python

   from pathlib import Path

   from sleman.formats import load_bundle, load_manifest

   bundle_bytes = Path("release.json").read_bytes()
   manifest_bytes, signature = load_bundle(bundle_bytes)
   manifest = load_manifest(manifest_bytes)

   print(manifest["package"])
   print(manifest["artifact"]["sha256"])
   print(len(signature))

Memverifikasi artefak:

.. code-block:: python

   from pathlib import Path

   from sleman.verification import verify_release

   result = verify_release(
       artifact_path=Path("dist/demo-app.txt"),
       bundle_path=Path("release.json"),
       trust_store_path=Path("trust.json"),
       expected_package="demo-app",
       expected_version="1.0.0",
   )

   print(result.status.value)
   print(result.as_dict())
   raise SystemExit(result.exit_code)

Menambah dan menampilkan trust store:

.. code-block:: python

   from pathlib import Path

   from sleman.trust_store import add_trust, list_trust

   add_trust(
       Path("trust.json"),
       Path("publisher.pub.pem").read_bytes(),
       "demo-app",
   )
   for entry in list_trust(Path("trust.json")):
       print(entry["keyid"], entry["packages"])

Contoh CLI:

.. code-block:: shell

   uv run sleman verify \
     --file dist/demo-app.txt \
     --bundle release.json \
     --trust-store trust.json \
     --package demo-app \
     --version 1.0.0 \
     --json

Penjelasan tambahan
-------------------

- Parser manifest memeriksa canonical serialization byte-for-byte. Byte manifest asli
  harus diberikan kembali kepada backend verifikasi.
- ``load_bundle`` tidak mengubah byte manifest; signature diverifikasi atas byte tersebut.
- ``FormatError`` digunakan untuk kesalahan struktur, tipe, encoding, Base64, ukuran, atau
  canonical.
- ``TrustKeyNotFoundError`` digunakan oleh ``remove_trust`` jika keyid tidak ditemukan.
- ``OSError`` dapat muncul saat file tidak dapat dibaca atau trust store gagal disimpan.
- ``backend`` dapat diinjeksi pada pengujian. Jalur produksi memakai implementasi
  ``sleman.crypto_backend``.
- Trust store harus berasal dari konfigurasi tepercaya, bukan dari bundle yang sedang
  diverifikasi.

Referensi otomatis
------------------

Status Constants
~~~~~~~~~~~~~~~~

.. automodule:: sleman.errors
   :members:

Algoritma yang Didukung
~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: sleman.profiles
   :members:

Format dan Parser
~~~~~~~~~~~~~~~~~

.. automodule:: sleman.formats
   :members:

Trust Store
~~~~~~~~~~~

.. automodule:: sleman.trust_store
   :members:

Alur Verifikasi
~~~~~~~~~~~~~~~

.. automodule:: sleman.verification
   :members:

Penandatanganan
~~~~~~~~~~~~~~~

.. automodule:: sleman.signing
   :members:

Antarmuka Kriptografi
~~~~~~~~~~~~~~~~~~~~~

.. automodule:: sleman.crypto_backend
   :members:

Command Line
~~~~~~~~~~~~

.. automodule:: sleman.cli
   :members: build_parser, main
