# Benchmark

Benchmark:

- pembangkitan kunci: `benchmark_sign.py`;
- hash artefak: `benchmark_hash.py`;
- operasi sign: `benchmark_sign.py`;
- operasi verify: `benchmark_verify.py`;
- end-to-end CLI sign: `benchmark_sign.py`;
- end-to-end CLI verify: `benchmark_verify.py`;
- ukuran kunci, signature, dan bundle: `benchmark_sign.py`.

Semua benchmark memakai artefak deterministik 1 KiB, 1 MiB, dan 16 MiB. Sign dan verify
memakai 5 warmup dan 30 sampel; median dan P95 memakai nearest-rank.

## Running

```sh
make benchmark-hash
uv run python benchmarks/benchmark_sign.py
make benchmark-verify
```

Hasil:

```text
benchmarks/results/hash-artifact.json
benchmarks/results/sign.json
benchmarks/results/verify.json
```

Benchmark hash mengukur SHA-256 dari byte di memori; I/O dan parsing tidak termasuk.
Benchmark verify memisahkan operasi kriptografi dari verify CLI end-to-end.
