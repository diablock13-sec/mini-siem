# Changelog

## 0.1.0 - 2026-11-12

Rilis pertama.

- Parser log Nginx format `combined`, baris rusak dilewati.
- Deteksi SQL injection, directory traversal (normalisasi URL berlapis), dan
  brute force (jendela waktu per IP). Aturan di `rules.yaml`.
- Alert ke Telegram dengan rate limit per IP dan jenis serangan.
- Mode `--follow` dengan dukungan rotasi dan pemotongan log.
- State tahan restart, ditulis atomik.
- Mode `--dry-run`.
- 111 test, `ruff` bersih, CI di GitHub Actions.

Belum diuji dengan lalu lintas internet sungguhan. Lihat Keterbatasan di README.
