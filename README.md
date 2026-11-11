# mini-siem

![CI](https://github.com/diablock13-sec/mini-siem/actions/workflows/ci.yml/badge.svg)

SIEM kecil untuk server web Nginx: membaca access log, mendeteksi tiga jenis
serangan, dan mengirim alert ke Telegram. Dibuat sebagai proyek belajar.
Baca bagian **Keterbatasan** sebelum memakainya untuk sesuatu yang penting.

## Yang dideteksi

| Jenis | Cara kerja |
|-------|-----------|
| `sql_injection` | 6 pola regex (misalnya `or 1=1`, `union select`, `sleep(...)`) pada path dan query yang sudah di-decode |
| `directory_traversal` | `../` atau `..\`, termasuk yang di-encode berlapis (`%2e%2e`, `%252e`) |
| `brute_force` | 5 respons 401 atau 403 pada `/login` dari satu IP dalam 60 detik |

Semua angka dan pola ada di `src/mini_siem/rules.yaml`.

Satu alert per IP per jenis serangan per 5 menit, supaya Telegram tidak banjir.

## Contoh alert

    [ALERT] brute_force
    IP: 198.51.100.7
    Waktu: 2026-11-11 10:01:14 +0700
    Path: /login
    Detail: 5 gagal login dalam 60 detik

IP di contoh ini dari rentang dokumentasi (RFC 5737), bukan milik siapa pun.

## Pasang

Butuh [uv](https://docs.astral.sh/uv/) dan Python sesuai file `.python-version`.

    git clone https://github.com/diablock13-sec/mini-siem.git
    cd mini-siem
    uv sync

## Pakai

Coba dulu tanpa Telegram. Mode `--dry-run` hanya mencetak alert ke layar, tidak
mengirim apa pun, dan tidak menyimpan state:

    uv run mini-siem --dry-run samples/access.log

Harapan: 3 alert (brute force, SQL injection, directory traversal). Dua IP lain
di contoh itu lalu lintas normal dan tidak memicu apa pun.

Mengikuti file log secara terus-menerus, seperti `tail -f`:

    uv run mini-siem --follow /var/log/nginx/access.log

Membaca log Nginx asli butuh izin. Di Debian dan Ubuntu, tambahkan pengguna ke
grup `adm`.

| Opsi | Arti |
|------|------|
| `--dry-run` | cetak alert ke layar, jangan kirim ke Telegram, jangan simpan state |
| `-f`, `--follow` | ikuti file terus-menerus; rotasi log dan pemotongan file ditangani |
| `--from-start` | dengan `--follow`: baca isi lama dulu (diabaikan kalau state sudah ada) |
| `--state FILE` | lokasi file state (default `~/.local/state/mini-siem/state.json`) |

Dengan `--follow`, posisi baca dan waktu alert terakhir disimpan, jadi setelah
restart baris lama tidak dibaca ulang dan alert yang sedang ditahan tetap ditahan.

## Menyiapkan Telegram

1. Di Telegram, chat dengan **@BotFather**, kirim `/newbot`, ikuti petunjuknya,
   dan simpan token yang diberikan.
2. Kirim satu pesan apa saja ke bot barumu.
3. Buka `https://api.telegram.org/bot<TOKEN>/getUpdates` di browser (ganti
   `<TOKEN>`) dan cari angka setelah `"chat":{"id":`. Itu chat ID-mu. URL ini
   memuat token: jangan dibagikan atau di-screenshot.
4. Buat file `.env` di folder proyek (sejajar `pyproject.toml`) dari contoh,
   lalu isi kedua nilainya:

        cp .env.example .env
        chmod 600 .env
        nano .env

Program membaca `.env` otomatis. `.env` sudah diabaikan Git, pastikan dengan
`git check-ignore -v .env`. Kalau muncul `KeyError: 'TELEGRAM_BOT_TOKEN'`,
berarti `.env` tidak ditemukan atau nilainya kosong.

Kalau token pernah bocor, cabut lewat @BotFather (`/revoke`) dan buat yang baru.

## Mengubah aturan

Edit `src/mini_siem/rules.yaml`. Pola dicocokkan ke path yang sudah di-decode dan
berhuruf kecil. Blok `|-` dipakai supaya karakter `'`, `"`, dan `\` tidak perlu
di-escape. Contoh menambah pola SQL injection:

    sql_injection:
      - name: contoh-baru
        pattern: |-
          \bwaitfor\s+delay\b

Setiap aturan baru sebaiknya disertai dua test: satu serangan yang harus
tertangkap, dan satu lalu lintas normal yang tidak boleh memicu alert. Lihat
`tests/test_detector.py`.

## Cara kerja

    baris log -> parser -> detektor -> rate limit -> Telegram

- `parser.py`: regex format Nginx `combined`; baris rusak dicatat lalu dilewati.
- `detector.py`, `bruteforce.py`, `rules.py`: pencocokan pola dan hitungan per IP.
- `ratelimit.py`: pembatas alert; memakai waktu dari log, bukan jam sistem, jadi
  memutar ulang log lama tetap konsisten.
- `follow.py`: membaca baris baru, baris setengah ditulis dibuffer.
- `state.py`: state ditulis atomik (file sementara, fsync, ganti nama).

## Keterbatasan

- **Belum diuji dengan lalu lintas internet sungguhan.** Pengujian sejauh ini:
  111 test otomatis, log serangan buatan di `samples/`, dan pengiriman alert
  nyata ke Telegram. Angka false positive pada trafik sebenarnya belum diukur.
- Deteksi berbasis pola, jadi bisa dikelabui (misalnya komentar SQL di tengah
  kata kunci).
- Hanya memeriksa path dan query dari log. Isi POST dan header tidak ada di log
  Nginx, jadi tidak terlihat.
- Brute force dihitung per IP. Serangan yang disebar ke banyak IP lolos. Hanya
  path di `login_paths` (bawaan `/login`) yang dipantau.
- Hanya format Nginx `combined`. Baris dengan permintaan kosong (`"-"`) belum terbaca.
- Hanya mendeteksi dan memberi tahu. Tidak memblokir IP.
- State disimpan tiap 50 baris atau 10 detik. Kalau proses dimatikan paksa
  (`kill -9`), alert ganda mungkin muncul.
- Path dari penyerang dipotong 200 karakter di pesan Telegram.

## Dibandingkan dengan alat lain

- **Wazuh**: platform keamanan lengkap dengan banyak sumber log, dashboard, dan
  respons aktif. Pakai untuk lingkungan nyata.
- **fail2ban**: membaca log dan **memblokir** IP lewat firewall. Kalau tujuanmu
  menghentikan brute force, ini lebih tepat.
- **mini-siem**: kecil dan mudah dibaca, tiga aturan, alert ke Telegram. Cocok
  untuk belajar atau server pribadi berisiko rendah yang ingin diberi tahu,
  bukan untuk melindungi sistem penting.

## Privasi dan keamanan

- Log Nginx berisi alamat IP pengunjung, yang termasuk data pribadi. Jangan
  commit log asli dan jangan tempel utuh di tempat publik. `samples/` hanya
  berisi log buatan.
- Token bot hanya di `.env`. Logger `httpx` diturunkan ke level WARNING karena
  URL request-nya memuat token.
- Jalankan hanya pada server milikmu sendiri.

## Pengembangan

    uv run pytest
    uv run ruff check .

CI menjalankan keduanya di setiap push.

## Lisensi

MIT. Lihat `LICENSE`.
