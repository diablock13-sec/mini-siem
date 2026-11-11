from datetime import UTC, datetime, timedelta

from mini_siem.detector import Alert
from mini_siem.ratelimit import AlertLimiter

T0 = datetime(2026, 11, 11, 10, 0, 0, tzinfo=UTC)


def buat_alert(ip="203.0.113.7", kind="sql_injection", detik=0) -> Alert:
    return Alert(kind, ip, T0 + timedelta(seconds=detik), "/x", "detail")


def kirim(limiter: AlertLimiter, alert: Alert) -> bool:
    """Meniru pipeline: cek, lalu catat hanya kalau lolos (anggap send() sukses)."""
    if not limiter.allow(alert):
        return False
    limiter.record(alert)
    return True


def test_alert_pertama_lolos():
    assert AlertLimiter().allow(buat_alert()) is True


def test_allow_tidak_mengubah_state():
    limiter = AlertLimiter()
    assert limiter.allow(buat_alert(detik=0)) is True
    # tanpa record(), alert yang sama masih boleh (kirim gagal tidak boleh menahan)
    assert limiter.allow(buat_alert(detik=1)) is True
    assert limiter.export() == []


def test_record_menahan_alert_berikutnya():
    limiter = AlertLimiter(window_seconds=300)
    limiter.record(buat_alert(detik=0))
    assert limiter.allow(buat_alert(detik=60)) is False


def test_alert_sama_dalam_jendela_ditahan():
    limiter = AlertLimiter(window_seconds=300)
    assert kirim(limiter, buat_alert(detik=0)) is True
    assert kirim(limiter, buat_alert(detik=60)) is False
    assert kirim(limiter, buat_alert(detik=299)) is False


def test_ip_berbeda_tidak_saling_menahan():
    limiter = AlertLimiter()
    assert kirim(limiter, buat_alert(ip="203.0.113.7")) is True
    assert kirim(limiter, buat_alert(ip="203.0.113.8")) is True


def test_jenis_berbeda_tidak_saling_menahan():
    limiter = AlertLimiter()
    assert kirim(limiter, buat_alert(kind="sql_injection")) is True
    assert kirim(limiter, buat_alert(kind="directory_traversal")) is True


def test_lolos_lagi_setelah_jendela_lewat():
    limiter = AlertLimiter(window_seconds=300)
    assert kirim(limiter, buat_alert(detik=0)) is True
    assert kirim(limiter, buat_alert(detik=300)) is True


def test_alert_yang_ditahan_tidak_memperpanjang_jendela():
    limiter = AlertLimiter(window_seconds=300)
    assert kirim(limiter, buat_alert(detik=0)) is True
    assert kirim(limiter, buat_alert(detik=200)) is False
    # 310 detik sejak alert yang dikirim, walau hanya 110 detik sejak yang ditahan
    assert kirim(limiter, buat_alert(detik=310)) is True


def test_memori_dibersihkan():
    limiter = AlertLimiter(window_seconds=300, max_tracked=10)
    for i in range(10):
        limiter.record(buat_alert(ip=f"10.0.0.{i}", detik=0))
    # 11 IP baru, jauh setelah jendela lewat: entri lama harus dibuang
    limiter.record(buat_alert(ip="10.0.1.1", detik=1000))
    assert len(limiter._last_sent) == 1


def test_export_restore_menahan_alert_setelah_restart():
    lama = AlertLimiter(window_seconds=300)
    lama.record(buat_alert(detik=0))
    baru = AlertLimiter(window_seconds=300)
    baru.restore(lama.export())
    assert baru.allow(buat_alert(detik=60)) is False
    assert baru.allow(buat_alert(detik=300)) is True


def test_restore_melewati_data_rusak():
    limiter = AlertLimiter()
    limiter.restore(
        [
            ("1.1.1.1", "sql_injection", "bukan-tanggal"),
            ("1.1.1.2", "sql_injection", "2026-11-11T10:00:00"),  # tanpa zona waktu
        ]
    )
    assert limiter.export() == []
