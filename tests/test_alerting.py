from datetime import UTC, datetime

from mini_siem.alerting import MAX_PATH_LEN, format_alert
from mini_siem.detector import Alert

WAKTU = datetime(2026, 11, 11, 10, 30, 5, tzinfo=UTC)


def buat_alert(**kw) -> Alert:
    data = {
        "kind": "sql_injection",
        "ip": "203.0.113.7",
        "time": WAKTU,
        "path": "/search?q=1' OR '1'='1",
        "detail": "boolean_or",
    }
    data.update(kw)
    return Alert(**data)


def test_pesan_memuat_semua_field():
    teks = format_alert(buat_alert())
    assert "sql_injection" in teks
    assert "203.0.113.7" in teks
    assert "2026-11-11 10:30:05 +0000" in teks
    assert "/search?q=1' OR '1'='1" in teks
    assert "boolean_or" in teks


def test_path_panjang_dipotong():
    teks = format_alert(buat_alert(path="/" + "A" * 5000))
    assert len(teks) < 4096
    assert "A" * (MAX_PATH_LEN + 1) not in teks
    assert "..." in teks


def test_path_pendek_tidak_diubah():
    teks = format_alert(buat_alert(path="/index.html"))
    assert "Path: /index.html\n" in teks
    assert "..." not in teks


def test_alert_brute_force():
    teks = format_alert(
        buat_alert(kind="brute_force", path="/login", detail="5 gagal login dalam 60 detik")
    )
    assert "brute_force" in teks
    assert "5 gagal login dalam 60 detik" in teks
