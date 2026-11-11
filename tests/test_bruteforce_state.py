import json
from datetime import UTC, datetime, timedelta

from mini_siem.bruteforce import BruteForceDetector
from mini_siem.state import State, load_state, save_state

T0 = datetime(2026, 11, 11, 10, 0, 0, tzinfo=UTC)


def gagal(ip="203.0.113.7", detik=0) -> dict:
    return {
        "ip": ip,
        "time": T0 + timedelta(seconds=detik),
        "method": "POST",
        "path": "/login",
        "status": 401,
        "size": 0,
        "referer": "-",
        "user_agent": "test",
    }


def buat(**kw) -> BruteForceDetector:
    return BruteForceDetector(threshold=3, window_seconds=60, **kw)


def test_hitungan_bertahan_setelah_restart():
    lama = buat()
    assert lama.feed(gagal(detik=0)) is None
    assert lama.feed(gagal(detik=10)) is None
    baru = buat()
    baru.restore(lama.export())
    alert = baru.feed(gagal(detik=20))
    assert alert is not None
    assert alert.kind == "brute_force"


def test_tanpa_restore_hitungan_hilang():
    lama = buat()
    lama.feed(gagal(detik=0))
    lama.feed(gagal(detik=10))
    assert buat().feed(gagal(detik=20)) is None


def test_export_membuang_ip_di_luar_jendela():
    det = buat()
    det.feed(gagal(ip="10.0.0.1", detik=0))
    det.feed(gagal(ip="10.0.0.1", detik=1))
    det.feed(gagal(ip="10.0.0.2", detik=100))
    assert set(det.export()) == {"10.0.0.2"}


def test_export_kosong_kalau_tidak_ada_data():
    assert buat().export() == {}


def test_restore_melewati_data_rusak():
    det = buat()
    det.restore(
        {
            "10.0.0.1": ["bukan-tanggal"],
            "10.0.0.2": ["2026-11-11T10:00:00"],  # tanpa zona waktu
        }
    )
    assert det.export() == {}


def test_restore_membatasi_jumlah_entri_per_ip():
    det = buat()
    isos = [(T0 + timedelta(seconds=i)).isoformat() for i in range(10)]
    det.restore({"10.0.0.1": isos})
    assert len(det._failures["10.0.0.1"]) == 2  # threshold - 1


def test_restore_membatasi_jumlah_ip():
    det = buat(max_tracked=2)
    iso = T0.isoformat()
    det.restore({f"10.0.0.{i}": [iso] for i in range(5)})
    assert len(det._failures) == 2


def test_state_roundtrip_dengan_failures(tmp_path):
    path = tmp_path / "state.json"
    save_state(path, State(failures={"10.0.0.1": [T0.isoformat()]}))
    assert load_state(path).failures == {"10.0.0.1": [T0.isoformat()]}


def test_state_lama_tanpa_failures_tetap_terbaca(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"version": 1, "logfile": "/x", "inode": 1, "offset": 5, "sent": []}))
    state = load_state(path)
    assert state.failures == {}
    assert state.offset == 5


def test_state_failures_rusak_diabaikan(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps({"version": 1, "failures": {"10.0.0.1": [1, 2], "10.0.0.2": ["2026-11-11T10:00:00+00:00"]}})
    )
    assert load_state(path).failures == {"10.0.0.2": ["2026-11-11T10:00:00+00:00"]}
