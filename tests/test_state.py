import json

import pytest

from mini_siem import state as state_mod
from mini_siem.state import State, load_state, save_state


def contoh() -> State:
    return State(
        logfile="/var/log/nginx/access.log",
        inode=123,
        offset=4567,
        sent=[["203.0.113.7", "sql_injection", "2026-11-11T10:00:00+07:00"]],
    )


def test_simpan_lalu_muat_sama(tmp_path):
    p = tmp_path / "sub" / "state.json"
    save_state(p, contoh())
    assert load_state(p) == contoh()


def test_file_tidak_ada_memberi_state_kosong(tmp_path):
    assert load_state(tmp_path / "x.json") == State()


def test_json_rusak_diabaikan(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("{rusak")
    assert load_state(p) == State()


def test_versi_tidak_dikenal_diabaikan(tmp_path):
    p = tmp_path / "state.json"
    p.write_text(json.dumps({"version": 99, "logfile": "x", "inode": 1, "offset": 2}))
    assert load_state(p) == State()


def test_entri_sent_rusak_disaring(tmp_path):
    p = tmp_path / "state.json"
    sent = [["a", "b", "c"], ["hanya", "dua"], "teks", [1, 2, 3]]
    p.write_text(json.dumps({"version": 1, "sent": sent}))
    assert load_state(p).sent == [["a", "b", "c"]]


def test_posisi_tidak_valid_diabaikan(tmp_path):
    p = tmp_path / "state.json"
    p.write_text(json.dumps({"version": 1, "logfile": "x", "inode": "1", "offset": -5}))
    s = load_state(p)
    assert s.inode is None
    assert s.offset is None


def test_tidak_ada_file_sementara_tersisa(tmp_path):
    p = tmp_path / "state.json"
    save_state(p, contoh())
    save_state(p, contoh())
    assert [f.name for f in tmp_path.iterdir()] == ["state.json"]


def test_gagal_menulis_tidak_merusak_file_lama(tmp_path, monkeypatch):
    p = tmp_path / "state.json"
    save_state(p, contoh())

    def rusak(*args, **kwargs):
        raise OSError("disk penuh")

    monkeypatch.setattr(state_mod.json, "dump", rusak)
    with pytest.raises(OSError):
        save_state(p, State(logfile="lain", inode=1, offset=1))
    assert load_state(p) == contoh()
    assert [f.name for f in tmp_path.iterdir()] == ["state.json"]
