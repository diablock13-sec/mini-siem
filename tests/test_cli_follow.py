import logging
from pathlib import Path

import pytest

from mini_siem import cli
from mini_siem.state import load_state

SAMPLE = Path(__file__).parent.parent / "samples" / "access.log"
LINES = SAMPLE.read_text().splitlines()
BENIGN = LINES[0]  # baris pertama contoh: lalu lintas normal
END_OFFSET = sum(len(line) + 1 for line in LINES)


def make_follow(lines, inode=7, calls=None):
    """Pengganti follow_with_position: memberi baris, lalu meniru Ctrl+C."""

    def _follow(logfile, from_start=False, resume=None):
        if calls is not None:
            calls.append({"from_start": from_start, "resume": resume})
        offset = 0
        for line in lines:
            offset += len(line) + 1
            yield line, inode, offset
        raise KeyboardInterrupt

    return _follow


@pytest.fixture
def logfile(tmp_path):
    f = tmp_path / "access.log"
    f.write_text("\n".join(LINES) + "\n")
    return f


@pytest.fixture
def sent(monkeypatch):
    """Ganti pengiriman Telegram dengan daftar. Tidak ada yang keluar ke internet."""
    messages = []
    monkeypatch.setattr("mini_siem.telegram.send_message", messages.append)
    return messages


def run(args, follow, monkeypatch):
    monkeypatch.setattr(cli, "follow_with_position", follow)
    return cli.main(args)


def test_follow_dry_run_prints_alerts_and_saves_no_state(
    tmp_path, logfile, monkeypatch, capsys
):
    state = tmp_path / "state.json"
    args = ["--follow", "--dry-run", "--state", str(state), str(logfile)]
    rc = run(args, make_follow(LINES), monkeypatch)
    out = capsys.readouterr().out
    assert rc == 0
    assert "[ALERT] brute_force" in out
    assert "[ALERT] sql_injection" in out
    assert "[ALERT] directory_traversal" in out
    assert "3 alert dicetak" in out
    assert not state.exists()


def test_follow_sends_alerts_and_saves_state(tmp_path, logfile, sent, monkeypatch):
    state = tmp_path / "state.json"
    rc = run(["--follow", "--state", str(state), str(logfile)], make_follow(LINES), monkeypatch)
    assert rc == 0
    assert len(sent) == 3
    saved = load_state(state)
    assert saved.logfile == str(logfile.resolve())
    assert saved.inode == 7
    assert saved.offset == END_OFFSET
    assert len(saved.sent) == 3


def test_follow_resumes_from_saved_position(tmp_path, logfile, sent, monkeypatch):
    state = tmp_path / "state.json"
    args = ["--follow", "--state", str(state), str(logfile)]
    run(args, make_follow(LINES), monkeypatch)
    calls = []
    run(args, make_follow([], calls=calls), monkeypatch)
    assert calls[0]["resume"] == (7, END_OFFSET)


def test_follow_ignores_state_of_another_logfile(tmp_path, logfile, sent, monkeypatch):
    state = tmp_path / "state.json"
    run(["--follow", "--state", str(state), str(logfile)], make_follow(LINES), monkeypatch)
    other = tmp_path / "other.log"
    other.write_text("")
    calls = []
    run(["--follow", "--state", str(state), str(other)], make_follow([], calls=calls), monkeypatch)
    assert calls[0]["resume"] is None


def test_restart_does_not_repeat_alerts(tmp_path, logfile, sent, monkeypatch):
    state = tmp_path / "state.json"
    args = ["--follow", "--state", str(state), str(logfile)]
    run(args, make_follow(LINES), monkeypatch)
    assert len(sent) == 3
    run(args, make_follow(LINES), monkeypatch)  # baris yang sama diputar ulang
    assert len(sent) == 3


def test_dry_run_does_not_touch_existing_state(tmp_path, logfile, sent, monkeypatch):
    state = tmp_path / "state.json"
    run(["--follow", "--state", str(state), str(logfile)], make_follow(LINES), monkeypatch)
    before = state.read_bytes()
    run(
        ["--follow", "--dry-run", "--state", str(state), str(logfile)],
        make_follow(LINES + LINES),
        monkeypatch,
    )
    assert state.read_bytes() == before


def test_garbage_line_skipped_and_offset_still_advances(
    tmp_path, logfile, sent, monkeypatch, caplog
):
    state = tmp_path / "state.json"
    lines = [BENIGN, "bukan log", BENIGN]
    with caplog.at_level(logging.WARNING):
        run(["--follow", "--state", str(state), str(logfile)], make_follow(lines), monkeypatch)
    assert "tidak bisa dibaca" in caplog.text
    assert load_state(state).offset == sum(len(line) + 1 for line in lines)
    assert sent == []


def test_state_saved_every_50_lines_and_on_exit(tmp_path, logfile, sent, monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "_save", lambda *args, **kwargs: calls.append(1))
    monkeypatch.setattr(cli, "SAVE_EVERY_SECONDS", 1e9)
    state = tmp_path / "state.json"
    run(
        ["--follow", "--state", str(state), str(logfile)],
        make_follow([BENIGN] * 120),
        monkeypatch,
    )
    assert len(calls) == 3  # baris ke-50, baris ke-100, dan saat keluar


def test_from_start_requires_follow(logfile):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--from-start", str(logfile)])
    assert exc.value.code == 2


def test_missing_logfile_exits(tmp_path):
    with pytest.raises(SystemExit) as exc:
        cli.main([str(tmp_path / "tidak-ada.log")])
    assert exc.value.code == 2
