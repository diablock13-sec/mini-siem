import contextlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

VERSION = 1


def default_state_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / "mini-siem" / "state.json"


@dataclass
class State:
    logfile: str | None = None
    inode: int | None = None
    offset: int | None = None
    sent: list[list[str]] = field(default_factory=list)  # [ip, jenis, waktu ISO]


def load_state(path: Path) -> State:
    """Muat state. File hilang atau rusak: kembalikan state kosong."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return State()
    except (OSError, ValueError) as exc:
        log.warning("state rusak, diabaikan: %s", type(exc).__name__)
        return State()
    if not isinstance(data, dict) or data.get("version") != VERSION:
        log.warning("state tidak dikenal, diabaikan")
        return State()

    state = State()
    logfile, inode, offset = data.get("logfile"), data.get("inode"), data.get("offset")
    if (
        isinstance(logfile, str)
        and type(inode) is int
        and type(offset) is int
        and offset >= 0
    ):
        state.logfile, state.inode, state.offset = logfile, inode, offset
    sent = data.get("sent")
    if isinstance(sent, list):
        state.sent = [
            e
            for e in sent
            if isinstance(e, list) and len(e) == 3 and all(isinstance(x, str) for x in e)
        ]
    return state


def save_state(path: Path, state: State) -> None:
    """Tulis atomik: file sementara di folder yang sama, lalu rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "version": VERSION,
        "logfile": state.logfile,
        "inode": state.inode,
        "offset": state.offset,
        "sent": state.sent,
    }
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".state-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
