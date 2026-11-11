import logging
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)

# Format Nginx "combined"
LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"$'
)
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line: str) -> dict | None:
    """Ubah satu baris log jadi dict. Baris rusak: kembalikan None."""
    m = LOG_RE.match(line.strip())
    if m is None:
        return None
    d = m.groupdict()
    try:
        time = datetime.strptime(d["time"], TIME_FORMAT)
    except ValueError:
        return None
    return {
        "ip": d["ip"],
        "time": time,
        "method": d["method"],
        "path": d["path"],
        "status": int(d["status"]),
        "size": 0 if d["size"] == "-" else int(d["size"]),
        "referer": d["referer"],
        "user_agent": d["agent"],
    }


def parse_file(path: Path) -> Iterator[dict]:
    """Baca file baris per baris. Baris rusak dicatat lalu dilewati."""
    with path.open(encoding="utf-8", errors="replace") as f:
        for number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            entry = parse_line(line)
            if entry is None:
                log.warning("baris %d tidak bisa dibaca, dilewati", number)
                continue
            yield entry
