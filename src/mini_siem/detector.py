from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote_plus

from mini_siem.rules import Rules, default_rules


@dataclass(frozen=True)
class Alert:
    kind: str
    ip: str
    time: datetime
    path: str
    detail: str


def normalize(text: str) -> str:
    """Decode URL sampai stabil (maks 3 kali), lalu huruf kecil."""
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text.lower()


def detect(entry: dict, rules: Rules | None = None) -> list[Alert]:
    """Kembalikan daftar alert untuk satu entri log. Jinak: daftar kosong."""
    if rules is None:
        rules = default_rules()
    text = normalize(entry["path"])
    alerts = []

    hits = [name for name, rx in rules.sql_injection.items() if rx.search(text)]
    if hits:
        alerts.append(
            Alert("sql_injection", entry["ip"], entry["time"], entry["path"], ", ".join(hits))
        )

    hits = [name for name, rx in rules.directory_traversal.items() if rx.search(text)]
    if hits:
        alerts.append(
            Alert("directory_traversal", entry["ip"], entry["time"], entry["path"], ", ".join(hits))
        )

    return alerts
