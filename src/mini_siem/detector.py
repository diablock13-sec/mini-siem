import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote_plus

SQLI_PATTERNS = {
    "or-1=1": re.compile(r"\bor\s+\d+\s*=\s*\d+"),
    "quote-or-quote": re.compile(r"'\s*or\s*'"),
    "union-select": re.compile(r"\bunion\s+(all\s+)?select\b"),
    "comment-after-quote": re.compile(r"['\"]\s*(--|#|/\*)"),
    "sleep-benchmark": re.compile(r"\b(sleep|benchmark)\s*\(\s*\d+"),
    "information-schema": re.compile(r"\binformation_schema\b"),
}
TRAVERSAL = re.compile(r"\.\.[/\\]")


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


def detect(entry: dict) -> list[Alert]:
    """Kembalikan daftar alert untuk satu entri log. Jinak: daftar kosong."""
    text = normalize(entry["path"])
    alerts = []

    hits = [name for name, rx in SQLI_PATTERNS.items() if rx.search(text)]
    if hits:
        alerts.append(
            Alert("sql_injection", entry["ip"], entry["time"], entry["path"], ", ".join(hits))
        )

    if TRAVERSAL.search(text):
        alerts.append(
            Alert("directory_traversal", entry["ip"], entry["time"], entry["path"], "../")
        )

    return alerts
