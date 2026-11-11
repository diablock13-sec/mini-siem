from datetime import UTC, datetime
from pathlib import Path

import pytest

from mini_siem.detector import detect
from mini_siem.parser import parse_file

SAMPLE = Path(__file__).parent.parent / "samples" / "access.log"


def entry(path: str) -> dict:
    return {
        "ip": "203.0.113.5",
        "time": datetime(2026, 11, 11, 10, 0, tzinfo=UTC),
        "path": path,
    }


def kinds(path: str) -> set[str]:
    return {a.kind for a in detect(entry(path))}


@pytest.mark.parametrize(
    "path",
    [
        "/products?id=1%27%20OR%201=1--",
        "/login?user=admin%27%20or%20%271%27=%271",
        "/items?id=1+UNION+SELECT+username,password+FROM+users",
        "/search?q=a%27--",
        "/items?id=1;SELECT+sleep(5)",
        "/q?x=information_schema.tables",
    ],
)
def test_sql_injection_detected(path):
    assert kinds(path) == {"sql_injection"}


@pytest.mark.parametrize(
    "path",
    [
        "/../../etc/passwd",
        "/files?name=..%2f..%2fetc%2fpasswd",
        "/%252e%252e/%252e%252e/etc/passwd",
        "/static/..\\..\\windows\\win.ini",
    ],
)
def test_traversal_detected(path):
    assert kinds(path) == {"directory_traversal"}


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/index.html",
        "/about",
        "/products?id=5",
        "/search?q=rock+and+roll",
        "/search?q=O%27Reilly",
        "/blog/how-to-select-a-camera?page=2",
        "/my--page",
        "/files/v1..2/readme.txt",
        "/colors?name=color+1=1",
    ],
)
def test_benign_paths_no_alert(path):
    assert detect(entry(path)) == []


def test_sample_file_exact_alerts():
    alerts = [a for e in parse_file(SAMPLE) for a in detect(e)]
    found = {(a.ip, a.kind) for a in alerts}
    assert found == {
        ("192.0.2.44", "sql_injection"),
        ("192.0.2.44", "directory_traversal"),
    }
    assert len(alerts) == 2
