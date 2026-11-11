from datetime import timedelta
from pathlib import Path

from mini_siem.parser import parse_file, parse_line

SAMPLE = Path(__file__).parent.parent / "samples" / "access.log"

NORMAL = (
    '203.0.113.5 - - [11/Nov/2026:10:00:01 +0700] '
    '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (X11; Linux x86_64)"'
)
LOGIN_FAIL = (
    '198.51.100.7 - - [11/Nov/2026:10:01:10 +0700] '
    '"POST /login HTTP/1.1" 401 128 "-" "curl/8.5.0"'
)
SQLI = (
    '192.0.2.44 - - [11/Nov/2026:10:02:30 +0700] '
    '"GET /products?id=1%27%20OR%201=1-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"'
)
WITH_REFERER = (
    '203.0.113.9 - - [11/Nov/2026:10:03:00 +0700] '
    '"GET /contact HTTP/1.1" 200 - "https://example.com/" "Mozilla/5.0"'
)


def test_normal_line():
    e = parse_line(NORMAL)
    assert e["ip"] == "203.0.113.5"
    assert e["method"] == "GET"
    assert e["path"] == "/index.html"
    assert e["status"] == 200
    assert e["size"] == 1024
    assert e["time"].hour == 10
    assert e["time"].utcoffset() == timedelta(hours=7)


def test_failed_login():
    e = parse_line(LOGIN_FAIL)
    assert e["method"] == "POST"
    assert e["path"] == "/login"
    assert e["status"] == 401
    assert e["user_agent"] == "curl/8.5.0"


def test_sqli_path_kept_raw():
    e = parse_line(SQLI)
    assert e["path"] == "/products?id=1%27%20OR%201=1--"
    assert e["user_agent"] == "sqlmap/1.7"


def test_dash_size_and_referer():
    e = parse_line(WITH_REFERER)
    assert e["size"] == 0
    assert e["referer"] == "https://example.com/"


def test_garbage_returns_none():
    assert parse_line("ini bukan log") is None
    assert parse_line("") is None


def test_sample_file_all_lines_parse():
    entries = list(parse_file(SAMPLE))
    assert len(entries) == 10
