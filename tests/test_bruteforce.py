from datetime import UTC, datetime, timedelta
from pathlib import Path

from mini_siem.bruteforce import BruteForceDetector
from mini_siem.parser import parse_file

SAMPLE = Path(__file__).parent.parent / "samples" / "access.log"
BASE = datetime(2026, 11, 11, 10, 0, tzinfo=UTC)


def e(ip="198.51.100.7", sec=0, path="/login", status=401):
    return {
        "ip": ip,
        "time": BASE + timedelta(seconds=sec),
        "path": path,
        "status": status,
    }


def run(entries):
    det = BruteForceDetector()
    return [det.feed(x) for x in entries]


def test_five_failures_in_window_alert_on_fifth():
    results = run([e(sec=i) for i in range(5)])
    assert results[:4] == [None] * 4
    assert results[4].kind == "brute_force"
    assert results[4].ip == "198.51.100.7"


def test_slow_failures_no_alert():
    results = run([e(sec=i * 20) for i in range(5)])
    assert all(r is None for r in results)


def test_successful_logins_not_counted():
    entries = [e(sec=i) for i in range(4)] + [e(sec=5 + i, status=200) for i in range(5)]
    assert all(r is None for r in run(entries))


def test_other_paths_ignored():
    entries = [e(sec=i, path="/api/data") for i in range(10)]
    assert all(r is None for r in run(entries))


def test_login_with_query_string_counts():
    results = run([e(sec=i, path="/login?next=/home") for i in range(5)])
    assert results[4] is not None


def test_different_ips_counted_separately():
    entries = []
    for i in range(3):
        entries.append(e(ip="198.51.100.7", sec=i))
        entries.append(e(ip="198.51.100.8", sec=i))
    assert all(r is None for r in run(entries))


def test_new_burst_alerts_again():
    alerts = [r for r in run([e(sec=i) for i in range(10)]) if r]
    assert len(alerts) == 2


def test_sample_file_one_brute_force_alert():
    det = BruteForceDetector()
    alerts = [a for x in parse_file(SAMPLE) if (a := det.feed(x))]
    assert len(alerts) == 1
    assert alerts[0].ip == "198.51.100.7"
