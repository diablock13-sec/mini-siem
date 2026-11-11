from datetime import UTC, datetime

import pytest

from mini_siem.bruteforce import BruteForceDetector
from mini_siem.detector import detect
from mini_siem.rules import RulesError, default_rules, load_rules

MINIMAL = """\
sql_injection:
  - name: evil
    pattern: evilword
directory_traversal:
  - name: dots
    pattern: zzz
"""

BENIGN = [
    "/",
    "/index.html",
    "/search?q=select+shoes",
    "/blog/union-station-guide",
    "/blog/sleep-tips",
    "/products?category=or&sort=asc",
    "/api/users?id=42",
    "/docs/sql-tutorial",
    "/docs/information-schema-overview",
    "/files/report..final.pdf",
    "/images/my..photo.jpg",
    "/search?q=O%27Brien",
    "/static/app.min.js?v=1.2.3",
    "/login?next=%2Fhome",
]

ATTACKS = [
    ("/item?id=1' OR 1=1--", "sql_injection"),
    ("/p?id=1+UNION+ALL+SELECT+null", "sql_injection"),
    ("/p?id=1;select+sleep(5)", "sql_injection"),
    ("/download?f=../../etc/passwd", "directory_traversal"),
    ("/download?f=%2e%2e%2fetc/passwd", "directory_traversal"),
    ("/download?f=%252e%252e%252fetc/passwd", "directory_traversal"),
]


def entry(path):
    return {
        "ip": "203.0.113.5",
        "time": datetime(2026, 11, 11, 10, 0, tzinfo=UTC),
        "path": path,
    }


def write(tmp_path, text):
    f = tmp_path / "rules.yaml"
    f.write_text(text, encoding="utf-8")
    return f


@pytest.mark.parametrize("path", BENIGN)
def test_benign_paths_no_alert(path):
    assert detect(entry(path)) == []


@pytest.mark.parametrize(("path", "kind"), ATTACKS)
def test_attacks_alert(path, kind):
    assert kind in {a.kind for a in detect(entry(path))}


def test_default_brute_force_config():
    det = BruteForceDetector(**default_rules().brute_force)
    assert det.threshold == 5
    assert det.window.total_seconds() == 60


def test_custom_rules_replace_defaults(tmp_path):
    rules = load_rules(write(tmp_path, MINIMAL))
    alerts = detect(entry("/a?evilword"), rules)
    assert [(a.kind, a.detail) for a in alerts] == [("sql_injection", "evil")]
    assert detect(entry("/a?1' or 1=1"), rules) == []


def test_bad_regex_names_the_rule(tmp_path):
    text = 'sql_injection:\n  - name: bad\n    pattern: "(unclosed"\n'
    with pytest.raises(RulesError, match="bad"):
        load_rules(write(tmp_path, text))


def test_missing_section(tmp_path):
    with pytest.raises(RulesError, match="sql_injection"):
        load_rules(write(tmp_path, "sql_injection: []\n"))


def test_unknown_brute_force_key(tmp_path):
    text = MINIMAL + "brute_force:\n  treshold: 3\n"
    with pytest.raises(RulesError, match="treshold"):
        load_rules(write(tmp_path, text))


def test_broken_yaml(tmp_path):
    with pytest.raises(RulesError, match="YAML"):
        load_rules(write(tmp_path, "sql_injection: [\n"))
