from pathlib import Path

from mini_siem.cli import main

SAMPLE = Path(__file__).parent.parent / "samples" / "access.log"


def test_dry_run_one_shot_prints_three_alerts(capsys):
    rc = main(["--dry-run", str(SAMPLE)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "3 alert dicetak" in out
    assert "dikirim" not in out
    assert "[ALERT] brute_force" in out
    assert "[ALERT] sql_injection" in out
    assert "[ALERT] directory_traversal" in out
