import logging
from datetime import UTC, datetime, timedelta

import httpx

from mini_siem.pipeline import Pipeline

T0 = datetime(2026, 11, 11, 10, 0, 0, tzinfo=UTC)
SQLI = "/search?q=1' OR '1'='1"


def entri(ip="203.0.113.7", path="/index.html", status=200, detik=0) -> dict:
    return {
        "ip": ip,
        "time": T0 + timedelta(seconds=detik),
        "method": "GET",
        "path": path,
        "status": status,
        "size": 0,
        "referer": "-",
        "user_agent": "test",
    }


def buat_pipeline() -> tuple[Pipeline, list[str]]:
    terkirim: list[str] = []
    return Pipeline(terkirim.append), terkirim


def test_entri_jinak_tidak_mengirim_apa_apa():
    pipe, terkirim = buat_pipeline()
    assert pipe.process(entri()) == []
    assert terkirim == []


def test_sql_injection_mengirim_satu_alert():
    pipe, terkirim = buat_pipeline()
    sent = pipe.process(entri(path=SQLI))
    assert [a.kind for a in sent] == ["sql_injection"]
    assert len(terkirim) == 1
    assert "203.0.113.7" in terkirim[0]


def test_serangan_berulang_dibatasi_laju():
    pipe, terkirim = buat_pipeline()
    pipe.process(entri(path=SQLI, detik=0))
    pipe.process(entri(path=SQLI, detik=30))
    assert len(terkirim) == 1


def test_brute_force_mengirim_satu_alert():
    pipe, terkirim = buat_pipeline()
    for i in range(pipe.brute.threshold):
        pipe.process(entri(path="/login", status=401, detik=i))
    assert len(terkirim) == 1
    assert "brute_force" in terkirim[0]


def test_gagal_kirim_tidak_crash_dan_token_tidak_bocor(caplog):
    req = httpx.Request("POST", "https://api.telegram.org/botRAHASIA123/sendMessage")

    def send_gagal(text: str) -> None:
        raise httpx.HTTPStatusError(
            f"401 untuk {req.url}", request=req, response=httpx.Response(401, request=req)
        )

    pipe = Pipeline(send_gagal)
    with caplog.at_level(logging.ERROR):
        sent = pipe.process(entri(path=SQLI))
    assert sent == []
    assert "401" in caplog.text
    assert "RAHASIA123" not in caplog.text
