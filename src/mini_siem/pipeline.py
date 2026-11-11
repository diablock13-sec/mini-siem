import logging
from collections.abc import Callable

import httpx

from mini_siem.alerting import format_alert
from mini_siem.bruteforce import BruteForceDetector
from mini_siem.detector import Alert, detect
from mini_siem.ratelimit import AlertLimiter
from mini_siem.rules import Rules, default_rules

log = logging.getLogger(__name__)


class Pipeline:
    """Satu entri log masuk: deteksi, batasi laju, kirim."""

    def __init__(
        self,
        send: Callable[[str], None],
        rules: Rules | None = None,
        limiter: AlertLimiter | None = None,
    ):
        self.rules = default_rules() if rules is None else rules
        self.brute = BruteForceDetector(**self.rules.brute_force)
        self.limiter = AlertLimiter() if limiter is None else limiter
        self.send = send

    def process(self, entry: dict) -> list[Alert]:
        """Kembalikan alert yang benar-benar terkirim."""
        alerts = detect(entry, self.rules)
        brute = self.brute.feed(entry)
        if brute is not None:
            alerts.append(brute)

        sent = []
        for alert in alerts:
            if not self.limiter.allow(alert):
                continue
            try:
                self.send(format_alert(alert))
            except httpx.HTTPStatusError as exc:
                # Jangan catat str(exc): isinya URL dengan token bot.
                log.error("gagal kirim alert: HTTP %d", exc.response.status_code)
                continue
            except httpx.HTTPError as exc:
                log.error("gagal kirim alert: %s", type(exc).__name__)
                continue
            self.limiter.record(alert)
            sent.append(alert)
        return sent
