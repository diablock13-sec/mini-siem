from datetime import datetime, timedelta

from mini_siem.detector import Alert


class AlertLimiter:
    """Izinkan maksimal 1 alert per (IP, jenis serangan) per `window_seconds`."""

    def __init__(self, window_seconds: int = 300, max_tracked: int = 10_000):
        self.window = timedelta(seconds=window_seconds)
        self.max_tracked = max_tracked
        self._last_sent: dict[tuple[str, str], datetime] = {}

    def allow(self, alert: Alert) -> bool:
        """True kalau alert boleh dikirim. Alert yang ditahan tidak memperpanjang jendela."""
        key = (alert.ip, alert.kind)
        last = self._last_sent.get(key)
        if last is not None and alert.time - last < self.window:
            return False

        self._last_sent[key] = alert.time
        if len(self._last_sent) > self.max_tracked:
            self._prune(alert.time)
        return True

    def _prune(self, now: datetime) -> None:
        """Buang entri yang jendelanya sudah lewat, supaya memori tidak membengkak."""
        for key in list(self._last_sent):
            if now - self._last_sent[key] >= self.window:
                del self._last_sent[key]
