from collections import defaultdict, deque
from datetime import datetime, timedelta

from mini_siem.detector import Alert


class BruteForceDetector:
    """Alert kalau satu IP gagal login `threshold` kali dalam `window_seconds`."""

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
        login_paths: tuple[str, ...] = ("/login",),
        statuses: tuple[int, ...] = (401, 403),
        max_tracked: int = 10_000,
    ):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.login_paths = login_paths
        self.statuses = statuses
        self.max_tracked = max_tracked
        self._failures: dict[str, deque[datetime]] = defaultdict(deque)

    def feed(self, entry: dict) -> Alert | None:
        """Proses satu entri log. Kembalikan Alert, atau None."""
        if entry["status"] not in self.statuses:
            return None
        if entry["path"].split("?")[0] not in self.login_paths:
            return None

        ip, now = entry["ip"], entry["time"]
        times = self._failures[ip]
        times.append(now)
        while times and now - times[0] > self.window:
            times.popleft()

        if len(times) >= self.threshold:
            times.clear()  # butuh gelombang baru untuk alert berikutnya
            return Alert(
                "brute_force",
                ip,
                now,
                entry["path"],
                f"{self.threshold} gagal login dalam {int(self.window.total_seconds())} detik",
            )

        if len(self._failures) > self.max_tracked:
            self._prune(now)
        return None

    def _prune(self, now: datetime) -> None:
        """Buang IP yang sudah lama tidak gagal login, supaya memori tidak membengkak."""
        for ip in list(self._failures):
            times = self._failures[ip]
            if not times or now - times[-1] > self.window:
                del self._failures[ip]
