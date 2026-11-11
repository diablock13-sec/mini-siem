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

    def export(self) -> dict[str, list[str]]:
        """Hitungan gagal login per IP sebagai data sederhana: {ip: [waktu ISO]}."""
        lasts = [times[-1] for times in self._failures.values() if times]
        if not lasts:
            return {}
        ref = max(lasts)  # waktu log terbaru, bukan jam sistem
        return {
            ip: [t.isoformat() for t in times]
            for ip, times in self._failures.items()
            if times and ref - times[-1] <= self.window
        }

    def restore(self, data: dict[str, list[str]]) -> None:
        """Muat hasil export(). Waktu rusak atau tanpa zona dilewati, jumlah dibatasi."""
        keep = max(self.threshold - 1, 0)
        for ip, isos in data.items():
            if len(self._failures) >= self.max_tracked:
                break
            times = []
            for iso in isos:
                try:
                    t = datetime.fromisoformat(iso)
                except ValueError:
                    continue
                if t.tzinfo is None:
                    continue  # tidak bisa dibandingkan dengan waktu log yang punya zona
                times.append(t)
            times.sort()
            times = times[max(len(times) - keep, 0) :]
            if times:
                self._failures[ip] = deque(times)

    def _prune(self, now: datetime) -> None:
        """Buang IP yang sudah lama tidak gagal login, supaya memori tidak membengkak."""
        for ip in list(self._failures):
            times = self._failures[ip]
            if not times or now - times[-1] > self.window:
                del self._failures[ip]
