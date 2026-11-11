from mini_siem.detector import Alert

MAX_PATH_LEN = 200


def format_alert(alert: Alert) -> str:
    """Ubah Alert jadi teks biasa untuk Telegram (tanpa parse_mode)."""
    path = alert.path
    if len(path) > MAX_PATH_LEN:
        # Path berasal dari penyerang: dipotong agar pesan tetap pendek.
        path = path[:MAX_PATH_LEN] + "..."
    return (
        f"[ALERT] {alert.kind}\n"
        f"IP: {alert.ip}\n"
        f"Waktu: {alert.time.strftime('%Y-%m-%d %H:%M:%S %z')}\n"
        f"Path: {path}\n"
        f"Detail: {alert.detail}"
    )
