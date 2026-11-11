import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path


def follow(
    path: Path,
    poll: float = 0.5,
    from_start: bool = False,
    sleep: Callable[[float], None] = time.sleep,
    stop: Callable[[], bool] | None = None,
) -> Iterator[str]:
    """Ikuti file seperti `tail -f`. Hanya baris lengkap (berakhir newline) yang dikeluarkan.

    `sleep` dan `stop` ada supaya bisa dites tanpa menunggu waktu nyata.
    """

    def open_file():
        return path.open(encoding="utf-8", errors="replace")

    f = open_file()
    try:
        if not from_start:
            f.seek(0, os.SEEK_END)
        inode = os.fstat(f.fileno()).st_ino
        buf = ""
        while True:
            chunk = f.readline()
            if chunk:
                buf += chunk
                if buf.endswith("\n"):
                    yield buf
                    buf = ""
                continue

            # Tidak ada data baru.
            if stop is not None and stop():
                return
            try:
                st = os.stat(path)
            except FileNotFoundError:
                st = None  # sedang dirotasi, file baru belum ada
            if st is not None and (st.st_ino != inode or st.st_size < f.tell()):
                f.close()
                f = open_file()
                inode = os.fstat(f.fileno()).st_ino
                buf = ""
                continue
            sleep(poll)
    finally:
        f.close()
