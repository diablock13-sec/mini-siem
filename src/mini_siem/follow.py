import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path


def follow_with_position(
    path: Path,
    poll: float = 0.5,
    from_start: bool = False,
    resume: tuple[int, int] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    stop: Callable[[], bool] | None = None,
) -> Iterator[tuple[str, int, int]]:
    """Ikuti file seperti `tail -f`. Keluarkan (baris, inode, offset setelah baris).

    Hanya baris lengkap (berakhir newline) yang dikeluarkan.
    `resume` = (inode, offset) dari state lama. Kalau inode beda atau file lebih
    pendek dari offset, file diganti atau dipotong saat program mati: baca dari awal.
    `sleep` dan `stop` ada supaya bisa dites tanpa menunggu waktu nyata.
    """

    def open_file():
        return path.open(encoding="utf-8", errors="replace")

    f = open_file()
    try:
        st0 = os.fstat(f.fileno())
        inode = st0.st_ino
        if resume is not None:
            if resume[0] == inode and resume[1] <= st0.st_size:
                f.seek(resume[1])
        elif not from_start:
            f.seek(0, os.SEEK_END)
        buf = ""
        while True:
            chunk = f.readline()
            if chunk:
                buf += chunk
                if buf.endswith("\n"):
                    yield buf, inode, f.tell()
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


def follow(
    path: Path,
    poll: float = 0.5,
    from_start: bool = False,
    sleep: Callable[[float], None] = time.sleep,
    stop: Callable[[], bool] | None = None,
) -> Iterator[str]:
    """Sama seperti follow_with_position, tapi hanya mengeluarkan teks baris."""
    for line, _, _ in follow_with_position(
        path, poll=poll, from_start=from_start, sleep=sleep, stop=stop
    ):
        yield line
