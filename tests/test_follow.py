from mini_siem.follow import follow


def jalankan(path, aksi, berhenti_di, **kw):
    """Panggil `aksi(n)` tiap kali follow idle ke-n; berhenti setelah n >= berhenti_di."""
    state = {"n": 0}

    def sleep(_):
        state["n"] += 1
        aksi(state["n"])

    def stop():
        return state["n"] >= berhenti_di

    return list(follow(path, sleep=sleep, stop=stop, **kw))


def tambah(path, teks):
    with path.open("a", encoding="utf-8") as f:
        f.write(teks)


def test_hanya_baris_baru(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("lama\n")

    def aksi(n):
        if n == 1:
            tambah(p, "baru1\n")

    assert jalankan(p, aksi, 2) == ["baru1\n"]


def test_from_start_membaca_isi_lama(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("lama\n")
    assert jalankan(p, lambda n: None, 1, from_start=True) == ["lama\n"]


def test_baris_setengah_ditulis_ditunggu(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("")

    def aksi(n):
        if n == 1:
            tambah(p, "abc")
        elif n == 2:
            tambah(p, "def\n")

    assert jalankan(p, aksi, 3) == ["abcdef\n"]


def test_rotasi_file_dibaca_dari_awal(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("x\n")

    def aksi(n):
        if n == 1:
            p.rename(tmp_path / "a.log.1")
            p.write_text("baru\n")

    assert jalankan(p, aksi, 2) == ["baru\n"]


def test_truncate_dibaca_dari_awal(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("aaaa\nbbbb\n")

    def aksi(n):
        if n == 1:
            p.write_text("c\n")

    hasil = jalankan(p, aksi, 2, from_start=True)
    assert hasil == ["aaaa\n", "bbbb\n", "c\n"]
