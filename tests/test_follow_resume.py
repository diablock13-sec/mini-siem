import os

from mini_siem.follow import follow_with_position


def baca(path, berhenti_di=1, **kw):
    state = {"n": 0}

    def sleep(_):
        state["n"] += 1

    return list(
        follow_with_position(
            path, sleep=sleep, stop=lambda: state["n"] >= berhenti_di, **kw
        )
    )


def inode(path):
    return os.stat(path).st_ino


def teks(hasil):
    return [line for line, _, _ in hasil]


def test_offset_dilaporkan_setelah_tiap_baris(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("ab\ncd\n")
    hasil = baca(p, from_start=True)
    assert [(line, off) for line, _, off in hasil] == [("ab\n", 3), ("cd\n", 6)]
    assert all(i == inode(p) for _, i, _ in hasil)


def test_resume_lanjut_dari_offset(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("a\nb\nc\n")
    assert teks(baca(p, resume=(inode(p), 2))) == ["b\n", "c\n"]


def test_resume_di_akhir_file_tidak_mengulang(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("a\n")
    assert baca(p, resume=(inode(p), 2)) == []


def test_resume_inode_beda_baca_dari_awal(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("a\nb\n")
    assert teks(baca(p, resume=(inode(p) + 1, 2))) == ["a\n", "b\n"]


def test_resume_offset_melebihi_ukuran_baca_dari_awal(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("a\n")
    assert teks(baca(p, resume=(inode(p), 999))) == ["a\n"]
