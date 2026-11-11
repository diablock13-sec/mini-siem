import argparse
import logging
import sys
import time
from pathlib import Path

from mini_siem.follow import follow_with_position
from mini_siem.parser import parse_file, parse_line
from mini_siem.pipeline import Pipeline
from mini_siem.state import State, default_state_path, load_state, save_state

log = logging.getLogger(__name__)

SAVE_EVERY_LINES = 50
SAVE_EVERY_SECONDS = 10.0


def _save(state_path: Path, logfile: Path, pos: tuple[int, int], pipeline: Pipeline) -> None:
    state = State(
        logfile=str(logfile),
        inode=pos[0],
        offset=pos[1],
        sent=[list(item) for item in pipeline.limiter.export()],
        failures=pipeline.brute.export(),
    )
    try:
        save_state(state_path, state)
    except OSError as exc:
        log.error("gagal simpan state: %s", type(exc).__name__)


def _run_follow(args: argparse.Namespace, pipeline: Pipeline) -> int:
    persist = not args.dry_run
    state_path = args.state or default_state_path()
    logfile = args.logfile.resolve()
    state = load_state(state_path) if persist else State()
    pipeline.limiter.restore(state.sent)
    pipeline.brute.restore(state.failures)

    resume = None
    if state.logfile == str(logfile) and state.inode is not None and state.offset is not None:
        resume = (state.inode, state.offset)
    pos = resume
    if pos is None and not args.from_start:
        st = logfile.stat()
        pos = (st.st_ino, st.st_size)

    print(f"mengikuti {logfile}, Ctrl+C untuk berhenti", file=sys.stderr)
    total = since_save = 0
    last_save = time.monotonic()
    try:
        for line, inode, offset in follow_with_position(
            logfile, from_start=args.from_start, resume=resume
        ):
            entry = parse_line(line)
            if entry is None:
                log.warning("baris tidak bisa dibaca, dilewati")
            else:
                total += len(pipeline.process(entry))
            pos = (inode, offset)
            since_save += 1
            due = since_save >= SAVE_EVERY_LINES
            if persist and (due or time.monotonic() - last_save >= SAVE_EVERY_SECONDS):
                _save(state_path, logfile, pos, pipeline)
                since_save, last_save = 0, time.monotonic()
    except KeyboardInterrupt:
        print(file=sys.stderr)
    finally:
        if persist and pos is not None:
            _save(state_path, logfile, pos, pipeline)
    return total


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mini-siem")
    ap.add_argument("logfile", type=Path, help="file log Nginx (format combined)")
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="cetak alert ke layar, jangan kirim ke Telegram dan jangan simpan state",
    )
    ap.add_argument(
        "-f", "--follow", action="store_true", help="ikuti file seperti tail -f"
    )
    ap.add_argument(
        "--from-start",
        action="store_true",
        help="dengan --follow: baca isi lama dulu. Diabaikan kalau state sudah ada",
    )
    ap.add_argument(
        "--state",
        type=Path,
        help="file state untuk --follow (default: ~/.local/state/mini-siem/state.json)",
    )
    args = ap.parse_args(argv)
    if args.from_start and not args.follow:
        ap.error("--from-start hanya berlaku bersama --follow")
    if not args.logfile.is_file():
        ap.error(f"file tidak ditemukan: {args.logfile}")

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    # httpx mencatat URL tiap request di level INFO, dan URL memuat token bot.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    if args.dry_run:

        def send(text: str) -> None:
            print(text, end="\n\n")

    else:
        from mini_siem.telegram import send_message as send

    pipeline = Pipeline(send)
    if args.follow:
        total = _run_follow(args, pipeline)
    else:
        total = 0
        try:
            for entry in parse_file(args.logfile):
                total += len(pipeline.process(entry))
        except KeyboardInterrupt:
            print(file=sys.stderr)
    verb = "dicetak" if args.dry_run else "dikirim"
    print(f"{total} alert {verb}")
    return 0
