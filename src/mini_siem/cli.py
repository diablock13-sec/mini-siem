import argparse
import logging
import sys
from pathlib import Path

from mini_siem.follow import follow
from mini_siem.parser import parse_file, parse_line
from mini_siem.pipeline import Pipeline

log = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mini-siem")
    ap.add_argument("logfile", type=Path, help="file log Nginx (format combined)")
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="cetak alert ke layar, jangan kirim ke Telegram",
    )
    ap.add_argument(
        "-f", "--follow", action="store_true", help="ikuti file seperti tail -f"
    )
    ap.add_argument(
        "--from-start",
        action="store_true",
        help="dengan --follow: baca isi lama dulu, bukan hanya baris baru",
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
    total = 0
    try:
        if args.follow:
            print(f"mengikuti {args.logfile}, Ctrl+C untuk berhenti", file=sys.stderr)
            for line in follow(args.logfile, from_start=args.from_start):
                entry = parse_line(line)
                if entry is None:
                    log.warning("baris tidak bisa dibaca, dilewati")
                    continue
                total += len(pipeline.process(entry))
        else:
            for entry in parse_file(args.logfile):
                total += len(pipeline.process(entry))
    except KeyboardInterrupt:
        print(file=sys.stderr)
    print(f"{total} alert dikirim")
    return 0
