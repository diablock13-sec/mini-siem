import argparse
import logging
from pathlib import Path

from mini_siem.parser import parse_file
from mini_siem.pipeline import Pipeline


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mini-siem")
    ap.add_argument("logfile", type=Path, help="file log Nginx (format combined)")
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="cetak alert ke layar, jangan kirim ke Telegram",
    )
    args = ap.parse_args(argv)
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
    for entry in parse_file(args.logfile):
        total += len(pipeline.process(entry))
    print(f"{total} alert dikirim")
    return 0
