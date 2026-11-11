import os

import httpx
from dotenv import load_dotenv

load_dotenv()

API = "https://api.telegram.org/bot{token}/sendMessage"


def send_message(text: str) -> None:
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    resp = httpx.post(
        API.format(token=token),
        data={"chat_id": chat_id, "text": text},
        timeout=10,
    )
    resp.raise_for_status()
