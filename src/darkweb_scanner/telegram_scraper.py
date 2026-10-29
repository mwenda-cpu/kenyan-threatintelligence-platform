"""
Telegram channel scraper — monitors public channels for keyword hits.
Uses Telethon to read messages without joining channels.
Requires a Telegram API ID and Hash from https://my.telegram.org
"""

import asyncio
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml
from telethon.sessions import StringSession

logger = logging.getLogger(__name__)

# Default Kenyan keywords used as a fallback when no keyword list is configured.
DEFAULT_KENYAN_KEYWORDS = ["m-pesa", "m pesa", "mpesa", "kcb", "ecitizen", "safaricom"]


@dataclass
class TelegramConfig:
    api_id: int
    api_hash: str
    session_path: str
    channels: list[str]
    session_string: Optional[str] = None
    limit_per_channel: int = 200

    @classmethod
    def from_env(cls) -> Optional["TelegramConfig"]:
        api_id = os.getenv("TELEGRAM_API_ID")
        api_hash = os.getenv("TELEGRAM_API_HASH")
        channels_raw = os.getenv("TELEGRAM_CHANNELS", "")
        if not api_id or not api_hash:
            return None
        channels = [c.strip().lstrip("@") for c in channels_raw.split(",") if c.strip()]
        return cls(
            api_id=int(api_id),
            api_hash=api_hash,
            session_path=os.getenv("TELEGRAM_SESSION_PATH", "/app/data/telegram.session"),
            session_string=os.getenv("TELEGRAM_SESSION_STRING"),
            channels=channels,
            limit_per_channel=int(os.getenv("TELEGRAM_LIMIT_PER_CHANNEL", "200")),
        )


async def scrape_channels(
    config: TelegramConfig,
    scanner=None,
    storage=None,
    alerter=None,
    session_id: Optional[int] = None,
) -> dict:
    """
    Scrape Telegram channels for keyword hits.
    Returns summary dict with pages_scraped and hits_found.
    """
    try:
        from telethon import TelegramClient
        from telethon.errors import (
            ChannelPrivateError,
            FloodWaitError,
            UsernameInvalidError,
            UsernameNotOccupiedError,
        )
        from telethon.sessions import StringSession
    except ImportError:
        logger.error("telethon not installed. Run: pip install telethon")
        return {"pages_scraped": 0, "hits_found": 0}

    if not config.channels:
        logger.warning("No Telegram channels configured. Set TELEGRAM_CHANNELS in .env")
        return {"pages_scraped": 0, "hits_found": 0}

    # TELEGRAM_SESSION_STRING takes precedence for headless/background runs;
    # otherwise fall back to the .session file path.
    session = StringSession(config.session_string) if config.session_string else config.session_path

    pages_scraped = 0
    hits_found = 0

    # Build/refresh the keyword scanner if none was provided or it has no
    # keywords — fall back to the seed YAML and a default Kenyan keyword list.
    if scanner is None or getattr(scanner, "keyword_count", 0) == 0:
        kw_list: list[str] = []
        yaml_path = Path("/app/config/keywords.yaml")
        try:
            if yaml_path.exists():
                raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
                keywords = raw.get("keywords", raw) or {}
                if isinstance(keywords, dict):
                    for key, value in keywords.items():
                        if isinstance(value, dict):
                            kw_list.append(str(key))
                        elif isinstance(value, (list, tuple, set)):
                            kw_list.extend(str(k) for k in value)
        except Exception:
            kw_list = []
        if not kw_list:
            kw_list = list(DEFAULT_KENYAN_KEYWORDS)
        # Normalize to lowercase for case-insensitive matching.
        kw_list = [k.lower() for k in kw_list if str(k).strip()]
        from ..scanner import KeywordConfig
        from ..scanner import Scanner as _ScannerClass

        kw_cfg = KeywordConfig.from_list(kw_list, category="telegram")
        scanner = _ScannerClass(kw_cfg)

    async with TelegramClient(
        session,
        config.api_id,
        config.api_hash,
    ) as client:
            if not await client.is_user_authorized():
                logger.error("Telegram session expired. Run: make telegram-auth to re-authenticate.")
                return {"pages_scraped": 0, "hits_found": 0}

            for channel in config.channels:
                logger.info(f"Scraping Telegram channel: @{channel} (limit={config.limit_per_channel})")
                channel_total = 0
                channel_text = 0
                channel_hits = 0

                try:
                    entity = await client.get_entity(channel)
                    async for message in client.iter_messages(
                        entity, limit=config.limit_per_channel
                    ):
                        channel_total += 1
                        # Capture text messages and media captions
                        text = message.text or message.message or ""
                        if not text.strip():
                            continue

                        channel_text += 1
                        pages_scraped += 1
                        url = f"https://t.me/{channel}/{message.id}"

                        if scanner is not None and storage is not None:
                            # Normalize to lowercase for case-insensitive matching.
                            text_lower = text.lower()
                            hits = scanner.scan(url=url, text=text_lower, depth=0)
                            for hit in hits:
                                hit_id = storage.save_hit(
                                    url=hit.url,
                                    keyword=hit.keyword,
                                    category=hit.category,
                                    context=hit.context,
                                    position=hit.position,
                                    depth=0,
                                    session_id=session_id,
                                    source_url=url,
                                )
                                hits_found += 1
                                channel_hits += 1
                                if alerter is not None and alerter.alert(hit):
                                    storage.mark_alerted(hit_id)

                        await asyncio.sleep(0.05)

                    logger.info(
                        f"@{channel}: {channel_total} total messages, "
                        f"{channel_text} with text, {channel_hits} keyword hits"
                    )

                except (UsernameNotOccupiedError, UsernameInvalidError):
                    logger.warning(f"Channel not found or invalid: @{channel}")
                except ChannelPrivateError:
                    logger.warning(f"Channel is private, cannot access: @{channel}")
                except FloodWaitError as e:
                    logger.warning(f"Flood wait {e.seconds}s for @{channel} — skipping")
                    await asyncio.sleep(e.seconds)
                except Exception as e:
                    logger.error(f"Error scraping @{channel}: {e}", exc_info=True)

    logger.info(f"Telegram scan complete. Messages with text: {pages_scraped} | Hits: {hits_found}")
    return {"pages_scraped": pages_scraped, "hits_found": hits_found}


async def interactive_auth(config: TelegramConfig):
    """
    Run interactive first-time authentication.
    Called by: make telegram-auth
    """
    try:
        from telethon import TelegramClient
    except ImportError:
        print("ERROR: telethon not installed. Run: pip install telethon")
        return

    session_file = Path(config.session_path)
    session_file.parent.mkdir(parents=True, exist_ok=True)

    # Refuse to run interactive auth in a non-interactive (headless) context:
    # client.start() would block on stdin for phone/OTP/2FA and raise EOFError.
    if not sys.stdin.isatty():
        print(
            "\nERROR: Interactive login required but running in a "
            "non-interactive (headless) environment. Telethon cannot prompt for "
            "phone/OTP/2FA here.\n"
            "       Generate a session on a machine with a TTY via 'make "
            "telegram-auth', then copy the .session file (or StringSession) "
            "into this environment. Alternatively set TELEGRAM_SESSION_STRING."
        )
        return

    print(f"\n{'=' * 55}")
    print("  Telegram Authentication")
    print(f"{'=' * 55}")
    print(f"  Session will be saved to: {config.session_path}")
    print(f"  API ID: {config.api_id}")
    print()

    client = TelegramClient(
        StringSession(config.session_string) if config.session_string else config.session_path,
        config.api_id,
        config.api_hash,
    )

    await client.start()
    me = await client.get_me()
    print(f"\n✅ Authenticated as: {me.first_name} (@{me.username})")
    print(f"   Session saved to: {config.session_path}")
    print("\nYou can now run Telegram scans with: make telegram-scan")
    await client.disconnect()
