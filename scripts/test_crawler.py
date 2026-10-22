#!/usr/bin/env python3
"""Standalone Tor connectivity + keyword test for the onion crawler.

Fetches ONE .onion URL through socks5h://tor:9050 (aiohttp routed over
aiohttp_socks.ProxyConnector via TorClient), scans the page for keywords,
and reports what matched.

Runnable from inside the dashboard container:

    docker compose exec dashboard python scripts/test_crawler.py

Exit codes:
    0 - Tor reachable and at least one keyword matched
    1 - Tor failure (could not fetch through the proxy)
    2 - Tor reachable but zero keyword matches (connectivity OK, zero signal)
"""

import asyncio
import json
import sys
from pathlib import Path

# Make `darkweb_scanner` importable when run as `python scripts/test_crawler.py`
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from darkweb_scanner.crawler import _fetch_page
from darkweb_scanner.keywords_db import keyword_config
from darkweb_scanner.scanner import Scanner
from darkweb_scanner.storage import Storage
from darkweb_scanner.tor_client import create_tor_client

CONFIG_DIR = Path("/app/config")
KEYWORDS_DEFAULT = CONFIG_DIR / "keywords.yaml"
SOURCES_DEFAULT = CONFIG_DIR / "sources.json"
FETCH_TIMEOUT = 45  # seconds


def _load_seeds(storage: Storage) -> list[str]:
    """Active onion seeds from the DB; fall back to config/sources.json."""
    seeds = storage.get_active_seeds()
    if seeds:
        return seeds
    if SOURCES_DEFAULT.exists():
        try:
            data = json.loads(SOURCES_DEFAULT.read_text(encoding="utf-8") or "{}")
            return [str(u) for u in (data.get("onion_seeds") or []) if u]
        except Exception:
            return []
    return []


async def main() -> int:
    storage = Storage()
    seeds = _load_seeds(storage)
    if not seeds:
        print("No onion seeds available (seeds table and config/sources.json are empty)", flush=True)
        return 1

    url = seeds[0]
    print(f"Fetching {url} through socks5h://tor:9050 (timeout {FETCH_TIMEOUT}s)...", flush=True)

    tor = create_tor_client()
    tor.request_timeout = FETCH_TIMEOUT
    session = await tor.get_session()
    text, error = await _fetch_page(session, url)
    await tor.close()

    if error:
        print(f"Tor failure: {error}", flush=True)
        return 1

    print("---- first 500 chars of response ----", flush=True)
    print(text[:500], flush=True)
    print("---- end ----", flush=True)

    kw_config = keyword_config(storage, KEYWORDS_DEFAULT)
    scanner = Scanner(kw_config)
    hits = scanner.scan(url=url, text=text, depth=0)
    matched = sorted({hit.keyword for hit in hits})
    print(f"Matched keywords: {matched}", flush=True)

    if not matched:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
