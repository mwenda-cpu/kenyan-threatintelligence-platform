"""
Tor onion scraper for dark web leak sites.

Routes requests through the Tor SOCKS5 proxy (socks5h://tor:9050) to scrape
.onion sites. Parses raw HTML, strips tags, and runs Kenyan keyword/PII
extraction against the text. Saves hits to paste_hits with source="DarkWeb_Tor".
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional

import requests
from bs4 import BeautifulSoup

from darkweb_scanner.storage import Storage

logger = logging.getLogger(__name__)

# Tor SOCKS5 proxy — uses the Docker service name 'tor' on port 9050
TOR_PROXY = {
    "http": "socks5h://tor:9050",
    "https": "socks5h://tor:9050",
}

REQUEST_TIMEOUT = 30
MAX_TEXT_LEN = 50_000

# Sample .onion targets to crawl (public directories / leak sites)
ONION_TARGETS = [
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",  # Ahmia
]


def _fetch_onion(url: str) -> Optional[str]:
    """Fetch raw HTML from an .onion URL via Tor proxy."""
    try:
        resp = requests.get(
            url,
            proxies=TOR_PROXY,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; OSINTPH-TorScraper/1.0)"},
        )
        resp.raise_for_status()
        return resp.text
    except Exception as exc:
        logger.warning("Failed to fetch %s via Tor: %s", url, exc)
        return None


def _strip_html(html: str) -> str:
    """Strip HTML tags and return plain text."""
    try:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "noscript", "header", "footer", "nav"]):
            tag.decompose()
        text = soup.get_text(" ", strip=True)
        return text[:MAX_TEXT_LEN]
    except Exception:
        # Fallback: regex strip
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:MAX_TEXT_LEN]


def scrape_onion(storage: Storage, targets: list[str] = None) -> dict:
    """Scrape .onion sites via Tor and extract Kenyan threat indicators.

    Loads active keywords from the keywords table, lowercases page text, and
    for each keyword occurrence inserts a separate paste_hits row with
    matched_pattern=<keyword>, matched_value=<context>, status_badges="KENYA".

    Deduplicates by (paste_id, matched_pattern). Pages matching zero keywords
    insert no rows.

    Returns a summary dict.
    """
    if targets is None:
        targets = ONION_TARGETS

    total_scanned = 0
    total_hits = 0
    per_target: dict[str, dict] = {}

    # Load active keywords from the keywords table
    try:
        keyword_list = storage.get_active_keywords()
        keywords = {k["keyword"].lower(): k["keyword"] for k in keyword_list}
    except Exception:
        keywords = {}

    for url in targets:
        logger.info("Scraping onion target: %s", url)
        html = _fetch_onion(url)
        if not html:
            per_target[url] = {"error": "fetch failed", "hits": 0}
            continue

        text = _strip_html(html)
        total_scanned += 1
        text_lower = text.lower()

        # Find all keywords present in the page text
        matched_keywords: dict[str, str] = {}
        for kw_lower, kw_original in keywords.items():
            if kw_lower in text_lower:
                matched_keywords[kw_lower] = kw_original

        if not matched_keywords:
            per_target[url] = {
                "hits": 0,
                "matched_keywords": [],
                "text_length": len(text),
            }
            continue

        hits_found = 0
        # Insert a separate paste_hits row per matching keyword
        for kw_lower, kw_original in matched_keywords.items():
            idx = text_lower.find(kw_lower)
            start = max(0, idx - 200)
            end = min(len(text), idx + len(kw_lower) + 200)
            context = text[start:end]

            paste_id = f"onion_kw_{abs(hash(url + kw_lower))}"

            # Deduplicate by (source, paste_id, matched_pattern)
            if storage.is_paste_seen("DarkWeb_Tor", paste_id):
                continue

            try:
                storage.save_paste_hit(
                    paste_id=paste_id,
                    url=url,
                    source="DarkWeb_Tor",
                    matched_pattern=kw_original,
                    matched_value=context.strip()[:500],
                    context=context.strip()[:500],
                    status_badges="KENYA",
                )
                storage.mark_paste_seen("DarkWeb_Tor", paste_id, url, had_hits=True)
                hits_found += 1
                total_hits += 1
            except Exception as exc:
                logger.debug("Failed to save keyword hit for %s: %s", kw_lower, exc)

        per_target[url] = {
            "hits": hits_found,
            "matched_keywords": list(matched_keywords.values()),
            "text_length": len(text),
        }
        logger.info(
            "Onion scrape %s: %d hits, matched_keywords=%s",
            url, hits_found, list(matched_keywords.values()),
        )

    return {
        "scanned": total_scanned,
        "total_hits": total_hits,
        "per_target": per_target,
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }


if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from darkweb_scanner.storage import Storage

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    storage = Storage()
    summary = scrape_onion(storage)
    print(f"\nOnion scrape complete: {summary}")
    for url, info in summary["per_target"].items():
        print(f"  {url}: {info}")
