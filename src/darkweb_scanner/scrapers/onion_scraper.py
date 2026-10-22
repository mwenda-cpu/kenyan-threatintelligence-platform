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
from darkweb_scanner.scrapers.keyword_extractor import extract_kenyan_pii

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

    Returns a summary dict.
    """
    if targets is None:
        targets = ONION_TARGETS

    total_scanned = 0
    total_hits = 0
    per_target: dict[str, dict] = {}

    for url in targets:
        logger.info("Scraping onion target: %s", url)
        html = _fetch_onion(url)
        if not html:
            per_target[url] = {"error": "fetch failed", "hits": 0}
            continue

        text = _strip_html(html)
        total_scanned += 1

        # Run Kenyan PII extraction
        pii_matches = extract_kenyan_pii(text)

        # Run keyword extraction (Kenyan domains, ransomware groups)
        from darkweb_scanner.scrapers.keyword_extractor import DOMAIN_WHITELIST, extract_kenyan_pii
        # Also check for ransomware group mentions
        ransomware_groups = {"lockbit", "cl0p", "akira", "alphv", "blackcat", "play", "medusa", "8base", "royal"}
        found_groups = [g for g in ransomware_groups if g in text.lower()]

        hits_found = 0
        # Save PII hits
        for pii in pii_matches:
            try:
                paste_id = f"tor_pii_{abs(hash(url + pii['value']))}"[:200]
                if storage.is_paste_seen("DarkWeb_Tor", paste_id):
                    continue
                storage.save_paste_hit(
                    paste_id=paste_id,
                    url=url,
                    source="DarkWeb_Tor",
                    matched_pattern=f"Tor PII: {pii['label']}",
                    matched_value=pii["value"],
                    context=text[:500],
                )
                storage.mark_paste_seen("DarkWeb_Tor", paste_id, url, had_hits=True)
                hits_found += 1
                total_hits += 1
            except Exception as exc:
                logger.debug("Failed to save Tor PII hit: %s", exc)

        # Save ransomware group mentions
        for group in found_groups:
            try:
                paste_id = f"tor_group_{abs(hash(url + group))}"[:200]
                if storage.is_paste_seen("DarkWeb_Tor", paste_id):
                    continue
                storage.save_paste_hit(
                    paste_id=paste_id,
                    url=url,
                    source="DarkWeb_Tor",
                    matched_pattern="Tor Ransomware Group",
                    matched_value=group.title(),
                    context=text[:500],
                )
                storage.mark_paste_seen("DarkWeb_Tor", paste_id, url, had_hits=True)
                hits_found += 1
                total_hits += 1
            except Exception as exc:
                logger.debug("Failed to save Tor group hit: %s", exc)

        per_target[url] = {
            "hits": hits_found,
            "pii_found": len(pii_matches),
            "groups_found": found_groups,
            "text_length": len(text),
        }
        logger.info("Onion scrape %s: %d hits, %d PII, groups=%s", url, hits_found, len(pii_matches), found_groups)

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
