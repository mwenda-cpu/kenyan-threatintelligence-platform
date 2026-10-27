"""
Clearnet paste-site scrapers for OSINT threat intelligence.

Sources (clearnet only — no .onion / Tor):
  - Rentry.co (HTML scraping, no API key needed)
  - Hastebin (HTML scraping, no API key needed)
  - Ghostbin (HTML scraping, no API key needed)
  - Pastebin (official API — requires PASTEBIN_API_KEY env var)

Only Kenyan-threat-relevant pastes are saved:
  - Kenyan phone numbers (+254, 07xx, 01xx)
  - M-Pesa / Safaricom / transaction keywords
  - Kenyan domains (.go.ke, .ke)
  - Kenyan bank names (KCB, Equity, Co-op, etc.)

Designed to be rate-limit friendly — minimal requests, polite headers,
and configurable delays between fetches.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ── Rate-limiting & politeness ──────────────────────────────────────────
REQUEST_TIMEOUT = 15
FETCH_DELAY = 2.0  # seconds between fetches to be rate-limit friendly
MAX_PASTES_PER_SOURCE = 30
MAX_TEXT_LEN = 500_000

POLL_HEADERS = {
    "User-Agent": "OSINT-PasteScraper/1.0 (Educational; contact: admin@example.com)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# ── Kenyan threat-indicator regexes ─────────────────────────────────────
KE_PATTERNS = {
    # Kenyan mobile: +254 7XX XXX XXX, 07XX XXX XXX, 01XX XXX XXX
    "ke_mobile": re.compile(r"(\+254|0)([17]\d{2}[-\s]?\d{3}[-\s]?\d{3})", re.IGNORECASE),

    # Kenyan domains: safaricom.co.ke, equitybank.co.ke, *.go.ke, etc.
    "ke_domain": re.compile(r"\b[\w.-]+\.ke\b", re.IGNORECASE),

    # Kenyan government domains
    "ke_gov_domain": re.compile(r"\b[\w.-]+\.go\.ke\b", re.IGNORECASE),

    # M-Pesa transaction codes (10-char alphanumeric)
    "ke_mpesa_txn": re.compile(r"\b[A-Z]{3}[A-Z0-9]{7}\b"),

    # Kenyan banks / telcos / fintechs / SACCOs
    "ke_bank": re.compile(
        r"\b("
        r"Equity|KCB|Kenya\s*Commercial\s*Bank|Co-?operative|CoopBank|"
        r"NCBA|Absa|Stanbic|Standard\s*Chartered|Barclays|DTB|"
        r"Diamond\s*Trust|Family\s*Bank|I&M|Prime\s*Bank|"
        r"HF\s*Group|Housing\s*Finance|CBA|Commercial\s*Bank\s*of\s*Africa|"
        r"National\s*Bank|NBK|Postbank|Post\s*Bank|"
        r"StanChart|Guaranty\s*Trust|GTBank|Ecobank|"
        r"M-?Pesa|Safaricom|Airtel\s*Money|Telkom|Equitel|"
        r"K-?Rep|Fuliza|M-?Shwari|"
        r"Stima\s*SACCO|Mwalimu\s*SACCO|Kenya\s*Police\s*SACCO|"
        r"Harambee\s*SACCO|Safaricom\s*SACCO"
        r")\b",
        re.IGNORECASE,
    ),

    # Additional Kenyan context keywords
    "ke_nhif": re.compile(r"\bNHIF|SHA|Social\s*Health\s*Authority\b", re.IGNORECASE),
    "ke_kra_pin": re.compile(r"\b[A-Z]{3}\d{7}[A-Z]\b", re.IGNORECASE),  # KRA PIN format
    "ke_card_bin": re.compile(r"\b\d{6}\b", re.IGNORECASE),  # Card BIN (first 6 digits)
    "ke_postal": re.compile(r"\b\d{5}\b", re.IGNORECASE),  # Kenyan postal codes
}


CONTEXT_WINDOW = 120


def _extract_context(text: str, match) -> str:
    start = max(0, match.start() - CONTEXT_WINDOW)
    end = min(len(text), match.end() + CONTEXT_WINDOW)
    return text[start:end].replace("\n", " ").strip()


@dataclass
class PasteResult:
    paste_id: str
    url: str
    source: str
    matched_pattern: str
    matched_value: str
    context: str
    found_at: datetime


def _safe_get(url: str, headers: Optional[dict] = None) -> Optional[requests.Response]:
    h = dict(POLL_HEADERS)
    if headers:
        h.update(headers)
    try:
        r = requests.get(url, headers=h, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r
    except Exception as exc:
        logger.debug("Paste fetch failed %s: %s", url, exc)
        return None


def _scan_text(text: str, url: str, paste_id: str, source: str) -> list[PasteResult]:
    """Scan paste text for Kenyan threat indicators. Returns list of PasteResult."""
    results: list[PasteResult] = []
    seen: set[tuple[str, str]] = set()

    for pattern_name, regex in KE_PATTERNS.items():
        for match in regex.finditer(text):
            key = (pattern_name, match.group(0)[:50])
            if key in seen:
                continue
            seen.add(key)
            results.append(
                PasteResult(
                    paste_id=paste_id,
                    url=url,
                    source=source,
                    matched_pattern=pattern_name,
                    matched_value=match.group(0)[:200],
                    context=_extract_context(text, match),
                    found_at=datetime.now(timezone.utc).replace(tzinfo=None),
                )
            )

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Source scrapers
# ══════════════════════════════════════════════════════════════════════════════

def scrape_rentry() -> list[PasteResult]:
    """Scrape rentry.co/recent for new pastes."""
    results: list[PasteResult] = []
    r = _safe_get("https://rentry.co/recent")
    if not r:
        return results

    soup = BeautifulSoup(r.text, "lxml")
    count = 0
    for a in soup.find_all("a", href=True):
        if count >= MAX_PASTES_PER_SOURCE:
            break
        href = a["href"]
        if not re.match(r"^/[a-zA-Z0-9_-]{4,20}$", href):
            continue
        if href in ("/recent", "/new", "/login", "/register", "/raw"):
            continue
        paste_id = href.strip("/")
        raw_url = f"https://rentry.co{href}/raw"

        page = _safe_get(raw_url)
        if not page:
            continue
        count += 1
        time.sleep(FETCH_DELAY)
        results.extend(_scan_text(page.text, raw_url, paste_id, "rentry"))

    return results


def scrape_hastebin() -> list[PasteResult]:
    """Scrape hastebin for new pastes (public documents endpoint)."""
    results: list[PasteResult] = []
    r = _safe_get("https://hastebin.com/documents")
    if not r:
        return results

    soup = BeautifulSoup(r.text, "lxml")
    count = 0
    for a in soup.find_all("a", href=True):
        if count >= MAX_PASTES_PER_SOURCE:
            break
        href = a["href"]
        if not re.match(r"^/[a-zA-Z0-9]{6,12}$", href):
            continue
        paste_id = href.strip("/")
        raw_url = f"https://hastebin.com/raw/{paste_id}"

        page = _safe_get(raw_url)
        if not page:
            continue
        count += 1
        time.sleep(FETCH_DELAY)
        results.extend(_scan_text(page.text, raw_url, paste_id, "hastebin"))

    return results


def scrape_ghostbin() -> list[PasteResult]:
    """Scrape ghostbin.com for new pastes."""
    results: list[PasteResult] = []
    r = _safe_get("https://ghostbin.com/paste")
    if not r:
        return results

    soup = BeautifulSoup(r.text, "lxml")
    count = 0
    for a in soup.find_all("a", href=True):
        if count >= MAX_PASTES_PER_SOURCE:
            break
        href = a["href"]
        if not re.match(r"^/paste/[a-z0-9]+$", href):
            continue
        paste_id = href.split("/")[-1]
        raw_url = f"https://ghostbin.com{href}/raw"

        page = _safe_get(raw_url)
        if not page:
            continue
        count += 1
        time.sleep(FETCH_DELAY)
        results.extend(_scan_text(page.text, raw_url, paste_id, "ghostbin"))

    return results


def scrape_pastebin_api() -> list[PasteResult]:
    """Use the official Pastebin API to fetch recent public pastes.

    Requires PASTEBIN_API_KEY environment variable. Without a key, returns empty
    (no scraping — Pastebin blocks unauthenticated HTML scraping).
    """
    results: list[PasteResult] = []
    api_key = os.getenv("PASTEBIN_API_KEY")
    if not api_key:
        logger.info("Pastebin API key not set — skipping Pastebin source")
        return results

    # Pastebin API: https://pastebin.com/api/api_post.php
    # We use the "trends" endpoint which doesn't require a user key, just an API key.
    try:
        resp = requests.post(
            "https://pastebin.com/api/api_post.php",
            data={
                "api_dev_key": api_key,
                "api_option": "trends",
                "api_results_limit": str(MAX_PASTES_PER_SOURCE),
            },
            headers=POLL_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("Pastebin API returned status %s: %s", resp.status_code, resp.text[:200])
            return results

        # Pastebin trends returns XML
        import xml.etree.ElementTree as ET
        root = ET.fromstring(resp.text)
        count = 0
        for paste in root.findall("paste"):
            if count >= MAX_PASTES_PER_SOURCE:
                break
            paste_id = paste.findtext("paste_key", "")
            paste.findtext("paste_title", "")
            paste_date = paste.findtext("paste_date", "")
            raw_url = f"https://pastebin.com/raw/{paste_id}"

            page = _safe_get(raw_url)
            if not page:
                continue
            count += 1
            time.sleep(FETCH_DELAY)
            found_at = None
            if paste_date:
                try:
                    found_at = datetime.strptime(paste_date, "%Y-%m-%d %H:%M:%S").replace(
                        tzinfo=None
                    )
                except ValueError:
                    found_at = None

            scanned = _scan_text(page.text, raw_url, paste_id, "pastebin")
            for r in scanned:
                if found_at:
                    r.found_at = found_at
                results.append(r)

    except Exception as exc:
        logger.warning("Pastebin API scrape failed: %s", exc)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Orchestrator
# ══════════════════════════════════════════════════════════════════════════════

SOURCE_SCRAPERS = {
    "rentry": scrape_rentry,
    "hastebin": scrape_hastebin,
    "ghostbin": scrape_ghostbin,
    "pastebin": scrape_pastebin_api,
}


def run_paste_scraper(storage, sources: Optional[list[str]] = None) -> dict:
    """Run paste scraping across all (or selected) sources.

    Args:
        storage: Storage instance with save_paste_hit / is_paste_seen / mark_paste_seen.
        sources: Optional list of source names to run. Defaults to all enabled sources.

    Returns:
        dict with scanned, new_pastes, hits, per_source breakdown, timestamp.
    """
    if sources is None:
        sources = list(SOURCE_SCRAPERS.keys())

    total_scanned = 0
    total_hits = 0
    total_new = 0
    per_source: dict[str, dict] = {}

    for source_name in sources:
        scraper = SOURCE_SCRAPERS.get(source_name)
        if not scraper:
            logger.warning("No scraper for source: %s", source_name)
            per_source[source_name] = {"error": "no scraper", "hits": 0}
            continue

        logger.info("Scraping %s...", source_name)
        try:
            results = scraper()
        except Exception as exc:
            logger.error("Scraper %s failed: %s", source_name, exc)
            per_source[source_name] = {"error": str(exc), "hits": 0}
            continue

        new_count = 0
        hit_count = 0
        for result in results:
            if storage.is_paste_seen(result.source, result.paste_id):
                continue
            new_count += 1
            try:
                storage.save_paste_hit(
                    paste_id=result.paste_id,
                    url=result.url,
                    source=result.source,
                    matched_pattern=result.matched_pattern,
                    matched_value=result.matched_value,
                    context=result.context,
                )
                hit_count += 1
            except Exception as exc:
                logger.debug("Failed to save paste hit %s: %s", result.paste_id, exc)

            storage.mark_paste_seen(
                result.source, result.paste_id, result.url, had_hits=True
            )
            total_scanned += 1

        total_new += new_count
        total_hits += hit_count
        per_source[source_name] = {
            "new_pastes": new_count,
            "hits": hit_count,
        }
        logger.info("%s: %d new pastes, %d hits", source_name, new_count, hit_count)

    return {
        "scanned": total_scanned,
        "new_pastes": total_new,
        "hits": total_hits,
        "per_source": per_source,
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }


if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from darkweb_scanner.storage import Storage

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    storage = Storage()
    summary = run_paste_scraper(storage)
    print("\nPaste scrape complete:")
    print(f"  New pastes: {summary['new_pastes']}")
    print(f"  Total hits: {summary['hits']}")
    for src, info in summary["per_source"].items():
        print(f"  {src}: {info}")
