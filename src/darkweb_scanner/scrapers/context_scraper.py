"""
Kenyan contextual data parser for clearnet seeds.

Fetches PDFs from URLs listed in config/sources.json (Clearnet Seeds),
extracts text using pdfplumber, and parses for Kenyan threat statistics,
ransomware group mentions, and affected sectors. Saves summaries to
the contextual_intel table.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

from darkweb_scanner.storage import Storage

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 30
MAX_TEXT_LEN = 100_000

# Ransomware groups to look for
RANSOMWARE_GROUPS = [
    "LockBit", "cl0p", "ALPHV", "BlackCat", "Akira", "Play", "8base",
    "Medusa", "Royal", "BlackSuit", "Cactus", "RansomHouse",
]

# Kenyan sectors to look for
KENYAN_SECTORS = [
    "government", "banking", "finance", "healthcare", "health",
    "telecom", "telecommunications", "education", "energy",
    "transport", "agriculture", "manufacturing", "retail",
    "insurance", "real estate", "media", "hospitality",
]


def _load_sources_config() -> dict:
    """Load config/sources.json."""
    config_path = Path(__file__).resolve().parents[3] / "config" / "sources.json"
    if not config_path.exists():
        # Try relative to project root
        config_path = Path("config/sources.json")
    if not config_path.exists():
        logger.warning("config/sources.json not found")
        return {"clearnet_seeds": [], "paste_sources": []}
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _fetch_pdf_text(url: str) -> Optional[str]:
    """Fetch a PDF from a URL and extract text using pdfplumber."""
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "ThreatIntel-Platform/1.0"},
            stream=True,
        )
        resp.raise_for_status()

        # Check if it's actually a PDF
        content_type = resp.headers.get("Content-Type", "")
        if "pdf" not in content_type.lower() and not url.lower().endswith(".pdf"):
            logger.debug("URL does not appear to be a PDF: %s (%s)", url, content_type)
            return None

        # Try pdfplumber first
        try:
            import pdfplumber
            import io
            with pdfplumber.open(io.BytesIO(resp.content)) as pdf:
                text_parts = []
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text_parts.append(page_text)
                text = "\n".join(text_parts)
                if text.strip():
                    return text[:MAX_TEXT_LEN]
        except ImportError:
            logger.warning("pdfplumber not installed, trying PyPDF2")
        except Exception as exc:
            logger.debug("pdfplumber failed: %s", exc)

        # Fallback: PyPDF2
        try:
            import PyPDF2
            import io
            reader = PyPDF2.PdfReader(io.BytesIO(resp.content))
            text_parts = []
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
            text = "\n".join(text_parts)
            if text.strip():
                return text[:MAX_TEXT_LEN]
        except ImportError:
            logger.warning("PyPDF2 not installed")
        except Exception as exc:
            logger.debug("PyPDF2 failed: %s", exc)

        return None
    except Exception as exc:
        logger.error("Failed to fetch/parse PDF from %s: %s", url, exc)
        return None


def _fetch_html_text(url: str) -> Optional[str]:
    """Fetch HTML page and extract text."""
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "ThreatIntel-Platform/1.0"},
        )
        resp.raise_for_status()
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "lxml")
        for tag in soup(["script", "style", "noscript", "nav", "footer"]):
            tag.decompose()
        text = soup.get_text(" ", strip=True)
        return text[:MAX_TEXT_LEN] if text.strip() else None
    except Exception as exc:
        logger.error("Failed to fetch HTML from %s: %s", url, exc)
        return None


def _extract_intel(text: str, source_name: str, url: str) -> dict:
    """Extract threat intelligence from text."""
    text_lower = text.lower()

    # Find ransomware group mentions
    groups_found = [g for g in RANSOMWARE_GROUPS if g.lower() in text_lower]

    # Find sector mentions
    sectors_found = [s for s in KENYAN_SECTORS if s in text_lower]

    # Find statistics (numbers followed by % or "attacks" or "incidents")
    stats = re.findall(r"(\d[\d,]*)\s*(?:%|attacks|incidents|breaches|cases)", text, re.IGNORECASE)

    # Build summary
    summary_parts = []
    if groups_found:
        summary_parts.append(f"Ransomware groups mentioned: {', '.join(groups_found)}")
    if sectors_found:
        summary_parts.append(f"Sectors affected: {', '.join(sectors_found)}")
    if stats:
        summary_parts.append(f"Key statistics: {', '.join(stats[:5])}")

    summary = " | ".join(summary_parts) if summary_parts else "No specific threat indicators extracted."

    # Generate a title from the first meaningful sentence
    sentences = re.split(r"[.!?]", text)
    title = None
    for s in sentences:
        s = s.strip()
        if len(s) > 20 and len(s) < 200:
            title = s
            break
    if not title:
        title = source_name

    return {
        "source": source_name,
        "title": title[:500],
        "summary": summary,
        "url": url,
        "groups": groups_found,
        "sectors": sectors_found,
        "stats": stats[:10],
    }


def scrape_context(storage: Storage) -> dict:
    """Scrape clearnet seeds from config/sources.json and extract contextual intel.

    Returns a summary dict.
    """
    config = _load_sources_config()
    seeds = config.get("clearnet_seeds", [])

    total_scraped = 0
    total_saved = 0
    per_source: dict[str, dict] = {}

    for seed in seeds:
        name = seed.get("name", "Unknown")
        url = seed.get("url", "")
        seed_type = seed.get("type", "news")

        if not url:
            continue

        logger.info("Scraping contextual source: %s (%s)", name, url)

        # Try PDF first, then HTML
        text = _fetch_pdf_text(url)
        if not text:
            text = _fetch_html_text(url)

        if not text:
            per_source[name] = {"error": "fetch failed", "saved": 0}
            continue

        total_scraped += 1
        intel = _extract_intel(text, name, url)

        try:
            storage.save_contextual_intel(
                source=name,
                title=intel["title"],
                summary=intel["summary"],
                url=url,
            )
            total_saved += 1
            per_source[name] = {
                "saved": 1,
                "groups": intel["groups"],
                "sectors": intel["sectors"],
                "stats": intel["stats"],
            }
            logger.info("Saved contextual intel from %s: groups=%s, sectors=%s", name, intel["groups"], intel["sectors"])
        except Exception as exc:
            logger.error("Failed to save contextual intel from %s: %s", name, exc)
            per_source[name] = {"error": str(exc), "saved": 0}

    return {
        "scraped": total_scraped,
        "saved": total_saved,
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
    summary = scrape_context(storage)
    print(f"\nContext scrape complete: {summary}")
    for src, info in summary["per_source"].items():
        print(f"  {src}: {info}")
