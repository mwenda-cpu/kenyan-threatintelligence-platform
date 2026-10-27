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
import threading
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


def _extract_text_from_pdf_file(path: Path) -> Optional[str]:
    """Extract text from a local PDF file using pdfplumber (with PyPDF2 fallback)."""
    try:
        try:
            import pdfplumber
            with pdfplumber.open(str(path)) as pdf:
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
            logger.debug("pdfplumber failed for %s: %s", path, exc)

        try:
            import PyPDF2
            reader = PyPDF2.PdfReader(str(path))
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
            logger.debug("PyPDF2 failed for %s: %s", path, exc)

        return None
    except Exception as exc:
        logger.error("Failed to read PDF file %s: %s", path, exc)
        return None


_RE_SIDE_MARKER = re.compile(r"--\s*(KE[-\s]?CIRT|CA|CBK)\s*--", re.IGNORECASE)
_RE_SIDE_FIELD = re.compile(
    r"^\s*(title|quarter|year|period|stats|summary|source_url|date|date_published|"
    r"threat_type|description)\s*:\s*(.+)$",
    re.IGNORECASE,
)

_SRC_URLS = {
    "ke_cirt": "https://ke-cirt.go.ke",
    "ca": "https://repository.ca.go.ke",
    "cbk": "https://www.centralbank.go.ke",
}


def _parse_kv_stats(text: str) -> dict:
    """Parse 'mobile_banking=8420, card=3910' into a stats dict."""
    stats: dict = {}
    for pair in (text or "").split(","):
        if "=" not in pair:
            continue
        key, _, val = pair.partition("=")
        key = key.strip().lower().replace(" ", "_")
        val = val.strip().replace(",", "")
        if not key or not val:
            continue
        try:
            stats[key] = float(val) if "." in val else int(val)
        except ValueError:
            continue
    return stats


def _parse_sidecar(kind: str, text: str) -> dict | None:
    """Parse a marker-format sidecar (.txt) into a record dict.

    Expected format::

        -- CA --
        title: ...
        date_published: ...
        threat_type: ...
        summary: ...
        source_url: ...

        -- CBK --
        period: 2024
        stats: mobile_banking=0, card=0, online=0, cyber=0
        source_url: https://www.centralbank.go.ke
    """
    lines = text.splitlines()
    marker_idx = -1
    for i, line in enumerate(lines):
        if _RE_SIDE_MARKER.search(line):
            marker_idx = i
            break
    if marker_idx < 0:
        return None
    marker = re.sub(r"[-\s]", "", _RE_SIDE_MARKER.search(lines[marker_idx]).group(1)).upper()
    expected = {"ke_cirt": "KECIRT", "ca": "CA", "cbk": "CBK"}[kind]
    if marker != expected:
        return None

    fields: dict = {}
    for line in lines[marker_idx + 1:]:
        s = line.strip()
        if not s or s.startswith("#") or "|" in s:
            continue
        m = _RE_SIDE_FIELD.match(s)
        if m:
            fields[m.group(1).lower()] = m.group(2).strip()

    if kind == "cbk":
        period = fields.get("period", "")
        stats = _parse_kv_stats(fields.get("stats", ""))
        if not period:
            return None
        return {
            "period": period,
            "stats": stats,
            "source_url": fields.get("source_url") or _SRC_URLS["cbk"],
            "summary": fields.get("summary", ""),
        }

    if kind == "ca":
        title = fields.get("title", "")
        date_published = fields.get("date_published") or fields.get("date", "")
        threat_type = (fields.get("threat_type") or "").strip().lower() or "general_advisory"
        summary = fields.get("summary") or fields.get("description", "")
        if not title:
            return None
        return {
            "title": title,
            "date_published": date_published,
            "threat_type": threat_type,
            "summary": summary,
            "source_url": fields.get("source_url") or _SRC_URLS["ca"],
        }

    return None


def _infer_kind(stem: str) -> str | None:
    """Map a filename stem to its source kind via the filename prefix."""
    name = str(stem or "").lower()
    if name.startswith(("ke_cirt", "ke-cirt", "kecirt")):
        return "ke_cirt"
    if name.startswith(("ca",)):
        return "ca"
    if name.startswith(("cbk",)):
        return "cbk"
    return None


def _cbk_stats_from_text(text: str) -> dict:
    """Best-effort CBK stat extraction from raw text when no sidecar is present."""
    stats: dict = {}
    lowered = text.lower()
    for key in ("mobile_banking", "mobile banking", "card", "online", "cyber", "fraud"):
        pattern = re.escape(key).replace("\\ ", r"[\s_]*") + r"[\s:,\-–—]{0,20}([\d][\d,]*\.?\d*)"
        m = re.search(pattern, lowered)
        if m:
            raw = m.group(1).replace(",", "").strip()
            try:
                stats[key.replace(" ", "_")] = float(raw) if "." in raw else int(raw)
            except ValueError:
                continue
    return stats


def _cbk_period_from_text(text: str, filename: str) -> str:
    """Best-effort CBK period extraction (a 4-digit year)."""
    m = re.search(r"\b(19|20)\d{2}\b", filename.replace("_", " ")) or re.search(
        r"\b(19|20)\d{2}\b", text
    )
    return m.group(0) if m else ""


def _ca_from_text(text: str, filename: str) -> dict | None:
    """Best-effort CA advisory extraction from raw text when no sidecar is present."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    title = lines[0] if lines else filename
    date_published = ""
    for ln in lines[:5]:
        m = re.search(r"\b(19|20)\d{2}-\d{2}-\d{2}\b", ln)
        if m:
            date_published = m.group(0)
            break
    threat_type = "general_advisory"
    blob = f"{filename} {text}".replace("_", " ").replace("-", " ").lower()
    blob = re.sub(r"\s+", " ", blob)
    rules = [
        ("sim_swap", ["sim swap", "sim-swap", "simswap"]),
        ("emotet", ["emotet"]),
        ("wangiri", ["wangiri"]),
        ("supply_chain", ["supply chain", "supply-chain", "third party software", "third-party software"]),
        ("ecommerce_fraud", ["online shopping"]),
        ("ransomware", ["ransomware"]),
        ("data_breach", ["personally identifiable", "personally-identifiable", "pii"]),
    ]
    for threat, keywords in rules:
        if any(k in blob for k in keywords):
            threat_type = threat
            break
    return {
        "title": title[:300],
        "date_published": date_published,
        "threat_type": threat_type,
        "summary": text[:500],
        "source_url": _SRC_URLS["ca"],
    }


def ingest_ke_reports(storage) -> dict:
    """Read .pdf/.txt files from /app/data/ke_reports/ and route them to the
    correct table:

    - CA Advisory files -> ``CAAdvisory`` table (via ``ke_context.py``)
    - CBK statistics files -> ``CBKFraudStats`` table (via ``ke_context.py``)
    - KE-CIRT/other files -> ``contextual_intel`` table

    Skips files already present in the target table. Returns
    ``{"scraped", "saved", "skipped"}``.
    """
    from ..ke_context import KenyaContext  # lazy import to avoid circular imports

    data_dir = Path(os.getenv("DATA_DIR", "/app/data"))
    reports_dir = data_dir / "ke_reports"
    if not reports_dir.is_dir():
        logger.warning("ke_reports dir not found: %s", reports_dir)
        return {"scraped": 0, "saved": 0, "skipped": 0}

    ctx = KenyaContext(storage)

    # Snapshot existing rows for dedup per target table.
    existing_ca = {
        str(a.get("title") or "").strip().lower()
        for a in (ctx.get_recent_ca_advisories(limit=1000) or [])
    }
    existing_cbk = {
        str(c.get("period") or "").strip()
        for c in (ctx.get_cbk_fraud_trends().get("periods") or [])
    }
    existing_intel = {
        str(r.get("title") or "").strip().lower()
        for r in (storage.get_contextual_intel(limit=10000) or [])
    }

    scraped = 0
    saved = 0
    skipped = 0

    for path in sorted(reports_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() not in (".pdf", ".txt"):
            continue

        scraped += 1
        stem = path.stem
        kind = _infer_kind(stem)

        # Read file content.
        if path.suffix.lower() == ".txt":
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                logger.error("Failed to read %s: %s", path, exc)
                skipped += 1
                continue
        else:
            text = _extract_text_from_pdf_file(path)
            if not text:
                skipped += 1
                continue

        if not text or not text.strip():
            skipped += 1
            continue

        # Sidecar marker files take precedence and carry structured fields.
        sidecar = None
        if path.suffix.lower() == ".txt":
            sidecar = _parse_sidecar(kind or "ke_report", text)

        try:
            if kind == "ca":
                rec = sidecar or _ca_from_text(text, stem)
                if not rec or not rec.get("title"):
                    skipped += 1
                    continue
                if rec["title"].strip().lower() in existing_ca:
                    skipped += 1
                    continue
                ctx.load_ca_advisory(
                    rec["title"],
                    rec.get("date_published") or "",
                    rec.get("summary") or "",
                    rec.get("threat_type") or "general_advisory",
                    rec.get("source_url") or _SRC_URLS["ca"],
                )
                existing_ca.add(rec["title"].strip().lower())
                saved += 1
                logger.info("Ingested CA advisory into CAAdvisory: %s", rec["title"])
            elif kind == "cbk":
                rec = sidecar or {
                    "period": _cbk_period_from_text(text, stem),
                    "stats": _cbk_stats_from_text(text),
                    "source_url": _SRC_URLS["cbk"],
                }
                if not rec.get("period") or not rec.get("stats"):
                    skipped += 1
                    continue
                if rec["period"].strip() in existing_cbk:
                    skipped += 1
                    continue
                ctx.delete_cbk_by_period(rec["period"])
                ctx.load_cbk_fraud_stats(rec["period"], rec.get("stats") or {}, rec.get("source_url") or _SRC_URLS["cbk"])
                existing_cbk.add(rec["period"].strip())
                saved += 1
                logger.info("Ingested CBK fraud stats into CBKFraudStats: %s", rec["period"])
            else:
                # KE-CIRT / unknown: keep in contextual_intel.
                key = stem.lower()
                if key in existing_intel:
                    skipped += 1
                    continue
                title = stem
                for line in text.splitlines():
                    line = line.strip()
                    if 10 <= len(line) <= 200 and not line.startswith("--"):
                        title = line
                        break
                storage.save_contextual_intel(
                    source=kind or "ke_report",
                    title=title,
                    summary=text.strip(),
                    url=str(path),
                )
                existing_intel.add(title.lower())
                saved += 1
                logger.info("Ingested KE report into contextual_intel: %s (source=%s)", title, kind)
        except Exception as exc:  # noqa: BLE001 - never fail the whole ingest on one row
            logger.error("Failed to ingest %s: %s", path, exc)
            skipped += 1

    return {"scraped": scraped, "saved": saved, "skipped": skipped}


def ingest_ke_reports_async(storage) -> None:
    """Run ``ingest_ke_reports`` in a daemon thread (non-blocking)."""

    def _run() -> None:
        try:
            result = ingest_ke_reports(storage)
            logger.info(
                "KE auto-ingest complete: scraped=%s saved=%s skipped=%s",
                result.get("scraped"), result.get("saved"), result.get("skipped"),
            )
        except Exception as exc:  # noqa: BLE001 - background ingest must not crash
            logger.error("KE auto-ingest failed: %s", exc)

    threading.Thread(target=_run, daemon=True, name="ke_ingest").start()


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
