"""
Ingest KE-CIRT / CAK / CBK advisories from a local CSV and from PDFs
in ``data/ke_reports`` into the ``ke_cirt_advisories`` table.

CSV columns: title, url, published_at, summary, severity, source
PDFs are read with pypdf (first 3 pages); the year is extracted from the
filename, summaries are cleaned of extra whitespace, and titles are
cleaned up. Rows are upserted (dedupe by ``url``). Idempotent: safe to
re-run.

CLI: python scripts/fetch_ke_cirt.py
"""

from __future__ import annotations

import csv
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from darkweb_scanner.storage import KECIRTAdvisory, Storage

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_CSV = _REPO_ROOT / "config" / "ke_cirt_advisories.csv"
_REPORTS_DIR = Path(os.getenv("DATA_DIR", "/app/data")) / "ke_reports"


def _csv_path() -> Path:
    raw = (os.getenv("KE_CIRT_ADVISORIES_CSV") or "").strip()
    if raw:
        p = Path(raw)
        return p if p.is_absolute() else _REPO_ROOT / p
    return _DEFAULT_CSV


def _parse_published_at(value: str):
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        logger.warning("Invalid published_at value %r; storing without timestamp", value)
        return None


def _upsert_advisory(storage, advisory: dict) -> bool:
    """Upsert a single advisory row (dedupe by ``url``).

    Updates ``published_at``, ``summary`` and ``severity`` when the row
    already exists, otherwise inserts a new row.

    Returns True when a new row was inserted, False when an existing row
    was updated.
    """
    url = advisory["url"]
    with storage.get_session() as db:
        existing = db.query(KECIRTAdvisory).filter(KECIRTAdvisory.url == url).first()
        if existing:
            existing.published_at = advisory["published_at"]
            existing.summary = advisory["summary"]
            existing.severity = advisory["severity"]
            db.commit()
            return False
        db.add(KECIRTAdvisory(**advisory))
        db.commit()
        return True


def _source_from_filename(filename: str) -> str:
    name = filename.lower()
    if "cbk" in name:
        return "CBK"
    if "cak" in name:
        return "CAK"
    return "KE-CIRT/CC"


def _severity_from_text(text: str) -> str:
    if "critical" in text.lower():
        return "critical"
    return "high"


def _clean_title(filename: str) -> str:
    """Clean a PDF filename into a human-readable title."""
    title = filename
    if title.lower().endswith(".pdf"):
        title = title[: -len(".pdf")]
    title = title.replace("_", " ").replace("-", " ")
    return title.strip()


def _clean_summary(full_text: str) -> str:
    """Clean extracted PDF text into a summary.

    Replaces newlines with spaces, collapses excessive whitespace, and
    truncates to 300 characters.
    """
    cleaned = re.sub(r"\s+", " ", (full_text or "").replace("\n", " ")).strip()
    return cleaned[:300]


def _extract_published_at(path: Path) -> datetime:
    """Extract a published date from the filename year or file mtime.

    Never returns None: falls back to the file's modified time.
    """
    match = re.search(r"(20\d{2})", path.name)
    if match:
        return datetime(int(match.group(1)), 1, 1)
    try:
        return datetime.fromtimestamp(os.path.getmtime(path))
    except Exception:
        return datetime.utcnow()


def _ingest_pdf(path: Path, storage) -> bool:
    """Ingest a single PDF file into ke_cirt_advisories.

    Reads the first 3 pages with pypdf, extracts a date from the filename
    year (or file mtime), builds a cleaned summary, cleans up the title,
    and upserts the row. Returns True when inserted.
    """
    try:
        from pypdf import PdfReader
    except ImportError:
        logger.warning("pypdf not installed; skipping PDF ingestion")
        return False

    try:
        reader = PdfReader(str(path))
    except Exception as exc:
        logger.warning("Failed to open PDF %s: %s", path.name, exc)
        return False

    text_parts = []
    for page in reader.pages[:3]:
        try:
            text_parts.append(page.extract_text() or "")
        except Exception:
            continue
    full_text = "\n".join(text_parts)

    advisory = {
        "title": _clean_title(path.name),
        "url": f"file:///app/data/ke_reports/{path.name}",
        "published_at": _extract_published_at(path),
        "summary": _clean_summary(full_text),
        "severity": _severity_from_text(full_text),
        "source": _source_from_filename(path.name),
    }
    return _upsert_advisory(storage, advisory)


def fetch_and_store_advisories(csv_path: Path | None = None) -> int:
    """Read the advisories CSV and PDFs and upsert rows into ke_cirt_advisories.

    Dedupe is by ``url``: existing rows are updated, new rows are inserted.
    Returns the number of new rows inserted.
    """
    inserted = 0
    updated = 0
    storage = Storage()

    # ── CSV ingestion ──────────────────────────────────────────────────
    path = csv_path or _csv_path()
    if path.exists():
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                url = (row.get("url") or "").strip()
                if not url:
                    continue
                advisory = {
                    "title": (row.get("title") or "").strip(),
                    "url": url,
                    "published_at": _parse_published_at(row.get("published_at", "")),
                    "summary": (row.get("summary") or "").strip(),
                    "severity": (row.get("severity") or "medium").strip(),
                    "source": (row.get("source") or "").strip(),
                }
                if _upsert_advisory(storage, advisory):
                    inserted += 1
                else:
                    updated += 1
    else:
        logger.info("KE-CIRT advisories CSV not found at %s; skipping CSV ingestion", path)

    # ── PDF ingestion from data/ke_reports ─────────────────────────────
    if _REPORTS_DIR.exists() and _REPORTS_DIR.is_dir():
        for pdf_path in sorted(_REPORTS_DIR.glob("*.pdf")):
            if _ingest_pdf(pdf_path, storage):
                inserted += 1
            else:
                updated += 1
    else:
        logger.info("KE reports directory %s not found; skipping PDF ingestion", _REPORTS_DIR)

    logger.info("INFO: Updated %d advisories, inserted %d new", updated, inserted)
    return inserted


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    inserted = fetch_and_store_advisories()
    print(f"KE-CIRT advisories ingested: {inserted} new row(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
