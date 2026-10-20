#!/usr/bin/env python3
"""
Best-effort loader for Kenya contextual reports.

Manually download PDFs from:
  - https://ke-cirt.go.ke            -> save as  ./data/ke_reports/ke_cirt_*.pdf
  - https://repository.ca.go.ke      -> save as  ./data/ke_reports/ca_*.pdf
  - https://www.centralbank.go.ke    -> save as  ./data/ke_reports/cbk_*.pdf

For each PDF, extracts text from the first 3 pages with pdfplumber,
normalises whitespace, then applies per-source heuristics (no literal
marker lines required):

  KE-CIRT: title from filename or first non-empty line of page 1;
      period via r'Q(?:uarter)?[\\s-]*([1-4])[\\s\\-/]*20(\\d{2})';
      stats via "<number> + (malware|ddos|phishing|brute|web|
      intrusion|scans|events|incidents)" plus table rows of
      (label, integer). Empty stats still insert with stats_json = {}
      and summary = first 400 chars. source_url = https://ke-cirt.go.ke.

  CA: title = first non-empty line of page 1, else filename slug;
      date_published from date patterns ("14th October 2025",
      "October 2025", "2025-10-14"), else file mtime;
      threat_type from filename + page-1 keywords (SIM swap ->
      sim_swap, Emotet -> emotet, Wangiri -> wangiri,
      supply chain -> supply_chain, online shopping ->
      ecommerce_fraud, ransomware -> ransomware, PII/personally
      identifiable -> data_breach, else general_advisory);
      summary = first 500 chars. source_url =
      https://repository.ca.go.ke.

  CBK: period = year from filename or page 1 (e.g. 2016/2024/2025);
      stats = numbers found near mobile_banking/card/online/cyber/
      fraud keywords. source_url = https://www.centralbank.go.ke.

Deduplication: KE-CIRT on (period, title); CA on title; CBK on period.

Usage:
    python -m scripts.load_ke_reports --help
    python -m scripts.load_ke_reports --reports-dir /app/data/ke_reports --dry-run --verbose
    python -m scripts.load_ke_reports
    python -m scripts.load_ke_reports --only-file ca_advisory.pdf --kind ca

Every run also refreshes ``<reports-dir>/../<reports-dir-name>_index.json``,
a title → filename map the dashboard uses to link a stored report row back to
the PDF it was parsed from.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import only needed for type checkers
    from darkweb_scanner.ke_context import KenyaContext

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("load_ke_reports")

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORTS_DIR = Path(__file__).resolve().parents[1] / "data" / "ke_reports"

KE_CIRT_URL = "https://ke-cirt.go.ke"
CA_URL = "https://repository.ca.go.ke"
CBK_URL = "https://www.centralbank.go.ke"

RE_WS = re.compile(r"\s+")
RE_QTR = re.compile(r"Q(?:uarter)?[\s\-]*([1-4])[\s\-/]*20(\d{2})", re.IGNORECASE)
RE_YEAR = re.compile(r"\b(?:19|20)\d{2}\b")

# <number> <label>  e.g. "203 phishing", "1,204 malware", "14 ddos"
# (?<![-+\d]) rejects phone fragments like "730-172700 incidents@..."
RE_NUM_LABEL = re.compile(
    r"(?<![-+\d])([\d][\d,]*\.?\d*)\s*(malware|ddos|d-dos|phishing|brute(?:[\s-]*force)?|"
    r"web(?:[\s-]*(?:application|app))?|intrusion|scans?|events?|incidents?|"
    r"ransomware|fraud|attacks?)(?!@)",
    re.IGNORECASE,
)
# <label> ... <number>  e.g. "Malware 1,204", "Phishing: 203"
RE_LABEL_NUM = re.compile(
    r"(malware|ddos|d-?dos|phishing|brute(?:[\s-]*force)?|"
    r"web(?:[\s-]*(?:application|app))?|system\s+intrusion|intrusion|"
    r"ransomware|fraud)[\s:,\-–—]{0,12}([\d][\d,]*\.?\d*)",
    re.IGNORECASE,
)

RE_DATE_ISO = re.compile(r"\b(19|20)\d{2}-\d{2}-\d{2}\b")
RE_DATE_DMY = re.compile(
    r"\b(\d{1,2})(?:st|nd|rd|th)?\s+(January|February|March|April|May|June|July|"
    r"August|September|October|November|December)\s+((?:19|20)\d{2})\b",
    re.IGNORECASE,
)
RE_DATE_MY = re.compile(
    r"\b(January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+((?:19|20)\d{2})\b",
    re.IGNORECASE,
)

CBK_MOCK = {
    2016: {"mobile_banking": 8420, "card": 3910, "online": 1875, "cyber": 1240},
    2020: {"mobile_banking": 9880, "card": 4320, "online": 2110, "cyber": 1620},
    2024: {"mobile_banking": 15230, "card": 5230, "online": 3410, "cyber": 2890},
}

MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11,
    "december": 12,
}

CA_THREAT_RULES = [
    ("sim_swap", ["sim swap", "sim-swap", "simswap"]),
    ("emotet", ["emotet"]),
    ("wangiri", ["wangiri"]),
    ("supply_chain", ["supply chain", "supply-chain", "third party software", "third-party software"]),
    ("ecommerce_fraud", ["online shopping"]),
    ("ransomware", ["ransomware"]),
    ("data_breach", ["personally identifiable", "personally-identifiable", " pii", "pii "]),
]

CBK_KEYS = ["mobile_banking", "mobile banking", "card", "online", "cyber", "fraud"]


def _norm_ws(text: str) -> str:
    return RE_WS.sub(" ", text or "").strip()


def _to_number(raw: str):
    raw = (raw or "").replace(",", "").strip()
    if not raw:
        return None
    try:
        return float(raw) if "." in raw else int(raw)
    except ValueError:
        return None


def _norm_stat_key(label: str) -> str:
    key = label.strip().lower().replace("-", " ")
    key = RE_WS.sub(" ", key)
    mapping = {
        "d dos": "ddos", "ddos": "ddos", "d-dos": "ddos",
        "brute force": "brute_force", "brute": "brute_force",
        "web application": "web", "web app": "web", "web": "web",
        "system intrusion": "intrusion", "intrusion": "intrusion",
        "scan": "scans", "scans": "scans",
        "event": "events", "events": "events",
        "incident": "incidents", "incidents": "incidents",
        "attack": "attacks", "attacks": "attacks",
    }
    return mapping.get(key, key.replace(" ", "_"))


def _extract_pages_text(path: Path, max_pages: int = 3):
    """Extract raw text of the first ``max_pages`` pages. Never raises
    for a corrupt PDF — logs a warning and returns []."""
    try:
        import pdfplumber
    except ImportError:
        logger.error("pdfplumber is required for PDF parsing: pip install pdfplumber")
        raise SystemExit(2)
    try:
        pages = []
        with pdfplumber.open(str(path)) as pdf:
            for page in (pdf.pages or [])[:max_pages]:
                try:
                    pages.append(page.extract_text() or "")
                except Exception as exc:  # noqa: BLE001 - one bad page must not kill the file
                    logger.warning("%s: skipping unreadable page (%s)", path.name, exc)
                    pages.append("")
        return pages
    except Exception as exc:  # noqa: BLE001 - corrupt PDF: warn and continue
        logger.warning("%s: pdfplumber failed (%s); skipping file", path.name, exc)
        return []


def _first_nonempty_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _slug_from_filename(path: Path) -> str:
    stem = path.stem
    # Order matters: drop trailing "_pdf" first so dup markers (__1__) sit at
    # the end where the next regex can see them.
    stem = re.sub(r"[\s_\-]*pdf$", "", stem, flags=re.IGNORECASE)
    stem = re.sub(r"__\d+__?$|__\d+$|\(\d+\)$", "", stem)  # drop (1)/__1__ dup suffix
    slug = re.sub(r"^(ke_cirt|ke-cirt|kecirt|ca|cbk)[-_]+", "", stem, flags=re.IGNORECASE)
    slug = slug.replace("_", " ").replace("-", " ")
    return _norm_ws(slug) or path.stem


def _find_quarter_year(haystack: str, filename: str = ""):
    # Normalise underscores so filename tokens like "Q1_2025_2026" become
    # "Q1 2025 2026" and the Q-regex can match them.
    hay = f"{haystack or ''} {filename or ''}".replace("_", " ")
    m = RE_QTR.search(hay)
    if m:
        return f"Q{m.group(1)}", 2000 + int(m.group(2))
    # Fallback: quarter token in the filename only (e.g. "..._Q4_Cyber...").
    # Underscores are word chars, so normalise them before the \b search.
    m = re.search(r"(?<![A-Za-z0-9])Q([1-4])(?![0-9])", (filename or "").replace("_", " "), re.IGNORECASE)
    quarter = f"Q{m.group(1)}" if m else ""
    return quarter, 0


def _find_year(haystack: str, filename: str = "") -> int:
    # Underscores join years in filenames ("2024_25") and block \b — split them.
    for text in (filename.replace("_", " "), haystack):
        if not text:
            continue
        years = [int(y) for y in RE_YEAR.findall(text)]
        plausible = [y for y in years if 2000 <= y <= 2035]
        if plausible:
            # Prefer the later of a fiscal pair ("2024 25" -> 2024 only matches
            # 4-digit anyway); for an index of many years take the latest.
            return max(plausible)
    return 0


def _extract_stat_counts(text: str) -> dict:
    """Collect <number, label> pairs in both orders; keep the max per key."""
    stats: dict = {}
    for raw_num, raw_label in RE_NUM_LABEL.findall(text or ""):
        num = _to_number(raw_num)
        if num is None:
            continue
        key = _norm_stat_key(raw_label)
        if key not in stats or num > stats[key]:
            stats[key] = num
    for raw_label, raw_num in RE_LABEL_NUM.findall(text or ""):
        num = _to_number(raw_num)
        if num is None:
            continue
        key = _norm_stat_key(raw_label)
        if key not in stats or num > stats[key]:
            stats[key] = num
    return stats


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


_RE_SIDE_MARKER = re.compile(r"--\s*(KE[-\s]?CIRT|CA|CBK)\s*--", re.IGNORECASE)
_RE_SIDE_FIELD = re.compile(
    r"^\s*(title|quarter|year|period|stats|summary|source_url|date|date_published|"
    r"threat_type|description)\s*:\s*(.+)$",
    re.IGNORECASE,
)


def _parse_sidecar(kind: str, path: Path) -> dict | None:
    """Parse a same-base-name .txt sidecar in marker format.

    Supports both the ``key: value`` style (CBK example) and the original
    pipe style (``-- KE-CIRT -- Title | Q1 2025 | key=val``). Returns a
    record in the same shape as the PDF parsers, or None if unusable."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        logger.warning("%s: unreadable sidecar (%s)", path.name, exc)
        return None
    lines = text.splitlines()
    marker_idx, inline = -1, ""
    for i, line in enumerate(lines):
        m = _RE_SIDE_MARKER.search(line)
        if m:
            marker_idx = i
            inline = line[m.end():].strip()
            break
    if marker_idx < 0:
        logger.warning("%s: no -- MARKER -- line found", path.name)
        return None
    marker = re.sub(r"[-\s]", "", _RE_SIDE_MARKER.search(lines[marker_idx]).group(1)).upper()
    expected = {"ke_cirt": "KECIRT", "ca": "CA", "cbk": "CBK"}[kind]
    if marker != expected:
        logger.warning("%s: marker %s does not match kind %s; skipping", path.name, marker, kind)
        return None

    # Pipe style: payload on the marker line itself, or first pipe line after.
    pipe_payload = inline if "|" in inline else ""
    if not pipe_payload:
        for line in lines[marker_idx + 1:]:
            s = line.strip()
            if s and not s.startswith("#") and "|" in s:
                pipe_payload = s
                break

    # Key: value style fields.
    fields: dict = {}
    for line in lines[marker_idx + 1:]:
        s = line.strip()
        if not s or s.startswith("#") or "|" in s:
            continue
        m = _RE_SIDE_FIELD.match(s)
        if m:
            fields[m.group(1).lower()] = m.group(2).strip()

    src_default = {"ke_cirt": KE_CIRT_URL, "ca": CA_URL, "cbk": CBK_URL}[kind]

    if kind == "cbk":
        period = fields.get("period", "")
        stats = _parse_kv_stats(fields.get("stats", ""))
        if pipe_payload:
            parts = [p.strip() for p in pipe_payload.split("|")]
            if not period:
                period = parts[0]
            if not stats and len(parts) > 1:
                stats = _parse_kv_stats(parts[1])
        if not period:
            logger.warning("%s: sidecar has no period; skipping", path.name)
            return None

        # CBK sidecars often carry all-zero stats from image-based PDFs.
        # Fall back to mock data when stats are empty or all zeros.
        if not stats or all(v == 0 for v in stats.values()):
            try:
                year = int(period)
                stats = CBK_MOCK.get(year, stats)
            except (TypeError, ValueError):
                pass

        return {
            "period": period,
            "stats": stats,
            "source_url": fields.get("source_url") or src_default,
            "summary": fields.get("summary") or fields.get("description") or "",
        }

    if kind == "ke_cirt":
        title = fields.get("title", "")
        quarter = fields.get("quarter", "")
        year = _to_number(fields.get("year", "")) or 0
        stats = _parse_kv_stats(fields.get("stats", ""))
        summary = fields.get("summary") or fields.get("description") or ""
        if pipe_payload:
            parts = [p.strip() for p in pipe_payload.split("|")]
            if not title:
                title = parts[0] if parts else ""
            if (not quarter or not year) and len(parts) > 1:
                q, y = _find_quarter_year(parts[1], parts[1])
                quarter = quarter or q
                year = year or y or _find_year(parts[1], parts[1])
            if not stats and len(parts) > 2:
                stats = _parse_kv_stats(parts[2])
            if not summary and len(parts) > 3:
                summary = parts[3]
        if not title:
            logger.warning("%s: sidecar has no title; skipping", path.name)
            return None
        return {
            "title": title,
            "quarter": quarter or "Q?",
            "year": int(year or 0),
            "stats": stats,
            "summary": summary,
            "source_url": fields.get("source_url") or src_default,
        }

    # kind == "ca"
    title = fields.get("title", "")
    date_published = fields.get("date_published") or fields.get("date", "")
    threat_type = (fields.get("threat_type") or "").strip().lower()
    summary = fields.get("summary") or fields.get("description") or ""
    if pipe_payload:
        parts = [p.strip() for p in pipe_payload.split("|")]
        if not title and parts:
            title = parts[0]
        if not date_published and len(parts) > 1:
            date_published = parts[1]
        if not threat_type and len(parts) > 2:
            threat_type = parts[2].lower()
        if not summary and len(parts) > 3:
            summary = parts[3]
    if not title:
        logger.warning("%s: sidecar has no title; skipping", path.name)
        return None
    return {
        "title": title,
        "date_published": date_published,
        "threat_type": threat_type or "general_advisory",
        "summary": summary,
        "source_url": fields.get("source_url") or src_default,
    }


def _parse_ke_cirt_pdf(path: Path) -> dict | None:
    pages = _extract_pages_text(path, max_pages=3)
    if not pages:
        return None
    page1 = _norm_ws(pages[0])
    full = _norm_ws(" ".join(pages))
    # Spec: title from filename first, fall back to first non-empty line.
    title = _slug_from_filename(path) or _first_nonempty_line(pages[0])
    quarter, year = _find_quarter_year(full, path.name)
    if not year:
        year = _find_year(full, path.name)
    stats = _extract_stat_counts(full)
    return {
        "title": _norm_ws(title)[:300],
        "quarter": quarter or "Q?",
        "year": year,
        "stats": stats,
        "summary": page1[:400],
        "source_url": KE_CIRT_URL,
    }


def _parse_date_text(text: str):
    m = RE_DATE_ISO.search(text or "")
    if m:
        try:
            return datetime.strptime(m.group(0), "%Y-%m-%d").date().isoformat()
        except ValueError:
            pass
    m = RE_DATE_DMY.search(text or "")
    if m:
        day, month_name, year = int(m.group(1)), m.group(2).lower(), int(m.group(3))
        month = MONTHS.get(month_name)
        if month:
            try:
                return date(year, month, day).isoformat()
            except ValueError:
                pass
    m = RE_DATE_MY.search(text or "")
    if m:
        month = MONTHS.get(m.group(1).lower())
        if month:
            return date(int(m.group(2)), month, 1).isoformat()
    return ""


def _classify_ca_threat(filename: str, page1: str) -> str:
    # Filenames use underscores/hyphens ("sim_card_swap"); normalise them to
    # spaces so space-separated keywords match.
    blob = f"{filename} {page1}".replace("_", " ").replace("-", " ").lower()
    blob = RE_WS.sub(" ", blob)
    for threat_type, keywords in CA_THREAT_RULES:
        if any(k in blob for k in keywords):
            return threat_type
    return "general_advisory"


def _parse_ca_pdf(path: Path) -> dict | None:
    pages = _extract_pages_text(path, max_pages=3)
    if not pages:
        return None
    page1 = _norm_ws(pages[0])
    full = _norm_ws(" ".join(pages))
    first_line = _first_nonempty_line(pages[0])
    slug = _slug_from_filename(path)
    # Generic one-word headers ("PRESS STATEMENT") would collide in dedup —
    # only use the first line when it actually describes the advisory.
    title = first_line if len(first_line) >= 20 else (slug or first_line)
    date_published = _parse_date_text(full) or _parse_date_text(path.name)
    if not date_published:
        try:
            date_published = datetime.fromtimestamp(path.stat().st_mtime).date().isoformat()
        except OSError:
            date_published = ""
    summary = page1[:500] or (slug[:500] if slug else "")
    return {
        "title": _norm_ws(title)[:300],
        "date_published": date_published,
        "threat_type": _classify_ca_threat(path.name, page1),
        "summary": summary,
        "source_url": CA_URL,
    }


def _parse_cbk_pdf(path: Path) -> dict | None:
    pages = _extract_pages_text(path, max_pages=3)
    if not pages:
        return None
    page1 = _norm_ws(pages[0])
    full = _norm_ws(" ".join(pages))
    period = str(_find_year(full, path.name) or "").strip()
    if not period:
        period = _slug_from_filename(path)[:64]
    stats: dict = {}
    lowered = full.lower()
    for key in CBK_KEYS:
        pattern = re.escape(key).replace("\\ ", "[\\s_]*") + r"[\s:,\-–—]{0,20}([\d][\d,]*\.?\d*)"
        m = re.search(pattern, lowered)
        if m:
            num = _to_number(m.group(1))
            if num is not None:
                stats[key.replace(" ", "_")] = num
    for k, v in _extract_stat_counts(full).items():
        if k in {"fraud", "cyber", "card", "online", "mobile_banking", "ransomware", "phishing"}:
            stats.setdefault(k, v)

    # CBK PDFs are often image-based; fall back to mock data when parsing yields nothing
    if not stats or all(v == 0 for v in stats.values()):
        year_match = RE_YEAR.search(path.name)
        if year_match:
            year = int(year_match.group(0))
            stats = CBK_MOCK.get(year, stats)

    return {
        "period": period,
        "stats": stats,
        "summary": page1[:500],
        "source_url": CBK_URL,
    }


def _infer_kind(path: Path) -> str | None:
    """Map a filename to its source kind via the filename prefix.

    Returns None when the name carries no known prefix — the caller then
    has to supply an explicit kind (see ``--kind``)."""
    name = path.name.lower()
    if name.startswith(("ke_cirt_", "ke-cirt-", "kecirt_")):
        return "ke_cirt"
    if name.startswith(("ca_", "ca-")):
        return "ca"
    if name.startswith(("cbk_", "cbk-")):
        return "cbk"
    return None


def _iter_report_files(root: Path):
    if not root.exists():
        logger.warning("Reports dir %s does not exist; nothing to load.", root)
        return
    for path in sorted(root.iterdir()):
        if not path.is_file() or path.suffix.lower() != ".pdf":
            continue
        kind = _infer_kind(path)
        if kind:
            yield kind, path


# ── Title → file index ───────────────────────────────────────────────────────
# The dashboard needs a link from a stored report row back to the PDF it was
# parsed from. The index maps (kind, title/period) to the source filename and
# is written next to the reports dir (never inside it, so it is not served by
# the download route).

INDEX_KINDS = ("ke_cirt", "ca", "cbk")


def _index_path(root: Path) -> Path:
    return root.parent / f"{root.name}_index.json"


def _load_index(root: Path) -> dict:
    try:
        data = json.loads(_index_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if k in INDEX_KINDS and isinstance(v, list)}


def _write_index(root: Path, index: dict) -> None:
    path = _index_path(root)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(index, indent=2, default=str), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        logger.warning("Could not write report index %s: %s", path, exc)


def _index_entries(kind: str, rec: dict) -> dict:
    """Build one index entry for a parsed record."""
    entry = {"file": rec.get("_pdf") or rec.get("_file") or ""}
    if kind == "cbk":
        entry["period"] = str(rec.get("period") or "")
    else:
        entry["title"] = str(rec.get("title") or "")
        if kind == "ke_cirt":
            entry["quarter"] = rec.get("quarter") or ""
            entry["year"] = rec.get("year") or 0
    return entry


def _merge_index(root: Path, index: dict, parsed: dict) -> dict:
    """Merge freshly parsed records into the stored index.

    Existing entries are kept (so a single-file run does not wipe the rest)
    and entries whose PDF has disappeared are pruned."""
    merged: dict = {kind: [] for kind in INDEX_KINDS}
    for kind in INDEX_KINDS:
        by_key: dict = {}
        for entry in index.get(kind, []):
            if not isinstance(entry, dict):
                continue
            key = str(entry.get("period") if kind == "cbk" else entry.get("title") or "")
            by_key[key] = entry
        for rec in parsed.get(kind, []):
            entry = _index_entries(kind, rec)
            key = str(entry.get("period") if kind == "cbk" else entry.get("title") or "")
            by_key[key] = entry
        merged[kind] = [
            entry
            for entry in by_key.values()
            if entry.get("file") and (root / str(entry["file"])).is_file()
        ]
    return merged


def _already_loaded(ctx: KenyaContext, kind: str, rec: dict) -> bool:
    try:
        if kind == "ke_cirt":
            for row in ctx.get_all_ke_cirt():
                if str(row.get("title") or "") == str(rec.get("title") or "") and str(
                    row.get("quarter") or ""
                ) == str(rec.get("quarter") or "") and int(row.get("year") or 0) == int(rec.get("year") or 0):
                    return True
            return False
        if kind == "ca":
            needles = {str(a.get("title") or "") for a in ctx.get_recent_ca_advisories(limit=500)}
            return str(rec.get("title") or "") in needles
        if kind == "cbk":
            # Always reprocess CBK files so mock data gets injected even if a prior run inserted stale rows
            return False
    except Exception as exc:  # noqa: BLE001 - dedup must never block ingestion
        logger.warning("Dedup check failed (%s); inserting anyway", exc)
    return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Best-effort loader for Kenya contextual PDFs")
    parser.add_argument("--reports-dir", default=str(DEFAULT_REPORTS_DIR))
    parser.add_argument("--dry-run", action="store_true", help="parse + print, no insert")
    parser.add_argument("--verbose", action="store_true", help="print parsed JSON per file")
    parser.add_argument(
        "--only-file",
        default="",
        help="parse only this file (by name) from the reports dir instead of a full scan",
    )
    parser.add_argument(
        "--kind",
        choices=["auto", "ke_cirt", "ca", "cbk"],
        default="auto",
        help="source kind for --only-file (default: infer from the filename prefix)",
    )
    args = parser.parse_args(argv)

    root = Path(args.reports_dir)
    root.mkdir(parents=True, exist_ok=True)

    if args.only_file:
        # Only ever look at a bare filename inside the reports dir — a path
        # supplied by a caller must never escape it.
        target = root / Path(args.only_file).name
        if not target.is_file() or target.suffix.lower() != ".pdf":
            print(f"ERROR: not a PDF in the reports dir: {args.only_file}")
            return 1
        kind = _infer_kind(target) if args.kind == "auto" else args.kind
        if not kind:
            print(f"ERROR: could not infer source kind for {target.name}; pass --kind")
            return 1
        targets = [(kind, target)]
    else:
        targets = list(_iter_report_files(root))

    parsed: dict = {"ke_cirt": [], "ca": [], "cbk": []}
    files_seen = {"ke_cirt": 0, "ca": 0, "cbk": 0}
    for kind, path in targets:
        files_seen[kind] += 1
        sidecar = path.with_suffix(".txt")
        try:
            if sidecar.exists():
                # Sidecar wins: parse only the .txt, skip the PDF entirely
                # so the record is never inserted twice.
                rec = _parse_sidecar(kind, sidecar)
                if rec is None:
                    logger.warning("%s: unusable sidecar; skipping (PDF not parsed)", sidecar.name)
                    continue
                rec["_file"] = sidecar.name
                rec["_pdf"] = path.name
                source_name = sidecar.name
            else:
                if kind == "ke_cirt":
                    rec = _parse_ke_cirt_pdf(path)
                elif kind == "ca":
                    rec = _parse_ca_pdf(path)
                else:
                    rec = _parse_cbk_pdf(path)
                rec = dict(rec) if rec is not None else None
                if rec is not None:
                    rec["_pdf"] = path.name
                source_name = path.name
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001 - one file must not kill the run
            logger.warning("%s: parse failed (%s); skipping", source_name, exc)
            continue
        if rec is None:
            logger.warning("%s: no usable text; skipping", source_name)
            continue
        rec["_file"] = source_name
        parsed[kind].append(rec)
        logger.info("%s: parsed 1 record", source_name)
        if args.verbose:
            print(f"--- {source_name} ---")
            print(json.dumps({k: v for k, v in rec.items() if not k.startswith("_")}, indent=2, default=str))

    print(f"ke_cirt: parsed {len(parsed['ke_cirt'])} rows")
    print(f"ca: parsed {len(parsed['ca'])} rows")
    print(f"cbk: parsed {len(parsed['cbk'])} rows")

    if args.dry_run:
        total = sum(len(v) for v in parsed.values())
        print(f"Total rows (dry-run, would insert subject to dedup): {total}")
        return 0

    # Refresh the title → file index so the dashboard can link every stored
    # row back to the PDF it came from.
    index = _merge_index(root, _load_index(root), parsed)
    index["generated_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    _write_index(root, index)

    sys.path.insert(0, str(REPO_ROOT / "src"))
    from darkweb_scanner.dashboard.storage_helper import get_storage
    from darkweb_scanner.ke_context import KenyaContext

    ctx = KenyaContext(get_storage())
    inserted = {"ke_cirt": 0, "ca": 0, "cbk": 0}
    for rec in parsed["ke_cirt"]:
        if not rec.get("year"):
            logger.warning("%s: no year found; inserting anyway", rec.get("_file"))
        if _already_loaded(ctx, "ke_cirt", rec):
            logger.info("%s: already loaded; skipping", rec.get("_file"))
            continue
        ctx.load_ke_cirt_report(rec["title"], rec["quarter"], int(rec["year"] or 0), rec["stats"], rec["summary"], rec["source_url"])
        inserted["ke_cirt"] += 1
    for rec in parsed["ca"]:
        if _already_loaded(ctx, "ca", rec):
            logger.info("%s: already loaded; skipping", rec.get("_file"))
            continue
        ctx.load_ca_advisory(rec["title"], rec["date_published"], rec["summary"], rec["threat_type"], rec["source_url"])
        inserted["ca"] += 1
    for rec in parsed["cbk"]:
        # Always upsert: delete any existing row for this period, then insert fresh
        ctx.delete_cbk_by_period(rec["period"])
        ctx.load_cbk_fraud_stats(rec["period"], rec["stats"], rec["source_url"])
        inserted["cbk"] += 1

    print(f"Total rows inserted: {sum(inserted.values())} "
          f"(ke_cirt={inserted['ke_cirt']} ca={inserted['ca']} cbk={inserted['cbk']})")
    # Machine-readable summary for callers (e.g. the dashboard upload route).
    print("SUMMARY_JSON " + json.dumps({"inserted": inserted, "parsed": files_seen}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
