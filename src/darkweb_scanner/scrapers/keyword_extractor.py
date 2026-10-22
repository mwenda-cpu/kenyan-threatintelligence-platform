"""
Strict domain-focused keyword extraction for Kenyan targets.

Parses paste-hit text for URLs, extracts root domains, and keeps ONLY
domains from an exact whitelist of Kenyan government, health, banking,
and fintech targets. Also directly matches known ransomware groups and
Kenyan threat entities (M-Pesa, Fuliza, SHA, etc.). All previous junk
keywords are purged on first run.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func  # noqa: E402
from darkweb_scanner.storage import Keyword  # noqa: E402

logger = logging.getLogger(__name__)

# Kenyan PII regex patterns
KE_PHONE_RE = __import__("re").compile(r"(?:\+254|0)[17]\d{8}")
KE_MPESA_CODE_RE = __import__("re").compile(r"\b[A-Z0-9]{10}\b")
KE_KRA_PIN_RE = __import__("re").compile(r"\b[A-Z]\d{9}[A-Z]\b")


def extract_kenyan_pii(text):
    """Extract Kenyan PII from text using regex patterns."""
    if not text:
        return []
    import re
    results = []
    seen = set()
    for match in KE_PHONE_RE.finditer(text):
        val = match.group(0)
        if val not in seen:
            seen.add(val)
            results.append({"type": "phone", "value": val, "pii": True, "label": "KE Phone"})
    for match in KE_MPESA_CODE_RE.finditer(text):
        val = match.group(0)
        if val not in seen:
            has_letter = any(c.isalpha() for c in val)
            has_digit = any(c.isdigit() for c in val)
            if has_letter and has_digit:
                seen.add(val)
                results.append({"type": "mpesa", "value": val, "pii": True, "label": "M-Pesa Code"})
    for match in KE_KRA_PIN_RE.finditer(text):
        val = match.group(0)
        if val not in seen:
            seen.add(val)
            results.append({"type": "kra_pin", "value": val, "pii": True, "label": "KRA PIN"})
    return results

# ── STOP_WORDS: geographic / generic noise that must never be tracked ─────
STOP_WORDS = {
    # Geographic terms (East Africa noise)
    "nairobi", "mombasa", "kisumu", "nakuru", "eldoret", "thika",
    "uganda", "tanzania", "rwanda", "burundi", "south sudan",
    "east africa", "east african", "eastafrica",
    # Generic / noise terms
    "email dump", "dump", "leak", "database", "action", "alert",
    "credential", "credentials", "combo", "combolist", "sqli",
    "xss", "rce", "rfi", "lfi", "xxe", "csrf","email dump", "database"
}

# ── Ransomware groups (explicitly captured) ──────────────────────────────
RANSOMWARE_GROUPS = {
    "lockbit", "lockbit 3.0", "lockbitblack",
    "cl0p", "clop", "cl0p ransomware",
    "alphv", "alphv ransomware", "blackcat",
    "akira", "akira ransomware",
    "play", "play ransomware",
    "8base", "8base ransomware",
    "medusa", "medusa ransomware",
    "royal", "royal ransomware",
    "blacksuit", "black suit",
    "cactus", "cactus ransomware",
    "ransomhouse", "ransom house",
}

# ── Kenyan threat entities (heavily weighted) ────────────────────────────
KENYAN_ENTITIES = {
    "m-pesa", "mpesa", "fuliza", "sha", "kra", "ecitizen",
    "equity bank", "equitybank", "kcb", "kcb bank",
    "co-op bank", "cooperative bank", "ncba", "absabank",
    "stanbic", "dtb", "family bank", "safaricom",
    "airtel money", "telkom", "pesalink",
}

# ── Exact domain whitelist (root domains only) ──────────────────────────
DOMAIN_WHITELIST = {
    # Government
    "ecitizen.go.ke", "kra.go.ke", "ntsa.go.ke", "hudumakenya.go.ke",
    "treasury.go.ke", "sha.go.ke", "ict.go.ke", "internet.go.ke",
    # Public Health
    "health.go.ke", "nhif.or.ke", "pharmacy.go.ke", "kemri.org",
    # Banking
    "kcb.co.ke", "kcbgroup.com", "equitybank.co.ke", "co-opbank.co.ke",
    "ncba.co.ke", "absabank.co.ke", "stanbicbank.co.ke", "dtbafrica.com",
    "familybank.co.ke",
    # Fintech / Telco
    "safaricom.co.ke", "m-pesa.com", "airtel.co.ke", "telkom.co.ke",
    "pesalink.com",
}


# ── URL / domain extraction regex ───────────────────────────────────────
# Matches http://, https://, or bare domains with .ke/.co.ke/.go.ke/.or.ke/.com
_URL_RE = re.compile(
    r"https?://(?:www\.)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:/[^\s]*)?",
    re.IGNORECASE,
)
# Bare domain without protocol (e.g., "kra.go.ke/portal")
_BARE_DOMAIN_RE = re.compile(
    r"(?:^|\s)([A-Za-z0-9.-]+\.(?:go\.ke|co\.ke|or\.ke|ac\.ke|org|com))(?:/[^\s]*)?",
    re.IGNORECASE,
)


def purge_all_keywords(storage) -> int:
    """
    One-time purge: delete ALL existing keywords from the database.
    Returns the number of rows deleted.
    """
    with storage.get_session() as session:
        count = session.query(func.count(Keyword.id)).scalar() or 0
        session.query(Keyword).delete()
        session.commit()
    logger.info("Purged %d existing keywords from database", count)
    return count


def _extract_domain(text: str) -> Optional[str]:
    """
    Extract a root domain from text.

    Strips http://, https://, www., and trailing paths/params.
    Returns lowercase domain or None.
    """
    if not text:
        return None

    # Try full URL match first
    m = _URL_RE.search(text)
    if m:
        domain = m.group(1).lower().strip(".")
        return domain

    # Try bare domain match
    m = _BARE_DOMAIN_RE.search(text)
    if m:
        domain = m.group(1).lower().strip(".")
        return domain

    return None


def extract_domains_from_paste_hits(
    hits: list[dict],
) -> list[dict]:
    """
    Extract whitelisted root domains from paste-hit records.

    Args:
        hits: List of paste-hit dicts (from get_recent_paste_hits).

    Returns:
        List of {"keyword": str, "category": str, "frequency": int} dicts,
        sorted by frequency desc.
    """
    counter: Counter[str] = Counter()

    for hit in hits or []:
        context = hit.get("context") or ""
        matched_value = hit.get("matched_value") or ""
        combined = f"{matched_value} {context}"

        domain = _extract_domain(combined)
        if domain and domain in DOMAIN_WHITELIST:
            counter[domain] += 1

    # Build result list
    results = []
    for domain, freq in counter.most_common():
        cat = DOMAIN_CATEGORY.get(domain, "custom")
        results.append({
            "keyword": domain,
            "category": cat,
            "severity": "high",
            "frequency": freq,
        })

    return results


def extract_and_store_keywords(storage, lookback_days: int = 7,
                                min_freq: int = 1,
                                max_keywords: int = 50,
                                purge_first: bool = True) -> dict:
    """
    Fetch recent paste hits, extract whitelisted domains, and store them.

    Args:
        storage: Storage instance.
        lookback_days: How far back to look for paste hits.
        min_freq: Minimum frequency threshold.
        max_keywords: Max keywords to store.
        purge_first: If True, delete all existing keywords before inserting.

    Returns:
        Summary dict with counts.
    """
    # One-time purge of all existing (junk) keywords
    if purge_first:
        purge_all_keywords(storage)

    # Fetch recent paste hits
    hits = storage.get_recent_paste_hits(limit=2000)

    # Filter by lookback window
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=lookback_days)
    recent = []
    for h in hits:
        fa = h.get("found_at")
        if fa:
            try:
                dt = datetime.fromisoformat(str(fa))
                if dt >= cutoff:
                    recent.append(h)
            except (ValueError, TypeError):
                recent.append(h)
        else:
            recent.append(h)

    logger.info("Analyzing %d paste hits from last %d days", len(recent), lookback_days)

    keywords = extract_domains_from_paste_hits(recent)

    # Apply min_freq filter
    keywords = [kw for kw in keywords if kw["frequency"] >= min_freq]

    # Limit
    keywords = keywords[:max_keywords]

    # Store them (category = domain category, severity = high)
    added = storage.add_keywords([
        {"keyword": kw["keyword"], "category": kw["category"], "severity": "high"}
        for kw in keywords
    ])

    return {
        "hits_analyzed": len(recent),
        "keywords_extracted": len(all_kws),
        "keywords_added": added,
        "purge_performed": purge_first,
        "keywords": all_kws,
    }


if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from darkweb_scanner.storage import Storage

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    storage = Storage()
    summary = extract_and_store_keywords(storage)
    print("\nDomain keyword extraction complete:")
    print(f"  Hits analyzed: {summary['hits_analyzed']}")
    print(f"  Domains extracted: {summary['keywords_extracted']}")
    print(f"  Keywords added: {summary['keywords_added']}")
    print(f"  Purge performed: {summary['purge_performed']}")
    for kw in summary["keywords"][:10]:
        print(f"  {kw['keyword']} ({kw['category']}) freq={kw['frequency']}")
