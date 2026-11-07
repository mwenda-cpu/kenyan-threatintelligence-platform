"""
Text sanitization helpers for scraped/ingested content.

The scrapers occasionally pull raw page dumps that contain minified JS/CSS,
base64 blobs, crypto wallet addresses, onion URLs and connection strings.
Rendering those verbatim in the UI produces gibberish and can break table
layouts. This module provides :func:`sanitize_scraped_text` so callers can
scrub text before it is persisted to the database.
"""

from __future__ import annotations

import re
from typing import Union

# Fallback returned when the source text is deemed unreadable/minified.
FALLBACK = "[Page content unavailable / restricted]"

# Maximum length of the returned (sanitized) string.
MAX_LEN = 1000

# Minimum ratio of alphanumeric + space characters required for the text to be
# considered "readable". Below this ratio the content is treated as minified
# JS/CSS or binary garbage.
READABLE_DENSITY = 0.75

# Tokens that are disproportionately common in minified JS/CSS.
_MINIFIED_TOKENS = (
    "{",
    "}",
    ";",
    "function",
    "eval",
    "=>",
    "const ",
    "let ",
    "var ",
    "document.",
    "window.",
    "localStorage",
    ".prototype",
)

# A run of base64-ish characters (alphanumeric + ``+/``) longer than 50 chars
# with no spaces is almost certainly an encoded blob.
_RE_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{51,}={0,2}")

# ``data:`` / ``blob:`` URIs often wrap base64 payloads.
_RE_DATA_URI = re.compile(r"\b(?:data|blob):[^\s,;)]+", re.IGNORECASE)

# Connection strings (mongodb://, postgresql://, redis://, mysql://, ...)
_RE_CONN_STRING = re.compile(r"\b[a-z][a-z0-9+]*://[^\s/?#]+", re.IGNORECASE)

# Bitcoin addresses (legacy 1/3 prefix, base58, 25-34 chars).
_RE_BTC_ADDR = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
# Ethereum / EVM addresses: 0x + 40 hex chars.
_RE_ETH_ADDR = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
# Generic long base58-looking wallet addresses.
_RE_WALLET_ADDR = re.compile(r"\b[a-zA-Z1-9]{32,44}\b")
# Tor onion v2 (16 chars) and v3 (56 chars) addresses.
_RE_ONION = re.compile(r"\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b", re.IGNORECASE)

# Control characters (except common whitespace) that should be removed.
_RE_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# HTML tags to strip when tag density is high.
_RE_HTML_TAG = re.compile(r"<[^>]+>")

# SQL keywords that indicate a leaked DB dump / raw SQL.
_SQL_KEYWORDS = ("SELECT ", "INSERT INTO", "CREATE TABLE", "UNION ALL")

# Below this unique-word ratio the text is treated as a scraping artifact
# (the same phrase scraped repeatedly from page structure).
_REPETITION_RATIO_FLOOR = 0.30

# Minimum length (in chars) required after stripping HTML tags.
_HTML_STRIP_MIN_LEN = 50

# Angle-bracket-to-letter ratio above which raw HTML is suspected.
_HTML_TAG_RATIO_FLOOR = 0.30

# Metadata-dump heuristics: if 2+ of these patterns match, the text is a
# search-results / leak-site metadata sidebar, not threat context.
_RE_METADATA_VIEWS = re.compile(r"\(views:\s*\d+\)|views:\s*\d+")
_RE_METADATA_TS = re.compile(r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+UTC")
_RE_METADATA_PUBLISHED = re.compile(r"Published\s+[a-z0-9.-]+", re.IGNORECASE)
_METADATA_PATTERN_FLOOR = 2


def _looks_minified(text: str) -> bool:
    """Heuristic: return True when *text* looks like minified JS/CSS."""
    if not text:
        return False
    total = len(text)
    if total == 0:
        return False
    # Ratio of alphanumeric + space characters.
    alnum_space = sum(1 for ch in text if ch.isalnum() or ch == " ")
    density = alnum_space / total
    # Count minified-token occurrences relative to length.
    token_hits = sum(text.lower().count(tok) for tok in _MINIFIED_TOKENS)
    token_density = token_hits / total
    return density < READABLE_DENSITY or token_density > 0.03


def _looks_like_json(text: str) -> bool:
    """Heuristic: return True when *text* looks like a raw JSON/dict dump."""
    t = text.strip()
    if not t or t[0] not in "{[":
        return False
    # Multiple key-value pairs indicated by quotes and colons.
    return t.count('"') >= 4 and t.count(":") >= 2


def _looks_like_sql(text: str) -> bool:
    """Heuristic: return True when *text* looks like SQL or a DB row dump."""
    upper = text.upper()
    sql_hits = sum(upper.count(kw) for kw in _SQL_KEYWORDS)
    if sql_hits >= 2:
        return True
    # Tab-separated / pipe-delimited dump with numbers (leaked rows).
    if text.count("|") >= 3 and any(ch.isdigit() for ch in text):
        return True
    return False


def _strip_html_if_noisy(text: str) -> str:
    """Strip HTML tags when tag density is high; return the cleaned text.

    If the cleaned text is too short to be useful, return ``FALLBACK`` so the
    caller can treat the whole blob as noise.
    """
    letters = sum(1 for ch in text if ch.isalpha())
    angle = text.count("<") + text.count(">")
    if letters and angle / max(letters, 1) > _HTML_TAG_RATIO_FLOOR:
        stripped = _RE_HTML_TAG.sub(" ", text)
        stripped = re.sub(r"\s+", " ", stripped).strip()
        if len(stripped) < _HTML_STRIP_MIN_LEN:
            return FALLBACK
        return stripped
    return text


def _has_low_word_diversity(text: str) -> bool:
    """Heuristic: return True when the same phrase is scraped repeatedly."""
    words = text.split()
    if not words:
        return False
    return len(set(words)) / len(words) < _REPETITION_RATIO_FLOOR


def _looks_like_metadata_dump(text: str) -> bool:
    """Heuristic: return True when *text* looks like a metadata sidebar dump.

    Matches search-results / leak-site metadata: view counters, raw UTC
    timestamps, and "Published <domain>" lines. Returns True when 2+ patterns
    match.
    """
    hits = 0
    if _RE_METADATA_VIEWS.search(text):
        hits += 1
    if _RE_METADATA_TS.search(text):
        hits += 1
    if _RE_METADATA_PUBLISHED.search(text):
        hits += 1
    return hits >= _METADATA_PATTERN_FLOOR


def sanitize_scraped_text(raw_text: Union[str, bytes, None]) -> str:
    """Clean raw scraped text so it is safe to persist and display.

    Steps:
      1. Decode ``bytes`` input (utf-8, errors ``ignore``).
      2. Strip base64-looking blobs (>50 chars, no spaces).
      3. Strip data/blob URIs, connection strings, wallet addresses, onion URLs.
      4. Remove control characters and collapse whitespace.
      5. Strip HTML tags when tag density is high (reject if too short).
      6. Reject raw JSON/dict dumps.
      7. Reject SQL / leaked database row dumps.
      8. Reject metadata sidebar dumps (view counters, UTC timestamps,
         "Published <domain>" lines).
      9. Reject low-diversity (repeated-phrase) scraping artifacts.
      10. Reject minified JS/CSS-like content (returns ``FALLBACK``).
      11. Truncate to :data:`MAX_LEN` characters, ending on a word boundary.

    Returns the sanitized string, :data:`FALLBACK` for unreadable content, or
    ``""`` when the input was empty or nothing usable remained.
    """
    # 1. Decode bytes if necessary.
    if raw_text is None:
        return ""
    if isinstance(raw_text, bytes):
        try:
            text = raw_text.decode("utf-8", errors="ignore")
        except Exception:  # pragma: no cover - defensive
            text = raw_text.decode("latin-1", errors="ignore")
    else:
        text = str(raw_text)

    if not text:
        return ""

    # 2. Strip base64-looking blobs.
    text = _RE_BASE64_BLOB.sub(" ", text)

    # 3. Strip data/blob URIs, connection strings, wallet addresses, onion URLs.
    text = _RE_DATA_URI.sub(" ", text)
    text = _RE_CONN_STRING.sub(" ", text)
    text = _RE_BTC_ADDR.sub(" ", text)
    text = _RE_ETH_ADDR.sub(" ", text)
    text = _RE_WALLET_ADDR.sub(" ", text)
    text = _RE_ONION.sub(" ", text)

    # 4. Remove control characters and collapse whitespace.
    text = _RE_CONTROL.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()

    if not text:
        return ""

    # 5. Strip HTML tags when tag density is high.
    text = _strip_html_if_noisy(text)
    if text == FALLBACK:
        return FALLBACK

    # 6. Reject raw JSON / dict dumps.
    if _looks_like_json(text):
        return FALLBACK

    # 7. Reject SQL / leaked database row dumps.
    if _looks_like_sql(text):
        return FALLBACK

    # 8. Reject metadata sidebar dumps (view counters, UTC timestamps,
    #    "Published <domain>" lines).
    if _looks_like_metadata_dump(text):
        return FALLBACK

    # 9. Reject low-diversity (repeated-phrase) scraping artifacts.
    if _has_low_word_diversity(text):
        return FALLBACK

    # 9. Readable-density / minified check.
    if _looks_minified(text):
        return FALLBACK

    # 10. Truncate to MAX_LEN at a word boundary.
    if len(text) > MAX_LEN:
        cut = text[:MAX_LEN]
        last_space = cut.rfind(" ")
        if last_space > MAX_LEN // 2:
            text = cut[:last_space].strip()
        else:
            text = cut.strip()

    return text
