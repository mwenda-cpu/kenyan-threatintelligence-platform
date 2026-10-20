"""Clean, human-readable snippets for keyword hits.

Dark web pages are mostly navigation chrome: leak-site menus listing every
ransomware group ("v3 Open Bl4ckt0r v3 Open CL0P"), long onion addresses,
crypto wallet dumps and cookie banners. Saving a raw window around a keyword
captures that noise, so hits end up looking like gibberish in the dashboard
and in the PDF report.

This module strips the noise and keeps only the readable text around the
keyword, capped at a short length.
"""

import logging
import re

logger = logging.getLogger(__name__)

DEFAULT_SNIPPET_LEN = 250
MAX_SNIPPET_LEN = 500

# Long opaque strings: onion ids, wallet addresses, hashes, base58 blobs.
_CRYPTO_RE = re.compile(r"\b[A-Za-z0-9]{32,}\b")
# Address fragments ("gzR1QCHV4i84") — 12+ chars mixing letters and digits.
_ADDR_RE = re.compile(r"\b(?=[A-Za-z0-9]{12,})(?=[^\s]*[A-Za-z])(?=[^\s]*\d)[A-Za-z0-9]{12,}\b")
# "BTC: 1FyCD8kp9ekiTTgdyhFtZRgzR1QCHV4i84"
_MONEY_RE = re.compile(
    r"\b(?:BTC|XMR|ETH|LTC|monero|bitcoin|ethereum)\s*[:=]?\s*[A-Za-z0-9]{10,}\b",
    re.IGNORECASE,
)
_ONION_URL_RE = re.compile(r"https?://[a-z2-7]{16,56}\.onion\S*", re.IGNORECASE)
_HTML_ENTITY_RE = re.compile(r"&(?:[a-zA-Z]+|#\d+);")
_WS_RE = re.compile(r"\s+")
_REPEAT_TOKEN_RE = re.compile(r"\b(\w+)(?:\s+\1\b)+", re.IGNORECASE)

# A "brand" token: mixed case with a digit (Bl4ckt0r), ALL CAPS (CONTI),
# or a slug with a slash (AlphaVM/BlackCat). These are what distinguishes a
# leak-site menu of group names from an ordinary sentence.
_BRAND_TOKEN_RE = re.compile(r"^(?=[A-Za-z0-9]*[A-Za-z])(?=[A-Za-z0-9]*\d)[A-Za-z0-9&/'\.\-]{4,20}$")
_ALLCAPS_TOKEN_RE = re.compile(r"^[A-Z0-9&/\-]{3,20}$")
_SLASH_TOKEN_RE = re.compile(r"^[A-Z][A-Za-z0-9]*/[A-Za-z0-9]+$")
# A short, capitalised token — the building block of a menu row.
_LIST_TOKEN_RE = re.compile(r"^[A-Z0-9][A-Za-z0-9&/'\.\-]{0,15}$")

# Column headers and chrome of leak-site index pages.
_MENU_HEADERS = (
    "group name", "onion v. link", "onion v link", "onion link", "victim name",
    "leaked data", "skip to content", "cookie policy", "privacy policy",
    "terms of service", "terms of use", "read more", "share this", "follow us",
    "all posts", "no posts found", "all rights reserved", "toggle navigation",
    "previous", "next", "contact us", "about us", "sign in", "sign up",
    "log in", "log out", "register", "search", "home", "rss", "menu",
    "back to top", "loading", "copyright", "more", "posts", "pages",
    "index of", "file name", "file size", "affiliate", "mirrors",
    "encrypting the planet", "how to buy",
)

# Markers used by leak sites when listing groups ("Arvin Club v3 Open ...").
_GROUP_MARKER_RE = re.compile(r"(?:\bv\d+\s+open\b[\s,|]*)+", re.IGNORECASE)
_VERSION_MARKER_RE = re.compile(r"\bv\d+\s*open\b", re.IGNORECASE)

# Words that never carry meaning on their own in a snippet.
_FILLER_RE = re.compile(r"^[\s\W_]+|[\s\W_]+$", re.UNICODE)

_GROUP_TERMS: set[str] | None = None


def known_group_terms() -> set[str]:
    """Lower-cased names/keywords of known ransomware groups and threat actors.

    These names appear in leak-site navigation menus, which is where most
    false-positive hits come from.
    """
    global _GROUP_TERMS
    if _GROUP_TERMS is not None:
        return _GROUP_TERMS

    terms: set[str] = set()
    try:
        from .ransomware_data import RANSOMWARE_GROUPS

        for group in RANSOMWARE_GROUPS:
            name = (group.get("name") or "").strip()
            if name:
                terms.add(name.lower())
            for kw in group.get("keywords") or []:
                if kw and len(kw) > 2:
                    terms.add(str(kw).strip().lower())
    except Exception as exc:  # noqa: BLE001 - never break scanning on this
        logger.debug("Could not load ransomware group terms: %s", exc)

    try:
        from .threat_actors import THREAT_ACTORS

        for actor in THREAT_ACTORS:
            for field in ("name", "aliases"):
                value = actor.get(field) if isinstance(actor, dict) else None
                if isinstance(value, str) and value.strip():
                    terms.add(value.strip().lower())
                elif isinstance(value, (list, tuple)):
                    for item in value:
                        if item and len(str(item)) > 2:
                            terms.add(str(item).strip().lower())
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load threat actor terms: %s", exc)

    _GROUP_TERMS = {t for t in terms if len(t) > 2}
    return _GROUP_TERMS


def _strip_group_terms(text: str, keep: str = "") -> str:
    """Remove known group names (the matched keyword is kept)."""
    keep_key = (keep or "").strip().lower()
    for term in sorted(known_group_terms(), key=len, reverse=True):
        if term == keep_key:
            continue
        text = re.sub(rf"\b{re.escape(term)}\b", " ", text, flags=re.IGNORECASE)
    return text


def _is_brand_token(token: str) -> bool:
    if not token:
        return False
    if _SLASH_TOKEN_RE.match(token):
        return True
    if _BRAND_TOKEN_RE.match(token):
        return True
    if _ALLCAPS_TOKEN_RE.match(token) and any(c.isalpha() for c in token):
        return True
    return False


def _strip_nav_lists(text: str) -> str:
    """Remove leak-site menu rows: runs of short capitalised tokens.

    A leak-site index renders as a table of group names ("Arvin Club Babuk
    Black Basta AlphaVM/BlackCat Bl4ckt0r ..."). Such a run is recognised by
    being made only of short capitalised tokens and containing a couple of
    brand-like ones (leet names, ALL CAPS, slugs). Ordinary prose always has
    lowercase words, so it is left alone.
    """
    tokens = text.split()
    out: list[str] = []
    run: list[str] = []

    def flush() -> None:
        if len(run) >= 5 and sum(1 for t in run if _is_brand_token(t)) >= 2:
            out.append(" ")  # drop the whole menu row
        else:
            out.extend(run)
        run.clear()

    for token in tokens:
        stripped = token.strip()
        if stripped and _LIST_TOKEN_RE.match(stripped):
            run.append(stripped)
            continue
        flush()
        if stripped:
            out.append(stripped)
    flush()
    return " ".join(out)


def clean_snippet(text: str, keep: str = "", max_len: int = DEFAULT_SNIPPET_LEN) -> str:
    """Turn a raw window of page text into a short, readable snippet.

    ``keep`` is the matched keyword: it is preserved even when it is also a
    known group name. Returns an empty string when nothing readable is left.
    """
    if not text:
        return ""

    snippet = _HTML_ENTITY_RE.sub(" ", str(text))
    snippet = _ONION_URL_RE.sub(" ", snippet)
    snippet = _MONEY_RE.sub(" ", snippet)
    snippet = _CRYPTO_RE.sub(" ", snippet)
    snippet = _ADDR_RE.sub(" ", snippet)

    for header in _MENU_HEADERS:
        snippet = re.sub(rf"\b{re.escape(header)}\b", " ", snippet, flags=re.IGNORECASE)

    snippet = _strip_group_terms(snippet, keep=keep)
    snippet = _GROUP_MARKER_RE.sub(" ", snippet)
    snippet = _VERSION_MARKER_RE.sub(" ", snippet)
    snippet = _strip_nav_lists(snippet)

    # Collapse duplicated words ("the the the") and whitespace.
    snippet = _REPEAT_TOKEN_RE.sub(r"\1", snippet)
    snippet = _WS_RE.sub(" ", snippet)
    snippet = _FILLER_RE.sub("", snippet)
    snippet = re.sub(r"\s+([,;:.!?])", r"\1", snippet)
    snippet = re.sub(r"([,;|])\s*([,;|])", r"\2", snippet)
    snippet = _WS_RE.sub(" ", snippet).strip()

    if not snippet:
        return ""

    # A snippet needs a couple of real words to be worth storing.
    words = [w for w in re.split(r"\W+", snippet) if len(w) > 2]
    if len(words) < 2:
        return ""

    limit = max(40, min(int(max_len or DEFAULT_SNIPPET_LEN), MAX_SNIPPET_LEN))
    if len(snippet) > limit:
        snippet = snippet[:limit].rstrip()
        if " " in snippet:
            snippet = snippet[: snippet.rfind(" ")].rstrip()
        snippet += "..."
    return snippet


# ── Actionable-hit filter ────────────────────────────────────────────────────

# Search engines, legal pages and site chrome are never threat intelligence.
BLOCKED_URL_PARTS = (
    "ahmia.fi", "/terms", "/privacy", "/login", "/signin", "/search",
    "/register", "/cookie", "/sitemap",
)

# Keywords produced by the broken configuration (never real hits).
JUNK_KEYWORDS = {"category", "severity"}

# Categories that represent an actual threat.
THREAT_CATEGORIES = {
    "ransomware", "threat-actors", "threat_actor", "threat-actor", "threat_type",
    "phishing", "malware", "cybercrime", "infostealer", "data_leak", "data-leak",
    "apt", "intrusion", "breach", "vulnerability", "cve", "banking_fraud",
    "sim_swap", "identity_theft", "credential",
}

# Kenyan target markers.
_KE_MARKERS = (
    "kenya", "kenyan", "nairobi", "mombasa", "kisumu", "nakuru", "eldoret",
    "kra", "ecitizen", "ifmis", "kcb", "equity bank", "co-operative bank",
    "coopbank", "sacco", "kenya revenue authority", "kcs", "ict authority",
    "cybersecurity authority", "ke-cirt", "kecirt", "communications authority",
)


def is_actionable_hit(hit) -> bool:
    """True when a hit is real threat intelligence worth reporting.

    Rejects: junk keywords from the broken config, search-engine and legal
    pages, and hits whose only evidence is navigation chrome.
    """
    keyword = str(getattr(hit, "keyword", "") or "").strip().lower()
    if not keyword or keyword in JUNK_KEYWORDS:
        return False

    url = str(getattr(hit, "url", "") or "").lower()
    if any(part in url for part in BLOCKED_URL_PARTS):
        return False

    category = str(getattr(hit, "category", "") or "").strip().lower()
    context = str(getattr(hit, "context", "") or "").lower()

    # A known ransomware group or threat actor is always actionable.
    if keyword in known_group_terms():
        return True
    # A threat category is actionable.
    if category in THREAT_CATEGORIES:
        return True
    # A Kenyan target mention is actionable.
    if any(marker in context for marker in _KE_MARKERS):
        return True
    return False
