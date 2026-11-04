"""
Keyword scanner — matches keywords/regex patterns against crawled page text
and returns structured hits with surrounding context.
"""

import logging
import re
from dataclasses import dataclass, field

import yaml

from .snippets import DEFAULT_SNIPPET_LEN as SNIPPET_LEN
from .snippets import clean_snippet, is_actionable_hit, _WS_RE

logger = logging.getLogger(__name__)

# Residual HTML tags that may survive page-text extraction.
_HTML_TAG_RE = re.compile(r"<[^>]+>", re.IGNORECASE)


@dataclass
class KeywordHit:
    url: str
    keyword: str
    category: str
    context: str  # surrounding text window
    position: int  # character offset in text
    depth: int = 0


# Generic/low-signal keyword categories that should not produce hits on
# their own — they require additional threat signals in the context.
_GENERIC_CATEGORIES = {"geography", "domain", "news"}

# Threat signals that elevate a generic keyword match to actionable.
_THREAT_SIGNALS = (
    "ransomware", "ransom", "breach", "hack", "cyber", "attack", "leak",
    "malware", "phishing", "intrusion", "vulnerability", "cve", "exploit",
    "ddos", "botnet", "trojan", "spyware", "rootkit", "wiper", "extortion",
    "data theft", "credential", "session", "access", "initial access",
    "lateral movement", "privilege escalation", "command and control",
)

# Distinct Kenyan government / corporate targets that count as signal.
_KE_TARGETS = (
    "kra", "ecitizen", "itax", "ifmis", "ntsa", "kcb", "equity bank",
    "co-operative bank", "coopbank", "ncba", "absa kenya", "stanbic",
    "standard chartered", "dtb kenya", "diamond trust bank", "i&m bank",
    "family bank", "prime bank", "hf group", "national bank of kenya",
    "nbk", "postbank", "safaricom", "airtel money", "airtel kenya",
    "telkom kenya", "equitel", "fuliza", "m-shwari", "kcb m-pesa",
    "pesalink", "m-pesa", "central bank of kenya", "cbk", "capital markets",
    "cma kenya", "sasra", "financial reporting centre", "communications authority",
    "ca kenya", "bs-soc", "ke-cirt", "kecirt", "kenya defence forces",
    "national intelligence service", "national treasury", "ministry of health",
    "ministry of interior", "ministry of ict", "ministry of defence",
    "kenya revenue authority", "kenya pipeline", "kengen", "ketraco",
    "kenya ports authority", "jomo kenyatta", "jomo kenyatta international",
    "wilson airport", "kenya railways", "kenya law", "judiciary kenya",
    "parliament kenya", "iebr", "ieBC", "kebs", "kplc", "kpc", "nssf",
    "nhif", "sha", "iprs", "huduma namba", "business registration service",
)


@dataclass
class KeywordConfig:
    categories: dict[str, list[str]] = field(default_factory=dict)
    case_sensitive: bool = False
    context_window: int = 200  # chars on each side of hit
    alert_on_first_hit_only: bool = True

    @classmethod
    def from_yaml(cls, path: str) -> "KeywordConfig":
        with open(path) as f:
            raw = yaml.safe_load(f)

        settings = raw.get("settings", {})
        keywords = raw.get("keywords", {})

        return cls(
            categories=keywords,
            case_sensitive=settings.get("case_sensitive", False),
            context_window=settings.get("context_window", 200),
            alert_on_first_hit_only=settings.get("alert_on_first_hit_only", True),
        )

    @classmethod
    def from_list(cls, keywords: list[str], category: str = "default") -> "KeywordConfig":
        return cls(categories={category: keywords})


class Scanner:
    def __init__(self, config: KeywordConfig):
        self.config = config
        self._patterns: dict[str, tuple[str, re.Pattern]] = {}  # keyword -> (category, pattern)
        self._compile_patterns()

    def _compile_patterns(self):
        flags = 0 if self.config.case_sensitive else re.IGNORECASE
        for category, keywords in self.config.categories.items():
            for keyword in keywords:
                try:
                    pattern = re.compile(r"\b" + re.escape(keyword) + r"\b", flags)
                    self._patterns[keyword] = (category, pattern)
                except re.error as e:
                    logger.warning(f"Invalid keyword pattern '{keyword}': {e}")

    def _get_context(self, text: str, match: re.Match, keyword: str = "") -> str:
        """Extract exactly 60 chars before and after the keyword match.

        1. Isolates the exact keyword index via match.start()/match.end().
        2. Slices text[max(0, idx-60):idx+60].
        3. Strips HTML tags, newlines, and collapses multiple spaces.
        4. Adds ellipses if the slice cut off words at either boundary.
        5. Returns empty string when the slice is boilerplate without threat
           signals (so the caller skips saving it).
        """
        idx = match.start()
        text_len = len(text)

        # Strict 60-char window on each side of the keyword index.
        start = max(0, idx - 60)
        end = min(text_len, idx + 60)
        raw = text[start:end]

        # Strip HTML tags.
        raw = _HTML_TAG_RE.sub(" ", raw)
        # Strip newlines and carriage returns.
        raw = raw.replace("\n", " ").replace("\r", " ")
        # Collapse multiple spaces into one.
        raw = re.sub(r"\s+", " ", raw).strip()

        if not raw:
            return ""

        # Add ellipses if the slice cut off words at either boundary.
        if start > 0 and not raw.startswith("..."):
            raw = "..." + raw
        if end < text_len and not raw.endswith("..."):
            raw = raw + "..."

        snippet = raw.strip()

        # Filter boilerplate: if the slice contains no threat signal, skip it.
        if snippet and not self._has_threat_signal(snippet, keyword):
            return ""

        return snippet

    def _threat_priority(self, keyword: str, context: str) -> int:
        """Return a relevance score — higher = more threat-relevant context."""
        score = 0
        kw = (keyword or "").lower()
        ctx = (context or "").lower()
        combined = f"{kw} {ctx}"

        for signal in _THREAT_SIGNALS:
            if signal in combined:
                score += 100
        for target in _KE_TARGETS:
            if target in combined:
                score += 50
        return score

    def _has_threat_signal(self, context: str, keyword: str) -> bool:
        """True when the context contains threat intelligence signals.

        Only checks _THREAT_SIGNALS (ransomware, breach, hack, leak, etc.).
        Kenyan targets alone (e.g. "ifmis" in a URL) are NOT threat signals
        — they only affect dedup priority via _threat_priority.
        """
        ctx = (context or "").lower()
        # Any threat signal word in context makes it actionable.
        for signal in _THREAT_SIGNALS:
            if signal in ctx:
                return True
        return False

    def scan(self, url: str, text: str, depth: int = 0) -> list[KeywordHit]:
        """Scan text for all configured keywords. Returns list of hits.

        Deduplicates by URL: when multiple keywords match on the same page,
        only the hit with the most threat-relevant context is kept.
        """
        if not text:
            return []

        all_hits: list[KeywordHit] = []
        seen_keywords: set[str] = set()

        for keyword, (category, pattern) in self._patterns.items():
            matches = list(pattern.finditer(text))
            if not matches:
                continue

            if self.config.alert_on_first_hit_only:
                matches = matches[:1]

            for match in matches:
                if self.config.alert_on_first_hit_only and keyword in seen_keywords:
                    break

                context = self._get_context(text, match, keyword)
                if not context:
                    # Boilerplate or empty — skip saving.
                    continue

                if keyword.lower() not in context.lower():
                    # Keyword only appeared in page chrome, not in context.
                    continue

                hit = KeywordHit(
                    url=url,
                    keyword=keyword,
                    category=category,
                    context=context,
                    position=match.start(),
                    depth=depth,
                )
                if not is_actionable_hit(hit):
                    continue

                all_hits.append(hit)
                seen_keywords.add(keyword)

        if not all_hits:
            return []

        # Deduplicate by URL: keep only the hit with the highest threat priority.
        best_by_url: dict[str, KeywordHit] = {}
        for hit in all_hits:
            existing = best_by_url.get(hit.url)
            if existing is None:
                best_by_url[hit.url] = hit
            else:
                existing_score = self._threat_priority(
                    existing.keyword, existing.context
                )
                new_score = self._threat_priority(hit.keyword, hit.context)
                if new_score > existing_score:
                    best_by_url[hit.url] = hit

        return list(best_by_url.values())

    def add_keyword(self, keyword: str, category: str = "custom"):
        """Dynamically add a keyword at runtime."""
        flags = 0 if self.config.case_sensitive else re.IGNORECASE
        try:
            pattern = re.compile(re.escape(keyword), flags)
            self._patterns[keyword] = (category, pattern)
            if category not in self.config.categories:
                self.config.categories[category] = []
            self.config.categories[category].append(keyword)
        except re.error as e:
            logger.warning(f"Could not add keyword '{keyword}': {e}")

    def remove_keyword(self, keyword: str):
        """Remove a keyword."""
        self._patterns.pop(keyword, None)
        for kws in self.config.categories.values():
            if keyword in kws:
                kws.remove(keyword)

    @property
    def keyword_count(self) -> int:
        return len(self._patterns)
