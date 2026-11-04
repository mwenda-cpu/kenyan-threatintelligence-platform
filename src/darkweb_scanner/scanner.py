"""
Keyword scanner — matches keywords/regex patterns against crawled page text
and returns structured hits with surrounding context.
"""

import logging
import re
from dataclasses import dataclass, field

import yaml

from .snippets import DEFAULT_SNIPPET_LEN as SNIPPET_LEN
from .snippets import clean_snippet

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
        """Extract a readable snippet around the keyword match.

        1. Slices text around the match using the configured context window.
        2. Strips HTML tags, newlines, and collapses multiple spaces.
        3. Passes through clean_snippet to remove navigation chrome
           (leak-site menus, group listings, crypto dumps).
        4. Returns empty string when nothing readable remains.
        """
        idx = match.start()
        text_len = len(text)

        window = min(int(self.config.context_window or 200), 100)
        start = max(0, idx - window)
        end = min(text_len, idx + window)
        raw = text[start:end]

        # Strip HTML tags, newlines, collapse whitespace.
        raw = _HTML_TAG_RE.sub(" ", raw)
        raw = raw.replace("\n", " ").replace("\r", " ")
        raw = re.sub(r"\s+", " ", raw).strip()

        if not raw:
            return ""

        # Pass through the snippet cleaner to remove nav menus, group listings,
        # crypto addresses, etc. Returns "" when nothing readable is left.
        snippet = clean_snippet(raw, keep=keyword, max_len=SNIPPET_LEN)
        return snippet.strip() if snippet else ""

    def scan(self, url: str, text: str, depth: int = 0) -> list[KeywordHit]:
        """Scan text for all configured keywords. Returns list of hits."""
        if not text:
            return []

        hits = []
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
                    # Empty snippet after cleaning — skip saving.
                    continue

                hit = KeywordHit(
                    url=url,
                    keyword=keyword,
                    category=category,
                    context=context,
                    position=match.start(),
                    depth=depth,
                )
                hits.append(hit)
                seen_keywords.add(keyword)

        if hits:
            logger.info(f"Found {len(hits)} keyword hit(s) on {url}")

        return hits

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
