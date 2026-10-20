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


@dataclass
class KeywordHit:
    url: str
    keyword: str
    category: str
    context: str  # surrounding text window
    position: int  # character offset in text
    depth: int = 0


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
                    pattern = re.compile(re.escape(keyword), flags)
                    self._patterns[keyword] = (category, pattern)
                except re.error as e:
                    logger.warning(f"Invalid keyword pattern '{keyword}': {e}")

    def _get_context(self, text: str, match: re.Match, keyword: str = "") -> str:
        """Short, readable snippet around a match.

        The raw window is passed through the snippet cleaner so that page
        chrome (leak-site menus, onion lists, crypto dumps) never reaches the
        database. An empty string means the match was only navigation noise.
        """
        window = min(int(self.config.context_window or 200), 140)
        start = max(0, match.start() - window)
        end = min(len(text), match.end() + window)
        snippet = clean_snippet(text[start:end], keep=keyword, max_len=SNIPPET_LEN)
        if snippet:
            # Keep the original position of the keyword for reference.
            if not snippet.lower().startswith("..."):
                snippet = ("..." if start > 0 else "") + snippet
            if end < len(text) and not snippet.endswith("..."):
                snippet += "..."
        return snippet.strip()

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
                if not context or keyword.lower() not in context.lower():
                    # The keyword only appeared in page chrome (a leak-site
                    # menu listing group names, a crypto dump, a nav bar) —
                    # that is not an actionable hit.
                    logger.debug("Skipping navigation-noise hit for %r on %s", keyword, url)
                    continue
                hits.append(
                    KeywordHit(
                        url=url,
                        keyword=keyword,
                        category=category,
                        context=context,
                        position=match.start(),
                        depth=depth,
                    )
                )
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
