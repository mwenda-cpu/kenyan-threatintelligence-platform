"""Clearnet paste-site scrapers and OSINT modules for threat intelligence."""

from .context_scraper import scrape_context
from .ioc_scraper import run_ioc_scraper
from .keyword_extractor import (
    DOMAIN_WHITELIST,
    extract_and_store_keywords,
    extract_domains_from_paste_hits,
    extract_kenyan_pii,
    purge_all_keywords,
)
from .onion_scraper import scrape_onion
from .paste_scraper import (
    KE_PATTERNS,
    SOURCE_SCRAPERS,
    PasteResult,
    run_paste_scraper,
    scrape_ghostbin,
    scrape_hastebin,
    scrape_pastebin_api,
    scrape_rentry,
)

__all__ = [
    "KE_PATTERNS",
    "PasteResult",
    "SOURCE_SCRAPERS",
    "run_paste_scraper",
    "scrape_ghostbin",
    "scrape_hastebin",
    "scrape_pastebin_api",
    "scrape_rentry",
    "extract_kenyan_pii",
    "extract_and_store_keywords",
    "extract_domains_from_paste_hits",
    "purge_all_keywords",
    "DOMAIN_WHITELIST",
    "run_ioc_scraper",
    "scrape_onion",
    "scrape_context",
]
