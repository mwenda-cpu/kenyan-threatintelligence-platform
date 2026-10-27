"""
Async BFS crawler for .onion sites.
Follows links up to a configurable depth, respects rate limits,
and yields page content for downstream processing.
"""

import asyncio
import logging
import os
import pathlib
import random
import re
from collections import deque
from dataclasses import dataclass
from typing import AsyncIterator, Optional, Set
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from .storage import Storage
from .tor_client import TorClient, create_tor_client

logger = logging.getLogger(__name__)

KEYWORDS_DEFAULT = pathlib.Path(__file__).resolve().parents[2] / "config" / "keywords.yaml"

ONION_PATTERN = re.compile(r"https?://[a-z2-7]{16,56}\.onion", re.IGNORECASE)

# ── URL blocklist: junk / legal / search-engine pages never worth crawling ─────
BLOCKED_URL_PARTS = (
    "ahmia.fi",
    "juhanurmihxlp",          # Ahmia .onion
    "/terms", "/privacy", "/about", "/faq", "/contact", "/login",
    "/register", "/signin", "/search", "/cookie", "/sitemap",
    "torch", "darksearch",
    "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
)


@dataclass
class CrawlResult:
    url: str
    status_code: int
    html: str
    text: str
    links: list[str]
    depth: int
    error: Optional[str] = None


@dataclass
class CrawlConfig:
    max_depth: int = int(os.getenv("MAX_DEPTH", "3"))
    max_concurrent: int = int(os.getenv("MAX_CONCURRENT_REQUESTS", "10"))
    delay_min: float = float(os.getenv("CRAWL_DELAY_MIN", "2"))
    delay_max: float = float(os.getenv("CRAWL_DELAY_MAX", "8"))
    rotate_circuit_every: int = int(os.getenv("ROTATE_CIRCUIT_EVERY", "50"))
    max_pages_per_domain: int = int(os.getenv("MAX_PAGES_PER_DOMAIN", "100"))
    max_pages_per_crawl: int = int(os.getenv("MAX_PAGES_PER_CRAWL", "50"))
    stay_on_domain: bool = os.getenv("STAY_ON_DOMAIN", "false").lower() == "true"
    allowed_content_types: tuple = ("text/html",)

    # Pagination URL patterns to follow for historical data.
    pagination_patterns: tuple = (
        "?page=", "&page=", "?p=", "&p=",
        "/page/", "/p/", "/archive", "/archives",
    )


class Crawler:
    def __init__(self, tor_client: TorClient, config: Optional[CrawlConfig] = None):
        self.tor = tor_client
        self.config = config or CrawlConfig()
        self._visited: Set[str] = set()
        self._domain_counts: dict[str, int] = {}
        self._pages_crawled: int = 0
        self._pagination_pages_crawled: int = 0
        self._semaphore: Optional[asyncio.Semaphore] = None

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        # strip fragments and normalize
        return parsed._replace(fragment="").geturl().rstrip("/")

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("#", "mailto:", "javascript:")):
                continue
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            if parsed.scheme in ("http", "https") and parsed.netloc.endswith(".onion"):
                links.append(self._normalize_url(absolute))
        return links

    def _get_domain(self, url: str) -> str:
        return urlparse(url).netloc

    def _is_pagination_url(self, url: str) -> bool:
        """True when a URL looks like a pagination/archive page."""
        url_lower = url.lower()
        return any(p in url_lower for p in self.config.pagination_patterns)

    def _should_crawl(self, url: str, origin_domain: str) -> bool:
        normalized = self._normalize_url(url)
        if normalized in self._visited:
            return False
        # Discard junk / legal / search-engine URLs immediately.
        url_lower = normalized.lower()
        if any(part in url_lower for part in BLOCKED_URL_PARTS):
            return False
        domain = self._get_domain(url)
        if not domain.endswith(".onion"):
            return False
        if self.config.stay_on_domain and domain != origin_domain:
            return False
        count = self._domain_counts.get(domain, 0)
        if count >= self.config.max_pages_per_domain:
            logger.debug(f"Domain page limit reached for {domain}")
            return False
        return True

    async def _fetch(self, url: str, session: aiohttp.ClientSession) -> CrawlResult:
        try:
            async with session.get(url, ssl=False, allow_redirects=True) as resp:
                content_type = resp.headers.get("Content-Type", "")
                if not any(ct in content_type for ct in self.config.allowed_content_types):
                    return CrawlResult(
                        url=url,
                        status_code=resp.status,
                        html="",
                        text="",
                        links=[],
                        depth=0,
                        error=f"Skipped content-type: {content_type}",
                    )
                html = await resp.text(errors="replace")
                soup = BeautifulSoup(html, "lxml")
                # remove scripts and styles before extracting text
                for tag in soup(["script", "style", "noscript"]):
                    tag.decompose()
                text = soup.get_text(separator=" ", strip=True)
                links = self._extract_links(html, url)
                return CrawlResult(
                    url=url, status_code=resp.status, html=html, text=text, links=links, depth=0
                )
        except asyncio.TimeoutError:
            return CrawlResult(
                url=url, status_code=0, html="", text="", links=[], depth=0, error="Timeout"
            )
        except Exception as e:
            return CrawlResult(
                url=url, status_code=0, html="", text="", links=[], depth=0, error=str(e)
            )

    async def _crawl_url(self, url: str, depth: int) -> CrawlResult:
        async with self._semaphore:
            stop_flag = pathlib.Path(os.environ.get("DATA_DIR", "/app/data")) / "crawl.stop"
            if stop_flag.exists():
                return CrawlResult(url=url, status_code=0, html="", text="", links=[], depth=depth, error="stopped")
            delay = random.uniform(self.config.delay_min, self.config.delay_max)
            await asyncio.sleep(delay)
            logger.info(f"Fetching [{depth}] {url}")
            session = await self.tor.get_session()
            result = await self._fetch(url, session)
            result.depth = depth
            self._pages_crawled += 1

            # rotate circuit periodically
            if self._pages_crawled % self.config.rotate_circuit_every == 0:
                logger.info("Rotating Tor circuit...")
                await self.tor.rotate_circuit_async()
                await asyncio.sleep(5)  # wait for new circuit to establish

            return result

    async def crawl(self, seed_urls: list[str]) -> AsyncIterator[CrawlResult]:
        """BFS crawl from seed URLs, yielding CrawlResult for each page."""
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)
        queue: deque[tuple[str, int, str, bool]] = deque()  # (url, depth, origin_domain, is_pagination)

        for url in seed_urls:
            normalized = self._normalize_url(url)
            domain = self._get_domain(normalized)
            queue.append((normalized, 0, domain, False))
            self._visited.add(normalized)

        stop_flag = pathlib.Path(os.environ.get("DATA_DIR", "/app/data")) / "crawl.stop"

        while queue:
            # Enforce global page limit per crawl.
            if self._pages_crawled >= self.config.max_pages_per_crawl:
                logger.info(f"Max pages per crawl ({self.config.max_pages_per_crawl}) reached — stopping.")
                break

            # Check for stop signal from dashboard
            if stop_flag.exists():
                logger.info("Stop flag detected — halting crawl gracefully.")
                try:
                    stop_flag.unlink()
                except Exception:
                    pass
                break

            batch = []
            while queue and len(batch) < self.config.max_concurrent:
                batch.append(queue.popleft())

            tasks = [self._crawl_url(url, depth) for url, depth, _, _ in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(results):
                url, depth, origin_domain, is_pagination = batch[i]

                if isinstance(result, Exception):
                    logger.error(f"Unhandled exception crawling {url}: {result}")
                    continue

                domain = self._get_domain(url)
                self._domain_counts[domain] = self._domain_counts.get(domain, 0) + 1
                self._pages_crawled += 1
                if is_pagination:
                    self._pagination_pages_crawled += 1

                yield result

                # Enforce pagination page limit (max 10 pagination pages per crawl).
                if self._pagination_pages_crawled >= 10:
                    logger.info("Max pagination pages (10) reached — no more pagination links will be followed.")

                # enqueue discovered links
                if depth < self.config.max_depth and not result.error:
                    for link in result.links:
                        if self._should_crawl(link, origin_domain):
                            is_pag = self._is_pagination_url(link)
                            # Don't enqueue more pagination links if we've hit the limit.
                            if is_pag and self._pagination_pages_crawled >= 10:
                                continue
                            self._visited.add(link)
                            queue.append((link, depth + 1, origin_domain, is_pag))
                            if is_pag:
                                logger.info(f"Pagination discovered: {link} (page {self._pagination_pages_crawled + 1})")

        logger.info(f"Crawl complete. Total pages crawled: {self._pages_crawled} (pagination: {self._pagination_pages_crawled})")

    def reset(self):
        self._visited.clear()
        self._domain_counts.clear()
        self._pages_crawled = 0


async def _fetch_page(session: aiohttp.ClientSession, url: str) -> tuple[Optional[str], Optional[str]]:
    """Fetch one page through the Tor-routed aiohttp session.

    Returns ``(plain_text, error)`` — exactly one of the two is non-None.
    """
    try:
        async with session.get(url, ssl=False, allow_redirects=True) as resp:
            html = await resp.text(errors="replace")
    except asyncio.TimeoutError:
        return None, "Timeout"
    except Exception as e:  # noqa: BLE001 - a fetch failure must not kill the cycle
        return None, str(e)

    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = soup.get_text(separator=" ", strip=True)
    return text, None


async def run_onion_crawl_cycle(
    storage: Optional[Storage] = None,
    tor: Optional[TorClient] = None,
    config: Optional[CrawlConfig] = None,
    session_id: Optional[int] = None,
) -> dict[str, int]:
    """Run one crawl cycle over every active onion seed.

    * Reads seeds from the ``seeds`` table WHERE ``active = TRUE`` (never a
      hardcoded list).
    * Fetches each seed through Tor with aiohttp routed over the SOCKS5 proxy
      (``socks5h://tor:9050`` equivalent via ``aiohttp_socks.ProxyConnector``
      in ``TorClient``).
    * Loads keywords from the ``keywords`` table, falling back to
      ``config/keywords.yaml`` when the table is empty.
    * Scans each page case-insensitively and inserts one ``paste_hits`` row per
      matched keyword with ``source = 'onion_crawler'``.
    * Deduplicates by ``(paste_id, matched_pattern)``.
    """
    from .keywords_db import keyword_config
    from .scanner import Scanner

    storage = storage or Storage()
    config = config or CrawlConfig()

    # ── Seeds from the database, active only ───────────────────────────────
    seeds = storage.get_active_seeds()
    if not seeds:
        msg = "[crawler] no active onion seeds in the seeds table"
        logger.warning(msg)
        print(msg, flush=True)
        return {"fetched": 0, "hits": 0}

    # ── Keywords from the DB (YAML is the fallback seed) ───────────────────
    from pathlib import Path as _P
    _seed_paths = []
    _data_kw = _P(os.getenv("DATA_DIR", "/app/data")) / "keywords.yaml"
    if _data_kw.exists():
        _seed_paths.append(_data_kw)
    _seed_paths.append(KEYWORDS_DEFAULT)
    kw_config = keyword_config(storage, _seed_paths)
    scanner = Scanner(kw_config)

    tor_client = tor or create_tor_client()
    fetched = 0
    hits = 0
    session = await tor_client.get_session()
    try:
        stop_flag = pathlib.Path(os.environ.get("DATA_DIR", "/app/data")) / "crawl.stop"
        for url in seeds:
            if stop_flag.exists():
                logger.info("Stop flag detected — halting crawl.")
                break
            fetched += 1
            text, error = await _fetch_page(session, url)
            matched = 0
            if error or not text:
                storage.increment_seed_attempt(url)
                logger.warning(
                    "Crawl failed for %s (error: %s); seed deactivated if attempt_count >= 3",
                    url,
                    error or "empty response",
                )
                print(
                    f"[crawler] fetched {url} | keywords matched: 0 (error: {error or 'empty response'})",
                    flush=True,
                )
                if session_id is not None:
                    storage.update_crawl_session(session_id, fetched, hits, status="running")
                continue

            hit_list = scanner.scan(url=url, text=text, depth=0)
            matched = len(hit_list)
            seen_patterns = storage.get_paste_hit_patterns(url)
            for hit in hit_list:
                if hit.keyword not in seen_patterns:
                    storage.save_paste_hit(
                        paste_id=url,
                        url=url,
                        source="onion_crawler",
                        matched_pattern=hit.keyword,
                        matched_value=hit.keyword,
                        context=hit.context,
                    )
                    seen_patterns.add(hit.keyword)
                # Persist to keyword_hits (session-linked) for every found hit.
                try:
                    storage.save_hit(
                        url=hit.url or url,
                        keyword=hit.keyword,
                        category=hit.category,
                        context=hit.context,
                        position=hit.position,
                        depth=hit.depth,
                        session_id=session_id,
                        source_url=hit.url or url,
                    )
                except Exception:
                    pass

            hits += matched
            print(f"[crawler] fetched {url} | keywords matched: {matched}", flush=True)
            if session_id is not None:
                storage.update_crawl_session(session_id, fetched, hits, status="running")
    finally:
        await tor_client.close()

    print(f"[crawler] cycle complete: fetched={fetched} hits={hits}", flush=True)
    return {"fetched": fetched, "hits": hits}
