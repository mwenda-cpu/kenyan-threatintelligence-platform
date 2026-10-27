"""
Kenya-focused ransomware press aggregator.
Merges Kenyan RSS feeds, NC4 official newsroom (HTML scrape), and filtered ransomware.live press data.
"""
import logging
from datetime import datetime
from typing import Dict, List, Optional

import feedparser
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

KENYA_RSS_FEEDS = [
    # Direct Kenyan / security feeds (no Google News — avoids global junk)
    ("TechTrendsKE",
     "https://techtrendske.co.ke/feed/"),
    ("Techweez",
     "https://techweez.com/feed/"),
]

# NC4 official newsroom — HTML scrape (no RSS feed)
NC4_NEWS_URL = "https://nc4.go.ke/news/"


KENYA_MATCH_KEYWORDS = [
    "kenya", "nairobi", "safaricom", "m-pesa", "kcb", "equity bank",
    "ncba", "co-operative", "ecitizen", "ifmis", "kra", "ntsa",
    "ke-cirt", "cbk",
]


def _matches_kenya(text: str) -> bool:
    """Strictly return True only if text contains a Kenya-specific keyword."""
    if not text:
        return False
    text_lower = text.lower()
    return any(kw in text_lower for kw in KENYA_MATCH_KEYWORDS)


def _parse_nc4_date(date_str: str) -> str:
    """Parse NC4 date format like 'FEBRUARY 10, 2026' to ISO string."""
    if not date_str:
        return ""
    try:
        dt = datetime.strptime(date_str.strip(), "%B %d, %Y")
        return dt.isoformat()
    except Exception:
        return date_str.strip()


def fetch_nc4_news(limit: int = 10) -> List[Dict]:
    """
    Scrape NC4 newsroom (https://nc4.go.ke/news/) for official alerts/news/events.
    Returns list of press-item dicts with source='NC4 Official'. Never raises.
    """
    items: List[Dict] = []
    seen_urls = set()
    try:
        response = requests.get(
            NC4_NEWS_URL,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (compatible; KE-ThreatIntel/1.0)"},
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "lxml")

        def _extract_from_container(container) -> Optional[Dict]:
            """Extract a single article card into a press-item dict."""
            # Category + Date: p containing "·" separator
            cat_date_p = None
            for p in container.find_all("p"):
                txt = p.get_text(" ", strip=True)
                if "·" in txt:
                    cat_date_p = p
                    break
            if not cat_date_p:
                return None

            cat_date_text = cat_date_p.get_text(" ", strip=True)
            parts = cat_date_text.split("·", 1)
            category = parts[0].strip() if len(parts) > 1 else "Advisory"
            date_str = parts[1].strip() if len(parts) > 1 else ""

            # Title: p with news-listing-title or news-featured-title class
            title_p = container.find("p", class_=lambda c: c and any(
                cls in c for cls in ("news-listing-title", "news-featured-title")
            ))
            if not title_p:
                return None
            title = title_p.get_text(" ", strip=True)

            # Link: a with href starting with /news/
            link_a = container.find("a", href=lambda h: h and h.startswith("/news/"))
            url = "https://nc4.go.ke" + link_a["href"] if link_a else NC4_NEWS_URL

            # Snippet: p after title that isn't category/date/title/read-time/author
            snippet = ""
            for p in container.find_all("p"):
                txt = p.get_text(" ", strip=True)
                if (txt and txt != title and txt != cat_date_text
                        and "min read" not in txt
                        and not txt.startswith("NC4 ")):
                    snippet = txt
                    break

            # Dedup
            norm_url = url.rstrip("/")
            if norm_url in seen_urls:
                return None
            seen_urls.add(norm_url)

            return {
                "title": title,
                "url": url,
                "date": _parse_nc4_date(date_str),
                "source": "NC4 Official",
                "category": category,
                "snippet": snippet,
                "relevance": "kenya",
            }

        # 1. Featured article (different DOM structure, no data-cursor-card)
        featured_title = soup.find("p", class_=lambda c: c and "news-featured-title" in c)
        if featured_title and featured_title.parent:
            item = _extract_from_container(featured_title.parent)
            if item:
                items.append(item)

        # 2. Listing cards (Alerts, News, Events sections) — data-cursor-card="true"
        for card in soup.select('div[data-cursor-card="true"]'):
            item = _extract_from_container(card)
            if item:
                items.append(item)

    except Exception as e:
        logger.warning("NC4 fetch failed: %s", e)

    return items[:limit]


def fetch_kenya_press(limit: int = 20) -> List[Dict]:
    """
    Return list of {"title", "url", "date" (ISO), "source", "relevance"}
    Merged from Kenyan RSS + filtered ransomware.live press.
    Sorted newest-first, deduplicated by URL.
    NEVER raises — always returns a list (possibly empty).
    """
    import datetime
    import logging
    from email.utils import parsedate_to_datetime
    log = logging.getLogger(__name__)
    items = []
    seen_urls = set()

    # 0. NC4 official newsroom (HTML scrape — always included, no keyword filter)
    try:
        for item in fetch_nc4_news(limit=10):
            norm_url = item['url'].rstrip('/').split('?')[0]
            if norm_url in seen_urls:
                continue
            seen_urls.add(norm_url)
            items.append(item)
    except Exception as e:
        log.warning('NC4 fetch failed: %s', e)

    # 1. Fetch each RSS feed defensively
    for source_name, feed_url in KENYA_RSS_FEEDS:
        try:
            response = requests.get(feed_url, timeout=8)
            parsed = feedparser.parse(response.content)

            if parsed.bozo:
                log.warning('Feed parser warning for %s: %s', source_name, parsed.bozo_exception)

            for entry in parsed.entries:
                try:
                    title = (getattr(entry, 'title', '') or '').strip()
                    link  = (getattr(entry, 'link', '') or '').strip()
                    if not title or not link:
                        continue

                    # Normalize URL for dedup
                    norm_url = link.rstrip('/').split('?')[0]
                    if norm_url in seen_urls:
                        continue
                    seen_urls.add(norm_url)

                    # Date extraction with fallbacks
                    date = ''
                    for attr in ('published', 'updated', 'created'):
                        val = getattr(entry, attr, None)
                        if val:
                            date = str(val)
                            break
                    if not date:
                        date = datetime.datetime.utcnow().isoformat()

                    # Kenya relevance: keep if the title/summary mentions Kenya
                    summary = getattr(entry, 'summary', '') or ''
                    haystack = (title + ' ' + summary).lower()
                    if not _matches_kenya(haystack):
                        continue

                    items.append({
                        'title': title,
                        'url': link,
                        'date': date,
                        'source': source_name,
                        'relevance': 'kenya' if _matches_kenya(haystack) else 'global',
                    })
                except Exception as e:
                    log.warning('entry parse failed in %s: %s', source_name, e)
                    continue
        except Exception as e:
            log.warning('feed fetch failed for %s (%s): %s', source_name, feed_url, e)
            continue

    # 2. Also pull ransomware.live press, filtered for Kenya
    try:
        from . import ransomware_live as rw
        global_press = rw.get_press_recent() or []
        for p in global_press:
            title = (p.get('title') or p.get('headline') or '').strip()
            url   = (p.get('url') or p.get('link') or '').strip()
            if not title or not url:
                continue
            haystack = (title + ' ' + (p.get('summary') or '')).lower()
            if not _matches_kenya(haystack):
                continue
            norm_url = url.rstrip('/').split('?')[0]
            if norm_url in seen_urls:
                continue
            seen_urls.add(norm_url)
            items.append({
                'title': title,
                'url': url,
                'date': p.get('date') or p.get('published') or '',
                'source': 'ransomware.live',
                'relevance': 'kenya',
            })
    except Exception as e:
        log.warning('ransomware.live press fetch failed: %s', e)

    # 3. Sort by source priority (NC4 Official first), then date descending
    def _sort_key(it):
        source_priority = 0 if it['source'] == 'NC4 Official' else 1
        try:
            d = parsedate_to_datetime(it['date'])
            if d.tzinfo is not None:
                d = d.replace(tzinfo=None)
        except Exception:
            try:
                d = datetime.datetime.fromisoformat(it['date'].replace('Z','+00:00'))
                if d.tzinfo is not None:
                    d = d.replace(tzinfo=None)
            except Exception:
                d = datetime.datetime(1970, 1, 1)
        # Negate date so newest-first; source_priority ensures NC4 floats to top
        return (source_priority, -d.toordinal())

    items.sort(key=_sort_key)
    return items[:limit]
