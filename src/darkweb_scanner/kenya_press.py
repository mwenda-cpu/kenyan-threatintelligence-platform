"""
Kenya-focused ransomware press aggregator.
Merges Kenyan RSS feeds with filtered ransomware.live press data.
"""
import feedparser
import requests
import logging
from datetime import datetime
from typing import List, Dict, Optional

from . import ransomware_live as rw

logger = logging.getLogger(__name__)

KENYA_RSS_FEEDS = [
    # Direct Kenyan / security feeds (no Google News — avoids global junk)
    ("TechTrendsKE",
     "https://techtrendske.co.ke/feed/"),
    ("Techweez",
     "https://techweez.com/feed/"),
]


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


def fetch_kenya_press(limit: int = 20) -> List[Dict]:
    """
    Return list of {"title", "url", "date" (ISO), "source", "relevance"}
    Merged from Kenyan RSS + filtered ransomware.live press.
    Sorted newest-first, deduplicated by URL.
    NEVER raises — always returns a list (possibly empty).
    """
    import logging
    from email.utils import parsedate_to_datetime
    import datetime
    log = logging.getLogger(__name__)
    items = []
    seen_urls = set()

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

    # 3. Sort by date descending (handle malformed dates gracefully)
    def _sort_key(it):
        try:
            d = parsedate_to_datetime(it['date'])
            if d.tzinfo is not None:
                d = d.replace(tzinfo=None)
            return d
        except Exception:
            try:
                d = datetime.datetime.fromisoformat(it['date'].replace('Z','+00:00'))
                if d.tzinfo is not None:
                    d = d.replace(tzinfo=None)
                return d
            except Exception:
                return datetime.datetime(1970, 1, 1)

    items.sort(key=_sort_key, reverse=True)
    return items[:limit]