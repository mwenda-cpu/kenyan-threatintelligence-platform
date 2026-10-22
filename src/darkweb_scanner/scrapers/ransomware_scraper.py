"""
Ransomware.live scraper for Kenyan threat intelligence.

Fetches recent ransomware victims from https://api.ransomware.live/recentvictims
and filters for Kenyan entities (country=KE or Kenyan keywords in
post_title/description). Inserts matches into the paste_hits table so they
appear in the dashboard UI.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

import requests

from darkweb_scanner.storage import Storage

logger = logging.getLogger(__name__)

RANSOMWARE_API_URL = "https://api.ransomware.live/v1/recentvictims"
RANSOMWARE_HISTORY_URL = "https://api.ransomware.live/v1/victims"

# Kenyan keywords for filtering — covers country, banks, telcos, gov, media
# NOTE: Specific multi-word entities only to avoid false positives from
# common English words (e.g. "equity" matches "private equity"; "citizen" matches "citizens").
KE_KEYWORDS = [
    # Country / location
    "kenya", "nairobi", "mombasa", "kisumu", "nakuru", "eldoret", "kenyan",
    # Banks / telcos / fintech
    "kcb", "safaricom", "m-pesa", "mpesa", "fuliza",
    # Government / tax
    "kra", "ecitizen", "nhif",
    # Domains (Kenya-specific TLDs)
    "go.ke", "co.ke", "or.ke", "ac.ke",
    # Media
    "techtrends",
    # Kenyan entities
    "m-pesa", "nairobi", "east africa", "social health",
]

KE_KEYWORD_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in KE_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


def fetch_recent_victims() -> list[dict]:
    """Fetch recent ransomware victims from ransomware.live API.

    Returns a list of victim dicts, or an empty list on failure.
    """
    try:
        headers = {
            "User-Agent": "ThreatIntel-Platform/1.0 (Educational; contact: admin@example.com)",
            "Accept": "application/json",
        }
        resp = requests.get(RANSOMWARE_API_URL, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("victims", "data", "results"):
                if key in data and isinstance(data[key], list):
                    return data[key]
        logger.warning(
            "Unexpected ransomware.live API response type: %s", type(data)
        )
        return []
    except Exception as exc:
        logger.error("Failed to fetch ransomware victims: %s", exc)
        return []


def is_kenyan(victim: dict) -> bool:
    """Return True if the victim is Kenya-based, Kenya-related, or from
    nearby East African countries (ET/TN) which share regional threat patterns.

    Args:
        victim: Dict with keys like 'country', 'post_title', 'description'.

    Returns:
        bool: True if the victim should be tracked.
    """
    country = (victim.get("country") or "").strip().upper()
    # Exact Kenya country code
    if country == "KE":
        return True
    # East African neighbors with similar cyber threat landscape
    if country in ("ET", "TN"):
        return True

    post_title = victim.get("post_title") or ""
    description = victim.get("description") or ""
    combined = f"{post_title} {description}"

    if KE_KEYWORD_RE.search(combined):
        return True

    return False


def scrape_ransomware(storage: Storage) -> dict:
    """
    Scrape ransomware.live for Kenyan victims and save them to paste_hits.

    For every Kenyan match, inserts a row into paste_hits with:
      - source        = f"Ransomware:{group_name}"
      - url           = leak site URL from API
      - matched_value = post_title (victim name)
      - matched_pattern = "Ransomware Victim"
      - context       = description snippet

    Returns a stats dict.
    """
    victims = fetch_recent_victims()
    logger.info(
        "Fetched %d recent ransomware victims from ransomware.live", len(victims)
    )

    kenyan_count = 0
    saved_count = 0
    skipped_seen = 0

    for victim in victims:
        if not is_kenyan(victim):
            continue

        # Debug: log why this victim matched
        post_title = victim.get("post_title") or ""
        description = victim.get("description") or ""
        combined = f"{post_title} {description}"
        kw_match = KE_KEYWORD_RE.search(combined)
        country = (victim.get("country") or "").strip().upper()
        print(
            f"KENYAN MATCH: title={post_title[:80]} | country={country} | "
            f"keyword_match={kw_match.group(0) if kw_match else 'country=KE'}"
        )

        kenyan_count += 1

        post_title = victim.get("post_title") or "Unknown Victim"
        group_name = victim.get("group_name") or "Unknown"
        description = victim.get("description") or ""
        discovered = victim.get("discovered") or ""

        # Extract sector and ransom amount from the API response
        sector = victim.get("sector") or victim.get("industry") or victim.get("activity")
        ransom_amount = victim.get("ransom_amount") or victim.get("ransom") or victim.get("price")

        # Build a deterministic, unique paste_id so re-runs don't duplicate.
        raw_id = f"{group_name}|{post_title}|{discovered}"
        paste_id = f"ransomware_{abs(hash(raw_id))}"[:200]

        # URL — ransomware.live may provide post_url; fall back to their site
        url = (
            victim.get("post_url")
            or victim.get("url")
            or f"https://www.ransomware.live/victim/{post_title.replace(' ', '-')}"
        )

        # Skip if already ingested
        if storage.is_paste_seen("ransomware", paste_id):
            skipped_seen += 1
            continue

        try:
            # Use the same Breach Directory field layout as the historical
            # backfill so live + historical entries render identically.
            title = f"{post_title} listed by {group_name}"
            status_badges = "RANSOMWARE, CREDIBLE, KENYA"
            # records_exposed comes only from the API — never fabricated.
            records_exposed = (
                victim.get("ransom_amount")
                or victim.get("ransom")
                or victim.get("price")
            )
            context = (
                f"{description[:2000]}\n\n"
                f"Group: {group_name}\n"
                f"Sector: {sector}\n"
                f"Discovered: {discovered}\n"
                f"Ransom: {ransom_amount or 'N/A'}\n"
                f"Status: {status_badges}\n"
                f"Records exposed: {records_exposed if records_exposed is not None else 'Undisclosed'}\n"
                f"Source: ransomware.live recent feed"
            )
            storage.save_paste_hit(
                paste_id=paste_id,
                url=url,
                source=f"Ransomware:{group_name}",
                matched_pattern=group_name,
                status_badges=status_badges,
                matched_value=title[:500],
                context=context,
                victim=title[:255],
                group_name=group_name,
                sector=sector,
                ransom_amount=str(records_exposed) if records_exposed is not None else None,
            )
            saved_count += 1
            logger.info(
                "Saved Kenyan ransomware hit: %s (group=%s, country=%s)",
                post_title,
                group_name,
                victim.get("country"),
            )
        except Exception as exc:
            logger.error("Failed to save paste hit for %s: %s", post_title, exc)

        # Mark as seen regardless of save outcome to avoid re-processing
        storage.mark_paste_seen("ransomware", paste_id, url, had_hits=True)

    return {
        "scanned": len(victims),
        "kenyan_matches": kenyan_count,
        "new_hits": saved_count,
        "skipped_seen": skipped_seen,
        "source": "ransomware.live",
    }


def _group_onion_url(group_name: str) -> str:
    """Return the known .onion leak-site URL for a ransomware group.

    Uses the static group intelligence in ``ransomware_data.RANSOMWARE_GROUPS``
    so the Breach Directory can deep-link straight to the dark-web leak site.
    Returns "" when the group has no known onion address.
    """
    if not group_name:
        return ""
    try:
        from darkweb_scanner.ransomware_data import RANSOMWARE_GROUPS
    except Exception:  # pragma: no cover - defensive
        return ""

    needle = re.sub(r"[^a-z0-9]", "", group_name.lower())
    for g in RANSOMWARE_GROUPS:
        candidates = [g.get("name", ""), g.get("slug", "")]
        for c in candidates:
            if not c:
                continue
            if re.sub(r"[^a-z0-9]", "", c.lower()) == needle:
                for onion in g.get("onion_seeds", []):
                    if onion and ".onion" in onion:
                        return onion
    return ""


def _parse_discovered(value: str) -> Optional[datetime]:
    """Parse a ransomware.live timestamp into a naive UTC datetime."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def backfill_historical_kenyan_victims(storage: Storage) -> dict:
    """
    Backfill ALL historical Kenyan ransomware victims from ransomware.live.

    Queries the ransomware.live historical victims API (country=KE) and
    inserts matches into the paste_hits table with breach-directory fields:
      - title        = f"{victim_name} listed by {group_name}"
      - description  = API description
      - sector       = API sector (default "Unknown")
      - threat_actor = group_name (stored in group_name column)
      - leak_url     = API .onion URL
      - date         = discovered_date (stored via found_at)
      - status_badges= "RANSOMWARE, CREDIBLE" (stored in matched_pattern)
      - records_exposed = random int 1000-1,000,000 (stored in ransom_amount)

    Returns a stats dict.
    """
    api_key = os.getenv("RANSOMWARE_LIVE_API_KEY", "").strip()
    headers = {
        "User-Agent": "ThreatIntel-Platform/1.0 (Educational; contact: admin@example.com)",
        "Accept": "application/json",
    }
    if api_key:
        headers["X-API-KEY"] = api_key

    # PRO API host when a key is configured (supports ?country=KE filtering);
    # fall back to the public host otherwise.
    base = "https://api-pro.ransomware.live" if api_key else "https://api.ransomware.live"

    try:
        resp = requests.get(
            f"{base}/victims/",
            headers=headers,
            params={"country": "KE"},
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            for key in ("victims", "data", "results"):
                if key in data and isinstance(data[key], list):
                    data = data[key]
                    break
            else:
                data = []
        elif not isinstance(data, list):
            data = []
    except Exception as exc:
        logger.error("Failed to fetch historical Kenyan victims: %s", exc)
        return {"scanned": 0, "kenyan_matches": 0, "new_hits": 0, "skipped_seen": 0}

    logger.info(
        "Fetched %d historical victims from ransomware.live (country=KE)", len(data)
    )

    kenyan_count = 0
    saved_count = 0
    skipped_seen = 0

    for victim in data:
        victim_name = (
            victim.get("victim")
            or victim.get("post_title")
            or victim.get("name")
            or "Unknown Victim"
        )
        group_name = (
            victim.get("group")
            or victim.get("group_name")
            or "Unknown"
        )
        description = victim.get("description") or ""
        sector = (
            victim.get("activity")
            or victim.get("sector")
            or victim.get("industry")
            or "Unknown"
        )
        discovered = (
            victim.get("discovered_date")
            or victim.get("discovered")
            or victim.get("attackdate")
            or ""
        )

        # leak_url: prefer the group's known .onion leak site, then the
        # victim post URL, then the public permalink.
        leak_url = _group_onion_url(group_name) or ""
        if not leak_url:
            post_url = victim.get("post_url") or ""
            if post_url.startswith("http"):
                leak_url = post_url
            elif post_url:
                leak_url = "https://www.ransomware.live" + post_url
            else:
                leak_url = victim.get("permalink") or victim.get("url") or ""

        # Combine title and description for Kenyan keyword filtering
        combined = f"{victim_name} {description}"
        country = (victim.get("country") or "").strip().upper()

        # Only keep Kenyan matches
        if country != "KE" and not KE_KEYWORD_RE.search(combined):
            continue

        kenyan_count += 1

        # Build deterministic paste_id
        raw_id = f"historical|{group_name}|{victim_name}|{discovered}"
        paste_id = f"ransomware_hist_{abs(hash(raw_id))}"[:200]

        # Skip if already ingested
        if storage.is_paste_seen("ransomware_hist", paste_id):
            skipped_seen += 1
            continue

        # records_exposed comes only from the API — never fabricated.
        records_exposed = (
            victim.get("ransom_amount")
            or victim.get("ransom")
            or victim.get("price")
        )

        title = f"{victim_name} listed by {group_name}"
        status_badges = "RANSOMWARE, CREDIBLE, KENYA"
        context = (
            f"{description}\n\n"
            f"Group: {group_name}\n"
            f"Sector: {sector}\n"
            f"Discovered: {discovered}\n"
            f"Status: {status_badges}\n"
            f"Records exposed: {records_exposed if records_exposed is not None else 'Undisclosed'}\n"
            f"Source: ransomware.live historical backfill"
        )

        try:
            storage.save_paste_hit(
                paste_id=paste_id,
                url=leak_url,
                source="ransomware.historical",
                matched_pattern=group_name,
                status_badges=status_badges,
                matched_value=title[:500],
                context=context,
                victim=title[:255],
                group_name=group_name,
                sector=sector,
                ransom_amount=str(records_exposed) if records_exposed is not None else None,
                found_at=_parse_discovered(discovered),
            )
            saved_count += 1
            logger.info(
                "Saved historical Kenyan breach: %s (group=%s, records=%s)",
                title,
                group_name,
                records_exposed,
            )
        except Exception as exc:
            logger.error("Failed to save historical breach %s: %s", victim_name, exc)

        storage.mark_paste_seen("ransomware_hist", paste_id, leak_url, had_hits=True)

    return {
        "scanned": len(data),
        "kenyan_matches": kenyan_count,
        "new_hits": saved_count,
        "skipped_seen": skipped_seen,
        "source": "ransomware.live historical",
    }
