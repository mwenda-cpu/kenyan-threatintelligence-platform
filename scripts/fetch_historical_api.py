"""
Fetch historical ransomware incidents for Kenya from the Ransomware.live API.

Hits https://api.ransomware.live/v2/country/KE, parses the JSON response,
and inserts each incident into the `historical_attacks` table using
ON CONFLICT DO NOTHING (deduplicated by source_url).
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from darkweb_scanner.storage import Storage

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

RANSOMWARE_LIVE_URL = "https://api.ransomware.live/v2/country/KE"


def fetch_ke_incidents() -> list[dict]:
    """Fetch Kenya ransomware incidents from Ransomware.live API."""
    try:
        resp = requests.get(RANSOMWARE_LIVE_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        logger.info("Fetched %d incident records from Ransomware.live", len(data))
        return data
    except Exception as exc:
        logger.error("Failed to fetch Ransomware.live data: %s", exc)
        return []


def parse_incident(item: dict) -> dict | None:
    """Parse a single incident dict into historical_attack fields."""
    try:
        victim = item.get("company") or item.get("victim") or item.get("name")
        if not victim:
            return None

        source_url = item.get("url") or item.get("source_url") or ""
        if not source_url:
            return None

        attack_date = None
        date_str = item.get("date") or item.get("publish_date") or item.get("discovered")
        if date_str:
            try:
                attack_date = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
            except Exception:
                attack_date = None

        group = item.get("group") or item.get("ransomware_group") or item.get("leak_site")

        return {
            "victim_name": victim,
            "target_country": "Kenya",
            "leak_site": group,
            "keyword_matched": None,
            "source_url": source_url,
            "attack_date": attack_date,
            "raw_content": str(item)[:2000],
        }
    except Exception as exc:
        logger.debug("Skipping malformed incident: %s", exc)
        return None


def main() -> int:
    storage = Storage()
    incidents = fetch_ke_incidents()
    inserted = 0
    skipped = 0

    for item in incidents:
        parsed = parse_incident(item)
        if not parsed:
            skipped += 1
            continue

        try:
            # Use storage.save_historical_attack which dedupes on source_url.
            # We call it directly; it uses ON CONFLICT DO NOTHING semantics
            # via the unique constraint on source_url.
            new_id = storage.save_historical_attack(
                source_url=parsed["source_url"],
                victim_name=parsed.get("victim_name"),
                target_country=parsed.get("target_country"),
                leak_site=parsed.get("leak_site"),
                keyword_matched=parsed.get("keyword_matched"),
                attack_date=parsed.get("attack_date"),
                raw_content=parsed.get("raw_content"),
            )
            if new_id:
                inserted += 1
                logger.info("Inserted historical attack: %s", parsed.get("victim_name"))
            else:
                skipped += 1
        except Exception as exc:
            logger.warning("Failed to insert incident %s: %s", parsed.get("victim_name"), exc)
            skipped += 1

    print(f"\nRansomware.live sync complete: {inserted} inserted, {skipped} skipped/duplicates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
