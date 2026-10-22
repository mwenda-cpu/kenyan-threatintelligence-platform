"""
Threat Intelligence IOC scraper for Kenyan threat intelligence.

Fetches real-time malicious IPs, URLs, and hashes from free open-source APIs:
  - URLhaus (Abuse.ch) for malicious URLs
  - Feodo Tracker (Abuse.ch) for botnet C2 IPs
  - AlienVault OTX for recent pulses

Saves IOCs into the threat_iocs table with deduplication.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import requests

from darkweb_scanner.storage import Storage

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 30


def fetch_urlhaus() -> list[dict]:
    """Fetch recent malicious URLs from URLhaus (Abuse.ch).

    Uses the URLhaus API to get recent URLs. No API key required.
    """
    results = []
    try:
        # URLhaus provides a CSV download of recent URLs
        resp = requests.get(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "ThreatIntel-Platform/1.0"},
        )
        if resp.status_code != 200:
            logger.warning("URLhaus returned status %d", resp.status_code)
            return results

        # Parse CSV (skip comment lines starting with #)
        lines = resp.text.splitlines()
        for line in lines:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) < 4:
                continue
            # CSV format: id,dateadded,url,url_status,threat,tags,reporter
            url = parts[2].strip().strip('"')
            threat = parts[4].strip().strip('"') if len(parts) > 4 else "malware"
            if url and url.startswith("http"):
                results.append({
                    "indicator": url,
                    "type": "URL",
                    "threat_type": threat or "malware",
                    "source": "URLhaus",
                })
    except Exception as exc:
        logger.error("URLhaus fetch failed: %s", exc)
    return results


def fetch_feodo_tracker() -> list[dict]:
    """Fetch botnet C2 IPs from Feodo Tracker (Abuse.ch).

    Uses the Feodo Tracker IP blocklist. No API key required.
    """
    results = []
    try:
        resp = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "ThreatIntel-Platform/1.0"},
        )
        if resp.status_code != 200:
            logger.warning("Feodo Tracker returned status %d", resp.status_code)
            return results

        data = resp.json()
        if not isinstance(data, list):
            logger.warning("Unexpected Feodo Tracker response type: %s", type(data))
            return results

        for entry in data:
            ip = entry.get("ip_address") or entry.get("ip")
            if not ip:
                continue
            results.append({
                "indicator": ip,
                "type": "IP",
                "threat_type": entry.get("malware") or "botnet C2",
                "source": "Feodo Tracker",
            })
    except Exception as exc:
        logger.error("Feodo Tracker fetch failed: %s", exc)
    return results


def fetch_alienvault_otx() -> list[dict]:
    """Fetch recent pulses from AlienVault OTX.

    Uses the OTX API. Free tier available with API key (OTX_API_KEY env var).
    Without a key, attempts unauthenticated access (limited).
    """
    results = []
    api_key = None
    try:
        import os
        api_key = os.getenv("OTX_API_KEY")
    except Exception:
        pass

    try:
        headers = {"User-Agent": "ThreatIntel-Platform/1.0"}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key

        resp = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("AlienVault OTX returned status %d", resp.status_code)
            return results

        data = resp.json()
        pulses = data.get("results", []) if isinstance(data, dict) else []
        for pulse in pulses:
            for indicator in pulse.get("indicators", []):
                ind_type = indicator.get("type", "").lower()
                value = indicator.get("indicator", "")
                if not value:
                    continue
                # Map OTX indicator types to our types
                if ind_type in ("ipv4", "ipv6"):
                    ioc_type = "IP"
                elif ind_type in ("domain", "hostname"):
                    ioc_type = "Domain"
                elif ind_type in ("url", "uri"):
                    ioc_type = "URL"
                elif ind_type in ("filehash-md5", "filehash-sha1", "filehash-sha256", "hash"):
                    ioc_type = "Hash"
                else:
                    ioc_type = "IP"

                results.append({
                    "indicator": value,
                    "type": ioc_type,
                    "threat_type": pulse.get("name", "OTX Pulse"),
                    "source": "AlienVault OTX",
                })
    except Exception as exc:
        logger.error("AlienVault OTX fetch failed: %s", exc)
    return results


def run_ioc_scraper(storage: Storage) -> dict:
    """Run all IOC scrapers and save results to the database.

    Returns a summary dict.
    """
    all_iocs = []
    all_iocs.extend(fetch_urlhaus())
    all_iocs.extend(fetch_feodo_tracker())
    all_iocs.extend(fetch_alienvault_otx())

    saved = 0
    skipped = 0
    for ioc in all_iocs:
        try:
            storage.save_threat_ioc(
                indicator=ioc["indicator"],
                ioc_type=ioc["type"],
                threat_type=ioc.get("threat_type"),
                source=ioc.get("source"),
            )
            saved += 1
        except Exception as exc:
            logger.debug("Failed to save IOC %s: %s", ioc["indicator"], exc)
            skipped += 1

    logger.info("IOC scraper complete: %d total, %d saved, %d skipped", len(all_iocs), saved, skipped)
    return {
        "total_fetched": len(all_iocs),
        "saved": saved,
        "skipped": skipped,
        "sources": {
            "urlhaus": len([i for i in all_iocs if i["source"] == "URLhaus"]),
            "feodo": len([i for i in all_iocs if i["source"] == "Feodo Tracker"]),
            "otx": len([i for i in all_iocs if i["source"] == "AlienVault OTX"]),
        },
    }


if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from darkweb_scanner.storage import Storage

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    storage = Storage()
    summary = run_ioc_scraper(storage)
    print(f"\nIOC scrape complete: {summary}")
    for src, count in summary["sources"].items():
        print(f"  {src}: {count}")
