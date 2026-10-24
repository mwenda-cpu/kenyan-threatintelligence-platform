"""
CVE Intelligence Ingestor — pulls real CVE data from public APIs.

Sources:
  - CISA Known Exploited Vulnerabilities (KEV) catalog
  - FIRST EPSS scores
  - NVD CVE 2.0 API

Each source upserts into the `cves` table via Storage.upsert_cve.
Designed to be invoked by APScheduler (job function `run_cve_ingestor(storage)`).
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Optional

import requests

from darkweb_scanner.storage import Storage

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 30
USER_AGENT = "ThreatIntel-Platform/1.0"

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD allows ~1 request per 6 seconds without an API key.
NVD_REQUEST_DELAY_SECONDS = 1


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(
            tzinfo=None
        )
    except Exception:
        return None


def ingest_cisa_kev(storage: Storage) -> dict:
    """Fetch CISA KEV catalog and upsert each vulnerability."""
    logger.info("Ingesting CISA KEV catalog from %s", CISA_KEV_URL)
    try:
        resp = requests.get(
            CISA_KEV_URL,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.error("Failed to fetch CISA KEV: %s", exc)
        return {"source": "cisa_kev", "count": 0, "error": str(exc)}

    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    count = 0
    for item in vulnerabilities:
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        storage.upsert_cve(
            cve_id=cve_id,
            description=item.get("shortDescription"),
            cvss_score=None,
            epss_score=None,
            kev_flag=True,
            published_date=_parse_date(item.get("dateAdded")),
            affected_products=item.get("vendorProject"),
            source="cisa_kev",
        )
        count += 1
    logger.info("CISA KEV upserted %d records", count)
    return {"source": "cisa_kev", "count": count}


def ingest_epss(storage: Storage) -> dict:
    """Fetch FIRST EPSS scores and upsert onto existing CVEs."""
    logger.info("Ingesting EPSS scores from %s", EPSS_URL)
    try:
        resp = requests.get(
            EPSS_URL,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            params={"format": "json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.error("Failed to fetch EPSS: %s", exc)
        return {"source": "epss", "count": 0, "error": str(exc)}

    rows = data.get("data", []) if isinstance(data, dict) else []
    count = 0
    for item in rows:
        cve_id = item.get("cve")
        epss = item.get("epss")
        if not cve_id or epss is None:
            continue
        storage.upsert_cve(
            cve_id=cve_id,
            epss_score=str(epss),
            source="epss",
        )
        count += 1
    logger.info("EPSS upserted %d records", count)
    return {"source": "epss", "count": count}


def _extract_affected_products(configurations) -> Optional[str]:
    """Extract affected product strings from NVD configurations nodes (v1 format)."""
    if not configurations:
        return None
    products = []
    try:
        for node in configurations:
            for match in node.get("match", []) or []:
                criteria = match.get("criteria")
                if criteria:
                    products.append(criteria)
    except Exception:
        return None
    return "; ".join(products) if products else None


def _extract_affected_products_v2(configurations) -> Optional[str]:
    """Extract affected product strings from NVD 2.0 configurations nodes."""
    if not configurations:
        return None
    products = []
    try:
        for config in configurations:
            for node in config.get("nodes", []) or []:
                for match in node.get("cpeMatch", []) or []:
                    criteria = match.get("criteria")
                    if criteria:
                        products.append(criteria)
    except Exception:
        return None
    return "; ".join(products) if products else None


def ingest_nvd(storage: Storage, results_per_page: int = 100) -> dict:
    """Query NVD CVE 2.0 API for the most recent CVEs and upsert them."""
    logger.info("Ingesting NVD CVEs from %s", NVD_URL)
    count = 0
    total_fetched = 0

    try:
        resp = requests.get(
            NVD_URL,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            params={
                "resultsPerPage": results_per_page,
                "startIndex": 0,
            },
        )
        if resp.status_code == 403:
            logger.warning("NVD rate limited — sleeping and retrying")
            time.sleep(1)
            resp = requests.get(
                NVD_URL,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
                params={
                    "resultsPerPage": 100,
                    "startIndex": 0,
                },
            )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.error("Failed to fetch NVD: %s", exc)
        return {"source": "nvd", "count": 0, "error": str(exc)}

    # NVD 2.0 API response format
    vulnerabilities = data.get("vulnerabilities", []) or []
    total = data.get("totalResults", 0)

    for vuln in vulnerabilities:
        cve_meta = vuln.get("cve", {})
        cve_id = cve_meta.get("id")
        if not cve_id:
            continue

        # Description (prefer English)
        descriptions = cve_meta.get("descriptions", [])
        description = None
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value")
                break
        if not description and descriptions:
            description = descriptions[0].get("value")

        # CVSS score (prefer v3.1, then v3.0, then v2)
        metrics = cve_meta.get("metrics", {})
        cvss_score = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            m_list = metrics.get(metric_key, [])
            if m_list:
                cvss_score = str(
                    m_list[0].get("cvssData", {}).get("baseScore")
                )
                break
        if not cvss_score:
            m_list = metrics.get("cvssMetricV2", [])
            if m_list:
                cvss_score = str(
                    m_list[0].get("cvssData", {}).get("baseScore")
                )

        # Affected products from configurations (nodes -> cpeMatch -> criteria)
        affected_products = _extract_affected_products_v2(
            cve_meta.get("configurations", [])
        )

        published_date = _parse_date(cve_meta.get("published"))

        storage.upsert_cve(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            epss_score=None,
            kev_flag=False,
            published_date=published_date,
            affected_products=affected_products,
            source="nvd",
        )
        count += 1
        total_fetched += 1

    logger.info("NVD upserted %d records", count)
    return {"source": "nvd", "count": count, "total": total_fetched}


def run_cve_ingestor(storage: Storage = None) -> dict:
    """Run all CVE ingestion sources. Returns a summary dict."""
    storage = storage or Storage()
    results = {
        "cisa_kev": ingest_cisa_kev(storage),
        "epss": ingest_epss(storage),
        "nvd": ingest_nvd(storage),
    }
    total = sum(r.get("count", 0) for r in results.values())
    results["total"] = total
    logger.info("CVE ingestion complete — %d records", total)
    return results


def run_all_ingestors() -> dict:
    """Run all CVE ingestion sources. Returns a summary dict."""
    storage = Storage()
    results = {
        "cisa_kev": ingest_cisa_kev(storage),
        "epss": ingest_epss(storage),
        "nvd": ingest_nvd(storage),
    }
    total = sum(r.get("count", 0) for r in results.values())
    results["total"] = total
    logger.info("CVE ingestion complete — %d records", total)
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    summary = run_all_ingestors()
    print(f"\nCVE ingestion complete: {summary}")
