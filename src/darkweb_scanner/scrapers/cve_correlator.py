"""
CVE <-> Kenyan Asset Correlator.

Matches CVE.affected_products against KenyanAsset.product_name and, on a
match, calculates a priority score and persists a CVEAlert.

Priority:
  - High   if KEV=True OR EPSS > 0.7
  - Medium otherwise
"""

from __future__ import annotations

import logging

from darkweb_scanner.storage import Storage

logger = logging.getLogger(__name__)

EPSS_HIGH_THRESHOLD = 0.7


def _priority_for(cve: dict) -> str:
    kev = bool(cve.get("kev_flag", False))
    epss_raw = cve.get("epss_score")
    epss = None
    if epss_raw is not None:
        try:
            epss = float(epss_raw)
        except (TypeError, ValueError):
            epss = None
    if kev or (epss is not None and epss > EPSS_HIGH_THRESHOLD):
        return "High"
    return "Medium"


def _products_match(cve_affected_products: str, asset_product_name: str) -> bool:
    if not cve_affected_products or not asset_product_name:
        return False
    cve_lower = cve_affected_products.lower()
    asset_lower = asset_product_name.lower()
    # Match on the first token (e.g., "cpe:/a:nginx:nginx" -> "nginx")
    asset_token = asset_lower.split(":")[-1].split("/")[0].strip()
    if not asset_token:
        asset_token = asset_lower
    return asset_token in cve_lower


def correlate_cves(storage: Storage = None) -> dict:
    """Correlate CVEs against Kenyan assets and save CVEAlerts.

    Returns a summary dict with counts.
    """
    storage = storage or Storage()
    cves = storage.get_cves(limit=5000)
    assets = storage.get_kenyan_assets()

    alerts_created = 0
    cves_matched = 0

    for cve in cves:
        affected = cve.get("affected_products") or ""
        matched_any = False
        for asset in assets:
            if _products_match(affected, asset["product_name"]):
                matched_any = True
                priority = _priority_for(cve)
                storage.save_cve_alert(
                    cve_id=cve["cve_id"],
                    asset_id=asset["id"],
                    priority_score=priority,
                )
                alerts_created += 1
        if matched_any:
            cves_matched += 1

    logger.info(
        "CVE correlation complete — %d CVEs matched, %d alerts created",
        cves_matched,
        alerts_created,
    )
    return {
        "cves_matched": cves_matched,
        "alerts_created": alerts_created,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    storage = Storage()
    summary = correlate_cves(storage)
    print(f"\nCVE correlation complete: {summary}")
