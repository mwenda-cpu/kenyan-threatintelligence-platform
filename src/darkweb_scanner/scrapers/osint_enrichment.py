import logging

import requests

logger = logging.getLogger(__name__)


def enrich_with_shodan(ip: str) -> dict:
    """Query Shodan InternetDB for an IP (no API key required)."""
    try:
        resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ip": ip,
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", []),
                "cpes": data.get("cpes", []),
                "vulns": data.get("vulns", []),
            }
        return {"ip": ip, "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        logger.debug("Shodan lookup failed for %s: %s", ip, exc)
        return {"ip": ip, "error": str(exc)}


def enrich_with_urlscan(domain: str) -> dict:
    """Query URLScan.io for a domain (free tier, no API key for search)."""
    try:
        resp = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5",
            timeout=10,
            headers={"User-Agent": "ThreatIntel-Platform/1.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            malicious = sum(1 for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious", False))
            return {
                "domain": domain,
                "total_scans": data.get("total", 0),
                "recent_scans": len(results),
                "malicious_count": malicious,
                "scan_urls": [r.get("page", {}).get("url", "") for r in results[:3]],
            }
        return {"domain": domain, "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        logger.debug("URLScan lookup failed for %s: %s", domain, exc)
        return {"domain": domain, "error": str(exc)}


def enrich_dns_with_osint(domain: str, ips: list[str]) -> dict:
    """Enrich DNS investigation results with OSINT data from Shodan and URLScan."""
    osint_data = {
        "shodan": {},
        "urlscan": {},
    }

    # Shodan InternetDB for each resolved IP
    for ip in ips[:5]:  # Limit to 5 IPs
        osint_data["shodan"][ip] = enrich_with_shodan(ip)

    # URLScan for the domain
    osint_data["urlscan"] = enrich_with_urlscan(domain)

    return osint_data
