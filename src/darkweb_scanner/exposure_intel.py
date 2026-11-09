"""Exposure intelligence helpers for Shodan, URLScan, and GreyNoise."""

import json
import logging
import os

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

import requests as _requests

from .dashboard.http_client import safe_fetch

logger = logging.getLogger(__name__)


def _api_key(name):
    return (os.getenv(name) or "").strip()


"""Exposure intelligence helpers for Shodan, URLScan, and GreyNoise."""

import ipaddress
import json
import logging
import os

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

import requests as _requests

from .dashboard.http_client import safe_fetch

logger = logging.getLogger(__name__)


def _api_key(name):
    return (os.getenv(name) or "").strip()


# Shodan free-tier only: /dns/domain and /dns/resolve are available on free plans.
# /shodan/host/search requires a paid membership, so we avoid it. We resolve a
# domain to its subdomains/IPs via free endpoints, then lookup each IP via
# /shodan/host/{ip} (also free-tier).
def shodan_search(query):
    key = _api_key("SHODAN_API_KEY")
    if not key:
        return {"error": "SHODAN_API_KEY not configured", "results": []}
    # Force IPv4 to avoid SSLEOFError from Cloudflare dropping HTTP/2
    # connections in Docker containers.
    from urllib3.util import connection as _conn
    _conn.HAS_IPV6 = False

    results = []

    def _get(path):
        url = f"https://api.shodan.io{path}?key={key}"
        logger.info("[shodan] GET %s", path)
        try:
            resp = _requests.get(url, timeout=15)
            return resp.status_code, resp.content
        except _requests.exceptions.SSLError as exc:
            logger.error("Shodan SSL Error: %s detail=%s", path, exc)
            return None, None
        except Exception as exc:
            logger.error("Shodan error: %s detail=%s", path, exc)
            return None, None

    def _parse_host(data):
        out = []
        for m in data.get("matches", []) or []:
            out.append({
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "service": m.get("product") or m.get("_shodan", {}).get("module"),
            })
        return out

    try:
        is_ip = False
        try:
            ipaddress.ip_address(query)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            status, body = _get(f"/shodan/host/{query}")
            if status is None:
                return {"error": "Shodan request failed", "results": []}
            if status in (401, 403):
                try:
                    data = json.loads(body)
                    msg = data.get("error", data.get("message", ""))
                except Exception:
                    msg = body.decode("utf-8", "replace")
                return {"error": f"Shodan {status}: {msg}", "results": []}
            if status != 200:
                return {"error": f"Shodan {status}", "results": []}
            return {"results": _parse_host(json.loads(body))}

        # Domain: use free-tier DNS endpoints
        status, body = _get(f"/dns/domain/{query}")
        if status is None:
            return {"error": "Shodan DNS lookup failed", "results": []}
        if status in (401, 403):
            try:
                data = json.loads(body)
                msg = data.get("error", data.get("message", ""))
            except Exception:
                msg = body.decode("utf-8", "replace")
            return {"error": f"Shodan {status}: {msg}", "results": []}
        if status != 200:
            return {"error": f"Shodan DNS {status}", "results": []}
        dns_data = json.loads(body) or {}
        subdomains = dns_data.get("subdomains", []) or []
        for sub in subdomains[:5]:
            fqdn = f"{sub}.{query}"
            st2, bd2 = _get(f"/dns/resolve?hostnames={fqdn}")
            if st2 is None or st2 != 200:
                continue
            try:
                resolve_data = json.loads(bd2) or {}
            except Exception:
                continue
            ips = resolve_data.get(fqdn) or []
            for ip in ips:
                st3, bd3 = _get(f"/shodan/host/{ip}")
                if st3 is None or st3 in (401, 403) or st3 != 200:
                    continue
                try:
                    results.extend(_parse_host(json.loads(bd3)))
                except Exception:
                    continue
        return {"results": results}
    except Exception as exc:
        logger.error("Shodan error: %s", exc)
        return {"error": str(exc), "results": []}


def urlscan_search(query):
    key = _api_key("URLSCAN_API_KEY")
    if not key:
        return {"error": "URLSCAN_API_KEY not configured", "results": []}
    url = f"https://urlscan.io/api/v1/search/?q={query}"
    try:
        resp = safe_fetch(url, headers={"API-Key": key})
        data = json.loads(resp["body"])
        results = []
        for r in data.get("results", []):
            page = r.get("page", {})
            results.append({
                "url": page.get("url"),
                "screenshot": r.get("screenshot"),
                "asn": page.get("asn"),
            })
        return {"results": results}
    except Exception as exc:
        print(f"[Exposure Intel] URLScan error: {exc}")
        return {"error": "API Connection Failed. Check logs for details.", "results": []}


def greynoise_community(ip):
    key = _api_key("GREYNOISE_API_KEY")
    if not key:
        return {"error": "GREYNOISE_API_KEY not configured", "result": {}}
    url = f"https://api.greynoise.io/v3/community/{ip}"
    try:
        resp = safe_fetch(url, headers={"key": key})
        return {"result": json.loads(resp["body"])}
    except Exception as exc:
        print(f"[Exposure Intel] GreyNoise error: {exc}")
        return {"error": "API Connection Failed. Check logs for details.", "result": {}}
