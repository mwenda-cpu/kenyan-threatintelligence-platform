"""Exposure intelligence helpers for Shodan, URLScan, and GreyNoise."""

import json
import os

from .dashboard.http_client import safe_fetch


def _api_key(name):
    return (os.getenv(name) or "").strip()


def shodan_search(query):
    key = _api_key("SHODAN_API_KEY")
    if not key:
        return {"error": "SHODAN_API_KEY not configured", "results": []}
    url = f"https://api.shodan.io/shodan/host/search?query={query}&key={key}"
    try:
        resp = safe_fetch(url)
        data = json.loads(resp["body"])
        results = []
        for m in data.get("matches", []):
            results.append({
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "service": m.get("product") or m.get("_shodan", {}).get("module"),
            })
        return {"results": results}
    except Exception as exc:
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
        return {"error": str(exc), "results": []}


def greynoise_community(ip):
    key = _api_key("GREYNOISE_API_KEY")
    if not key:
        return {"error": "GREYNOISE_API_KEY not configured", "result": {}}
    url = f"https://api.greynoise.io/v3/community/{ip}"
    try:
        resp = safe_fetch(url, headers={"key": key})
        return {"result": json.loads(resp["body"])}
    except Exception as exc:
        return {"error": str(exc), "result": {}}
