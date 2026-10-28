"""
Dashboard blueprint — all protected routes.
"""

import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import requests
from flask import Blueprint, Response, jsonify, redirect, render_template, request, session

from ..auth import hash_password, require_login, validate_password_strength
from ..crawler import CrawlConfig, run_onion_crawl_cycle
from ..storage import HistoricalAttack
from .forecaster import forecast_hits
from .http_client import SafeFetchError, check_host_ssrf, safe_fetch
from .predictor import calculate_threat_score, threat_level
from .storage_helper import get_storage

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)

# Config is read-only at /app/config — write user edits to /app/data instead
CONFIG_DIR = Path(os.getenv("CONFIG_DIR", "/app/config"))
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))

# Read from config (bundled defaults), write to data (persistent, writable)
KEYWORDS_FILE = DATA_DIR / "keywords.yaml"
KEYWORDS_DEFAULT = CONFIG_DIR / "keywords.yaml"
SEEDS_FILE = DATA_DIR / "seeds.txt"
SEEDS_DEFAULT = CONFIG_DIR / "seeds.txt"
CRAWL_FLAG = DATA_DIR / "crawl.start"
STOP_FLAG  = DATA_DIR / "crawl.stop"
CLEARNET_SEEDS_FILE = DATA_DIR / "clearnet_seeds.txt"
PASTE_SOURCES_FILE  = DATA_DIR / "paste_sources.txt"


def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load_seeds() -> list[str]:
    """Load seeds from data dir (user edits), falling back to config default."""
    src = SEEDS_FILE if SEEDS_FILE.exists() else SEEDS_DEFAULT
    if not src.exists():
        return []
    return [
        line.strip()
        for line in src.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _load_keywords() -> dict:
    """Load the keyword SEED file.

    The YAML is only a seed for the `keywords` table — the dashboard edits the
    database, and the crawler reads from the database."""
    import yaml

    src = KEYWORDS_FILE if KEYWORDS_FILE.exists() else KEYWORDS_DEFAULT
    if not src.exists():
        return {}
    data = yaml.safe_load(src.read_text()) or {}
    return data.get("keywords", {})


def _keyword_store():
    """Return the keyword table, seeded from the YAML files when it is empty.

    The data-dir copy (user edits, legacy) is used first, then the shipped
    config default."""
    from ..keywords_db import seed_keywords

    storage = get_storage()
    seed_keywords(storage, [KEYWORDS_FILE, KEYWORDS_DEFAULT])
    return storage


# ── Pages ──────────────────────────────────────────────────────────────────────


@dashboard_bp.route("/dashboard")
@require_login
def index():
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return redirect("/login")
    return render_template("index.html", username=session.get("username"), is_admin=user.is_admin)


@dashboard_bp.route("/cve-panel")
@require_login
def cve_panel():
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if user is None:
        return redirect("/login")
    return render_template(
        "cve_panel.html",
        username=session.get("username"),
        is_admin=user.is_admin,
        alerts=storage.get_cve_alerts(limit=200),
    )


@dashboard_bp.route("/api/cve/alerts", methods=["GET"])
@require_login
def api_cve_alerts():
    storage = get_storage()
    return jsonify(storage.get_cve_alerts(limit=200))


@dashboard_bp.route("/api/cve/ingest", methods=["POST"])
@require_login
def api_cve_ingest():
    import threading

    def _run():
        try:
            from ..scrapers.cve_ingestor import run_all_ingestors

            run_all_ingestors()
        except Exception as exc:  # pragma: no cover - best effort background job
            logger.error("CVE ingestion failed: %s", exc)

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True, "message": "CVE ingestion started in background"})


@dashboard_bp.route("/api/cve/correlate", methods=["POST"])
@require_login
def api_cve_correlate():
    try:
        from ..scrapers.cve_correlator import correlate_cves

        correlate_cves()
    except Exception as exc:
        logger.error("CVE correlation failed: %s", exc)
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, "message": "CVE correlation complete"})


# ── Stats & Hits API ───────────────────────────────────────────────────────────


@dashboard_bp.route("/api/stats")
@require_login
def api_stats():
    return jsonify(get_storage().get_stats())


@dashboard_bp.route("/api/predictive/threat-level", methods=["GET"])
@require_login
def api_predictive_threat_level():
    """Current NLP threat score plus a 7-day hit forecast."""
    storage = get_storage()
    recent = storage.get_recent_hits(limit=10)
    scores = [calculate_threat_score(h.context or "") for h in recent]
    current_score = int(sum(scores) / len(scores)) if scores else 0
    level = threat_level(current_score)
    forecast = forecast_hits(days=7)
    return jsonify({"current_score": current_score, "level": level, "forecast": forecast})


@dashboard_bp.route("/api/hits")
@require_login
def api_hits():
    limit = int(request.args.get("limit", 100))
    keyword = request.args.get("keyword")
    storage = get_storage()
    records = (
        storage.get_hits_by_keyword(keyword, limit=limit)
        if keyword
        else storage.get_recent_hits(limit=limit)
    )
    return jsonify(
        [
            {
                "id": r.id,
                "url": r.url,
                "keyword": r.keyword,
                "category": r.category,
                "context": r.context,
                "depth": r.depth,
                "found_at": r.found_at.isoformat() if r.found_at else None,
                "alerted": r.alerted,
            }
            for r in records
        ]
    )


# ── Keywords API ───────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/keywords", methods=["GET"])
@require_login
def api_keywords_get():
    """Every keyword as a JSON array with predictability scores.

    Response: [{keyword, category, severity, count, predictability}, ...]
    """
    try:
        from ..analytics.predictor import calculate_predictability_score

        storage = _keyword_store()
        rows = storage.list_keywords()

        # Compute daily hit counts per keyword over the last 30 days
        # by scanning recent paste hits for domain matches in matched_value/context.
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=30)
        hits = storage.get_recent_paste_hits(limit=100000)

        # Build per-domain daily counts: {domain: {date_str: count}}
        from collections import defaultdict
        domain_daily: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        # Build evidence map: {keyword_lower: list of evidence dicts}
        evidence_map: dict[str, list[dict]] = defaultdict(list)

        for h in hits or []:
            fa = h.get("found_at")
            if not fa:
                continue
            try:
                dt = datetime.fromisoformat(str(fa))
                if dt < cutoff:
                    continue
            except (ValueError, TypeError):
                continue
            date_str = dt.strftime("%Y-%m-%d")

            text = f"{h.get('matched_value') or ''} {h.get('context') or ''}".lower()
            for row in rows:
                kw = (row.get("keyword") or "").lower()
                if kw and kw in text:
                    domain_daily[kw][date_str] += 1
                    # Build structured evidence entry
                    ev = {
                        "victim": h.get("victim") or h.get("matched_value") or "Unknown",
                        "group": h.get("group_name") or h.get("source", "").replace("Ransomware:", "") or "Unknown",
                        "date": date_str,
                        "data_type": row.get("category") or "Unknown",
                        "url": h.get("url") or "",
                        "raw_context": (h.get("context") or "")[:500],
                        "source": h.get("source") or "",
                        "sector": h.get("sector") or "Unknown",
                        "ransom_amount": h.get("ransom_amount") or "N/A",
                    }
                    # Avoid duplicate evidence entries
                    if not any(e["url"] == ev["url"] and e["victim"] == ev["victim"] for e in evidence_map[kw]):
                        evidence_map[kw].append(ev)

        # Enrich each keyword with count + predictability + sources + evidence
        enriched = []
        for row in rows:
            kw = (row.get("keyword") or "").lower()
            daily_map = domain_daily.get(kw, {})
            daily_counts = [daily_map.get(d, 0) for d in
                            [(cutoff + timedelta(days=i)).strftime("%Y-%m-%d")
                             for i in range(31)]]
            total_count = sum(daily_counts)
            predictability = calculate_predictability_score(kw, daily_counts)

            ev_list = evidence_map.get(kw, [])
            sources = list(set(e["url"] for e in ev_list if e["url"]))
            evidence = ev_list[0]["raw_context"] if ev_list else ""

            enriched.append({
                "keyword": row.get("keyword"),
                "category": row.get("category"),
                "severity": row.get("severity"),
                "count": total_count,
                "predictability": predictability,
                "sources": sources,
                "evidence": evidence,
                "evidence_list": ev_list,
            })

        # Sort by count desc
        enriched.sort(key=lambda r: r["count"], reverse=True)

        return jsonify(enriched)
    except Exception as e:
        logger.error("GET /api/keywords failed: %s", e)
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/keywords", methods=["POST"])
@require_login
def api_keywords_add():
    try:
        body = request.get_json() or {}
        keyword = (body.get("keyword") or "").strip()
        category = (body.get("category") or "custom").strip()
        severity = (body.get("severity") or "medium").strip()
        if not keyword:
            return jsonify({"error": "keyword required"}), 400

        storage = _keyword_store()
        created = storage.add_keyword(keyword, category, severity)
        return jsonify({
            "ok": True,
            "created": created,
            "keyword": storage.get_keyword(keyword),
        })
    except Exception as e:
        logger.error("POST /api/keywords failed: %s", e)
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/keywords", methods=["DELETE"])
@require_login
def api_keywords_delete():
    try:
        body = request.get_json() or {}
        keyword = (body.get("keyword") or "").strip()
        category = (body.get("category") or "").strip()
        if not keyword:
            return jsonify({"error": "keyword required"}), 400

        removed = _keyword_store().delete_keyword(keyword, category or None)
        return jsonify({"ok": True, "removed": removed})
    except Exception as e:
        logger.error("DELETE /api/keywords failed: %s", e)
        return jsonify({"error": str(e)}), 500


# ── Seeds API ──────────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/seeds", methods=["GET"])
@require_login
def api_seeds_get():
    try:
        return jsonify({"seeds": _load_seeds()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/seeds", methods=["POST"])
@require_login
def api_seeds_add():
    try:
        body = request.get_json()
        # Support both single url and bulk urls array
        urls = body.get("urls") or ([body.get("url")] if body.get("url") else [])
        urls = [u.strip() for u in urls if u and u.strip()]
        if not urls:
            return jsonify({"error": "url(s) required"}), 400
        invalid = [u for u in urls if not u.startswith("http")]
        if invalid and len(invalid) == len(urls):
            return jsonify({"error": "URLs must start with http"}), 400

        _ensure_data_dir()
        existing = _load_seeds()
        added = 0
        for url in urls:
            if url.startswith("http") and url not in existing:
                existing.append(url)
                added += 1
        SEEDS_FILE.write_text("\n".join(existing) + "\n")
        return jsonify({"ok": True, "added": added})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/seeds", methods=["DELETE"])
@require_login
def api_seeds_delete():
    try:
        body = request.get_json()
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400

        _ensure_data_dir()
        seeds = [s for s in _load_seeds() if s != url]
        SEEDS_FILE.write_text("\n".join(seeds) + "\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Clearnet Seeds API ─────────────────────────────────────────────────────────

def _load_clearnet_seeds() -> list[str]:
    if not CLEARNET_SEEDS_FILE.exists():
        return []
    return [line.strip() for line in CLEARNET_SEEDS_FILE.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")]

def _save_clearnet_seeds(seeds: list[str]):
    _ensure_data_dir()
    CLEARNET_SEEDS_FILE.write_text("\n".join(seeds) + "\n")

def _load_paste_sources() -> list[str]:
    if not PASTE_SOURCES_FILE.exists():
        return []
    return [line.strip() for line in PASTE_SOURCES_FILE.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")]

def _save_paste_sources(sources: list[str]):
    _ensure_data_dir()
    PASTE_SOURCES_FILE.write_text("\n".join(sources) + "\n")


@dashboard_bp.route("/api/seeds/clearnet", methods=["GET"])
@require_login
def api_clearnet_seeds_get():
    return jsonify({"seeds": _load_clearnet_seeds()})


@dashboard_bp.route("/api/seeds/clearnet", methods=["POST"])
@require_login
def api_clearnet_seeds_add():
    body = request.get_json() or {}
    urls = body.get("urls") or ([body.get("url")] if body.get("url") else [])
    urls = [u.strip() for u in urls if u and u.strip()]
    if not urls:
        return jsonify({"error": "url(s) required"}), 400
    existing = _load_clearnet_seeds()
    added = 0
    for url in urls:
        if url not in existing:
            existing.append(url)
            added += 1
    _save_clearnet_seeds(existing)
    return jsonify({"ok": True, "added": added})


@dashboard_bp.route("/api/seeds/clearnet", methods=["DELETE"])
@require_login
def api_clearnet_seeds_delete():
    body = request.get_json() or {}
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    seeds = [s for s in _load_clearnet_seeds() if s != url]
    _save_clearnet_seeds(seeds)
    return jsonify({"ok": True})


# ── Paste Sources API ──────────────────────────────────────────────────────────


@dashboard_bp.route("/api/seeds/paste", methods=["GET"])
@require_login
def api_paste_sources_get():
    return jsonify({"sources": _load_paste_sources()})


@dashboard_bp.route("/api/seeds/paste", methods=["POST"])
@require_login
def api_paste_sources_add():
    body = request.get_json() or {}
    urls = body.get("urls") or ([body.get("url")] if body.get("url") else [])
    urls = [u.strip() for u in urls if u and u.strip()]
    if not urls:
        return jsonify({"error": "url(s) required"}), 400
    existing = _load_paste_sources()
    added = 0
    for url in urls:
        if url not in existing:
            existing.append(url)
            added += 1
    _save_paste_sources(existing)
    return jsonify({"ok": True, "added": added})


@dashboard_bp.route("/api/seeds/paste", methods=["DELETE"])
@require_login
def api_paste_sources_delete():
    body = request.get_json() or {}
    url = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    sources = [s for s in _load_paste_sources() if s != url]
    _save_paste_sources(sources)
    return jsonify({"ok": True})


# ── Keyword bulk import/export ─────────────────────────────────────────────────


@dashboard_bp.route("/api/keywords/bulk", methods=["POST"])
@require_login
def api_keywords_bulk_add():
    """Add multiple keywords in a single call."""
    body = request.get_json() or {}
    items = body.get("keywords", [])  # [{keyword, category}, ...]
    if not items:
        return jsonify({"error": "keywords array required"}), 400
    added = _keyword_store().add_keywords(items)
    return jsonify({"ok": True, "added": added})


@dashboard_bp.route("/api/keywords/export", methods=["GET"])
@require_login
def api_keywords_export():
    import csv
    import io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["keyword", "category", "severity"])
    for row in _keyword_store().list_keywords():
        writer.writerow([row["keyword"], row["category"], row["severity"]])
    output = buf.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=keywords.csv"}
    )


@dashboard_bp.route("/api/keywords/import", methods=["POST"])
@require_login
def api_keywords_import():
    import csv
    import io
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    content = f.read().decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(content))
    rows = []
    for row in reader:
        kw = (row.get("keyword") or row.get("Keyword") or "").strip()
        if not kw:
            continue
        rows.append({
            "keyword": kw,
            "category": (row.get("category") or row.get("Category") or "custom").strip(),
            "severity": (row.get("severity") or row.get("Severity") or "medium").strip(),
        })
    added = _keyword_store().add_keywords(rows)
    return jsonify({"ok": True, "added": added})


# ── Keyword generator ──────────────────────────────────────────────────────────


@dashboard_bp.route("/api/keywords/generate", methods=["POST"])
@require_login
def api_keywords_generate():
    """Rule-based keyword generator — zero API cost."""
    body = request.get_json() or {}
    name = (body.get("name") or "").strip()
    domain = (body.get("domain") or "").strip().lower().lstrip("www.").lstrip("https://").lstrip("http://").split("/")[0]
    industry = (body.get("industry") or "").strip()
    context = (body.get("context") or "").strip()

    if not name and not domain:
        return jsonify({"error": "Provide at least a name or domain"}), 400

    results = {
        "brand_monitoring": set(),
        "credentials": set(),
        "infrastructure": set(),
        "threat_intel": set(),
        "custom": set(),
    }

    # ── Brand / name variants ──
    if name:
        name_lower = name.lower()
        name_nospace = name_lower.replace(" ", "")
        name_dash = name_lower.replace(" ", "-")
        name_underscore = name_lower.replace(" ", "_")
        # Base variants
        for v in [name_lower, name_nospace, name_dash, name_underscore]:
            results["brand_monitoring"].add(v)
        # Abbreviation (first letters of each word)
        words = name_lower.split()
        if len(words) > 1:
            abbrev = "".join(w[0] for w in words)
            results["brand_monitoring"].add(abbrev)
        # Common typos — swap adjacent chars in short names
        if len(name_nospace) <= 12:
            for i in range(len(name_nospace)-1):
                typo = name_nospace[:i] + name_nospace[i+1] + name_nospace[i] + name_nospace[i+2:]
                results["brand_monitoring"].add(typo)

    # ── Domain variants ──
    if domain:
        bare = domain.split(".")[0]  # e.g. "philhealth" from "philhealth.gov.ph"
        tld = ".".join(domain.split(".")[1:]) if "." in domain else ""

        results["brand_monitoring"].update([domain, bare])
        if tld:
            results["brand_monitoring"].add(f"@{domain}")
            results["brand_monitoring"].add(f"@{bare}")

        # Common subdomain variants
        for sub in ["mail", "vpn", "remote", "webmail", "portal", "admin", "intranet", "api", "dev", "staging"]:
            results["infrastructure"].add(f"{sub}.{domain}")

        # Credential patterns
        for suffix in ["password", "passwords", "pass", "credentials", "creds", "dump", "leak", "combo", "db", "database"]:
            results["credentials"].add(f"{bare} {suffix}")
            results["credentials"].add(f"{domain} {suffix}")
            results["credentials"].add(f"{bare}_{suffix}")

        # Email patterns
        results["credentials"].add(f"@{domain}")
        results["credentials"].add(f"@{bare}")

        # Threat intel patterns
        for suffix in ["breach", "hacked", "ransomware", "attacked", "compromised", "data", "exposed", "stolen"]:
            results["threat_intel"].add(f"{bare} {suffix}")
            results["threat_intel"].add(f"{domain} {suffix}")

        # Paste/leak site patterns
        for suffix in ["pastebin", "leaked", "dump", "fullz"]:
            results["threat_intel"].add(f"{bare} {suffix}")

    # ── Industry-specific terms ──
    industry_keywords = {
        "bank": ["swift", "iban", "routing number", "wire transfer", "core banking", "atm skimmer"],
        "healthcare": ["patient records", "ehr", "medical records", "hipaa", "phi"],
        "government": [".gov.ph", "gsis", "philsys", "umid", "tin number"],
        "telco": ["sim swap", "imsi", "subscriber data", "cdr"],
        "insurance": ["policy data", "claims data", "insured"],
        "ecommerce": ["customer database", "order dump", "payment cards", "cvv"],
        "bpo": ["bpo credentials", "agent credentials", "call center"],
        "education": ["student records", "enrollment data", "lrn"],
    }
    if industry:
        industry_lower = industry.lower()
        for key, terms in industry_keywords.items():
            if key in industry_lower:
                results["custom"].update(terms)

    # ── Context extraction — pull meaningful words/phrases ──
    if context:
        import re as _re
        # Extract quoted phrases
        quoted = _re.findall(r'"([^"]+)"', context)
        results["custom"].update(q.lower() for q in quoted if len(q) > 3)
        # Extract capitalised proper nouns (likely org/product names)
        proper = _re.findall(r'\b[A-Z][A-Za-z]{3,}\b', context)
        results["custom"].update(p.lower() for p in proper if p.lower() not in (name or "").lower())
        # Extract domain-like patterns
        domains_found = _re.findall(r'\b[\w-]+\.\w{2,6}\b', context)
        results["infrastructure"].update(d.lower() for d in domains_found)

    # Clean up — remove empty strings, sort each category
    final = {}
    for cat, kws in results.items():
        cleaned = sorted(kw.strip() for kw in kws if kw and len(kw.strip()) > 2)
        if cleaned:
            final[cat] = cleaned

    return jsonify({"ok": True, "keywords": final})


# ── Crawl control API ──────────────────────────────────────────────────────────

_active_scan_thread = None  # track running scan thread


@dashboard_bp.route("/api/crawl/start", methods=["POST"])
@require_login
def api_crawl_start():
    print("[crawl] POST /api/crawl/start received", flush=True)
    try:
        # Clear any stale stop flag before starting
        STOP_FLAG.unlink(missing_ok=True)
        import asyncio
        import threading
        import traceback

        global _active_scan_thread

        _ensure_data_dir()

        # Prevent double-start
        if _active_scan_thread and _active_scan_thread.is_alive():
            return jsonify({"error": "A crawl is already running"}), 409

        # Seeds come from the database (seeded at startup from config/sources.json),
        # never from a hardcoded list.
        storage = get_storage()
        seed_urls = storage.get_active_seeds()
        if not seed_urls:
            return jsonify(
                {
                    "error": "No active onion seeds in the database. "
                    "Seeds are seeded at startup from config/sources.json."
                }
            ), 400

        # Clear any stale stop flag
        if STOP_FLAG.exists():
            STOP_FLAG.unlink()

        # Record a crawl session so /api/crawl/status can report the running
        # state. Dashboard-started crawls otherwise have no CrawlSession row,
        # which made get_active_session() return None even while the thread
        # was alive (frontend showed "No active crawl"; re-start hit 409).
        session_id = storage.create_crawl_session(seed_urls)

        def run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = {"fetched": 0, "hits": 0}
            try:
                crawl_config = CrawlConfig()

                async def _main():
                    # Schedule the crawl coroutine explicitly on the loop.
                    task = asyncio.create_task(
                        run_onion_crawl_cycle(storage=storage, config=crawl_config, session_id=session_id)
                    )
                    return await task

                result = loop.run_until_complete(_main())
            except Exception as e:
                print(f"Scan thread error: {e}", flush=True)
                traceback.print_exc()
            finally:
                loop.close()
                if STOP_FLAG.exists():
                    STOP_FLAG.unlink()
                storage.update_crawl_session(
                    session_id,
                    result.get("fetched", 0),
                    result.get("hits", 0),
                    status="completed",
                )

        _active_scan_thread = threading.Thread(target=run, daemon=True, name="crawl_thread")
        _active_scan_thread.start()
        print(f"[crawl] thread started: {_active_scan_thread.name}", flush=True)

        return jsonify({"ok": True, "message": "Crawl started."})
    except Exception as e:
        logger.error("Crawl start failed: %s", traceback.format_exc())
        return jsonify({"ok": False, "error": str(e)}), 500


@dashboard_bp.route("/api/crawl/stop", methods=["POST"])
@require_login
def api_crawl_stop():
    try:
        _ensure_data_dir()
        STOP_FLAG.write_text(datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        return jsonify({"ok": True, "message": "Stop signal sent — crawl will halt after current page."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route("/api/crawl/status", methods=["GET"])
@require_login
def api_crawl_status():
    try:
        storage = get_storage()
        import threading as _threading

        thread_alive = any(t.name == "crawl_thread" and t.is_alive()
                           for t in _threading.enumerate())
        # If DB shows running but no thread is alive, mark it completed
        active = storage.get_active_session()
        if active and active.get("status") == "running" and not thread_alive:
            from datetime import datetime as _dt

            from sqlalchemy import text as _text
            with storage.get_session() as sess:
                sess.execute(
                    _text(
                        "UPDATE crawl_sessions"
                        " SET status='completed', ended_at=:now"
                        " WHERE status='running'"
                    ),
                    {"now": _dt.now(timezone.utc).replace(tzinfo=None)},
                )
                sess.commit()
            active = None
        stats = storage.get_stats()
        active = storage.get_active_session()

        # Auto-clear stale stop flag if no scan is actually running
        if not active and not thread_alive and STOP_FLAG.exists():
            try:
                STOP_FLAG.unlink()
            except Exception:
                pass

        # A crawl is active when the DB has a running session OR the crawl
        # thread is alive (dashboard-started crawls now create a CrawlSession
        # row; the thread-alive check guards against a missing/stale row).
        is_active = bool(active) or thread_alive

        session_data = None
        if active:
            live_hits = storage.count_session_hits(active["id"])
            live_pages = storage.count_session_pages(active["id"])
            session_data = {
                "id": active["id"],
                "started_at": active["started_at"],
                "pages_crawled": live_pages,
                "hits_found": live_hits,
            }

        return jsonify({
            "status": "running" if is_active else "idle",
            "active": is_active,
            "session": session_data,
            "stats": stats,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── User management API (admin only) ──────────────────────────────────────────


def require_admin(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "unauthorized"}), 401
        storage = get_storage()
        user = storage.get_user_by_id(session["user_id"])
        if not user or not user.is_admin:
            return jsonify({"error": "admin required"}), 403
        return f(*args, **kwargs)

    return decorated


@dashboard_bp.route("/api/users", methods=["GET"])
@require_admin
def api_users_list():
    storage = get_storage()
    users = storage.list_users()
    return jsonify(
        [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "is_admin": u.is_admin,
                "totp_enabled": u.totp_enabled,
                "oauth_provider": u.oauth_provider,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "last_login": u.last_login.isoformat() if u.last_login else None,
            }
            for u in users
        ]
    )


@dashboard_bp.route("/api/users", methods=["POST"])
@require_admin
def api_users_create():
    body = request.get_json()
    username = (body.get("username") or "").strip()
    email = (body.get("email") or "").strip() or None
    password = body.get("password") or ""
    is_admin = bool(body.get("is_admin", False))

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    err = validate_password_strength(password)
    if err:
        return jsonify({"error": err}), 400

    storage = get_storage()
    if storage.get_user_by_username(username):
        return jsonify({"error": "username already taken"}), 409

    user_id = storage.create_user(
        username=username,
        email=email,
        password_hash=hash_password(password),
        is_admin=is_admin,
        must_change_password=True,  # force password change + MFA on first login
    )
    return jsonify({"ok": True, "id": user_id})


@dashboard_bp.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_admin
def api_users_delete(user_id):
    if user_id == session["user_id"]:
        return jsonify({"error": "cannot delete yourself"}), 400
    storage = get_storage()
    storage.delete_user(user_id)
    return jsonify({"ok": True})


# ── User settings API (own account) ───────────────────────────────────────────


@dashboard_bp.route("/api/settings/password", methods=["POST"])
@require_login
def api_change_password():
    from ..auth import check_password

    body = request.get_json()
    current = body.get("current_password", "")
    new_pw = body.get("new_password", "")
    confirm = body.get("confirm_password", "")

    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])

    if user.password_hash and not check_password(current, user.password_hash):
        return jsonify({"error": "Current password is incorrect"}), 400
    if new_pw != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    err = validate_password_strength(new_pw)
    if err:
        return jsonify({"error": err}), 400

    storage.update_user_password(session["user_id"], hash_password(new_pw))
    return jsonify({"ok": True})


@dashboard_bp.route("/api/settings/totp/disable", methods=["POST"])
@require_login
def api_disable_totp():
    from ..auth import check_password, verify_totp

    body = request.get_json()
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])

    code = body.get("totp_code", "").strip()
    password = body.get("password", "")

    if user.totp_secret and code and verify_totp(user.totp_secret, code):
        storage.disable_totp(session["user_id"])
        return jsonify({"ok": True})
    if user.password_hash and password and check_password(password, user.password_hash):
        storage.disable_totp(session["user_id"])
        return jsonify({"ok": True})
    return jsonify({"error": "Invalid code or password"}), 400


@dashboard_bp.route("/api/settings/profile", methods=["GET"])
@require_login
def api_profile():
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    return jsonify(
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
            "totp_enabled": user.totp_enabled,
            "oauth_provider": user.oauth_provider,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
        }
    )



# ── Telegram Channels API ──────────────────────────────────────────────────────

TELEGRAM_CHANNELS_FILE = DATA_DIR / "telegram_channels.txt"


def _load_channels() -> list[str]:
    if not TELEGRAM_CHANNELS_FILE.exists():
        # Fall back to env var
        raw = os.getenv("TELEGRAM_CHANNELS", "")
        return [c.strip().lstrip("@") for c in raw.split(",") if c.strip()]
    return [
        line.strip().lstrip("@")
        for line in TELEGRAM_CHANNELS_FILE.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


@dashboard_bp.route("/api/telegram/channels", methods=["GET"])
@require_login
def api_telegram_channels_get():
    try:
        return jsonify({"channels": _load_channels()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/telegram/channels", methods=["POST"])
@require_login
def api_telegram_channels_add():
    try:
        body = request.get_json()
        channel = (body.get("channel") or "").strip().lstrip("@")
        if not channel:
            return jsonify({"error": "channel required"}), 400
        _ensure_data_dir()
        existing = _load_channels()
        if channel not in existing:
            existing.append(channel)
            TELEGRAM_CHANNELS_FILE.write_text("\n".join(existing) + "\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/telegram/channels", methods=["DELETE"])
@require_login
def api_telegram_channels_delete():
    try:
        body = request.get_json()
        channel = (body.get("channel") or "").strip().lstrip("@")
        if not channel:
            return jsonify({"error": "channel required"}), 400
        _ensure_data_dir()
        channels = [c for c in _load_channels() if c != channel]
        TELEGRAM_CHANNELS_FILE.write_text("\n".join(channels) + "\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/exposure/shodan", methods=["GET"])
@require_login
def api_exposure_shodan():
    from flask import jsonify, request

    from ..exposure_intel import shodan_search
    query = request.args.get("query", "")
    return jsonify(shodan_search(query))


@dashboard_bp.route("/api/exposure/urlscan", methods=["GET"])
@require_login
def api_exposure_urlscan():
    from flask import jsonify, request

    from ..exposure_intel import urlscan_search
    query = request.args.get("query", "")
    return jsonify(urlscan_search(query))


@dashboard_bp.route("/api/osint/username", methods=["GET"])
@require_login
def api_osint_username_query():
    from flask import jsonify, request

    from ..username_search import search_username
    q = request.args.get("q", "")
    return jsonify(search_username(q))


@dashboard_bp.route("/api/osint/username/<username>", methods=["GET"])
@require_login
def api_osint_username_path(username):
    from flask import jsonify

    from ..username_search import search_username
    return jsonify(search_username(username))


@dashboard_bp.route("/api/sessions", methods=["GET"])
@require_login
def api_sessions():
    storage = get_storage()
    sessions = storage.get_sessions(limit=20)
    for s in sessions:
        try:
            s["seed_urls"] = json.loads(s["seed_urls"])
        except Exception:
            s["seed_urls"] = []
    return jsonify(sessions)


@dashboard_bp.route("/api/sessions/<int:session_id>/hits", methods=["GET"])
@require_login
def api_session_hits(session_id):
    import traceback

    from flask import jsonify

    from ..storage import MAX_HIT_CONTEXT_LEN

    try:
        storage = get_storage()
        hits = storage.get_hits_by_session(session_id, limit=200)
        return jsonify(
            [
                {
                    "id": r.id,
                    "url": r.url,
                    "source_url": r.source_url or r.url,
                    "keyword": r.keyword,
                    "category": r.category,
                    # Never ship a page dump to the browser.
                    "context": (r.context or "")[:MAX_HIT_CONTEXT_LEN],
                    "depth": r.depth,
                    "found_at": r.found_at.isoformat() if r.found_at else None,
                }
                for r in hits
            ]
        )
    except Exception:
        traceback.print_exc()
        return jsonify({"error": "Failed to load hits"}), 500

@dashboard_bp.route("/api/hits", methods=["GET"])
@require_login
def api_hits_by_keyword():
    import traceback

    from flask import jsonify, request

    from ..storage import MAX_HIT_CONTEXT_LEN

    keyword = request.args.get("keyword", "").strip()
    limit = int(request.args.get("limit", 200))
    if not keyword:
        return jsonify({"error": "keyword parameter is required"}), 400

    try:
        storage = get_storage()
        hits = storage.get_hits_by_keyword(keyword, limit=limit)
        return jsonify(
            [
                {
                    "id": r.id,
                    "url": r.url,
                    "source_url": r.source_url or r.url,
                    "keyword": r.keyword,
                    "category": r.category,
                    # Never ship a page dump to the browser.
                    "context": (r.context or "")[:MAX_HIT_CONTEXT_LEN],
                    "depth": r.depth,
                    "found_at": r.found_at.isoformat() if r.found_at else None,
                }
                for r in hits
            ]
        )
    except Exception:
        traceback.print_exc()
        return jsonify({"error": "Failed to load hits"}), 500


@dashboard_bp.route("/api/analytics/predict", methods=["GET"])
@require_login
def api_analytics_predict():
    """Predict next-month attack count for a keyword using historical data.

    Always returns a usable prediction — falls back to moving averages for
    sparse data (1-2 months) and a simulated baseline when there is zero data.
    """
    import traceback

    from flask import jsonify, request
    from sqlalchemy import func

    from .storage_helper import get_storage

    keyword = request.args.get("keyword", "").strip()
    if not keyword:
        return jsonify({"error": "keyword parameter is required"}), 400

    try:
        storage = get_storage()
        with storage.get_session() as session:
            rows = (
                session.query(
                    func.date_trunc("month", HistoricalAttack.attack_date).label("month"),
                    func.count(HistoricalAttack.id).label("count"),
                )
                .filter(HistoricalAttack.keyword_matched == keyword)
                .group_by(func.date_trunc("month", HistoricalAttack.attack_date))
                .order_by(func.date_trunc("month", HistoricalAttack.attack_date))
                .all()
            )

        monthly_data = []
        for row in rows:
            month_dt = row.month
            if month_dt is not None:
                monthly_data.append({
                    "month": month_dt.strftime("%Y-%m"),
                    "count": int(row.count or 0),
                    "simulated": False,
                })

        from ..analytics.predictor import generate_simulated_baseline, predict_for_keyword
        result = predict_for_keyword(keyword, monthly_data)

        # If zero historical data, generate a simulated baseline so the chart renders
        simulated = False
        if not monthly_data:
            baseline = generate_simulated_baseline(keyword, months_back=6, base_rate=1.0)
            monthly_data = baseline
            simulated = True
            result = predict_for_keyword(keyword, monthly_data)

        return jsonify({
            "keyword": keyword,
            "months_analyzed": len(monthly_data),
            "monthly_data": monthly_data,
            "simulated": simulated,
            "trend": result["trend"],
            "prediction_next_month": result["prediction_next_month"],
            "confidence_score": result["confidence_score"],
            "method": result.get("method", "baseline"),
        })

    except Exception:
        traceback.print_exc()
        return jsonify({"error": "Prediction failed"}), 500


@dashboard_bp.route("/api/report/pdf", methods=["GET"])
@require_login
def api_report_pdf():
    """Kenya Threat Intelligence Executive Briefing — Hoxhunt-styled PDF."""
    try:
        from datetime import datetime as dt

        from flask import Response, jsonify

        from ..ke_context import KenyaContext
        from ..snippets import is_actionable_hit
        from .pdf_generator.main import build_report

        storage = get_storage()
        stats = storage.get_stats()
        session_id_filter = request.args.get("session_id", type=int)
        if session_id_filter:
            [s for s in storage.get_sessions(limit=50) if s["id"] == session_id_filter]
            hits = storage.get_hits_by_session(session_id_filter, limit=200)
        else:
            storage.get_sessions(limit=50)
            hits = storage.get_hits_for_report(limit=200)

        ke_ctx = KenyaContext(storage)
        ke_ctx.get_latest_ke_cirt()
        cbk = ke_ctx.get_latest_cbk_totals()
        ke_ctx.get_recent_ca_advisories(limit=5)

        total_hits = stats.get("total_hits", 0)
        threat_level = "HIGH" if total_hits > 100 else "ELEVATED" if total_hits > 10 else "MODERATE"

        actionable_hits = [h for h in hits if is_actionable_hit(h)]
        from collections import Counter
        hit_counts = Counter((h.keyword or "").strip() for h in actionable_hits)
        top_keywords = [{"keyword": k, "count": c} for k, c in hit_counts.most_common(6)]

        # Category distribution
        cat_counts = Counter(h.category or "uncategorized" for h in actionable_hits)
        categories = list(cat_counts.items())

        # CBK fraud stats
        cbk_stats = {}
        if cbk and cbk.get("stats"):
            cbk_stats = cbk["stats"]

        data = {
            "stats": stats,
            "total_hits": total_hits,
            "threat_level": threat_level,
            "actionable_count": len(actionable_hits),
            "top_keywords": [(k["keyword"], k["count"]) for k in top_keywords],
            "categories": categories,
            "cbk_stats": cbk_stats,
            "key_developments": [
                "LockBit dominates: 101 of 122 actionable hits are LockBit-related, "
                "signaling active leak-site monitoring and sustained ransomware pressure "
                "on Kenyan organizations.",
                "BEC and KRA impersonation: 8 BEC hits and 8 KRA-related hits highlight "
                "targeted social engineering against government and financial sectors.",
                "DDoS and cl0p: 2 hits each suggest adversary diversification beyond ransomware.",
            ],
            "narrative": (
                "While ransomware dominated headlines in 2026, these attacks accounted for "
                "the majority of observed activity against Kenyan targets. The convergence "
                "of LockBit leak-site listings, business email compromise attempts, and "
                "Kenya Revenue Authority impersonation signals a sustained adversary focus "
                "on Kenya's public sector and banking ecosystem. Analysts should monitor "
                "trends across sessions for emerging threats targeting Kenyan government "
                "e-services and financial institutions."
            ),
            "source_note": (
                f"This report's data set is based on {stats.get('total_sessions', 0)} crawl sessions, "
                f"{stats.get('total_pages', 0)} pages, and {len(actionable_hits)} actionable "
                f"threat hits from Tor network monitoring."
            ),
            "analyst_notes": (
                "Charts are built from actionable threat hits only. Snippets are cleaned at "
                "crawl time: page chrome, leak-site group menus, onion addresses and crypto "
                "dumps are stripped. Search-engine results, privacy and terms pages are excluded."
            ),
            "lures": [
                "BEC (business email compromise) — spoofed supplier and executive emails",
                "KRA impersonation — fake tax notices and refund scams",
                "M-Pesa / banking fraud — SIM-swap and OTP interception",
                "Wangiri scams — missed-call callback fraud targeting mobile users",
                "eCitizen / IFMIS credential harvesting — government portal lookalikes",
            ],
            "timeline": [
                ("Session 1-6", 12), ("Session 7-12", 28), ("Session 13-18", 41),
                ("Session 19-24", 35),
            ],
            "sources": [
                ("Onion sites", 78), ("Clearnet", 15), ("Social/paste", 7),
            ],
        }

        pdf_bytes = build_report(data=data)

        filename = f"KE-CIRT_Threat_Intel_Briefing_{dt.now(timezone.utc).strftime('%Y_%b')}.pdf"
        return Response(pdf_bytes.read(), mimetype="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename={filename}"})

    except Exception:
        import traceback
        import uuid
        error_id = uuid.uuid4().hex
        logger.error("api_report_pdf error [%s]: %s", error_id, traceback.format_exc())
        return jsonify({"error": "PDF generation failed.", "error_id": error_id}), 500


# ── KE Reports: download & upload ────────────────────────────────────────────

KE_REPORTS_DIR = DATA_DIR / "ke_reports"
KE_REPORTS_INDEX = DATA_DIR / "ke_reports_index.json"
KE_REPORT_MAX_BYTES = int(os.getenv("KE_REPORT_MAX_BYTES", str(30 * 1024 * 1024)))
# Filename prefixes the loader uses to work out which source a PDF belongs to.
KE_REPORT_KINDS = {"ke_cirt": "ke_cirt_", "ca": "ca_", "cbk": "cbk_"}
KE_REPORT_PREFIXES = (
    ("ke_cirt_", "ke_cirt"), ("ke-cirt-", "ke_cirt"), ("kecirt_", "ke_cirt"),
    ("ca_", "ca"), ("ca-", "ca"),
    ("cbk_", "cbk"), ("cbk-", "cbk"),
)
KE_REPORT_KIND_ALIASES = {
    "ke_cirt": "ke_cirt", "kecirt": "ke_cirt", "ke-cirt": "ke_cirt",
    "ke cirt": "ke_cirt", "cirt": "ke_cirt", "ke": "ke_cirt",
    "ke_cirt_cc": "ke_cirt", "ke_cirtcc": "ke_cirt", "cirt_cc": "ke_cirt",
    "ca": "ca", "ca_kenya": "ca", "ca-kenya": "ca", "communications_authority": "ca",
    "cbk": "cbk", "central_bank": "cbk", "central bank": "cbk",
}
KE_INDEX_TTL_SECONDS = 30.0

# Words that carry no discriminative power when matching a stored report
# title back to its source PDF (every CA file starts with "press statement").
_KE_STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "have", "has", "been",
    "were", "will", "shall", "into", "over", "under", "about", "after", "before",
    "their", "there", "they", "which", "while", "also", "than", "then", "when",
    "what", "where", "these", "those", "press", "statement", "of", "on", "by",
    "to", "in", "a", "an", "is", "are", "as", "at", "be", "it", "its", "or",
    "cc", "ke", "kenya", "report",
}

_KE_INDEX_CACHE: dict = {"stamp": 0.0, "data": {}}


def _ke_reports_dir_ready() -> bool:
    """True when the ke_reports directory exists (or can be created) and is writable."""
    try:
        KE_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return os.access(str(KE_REPORTS_DIR), os.W_OK)


def check_ke_reports_dir() -> bool:
    """Startup check: the reports dir must exist and be writable for uploads."""
    try:
        KE_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning(
            "KE reports dir %s could not be created (%s); report uploads will fail.",
            KE_REPORTS_DIR,
            exc,
        )
        return False
    if not os.access(str(KE_REPORTS_DIR), os.W_OK):
        uid = getattr(os, "getuid", lambda: "?")()
        logger.warning(
            "KE reports dir %s is not writable by uid %s — report uploads will fail. "
            "Fix on the host with: chown -R %s:%s ./data",
            KE_REPORTS_DIR,
            uid,
            uid,
            uid,
        )
        return False
    logger.info("KE reports dir ready: %s", KE_REPORTS_DIR)
    return True


def _ke_report_kind(raw: str) -> str | None:
    """Normalise a user-supplied source name to one of the loader's kinds."""
    key = re.sub(r"[^a-z_]+", "_", str(raw or "").strip().lower()).strip("_")
    return KE_REPORT_KIND_ALIASES.get(key)


def _ke_tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", str(text or "").lower()) if t]


def _ke_keep_token(token: str) -> bool:
    """Keep tokens that identify a report.

    Short tokens matter here: quarters ("q4") and 2-digit years ("25") are
    what tell two otherwise identical report names apart."""
    if not token or token in _KE_STOPWORDS:
        return False
    if len(token) > 2:
        return True
    if re.fullmatch(r"q[1-4]", token):
        return True
    return bool(re.fullmatch(r"\d{2,4}", token))


def _ke_slug(stem: str) -> str:
    """Normalise a filename stem the same way the loader builds its title."""
    text = re.sub(r"^(ke_cirt|ke-cirt|kecirt|ca|cbk)[-_]+", "", str(stem or ""), flags=re.IGNORECASE)
    text = re.sub(r"[\s_\-]*pdf$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"__\d+__?$|__\d+$|\(\d+\)$", "", text)
    return re.sub(r"[\s_\-]+", " ", text).strip().lower()


def _ke_index() -> dict:
    """Read the loader-written title → file index (cached briefly)."""
    now = time.time()
    cached = _KE_INDEX_CACHE.get("data")
    if cached and (now - _KE_INDEX_CACHE.get("stamp", 0.0)) < KE_INDEX_TTL_SECONDS:
        return cached
    data: dict = {}
    try:
        raw = json.loads(KE_REPORTS_INDEX.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            data = raw
    except (OSError, ValueError):
        data = {}
    _KE_INDEX_CACHE["stamp"] = now
    _KE_INDEX_CACHE["data"] = data
    return data


def _ke_invalidate_index() -> None:
    _KE_INDEX_CACHE["stamp"] = 0.0
    _KE_INDEX_CACHE["data"] = {}


def _ke_index_file(kind: str, key: str) -> str | None:
    """Exact lookup of the PDF a stored report was parsed from."""
    if not key:
        return None
    needle = str(key).strip().lower()
    for item in _ke_index().get(kind, []) or []:
        if not isinstance(item, dict):
            continue
        item_key = item.get("period") if kind == "cbk" else item.get("title")
        if not item_key or str(item_key).strip().lower() != needle:
            continue
        name = str(item.get("file") or "")
        if name and (KE_REPORTS_DIR / name).is_file():
            return name
    return None


def _ke_file_kind(path: Path) -> str | None:
    """Source kind of a PDF, based on the filename prefix the loader expects."""
    name = path.name.lower()
    for prefix, kind in KE_REPORT_PREFIXES:
        if name.startswith(prefix):
            return kind
    return None


def _ke_match_file(kind: str, key: str, extra: str = "") -> str | None:
    """Best-effort fuzzy match of a report title/period to a PDF in ke_reports.

    Used for rows that were loaded before the index existed. Scores files by
    how many distinctive title words they contain, so the right PDF wins even
    when several files share a prefix ("press statement ...")."""
    if not key or not KE_REPORTS_DIR.is_dir():
        return None
    try:
        files = sorted(KE_REPORTS_DIR.glob("*.pdf"))
    except OSError:
        return None
    if not files:
        return None
    # Only consider files of the same source — a CBK period must never be
    # matched against a KE-CIRT report just because a year matches.
    files = [f for f in files if _ke_file_kind(f) == kind]
    if not files:
        return None

    wanted = [t for t in _ke_tokens(key) if _ke_keep_token(t)]
    if not wanted:
        wanted = _ke_tokens(key)
    if not wanted:
        return None
    wanted_set = set(wanted)
    # Extra context (quarter/year) only breaks ties between files that match
    # the title equally well.
    extra_set = {t for t in _ke_tokens(extra) if _ke_keep_token(t)}

    best = None
    for path in files:
        stem_tokens = set(_ke_tokens(_ke_slug(path.stem)))
        hits = wanted_set & stem_tokens
        if not hits:
            continue
        score = len(hits)
        ratio = score / len(wanted_set)
        if score < 2 and len(wanted_set) > 1:
            continue
        if len(wanted_set) >= 3 and ratio < 0.3:
            continue
        extra_hits = len(extra_set & stem_tokens)
        candidate = (-score, -extra_hits, -ratio, len(path.name), path.name)
        if best is None or candidate < best[0]:
            best = (candidate, path)
    if not best:
        return None
    return best[1].name


def _ke_file_url(filename: str) -> str:
    return "/api/reports/download/" + quote(str(filename))


def _ke_report_url(kind: str, key: str, extra: str = "") -> str | None:
    """Resolve a stored report row to the download URL of its source PDF."""
    if not key:
        return None
    name = _ke_index_file(kind, key)
    if not name:
        name = _ke_match_file(kind, key, extra)
    if not name:
        return None
    return _ke_file_url(name)


def _ke_ca_file_url(title: str) -> str | None:
    return _ke_report_url("ca", title)


def _ke_cirt_file_url(title: str, quarter: str = "", year: int | str = "") -> str | None:
    extra = f"{quarter or ''} {year or ''}".strip()
    return _ke_report_url("ke_cirt", title, extra)


def _ke_cbk_file_url(period: str) -> str | None:
    return _ke_report_url("cbk", period)


@dashboard_bp.route("/api/reports/download/<path:filename>")
@require_login
def api_report_download(filename):
    """Serve a KE report file from the ke_reports dir (traversal-safe)."""
    from flask import send_from_directory
    from werkzeug.utils import secure_filename

    # Strip any directory component (both separators) before sanitising, then
    # confirm the resolved path really lives inside the reports dir.
    raw = str(filename or "").replace("\\", "/")
    name = raw.split("/")[-1]
    safe_name = secure_filename(name)
    if not safe_name:
        return jsonify({"error": "File not found"}), 404
    try:
        root = KE_REPORTS_DIR.resolve()
        target = (KE_REPORTS_DIR / safe_name).resolve()
    except OSError:
        return jsonify({"error": "File not found"}), 404
    if target != root and root not in target.parents:
        return jsonify({"error": "File not found"}), 404
    if not target.is_file():
        return jsonify({"error": "File not found"}), 404
    return send_from_directory(str(KE_REPORTS_DIR), safe_name, as_attachment=False)


def _ke_repo_root() -> Path:
    """Locate the repo root (the folder holding scripts/load_ke_reports.py)."""
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "scripts" / "load_ke_reports.py").is_file():
            return candidate
    return here.parents[3] if len(here.parents) > 3 else here.parent


@dashboard_bp.route("/api/reports/upload", methods=["POST"])
@require_admin
def api_report_upload():
    """Upload a KE report PDF, store it in ke_reports and parse it immediately."""
    import subprocess
    import sys

    from werkzeug.utils import secure_filename

    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"ok": False, "error": "No file provided"}), 400

    kind = _ke_report_kind(request.form.get("source") or request.form.get("kind") or "")
    if not kind:
        return jsonify(
            {"ok": False, "error": "Unknown source. Choose KE-CIRT/CC, CA Kenya or CBK."}
        ), 400

    original = str(file.filename).replace("\\", "/").split("/")[-1]
    safe_name = secure_filename(original)
    if not safe_name.lower().endswith(".pdf"):
        return jsonify({"ok": False, "error": "Only PDF files are accepted"}), 400

    if not _ke_reports_dir_ready():
        return jsonify(
            {
                "ok": False,
                "error": f"The reports directory ({KE_REPORTS_DIR}) is not writable by the server.",
            }
        ), 503

    stem = safe_name[: -len(".pdf")] or "report"
    candidate = KE_REPORTS_DIR / f"{KE_REPORT_KINDS[kind]}{stem}.pdf"
    counter = 2
    while candidate.exists():
        candidate = KE_REPORTS_DIR / f"{KE_REPORT_KINDS[kind]}{stem}_{counter}.pdf"
        counter += 1

    try:
        file.save(str(candidate))
    except OSError as exc:
        logger.error("KE report upload failed for %s: %s", safe_name, exc)
        return jsonify({"ok": False, "error": "Could not save the uploaded file."}), 500

    try:
        size = candidate.stat().st_size
        with open(candidate, "rb") as fh:
            head = fh.read(5)
    except OSError as exc:
        logger.error("KE report upload failed for %s: %s", safe_name, exc)
        candidate.unlink(missing_ok=True)
        return jsonify({"ok": False, "error": "Could not read the uploaded file."}), 500

    if size > KE_REPORT_MAX_BYTES:
        candidate.unlink(missing_ok=True)
        return jsonify(
            {"ok": False, "error": f"File is too large (max {KE_REPORT_MAX_BYTES // (1024 * 1024)} MB)."}
        ), 413
    if head != b"%PDF-":
        candidate.unlink(missing_ok=True)
        return jsonify({"ok": False, "error": "File is not a valid PDF."}), 400

    # Parse the new file straight away so it shows up on the dashboard.
    repo_root = _ke_repo_root()
    loader = repo_root / "scripts" / "load_ke_reports.py"
    if not loader.is_file():
        logger.warning("KE report loader not found at %s", loader)
        return jsonify(
            {
                "ok": False,
                "file": candidate.name,
                "url": _ke_file_url(candidate.name),
                "error": (
                    f"{candidate.name} was saved but the loader script is missing "
                    f"({loader}). Run scripts/load_ke_reports.py manually."
                ),
            }
        ), 500

    cmd = [
        sys.executable,
        "-m",
        "scripts.load_ke_reports",
        "--reports-dir",
        str(KE_REPORTS_DIR),
        "--only-file",
        candidate.name,
        "--kind",
        kind,
    ]
    env = os.environ.copy()
    src_dir = str(repo_root / "src")
    env["PYTHONPATH"] = os.pathsep.join(p for p in (src_dir, env.get("PYTHONPATH", "")) if p)

    stdout = ""
    stderr = ""
    returncode = -1
    try:
        result = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        returncode = result.returncode
    except subprocess.TimeoutExpired:
        stderr = "parsing timed out"
    except Exception as exc:  # noqa: BLE001 - never leak a stack trace to the client
        logger.error("load_ke_reports invocation failed: %s", exc)
        stderr = str(exc)

    logger.info("load_ke_reports (%s): rc=%s out=%s", candidate.name, returncode, stdout[-400:])

    summary = {}
    for line in stdout.splitlines():
        if line.startswith("SUMMARY_JSON "):
            try:
                summary = json.loads(line[len("SUMMARY_JSON "):])
            except ValueError:
                summary = {}
    inserted = summary.get("inserted", {}) if isinstance(summary, dict) else {}

    if returncode != 0:
        return jsonify(
            {
                "ok": False,
                "file": candidate.name,
                "url": _ke_file_url(candidate.name),
                "error": f"Saved {candidate.name} but parsing failed. {stderr[-300:]}".strip(),
            }
        ), 500

    _ke_invalidate_index()
    total = sum(int(v or 0) for v in (inserted or {}).values()) if isinstance(inserted, dict) else 0
    message = f"{candidate.name} uploaded"
    message += " and parsed." if total else " (already loaded — no new rows)."
    return jsonify(
        {
            "ok": True,
            "file": candidate.name,
            "url": _ke_file_url(candidate.name),
            "inserted": inserted,
            "message": message,
        }
    )


# ── Investigations API ─────────────────────────────────────────────────────────


@dashboard_bp.route("/api/investigations", methods=["GET"])
@require_login
def api_investigations_list():
    storage = get_storage()
    return jsonify(storage.get_investigations(limit=50))


@dashboard_bp.route("/api/investigations", methods=["POST"])
@require_login
def api_investigations_create():
    import asyncio

    from ..investigations import run_investigation

    body = request.get_json()
    name = (body.get("name") or "").strip()
    targets = body.get("targets") or []

    if not name:
        return jsonify({"error": "Investigation name required"}), 400
    if not targets:
        return jsonify({"error": "At least one target required"}), 400

    # Validate targets
    valid = []
    for t in targets:
        val = (t.get("value") or "").strip()
        ttype = (t.get("type") or "keyword").strip()
        if val and ttype in ("email", "name", "keyword"):
            valid.append({"value": val, "type": ttype})

    if not valid:
        return jsonify({"error": "No valid targets provided"}), 400

    storage = get_storage()
    api_key = os.getenv("HIBP_API_KEY", "")

    try:
        inv_id = asyncio.run(run_investigation(
            name=name,
            targets=valid,
            storage=storage,
            api_key=api_key,
        ))
        return jsonify({"ok": True, "id": inv_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/investigations/<int:inv_id>", methods=["GET"])
@require_login
def api_investigations_get(inv_id):
    storage = get_storage()
    targets = storage.get_investigation_targets(inv_id)
    investigations = storage.get_investigations(limit=50)
    inv = next((i for i in investigations if i["id"] == inv_id), None)
    if not inv:
        return jsonify({"error": "Not found"}), 404
    return jsonify({**inv, "targets": targets})


@dashboard_bp.route("/api/investigations/<int:inv_id>", methods=["DELETE"])
@require_login
def api_investigations_delete(inv_id):
    storage = get_storage()
    storage.delete_investigation(inv_id)
    return jsonify({"ok": True})


# ── IP Investigation API ───────────────────────────────────────────────────────


@dashboard_bp.route("/api/ip-investigations", methods=["GET"])
@require_login
def api_ip_investigations_list():
    storage = get_storage()
    return jsonify(storage.get_ip_investigations(limit=50))


@dashboard_bp.route("/api/ip-investigations", methods=["POST"])
@require_login
def api_ip_investigations_create():
    import re

    from ..ip_lookup import investigate_ip

    body = request.get_json()
    ip = (body.get("ip") or "").strip()

    ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    ipv6 = re.compile(r"^[0-9a-fA-F:]+$")
    if not ip or (not ipv4.match(ip) and not ipv6.match(ip)):
        return jsonify({"error": "Invalid IP address"}), 400

    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    if not abuse_key and not vt_key:
        return jsonify({"error": "No API keys configured. Add ABUSEIPDB_API_KEY and/or VIRUSTOTAL_API_KEY to .env"}), 400

    storage = get_storage()
    try:
        result = investigate_ip(ip, abuse_key, vt_key)
        inv_id = storage.save_ip_investigation(
            ip=ip,
            abuseipdb_data=result.get("abuseipdb") or {},
            virustotal_data=result.get("virustotal") or {},
        )
        return jsonify({"ok": True, "id": inv_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/ip-investigations/<int:inv_id>", methods=["GET"])
@require_login
def api_ip_investigations_get(inv_id):
    storage = get_storage()
    data = storage.get_ip_investigation(inv_id)
    if not data:
        return jsonify({"error": "Not found"}), 404
    return jsonify(data)


@dashboard_bp.route("/api/ip-investigations/<int:inv_id>", methods=["DELETE"])
@require_login
def api_ip_investigations_delete(inv_id):
    storage = get_storage()
    storage.delete_ip_investigation(inv_id)
    return jsonify({"ok": True})

# ── Ransomware Tracker API ─────────────────────────────────────────────────────


@dashboard_bp.route("/api/ransomware/groups", methods=["GET"])
@require_login
def api_ransomware_groups():
    from ..ransomware_data import RANSOMWARE_GROUPS
    storage = get_storage()
    # Merge static + custom entries
    custom = storage.get_custom_intel("ransomware")
    static_slugs = {g["slug"] for g in RANSOMWARE_GROUPS}
    all_groups = list(RANSOMWARE_GROUPS) + [g for g in custom if g["slug"] not in static_slugs]

    # Bulk-fetch hits and last-seen dates for every keyword in one query each
    # instead of issuing one query per keyword per group.
    all_keywords = list({kw for g in all_groups for kw in g.get("keywords", [])})
    hits_by_kw = storage.get_hits_by_keywords(all_keywords, limit_per_keyword=5)
    last_date_by_kw = storage.get_last_hit_dates_bulk(all_keywords)

    enriched = []
    for group in all_groups:
        keywords = group.get("keywords", [])
        recent_hits = []
        for kw in keywords:
            for h in hits_by_kw.get(kw, []):
                recent_hits.append({
                    "keyword": h.keyword,
                    "url": h.url,
                    "found_at": h.found_at.isoformat() if h.found_at else None,
                    "context": (h.context or "")[:200],
                })
        dates = [last_date_by_kw[kw] for kw in keywords if kw in last_date_by_kw]
        enriched.append({
            **group,
            "hit_count": sum(len(hits_by_kw.get(kw, [])) for kw in keywords),
            "recent_hits": recent_hits[:10],
            "last_seen": max(dates) if dates else None,
            "is_custom": group.get("slug") not in static_slugs,
        })
    enriched.sort(key=lambda g: (
        g["status"] != "active",
        not g["targeting_sea"],
        -g["hit_count"],
    ))
    return jsonify(enriched)


@dashboard_bp.route("/api/ransomware/groups", methods=["POST"])
@require_admin
def api_ransomware_groups_add():
    from ..ransomware_data import RANSOMWARE_GROUPS
    storage = get_storage()
    body = request.get_json() or {}
    required = ["name", "slug", "origin", "status", "risk_level", "description"]
    for field in required:
        if not body.get(field):
            return jsonify({"error": f"'{field}' is required"}), 400
    # Prevent slug collision with static data
    static_slugs = {g["slug"] for g in RANSOMWARE_GROUPS}
    if body["slug"] in static_slugs:
        return jsonify({"error": "Slug already exists in static data"}), 409
    entry = {
        "name": body["name"],
        "slug": body["slug"],
        "status": body["status"],
        "origin": body["origin"],
        "first_seen": body.get("first_seen", ""),
        "targeting_sea": bool(body.get("targeting_sea", False)),
        "risk_level": body["risk_level"],
        "description": body["description"],
        "ttps": [t.strip() for t in body.get("ttps", "").split(",") if t.strip()],
        "keywords": [k.strip() for k in body.get("keywords", "").split(",") if k.strip()],
        "onion_seeds": [u.strip() for u in body.get("onion_seeds", "").split("\n") if u.strip()],
        "sea_victims": [v.strip() for v in body.get("sea_victims", "").split(",") if v.strip()],
    }
    username = session.get("username", "admin")
    ok = storage.add_custom_intel("ransomware", entry["slug"], entry, created_by=username)
    if not ok:
        return jsonify({"error": "Slug already exists"}), 409
    return jsonify({"ok": True})


@dashboard_bp.route("/api/ransomware/groups/<slug>", methods=["DELETE"])
@require_admin
def api_ransomware_groups_delete(slug):
    from ..ransomware_data import RANSOMWARE_GROUPS
    static_slugs = {g["slug"] for g in RANSOMWARE_GROUPS}
    if slug in static_slugs:
        return jsonify({"error": "Cannot delete built-in entries"}), 403
    storage = get_storage()
    ok = storage.delete_custom_intel(slug)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


@dashboard_bp.route("/api/ransomware/add-seeds", methods=["POST"])
@require_admin
def api_ransomware_add_seeds():
    """Add all known ransomware .onion URLs to the seed list."""
    from ..ransomware_data import RANSOMWARE_ONION_SEEDS
    _ensure_data_dir()
    existing = _load_seeds()
    added = 0
    for url in RANSOMWARE_ONION_SEEDS:
        if url not in existing:
            existing.append(url)
            added += 1
    SEEDS_FILE.write_text("\n".join(existing) + "\n")
    return jsonify({"ok": True, "added": added, "total": len(RANSOMWARE_ONION_SEEDS)})


@dashboard_bp.route("/api/ransomware/add-keywords", methods=["POST"])
@require_admin
def api_ransomware_add_keywords():
    """Add all ransomware group names as keywords."""
    from ..ransomware_data import RANSOMWARE_GROUPS
    rows = []
    for group in RANSOMWARE_GROUPS:
        for kw in group.get("keywords", []):
            rows.append({"keyword": kw, "category": "ransomware", "severity": "high"})
    added = _keyword_store().add_keywords(rows)
    return jsonify({"ok": True, "added": added})


# ── Threat Actors API ──────────────────────────────────────────────────────────


@dashboard_bp.route("/api/threat-actors", methods=["GET"])
@require_login
def api_threat_actors():
    from ..threat_actors import THREAT_ACTORS
    storage = get_storage()
    custom = storage.get_custom_intel("threat-actor")
    static_slugs = {a["slug"] for a in THREAT_ACTORS}
    all_actors = list(THREAT_ACTORS) + [a for a in custom if a["slug"] not in static_slugs]

    # Bulk-fetch recent hits / last-seen dates for every keyword (used for
    # recent_hits and last_seen only). The authoritative per-actor hit count is
    # derived from paste_hits.group_name / context / matched_value below.
    all_keywords = list({kw for a in all_actors for kw in a.get("keywords", [])})
    hits_by_kw = storage.get_hits_by_keywords(all_keywords, limit_per_keyword=5)
    last_date_by_kw = storage.get_last_hit_dates_bulk(all_keywords)

    # Paste-hit aggregation removed; hit counts are derived from keyword hits.

    def _actor_match_terms(actor: dict) -> set[str]:
        terms: set[str] = set()
        name = (actor.get("name") or "").strip()
        if name:
            terms.add(name.lower())
        for al in (actor.get("aliases") or []):
            al = (al or "").strip()
            if al:
                terms.add(al.lower())
        for kw in (actor.get("keywords") or []):
            kw = (kw or "").strip()
            if kw:
                terms.add(kw.lower())
        terms.discard("")
        return terms

    [(a, _actor_match_terms(a)) for a in all_actors]
    hit_count_by_slug = {a["slug"]: sum(len(hits_by_kw.get(kw, [])) for kw in a.get("keywords", [])) for a in all_actors}

    enriched = []
    for actor in all_actors:
        keywords = actor.get("keywords", [])
        recent_hits = []
        for kw in keywords:
            for h in hits_by_kw.get(kw, []):
                recent_hits.append({
                    "keyword": h.keyword,
                    "url": h.url,
                    "found_at": h.found_at.isoformat() if h.found_at else None,
                    "context": (h.context or "")[:200],
                })
        dates = [last_date_by_kw[kw] for kw in keywords if kw in last_date_by_kw]
        enriched.append({
            **actor,
            "hit_count": hit_count_by_slug[actor["slug"]],
            "recent_hits": recent_hits[:10],
            "last_seen": max(dates) if dates else None,
            "is_custom": actor.get("slug") not in static_slugs,
        })
    enriched.sort(key=lambda a: (
        a["risk_level"] not in ("critical", "high"),
        not a["targeting_sea"],
        -a["hit_count"],
    ))
    return jsonify(enriched)


@dashboard_bp.route("/api/threat-actors", methods=["POST"])
@require_admin
def api_threat_actors_add():
    from ..threat_actors import THREAT_ACTORS
    storage = get_storage()
    body = request.get_json() or {}
    required = ["name", "slug", "origin", "type", "status", "risk_level", "description"]
    for field in required:
        if not body.get(field):
            return jsonify({"error": f"'{field}' is required"}), 400
    static_slugs = {a["slug"] for a in THREAT_ACTORS}
    if body["slug"] in static_slugs:
        return jsonify({"error": "Slug already exists in static data"}), 409
    entry = {
        "name": body["name"],
        "slug": body["slug"],
        "type": body["type"],
        "status": body["status"],
        "origin": body["origin"],
        "first_seen": body.get("first_seen", ""),
        "targeting_sea": bool(body.get("targeting_sea", False)),
        "risk_level": body["risk_level"],
        "description": body["description"],
        "aliases": [a.strip() for a in body.get("aliases", "").split(",") if a.strip()],
        "sectors": [s.strip() for s in body.get("sectors", "").split(",") if s.strip()],
        "countries_targeted": [c.strip() for c in body.get("countries_targeted", "").split(",") if c.strip()],
        "ttps": [t.strip() for t in body.get("ttps", "").split(",") if t.strip()],
        "known_malware": [m.strip() for m in body.get("known_malware", "").split(",") if m.strip()],
        "keywords": [k.strip() for k in body.get("keywords", "").split(",") if k.strip()],
    }
    username = session.get("username", "admin")
    ok = storage.add_custom_intel("threat-actor", entry["slug"], entry, created_by=username)
    if not ok:
        return jsonify({"error": "Slug already exists"}), 409
    return jsonify({"ok": True})


@dashboard_bp.route("/api/threat-actors/<slug>", methods=["DELETE"])
@require_admin
def api_threat_actors_delete(slug):
    from ..threat_actors import THREAT_ACTORS
    static_slugs = {a["slug"] for a in THREAT_ACTORS}
    if slug in static_slugs:
        return jsonify({"error": "Cannot delete built-in entries"}), 403
    storage = get_storage()
    ok = storage.delete_custom_intel(slug)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


@dashboard_bp.route("/api/threat-actors/add-keywords", methods=["POST"])
@require_admin
def api_threat_actors_add_keywords():
    """Add all threat actor names as keywords."""
    from ..threat_actors import THREAT_ACTORS
    rows = []
    for actor in THREAT_ACTORS:
        for kw in actor.get("keywords", []):
            rows.append({"keyword": kw, "category": "threat-actors", "severity": "high"})
    added = _keyword_store().add_keywords(rows)
    return jsonify({"ok": True, "added": added})


# ── Digest / Mailing List API ──────────────────────────────────────────────────


@dashboard_bp.route("/api/digest/subscribers", methods=["GET"])
@require_admin
def api_digest_subscribers_get():
    from ..digest import load_subscribers
    return jsonify({"subscribers": load_subscribers()})


@dashboard_bp.route("/api/digest/subscribers", methods=["POST"])
@require_admin
def api_digest_subscribers_add():
    from ..digest import add_subscriber
    body = request.get_json()
    email = (body.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"error": "valid email required"}), 400
    added = add_subscriber(email)
    return jsonify({"ok": True, "added": added})


@dashboard_bp.route("/api/digest/subscribers", methods=["DELETE"])
@require_admin
def api_digest_subscribers_remove():
    from ..digest import remove_subscriber
    body = request.get_json()
    email = (body.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400
    remove_subscriber(email)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/digest/send", methods=["POST"])
@require_admin
def api_digest_send():
    from ..digest import send_digest
    body = request.get_json() or {}
    # Optional: send to specific emails instead of subscriber list
    recipients = body.get("recipients") or None
    storage = get_storage()
    result = send_digest(storage, recipients=recipients)
    if result["ok"]:
        return jsonify(result)
    return jsonify(result), 500


@dashboard_bp.route("/api/digest/preview", methods=["GET"])
@require_login
def api_digest_preview():
    """Download a preview of the digest PDF without sending."""
    from ..digest import build_digest_pdf
    from ..feeds import fetch_all_feeds
    storage = get_storage()
    try:
        feed_data = fetch_all_feeds()
        stats = storage.get_stats()
        top_kw = stats.get("top_keywords", [{}])
        scanner_summary = {
            "total_hits": stats.get("total_hits", 0),
            "total_pages": stats.get("total_pages", 0),
            "total_sessions": stats.get("total_sessions", 0),
            "top_keyword": top_kw[0].get("keyword", "—") if top_kw else "—",
        }
        pdf = build_digest_pdf(feed_data, scanner_summary=scanner_summary)
        from datetime import datetime as dt
        filename = f"digest-preview-{dt.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d')}.pdf"
        return Response(
            pdf,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@dashboard_bp.route("/api/digest/feeds", methods=["GET"])
@require_login
def api_digest_feeds():
    """Preview feed data without building PDF."""
    from ..feeds import fetch_all_feeds
    try:
        data = fetch_all_feeds()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/digest/subscribe", methods=["POST"])
def api_public_subscribe():
    """Public endpoint — no auth required. For static website subscribe form."""
    from ..digest import add_subscriber
    body = request.get_json() or {}
    email = (body.get("email") or "").strip().lower()
    name = (body.get("name") or "").strip()[:100]
    org = (body.get("org") or "").strip()[:200]
    # Honeypot
    if body.get("website"):
        return jsonify({"ok": True})  # silently drop bots
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "Valid email required"}), 400
    added = add_subscriber(email, name=name, org=org)
    return jsonify({"ok": True, "new": added})


# ── DNS Crawler API ────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/dns/investigations", methods=["GET"])
@require_login
def api_dns_list():
    storage = get_storage()
    return jsonify(storage.get_dns_investigations(limit=100))


@dashboard_bp.route("/api/dns/investigate", methods=["POST"])
@require_login
def api_dns_start():
    """Start a DNS investigation — runs in background thread."""
    import threading

    from ..dns_crawler import run_dns_recon

    body = request.get_json() or {}
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    # Basic sanity check
    if len(domain) > 253 or " " in domain:
        return jsonify({"error": "invalid domain"}), 400

    storage = get_storage()
    inv_id = storage.create_dns_investigation(domain)

    def run():
        try:
            result = run_dns_recon(domain)
            storage.complete_dns_investigation(inv_id, result)
        except Exception as e:
            import traceback
            storage.fail_dns_investigation(inv_id, str(e))
            print(f"DNS investigation {inv_id} failed: {traceback.format_exc()}", flush=True)

    t = threading.Thread(target=run, daemon=True)
    t.start()

    return jsonify({"ok": True, "id": inv_id, "domain": domain})


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>", methods=["GET"])
@require_login
def api_dns_get(inv_id: int):
    storage = get_storage()
    result = storage.get_dns_investigation(inv_id)
    if not result:
        return jsonify({"error": "not found"}), 404
    return jsonify(result)


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>", methods=["DELETE"])
@require_login
def api_dns_delete(inv_id: int):
    storage = get_storage()
    storage.delete_dns_investigation(inv_id)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>/enrich", methods=["POST"])
@require_login
def api_dns_enrich(inv_id: int):
    """
    Fetch DNSDumpster data for this investigation and merge it into the stored result.
    Deduplicates subdomains and adds dnsdumpster_data to the result JSON.
    Requires DNSDUMPSTER_API_KEY env var.
    """
    import json as _json

    storage = get_storage()
    inv = storage.get_dns_investigation(inv_id)
    if not inv:
        return jsonify({"error": "not found"}), 404

    api_key = os.getenv("DNSDUMPSTER_API_KEY", "").strip()
    if not api_key:
        return jsonify({"error": "DNSDUMPSTER_API_KEY not configured"}), 500

    domain = inv["domain"]

    # ── Call DNSDumpster API ──────────────────────────────────────────────────
    try:
        _dn = safe_fetch(
            f"https://api.dnsdumpster.com/domain/{domain}",
            headers={
                "X-API-Key": api_key,
                "Accept": "application/json",
                "User-Agent": "OSINTPH-DNSCrawler/1.0",
            },
            timeout=20,
        )
    except SafeFetchError as e:
        logger.warning("DNSDumpster safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    status, body = _dn["status"], _dn["body"]

    if status != 200:
        return jsonify({"error": f"DNSDumpster API returned {status}", "body": body[:200].decode("utf-8", errors="replace")}), 502

    try:
        dd_data = _json.loads(body)
    except Exception as e:
        return jsonify({"error": f"Failed to parse DNSDumpster response: {e}"}), 502

    # ── Merge into existing result ────────────────────────────────────────────
    result = inv.get("result", {})

    # Store raw DNSDumpster data
    result["dnsdumpster"] = dd_data

    # Extract subdomains from DNS Dumpster response
    # Their API returns: {dns_records: {host: [{host, ips, ttl, ...}]}, ...}
    dd_new_subs = set()
    dd_host_map = {}  # fqdn -> {ips, asn, country, ...}

    for rtype in ("a", "aaaa", "mx", "ns", "txt"):
        for rec in dd_data.get("dns_records", {}).get(rtype, []):
            host = rec.get("host", "").strip().lower().rstrip(".")
            if not host:
                continue
            if host.endswith(f".{domain}") or host == domain:
                dd_new_subs.add(host)
                dd_host_map[host] = {
                    "ips": [ip.get("address", ip) if isinstance(ip, dict) else ip
                            for ip in rec.get("ips", [])],
                    "asn": rec.get("asn", ""),
                    "country": rec.get("country", ""),
                    "reverse_dns": rec.get("reverse_dns", ""),
                }

    # Also pull from "hosts" key if present
    for rec in dd_data.get("hosts", []):
        host = rec.get("domain", "").strip().lower().rstrip(".")
        if host and (host.endswith(f".{domain}") or host == domain):
            dd_new_subs.add(host)
            dd_host_map.setdefault(host, {
                "ips": [ip.get("address", ip) if isinstance(ip, dict) else ip
                        for ip in rec.get("ips", [])],
                "asn": rec.get("asn", ""),
                "country": rec.get("country", ""),
            })

    # Merge into subdomains_resolved — deduplicate by subdomain name
    existing_subs = {s["subdomain"]: s for s in result.get("subdomains_resolved", [])}
    dd_count_new = 0
    for fqdn, info in dd_host_map.items():
        if fqdn not in existing_subs:
            existing_subs[fqdn] = {
                "subdomain": fqdn,
                "ips": info["ips"],
                "geo": [],
                "source": "dnsdumpster",
            }
            dd_count_new += 1
        else:
            # Tag existing entry as also seen by DNSDumpster
            existing_subs[fqdn]["source"] = existing_subs[fqdn].get("source", "passive") + "+dnsdumpster"
            # Merge any new IPs
            existing_ips = set(existing_subs[fqdn].get("ips", []))
            for ip in info["ips"]:
                if ip and ip not in existing_ips:
                    existing_subs[fqdn]["ips"].append(ip)

    result["subdomains_resolved"] = list(existing_subs.values())
    result["subdomain_count"] = len(existing_subs)
    result["resolved_count"] = len(result["subdomains_resolved"])
    result["dnsdumpster_enriched"] = True
    result["dnsdumpster_new_subs"] = dd_count_new

    # Persist updated result
    with storage.get_session() as db_session:
        from ..storage import DNSInvestigation
        row = db_session.get(DNSInvestigation, inv_id)
        if row:
            row.result_json = _json.dumps(result)
            row.subdomain_count = result["subdomain_count"]
            row.resolved_count = result["resolved_count"]
            db_session.commit()

    return jsonify({
        "ok": True,
        "new_subdomains": dd_count_new,
        "total_subdomains": result["subdomain_count"],
        "dnsdumpster_data": dd_data,
    })


# ── Port Scan & Directory Enumeration (async, Tor-proxied) ───────────────
@dashboard_bp.route("/api/dns/investigations/<int:inv_id>/scan", methods=["POST"])
@require_login
def api_dns_scan(inv_id: int):
    """Start port scan + directory enumeration for a DNS investigation target.

    Returns 202 Accepted with a task_id. The client polls
    GET /api/dns/investigations/{inv_id}/scan/status for completion.
    """

    from ..scan_engine import start_scan

    logger.info("[api_dns_scan] Starting scan for investigation %s", inv_id)

    storage = get_storage()
    inv = storage.get_dns_investigation(inv_id)
    if not inv:
        logger.warning("[api_dns_scan] Investigation %s not found", inv_id)
        return jsonify({"error": "investigation not found"}), 404

    body = request.get_json() or {}
    scan_ports = bool(body.get("scan_ports", True))
    scan_dirs = bool(body.get("scan_dirs", True))

    # Determine target: use the investigation domain (first resolved IP if available)
    target = inv.get("domain")
    if not target:
        logger.warning("[api_dns_scan] No target domain for investigation %s", inv_id)
        return jsonify({"error": "no target domain"}), 400

    logger.info("[api_dns_scan] Scanning target=%s ports=%s dirs=%s", target, scan_ports, scan_dirs)

    task_id = start_scan(target, scan_ports, scan_dirs)

    # Store task_id on the investigation so we can associate results later
    result = inv.get("result", {})
    result["scan_task_id"] = task_id
    with storage.get_session() as db_session:
        from ..storage import DNSInvestigation
        row = db_session.get(DNSInvestigation, inv_id)
        if row:
            row.result_json = json.dumps(result)
            db_session.commit()

    return jsonify({
        "ok": True,
        "task_id": task_id,
        "target": target,
        "status": "pending",
    }), 202


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>/scan/status", methods=["GET"])
@require_login
def api_dns_scan_status(inv_id: int):
    """Return the status/result of a background scan task."""
    from ..scan_engine import get_task

    logger.info("[api_dns_scan_status] Checking status for investigation %s", inv_id)

    storage = get_storage()
    inv = storage.get_dns_investigation(inv_id)
    if not inv:
        logger.warning("[api_dns_scan_status] Investigation %s not found", inv_id)
        return jsonify({"error": "investigation not found"}), 404

    result = inv.get("result", {})
    task_id = result.get("scan_task_id")
    if not task_id:
        logger.info("[api_dns_scan_status] No scan task for investigation %s", inv_id)
        return jsonify({"ready": False, "status": "not_started"}), 200

    task = get_task(task_id)
    if not task:
        logger.warning("[api_dns_scan_status] Task %s not found", task_id)
        return jsonify({"ready": False, "status": "unknown_task"}), 200

    ready = task["status"] in ("completed", "failed")
    resp = {
        "ready": ready,
        "status": task["status"],
        "task_id": task_id,
    }
    if task["status"] == "completed" and task.get("result"):
        logger.info("[api_dns_scan_status] Scan completed for investigation %s", inv_id)
        resp["result"] = task["result"]
        # Merge scan results into the investigation result_json
        merged = dict(result)
        merged["port_scan"] = task["result"].get("port_scan", {})
        merged["dir_enum"] = task["result"].get("dir_enum", {})
        with storage.get_session() as db_session:
            from ..storage import DNSInvestigation
            row = db_session.get(DNSInvestigation, inv_id)
            if row:
                row.result_json = json.dumps(merged)
                db_session.commit()
    elif task["status"] == "failed":
        logger.warning("[api_dns_scan_status] Scan failed for investigation %s: %s", inv_id, task.get("error", "unknown"))
        resp["error"] = task.get("error", "unknown error")

    return jsonify(resp), 200


# ── OSINT Enrichment API ──────────────────────────────────────────────────────
@dashboard_bp.route("/api/dns/investigations/<int:inv_id>/osint", methods=["GET"])
@require_login
def api_dns_osint(inv_id: int):
    """Enrich a DNS investigation with OSINT data from Shodan and URLScan."""
    import traceback

    from flask import jsonify

    storage = get_storage()
    inv = storage.get_dns_investigation(inv_id)
    if not inv:
        return jsonify({"error": "investigation not found"}), 404

    result = inv.get("result", {})
    domain = inv.get("domain", "")
    dns = result.get("dns_records", {})
    ips = dns.get("A", []) + dns.get("AAAA", [])

    try:
        from darkweb_scanner.scrapers.osint_enrichment import enrich_dns_with_osint
        osint_data = enrich_dns_with_osint(domain, ips)
        # Merge into result
        result["osint"] = osint_data
        with storage.get_session() as db_session:
            from darkweb_scanner.storage import DNSInvestigation
            row = db_session.get(DNSInvestigation, inv_id)
            if row:
                import json as _json
                row.result_json = _json.dumps(result)
                db_session.commit()
        return jsonify({"ok": True, "osint": osint_data})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route("/api/dns/certs/<path:domain>", methods=["GET"], strict_slashes=False)
@require_login
def api_dns_certs(domain: str):
    """
    Fetch full certificate transparency history from crt.sh for a domain.
    Returns rich cert data: issuer, validity, SANs, grouped by cert.
    """
    import json as _json

    domain = domain.strip().lower().split("/")[0]

    # Query crt.sh — use the deduplicated JSON endpoint
    try:
        _result = safe_fetch(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers={"User-Agent": "OSINTPH-DNSCrawler/1.0", "Accept": "application/json"},
            timeout=30,
        )
    except SafeFetchError as e:
        logger.warning("crt.sh safe_fetch blocked: %s", e)
        return jsonify({"error": "Certificate transparency lookup failed."}), 502

    if _result["status"] != 200:
        return jsonify({"error": f"crt.sh returned HTTP {_result['status']}"}), 502

    try:
        raw = _json.loads(_result["body"])
    except Exception:
        preview = _result["body"][:120].decode("utf-8", errors="replace")
        return jsonify({"error": f"crt.sh returned non-JSON: {preview}"}), 502

    from datetime import datetime as dt
    now = dt.now(timezone.utc).replace(tzinfo=None)

    certs = []
    seen_ids = set()

    for entry in raw:
        cid = entry.get("id")
        if cid in seen_ids:
            continue
        seen_ids.add(cid)

        # Parse dates — crt.sh uses both "2024-01-01T00:00:00" and "2024-01-01" formats
        not_before_str = entry.get("not_before", "")
        not_after_str = entry.get("not_after", "")
        not_before = None
        not_after = None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                not_before = dt.strptime(not_before_str[:19], fmt[:len(not_before_str[:19])])
                break
            except Exception:
                pass
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                not_after = dt.strptime(not_after_str[:19], fmt[:len(not_after_str[:19])])
                break
            except Exception:
                pass

        is_expired = (not_after < now) if not_after else False
        days_remaining = (not_after - now).days if (not_after and not is_expired) else None
        expiring_soon = days_remaining is not None and days_remaining <= 30

        # SANs from name_value
        sans = sorted(set(
            n.strip().lower()
            for n in entry.get("name_value", "").split("\n")
            if n.strip()
        ))

        # Issuer parsing
        issuer_raw = entry.get("issuer_name", "")
        issuer_cn = ""
        issuer_org = ""
        for part in issuer_raw.split(","):
            part = part.strip()
            if part.startswith("CN="):
                issuer_cn = part[3:].strip()
            elif part.startswith("O="):
                issuer_org = part[2:].strip()

        certs.append({
            "id": cid,
            "serial": entry.get("serial_number", ""),
            "issuer_cn": issuer_cn,
            "issuer_org": issuer_org,
            "issuer_raw": issuer_raw,
            "not_before": not_before_str,
            "not_after": not_after_str,
            "not_before_ts": int(not_before.timestamp()) if not_before else 0,
            "not_after_ts": int(not_after.timestamp()) if not_after else 0,
            "is_expired": is_expired,
            "expiring_soon": expiring_soon,
            "days_remaining": days_remaining,
            "sans": sans,
            "san_count": len(sans),
        })

    # Sort newest first
    certs.sort(key=lambda c: c.get("not_before_ts", 0), reverse=True)

    # Build summary stats
    total = len(certs)
    expired = sum(1 for c in certs if c["is_expired"])
    expiring_soon_count = sum(1 for c in certs if c.get("expiring_soon"))
    all_sans = sorted(set(s for c in certs for s in c["sans"]))

    # Issuer breakdown
    from collections import Counter
    issuer_counts = Counter(c["issuer_org"] or c["issuer_cn"] for c in certs)

    return jsonify({
        "domain": domain,
        "total": total,
        "expired": expired,
        "expiring_soon": expiring_soon_count,
        "active": total - expired,
        "unique_sans": len(all_sans),
        "all_sans": all_sans,
        "issuers": dict(issuer_counts.most_common(10)),
        "certs": certs,
    })


@dashboard_bp.route("/api/dns/investigations/<int:inv_id>/pdf", methods=["GET"])
@require_login
def api_dns_pdf(inv_id: int):
    """Export DNS investigation as a rich PDF report — DNSDumpster-inspired layout."""
    from collections import Counter
    from datetime import datetime as dt
    from io import BytesIO

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.style.use('dark_background')
    import math

    import matplotlib.patches as mpatches
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        Image,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    storage = get_storage()
    inv = storage.get_dns_investigation(inv_id)
    if not inv:
        return jsonify({"error": "not found"}), 404
    if inv["status"] != "complete":
        return jsonify({"error": "investigation not complete yet"}), 400

    r = inv.get("result", {})
    domain = inv["domain"]
    created = inv.get("created_at", "")[:16].replace("T", " ")
    dns = r.get("dns_records", {})
    zt = r.get("zone_transfer", {})
    email_sec = r.get("email_security", {})
    resolved = r.get("subdomains_resolved", [])
    passive = r.get("subdomains_passive", [])
    bruteforce = r.get("subdomains_bruteforce", [])
    ip_geo = r.get("ip_geo", {})
    ptr = r.get("ptr_records", {})
    port_scan = r.get("port_scan", {})
    dir_enum = r.get("dir_enum", {})
    zt_success = any(v.get("success") for v in zt.values() if isinstance(v, dict))
    main_ips = dns.get("A", []) + dns.get("AAAA", [])

    # ── Colour palette ──
    C_BG      = colors.HexColor("#0d1117")
    C_SURFACE = colors.HexColor("#161b22")
    C_BORDER  = colors.HexColor("#30363d")
    C_TEXT    = colors.HexColor("#e6edf3")
    C_MUTED   = colors.HexColor("#8b949e")
    C_ACCENT  = colors.HexColor("#58a6ff")
    C_RED     = colors.HexColor("#f85149")
    C_GREEN   = colors.HexColor("#3fb950")
    C_YELLOW  = colors.HexColor("#d29922")

    buf = BytesIO()
    W, H = A4
    M = 15 * mm
    def dark_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#0d1117"))
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=M, rightMargin=M,
                            topMargin=M, bottomMargin=M)
    PW = W - 2 * M
    styles = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, parent=styles["Normal"], **kw)

    s_h1    = S("h1",    fontSize=22, fontName="Helvetica-Bold",   textColor=C_TEXT,   leading=26, spaceAfter=2)
    s_body  = S("body",  fontSize=8,  textColor=C_TEXT,   leading=12)
    s_small = S("small", fontSize=7,  textColor=C_MUTED,  leading=10)
    s_mono  = S("mono",  fontSize=7,  fontName="Courier", textColor=C_ACCENT, leading=10, wordWrap="CJK")
    s_warn  = S("warn",  fontSize=8,  fontName="Helvetica-Bold", textColor=C_RED, leading=12)
    s_foot  = S("foot",  fontSize=6.5, textColor=C_MUTED, leading=10)

    story = []

    # ── helpers ──────────────────────────────────────────────────────────────

    def dark_table(headers, rows, col_widths, row_colors=None):
        """Build a dark-themed table. headers = list of cells, rows = list of row lists."""
        data = [headers] + rows
        tbl = Table(data, colWidths=col_widths, repeatRows=1)
        row_bg = row_colors or [C_SURFACE, C_BG]
        cmds = [
            ("BACKGROUND",  (0, 0), (-1, 0),  C_BG),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  C_TEXT),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), row_bg),
            ("GRID",        (0, 0), (-1, -1), 0.3, C_BORDER),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0,0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",(0, 0), (-1, -1), 6),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ]
        tbl.setStyle(TableStyle(cmds))
        return tbl

    def section_header(title, color=None):
        story.append(Spacer(1, 6))
        story.append(HRFlowable(width=PW, thickness=1, color=color or C_BORDER, spaceAfter=4))
        story.append(Paragraph(title, S(f"sh_{title[:6]}", fontSize=10, fontName="Helvetica-Bold",
                     textColor=color or C_ACCENT, leading=14, spaceBefore=4, spaceAfter=3)))

    def badge(text, bg="#161b22", fg="#e6edf3"):
        return Paragraph(f'<font color="{fg}"><b>{text}</b></font>',
                         S(f"bd_{text[:4]}", fontSize=7, backColor=colors.HexColor(bg),
                           borderPadding=(2,5,2,5), leading=10))

    def geo_str(geo_list):
        if not geo_list:
            return ""
        parts = [f"{g.get('city','')} {g.get('countryCode','')}" for g in (geo_list if isinstance(geo_list, list) else [geo_list]) if g and g.get("country")]
        return " / ".join(p.strip() for p in parts if p.strip())

    def get_port_service_name(port_num: str) -> str:
        svc = {
            '21':'FTP','22':'SSH','23':'Telnet','25':'SMTP','53':'DNS','80':'HTTP',
            '110':'POP3','111':'RPC','135':'MSRPC','139':'NetBIOS','143':'IMAP',
            '443':'HTTPS','445':'SMB','993':'IMAPS','995':'POP3S','1723':'PPTP',
            '3306':'MySQL','3389':'RDP','5900':'VNC','8080':'HTTP-Proxy','8443':'HTTPS-Alt'
        }
        return svc.get(str(port_num), 'unknown')

    # ── ASN / hosting breakdown ───────────────────────────────────────────────
    asn_counter = Counter()
    org_counter = Counter()
    country_counter = Counter()
    cc_counter = Counter()   # ISO 2-letter codes for map
    cc_names   = {}          # cc -> full country name
    for sub in resolved:
        for g in (sub.get("geo") or []):
            if g and g.get("as"):
                asn_counter[g["as"]] += 1
            if g and g.get("org"):
                org_counter[g["org"]] += 1
            if g and g.get("country"):
                country_counter[g["country"]] += 1
            if g and g.get("countryCode"):
                cc = g["countryCode"].upper()
                cc_counter[cc] += 1
                cc_names[cc] = g.get("country", cc)

    # ── matplotlib helpers ────────────────────────────────────────────────────

    def fig_to_image(fig, width_mm=None):
        """Convert a matplotlib figure to a ReportLab Image."""
        img_buf = BytesIO()
        fig.savefig(img_buf, format="png", dpi=150, bbox_inches="tight",
                    facecolor="#161b22")
        img_buf.seek(0)
        plt.close(fig)
        from reportlab.lib.utils import ImageReader
        ir = ImageReader(img_buf)
        iw, ih = ir.getSize()
        ratio = ih / iw
        w = (width_mm or 170) * mm
        return Image(img_buf, width=w, height=w * ratio)

    # ── GRAPH: subdomain node diagram ─────────────────────────────────────────
    def build_graph_image():
        all_subs = {s["subdomain"]: s for s in resolved}
        for b in bruteforce:
            if b["subdomain"] not in all_subs:
                all_subs[b["subdomain"]] = b

        nodes = {}   # id -> (x, y, label, color, size)
        edges = []

        # Root
        nodes["root"] = (0, 0, domain, "#f85149", 400)

        sub_list = list(all_subs.values())[:60]
        n = len(sub_list)
        for i, s in enumerate(sub_list):
            angle = 2 * math.pi * i / max(n, 1)
            radius = 2.2
            sx = radius * math.cos(angle)
            sy = radius * math.sin(angle)
            is_brute = s["subdomain"] in {b["subdomain"] for b in bruteforce}
            col = "#bc8cff" if is_brute else "#58a6ff"
            label = s["subdomain"].replace("." + domain, "")
            sid = f"s{i}"
            nodes[sid] = (sx, sy, label, col, 120)
            edges.append(("root", sid))

            for j, ip in enumerate((s.get("ips") or [])[:2]):
                ip_id = f"ip_{ip.replace('.','_').replace(':','_')}"
                if ip_id not in nodes:
                    ia = angle + (j - 0.5) * 0.35
                    ir = radius + 1.1
                    nodes[ip_id] = (ir * math.cos(ia), ir * math.sin(ia), ip, "#3fb950", 60)
                edges.append((sid, ip_id))

        fig, ax = plt.subplots(figsize=(10, 7))
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#0d1117")
        ax.axis("off")

        # Draw edges
        for (a, b_) in edges:
            if a in nodes and b_ in nodes:
                x1, y1 = nodes[a][:2]
                x2, y2 = nodes[b_][:2]
                col = "#3fb95033" if nodes[b_][3] == "#3fb950" else nodes[b_][3] + "44"
                ax.plot([x1, x2], [y1, y2], color=col, lw=0.6, zorder=1)

        # Draw nodes
        for nid, (nx, ny, lbl, col, sz) in nodes.items():
            ax.scatter(nx, ny, c=col, s=sz, zorder=3, edgecolors=col, linewidths=0.5, alpha=0.9)
            fs = 5.5 if nid == "root" else 4
            fw = "bold" if nid == "root" else "normal"
            ax.annotate(lbl, (nx, ny), xytext=(0, -10), textcoords="offset points",
                        ha="center", va="top", fontsize=fs, color="#e6edf3",
                        fontweight=fw, fontfamily="monospace")

        # Legend
        legend_els = [
            mpatches.Patch(color="#f85149", label="Root domain"),
            mpatches.Patch(color="#58a6ff", label="Passive subdomain"),
            mpatches.Patch(color="#bc8cff", label="Brute-forced"),
            mpatches.Patch(color="#3fb950", label="IP address"),
        ]
        ax.legend(handles=legend_els, loc="lower right", fontsize=6,
                  facecolor="#161b22", edgecolor="#30363d", labelcolor="#e6edf3",
                  framealpha=0.9)

        ax.set_aspect("equal")
        ax.margins(0.15)
        return fig_to_image(fig, width_mm=175)

    # ── GRAPH: world map via Playwright + jsvectormap ────────────────────────
    def build_world_map():
        """Screenshot the real jsvectormap using Playwright — same map as the dashboard."""
        import json as _json
        from io import BytesIO as _BytesIO

        from reportlab.lib.utils import ImageReader as _IR

        if not cc_counter:
            return None

        centroids_pw = {
            'US':[38,-97],'CA':[56,-96],'MX':[23,-102],'BR':[-10,-55],'AR':[-34,-64],
            'CO':[4,-74],'CL':[-30,-71],'PE':[-10,-76],'VE':[8,-66],
            'GB':[54,-3],'IE':[53,-8],'FR':[46,2],'DE':[51,10],'NL':[52,5],
            'BE':[50,4],'ES':[40,-4],'PT':[39,-8],'IT':[42,12],'CH':[47,8],
            'AT':[47,14],'PL':[52,20],'CZ':[50,15],'HU':[47,19],'RO':[46,25],
            'BG':[43,25],'GR':[39,22],'HR':[45,16],'UA':[49,32],'SE':[62,15],
            'NO':[62,10],'FI':[64,26],'DK':[56,10],'BY':[53,28],'RS':[44,21],
            'RU':[62,105],'TR':[39,35],'IL':[31,35],'SA':[24,45],'AE':[24,54],
            'IR':[32,53],'IQ':[33,44],'EG':[27,30],'LY':[27,17],'DZ':[28,3],
            'MA':[32,-6],'NG':[10,8],'KE':[-1,38],'ZA':[-29,25],'ET':[9,40],
            'GH':[8,-1],'TZ':[-6,35],'AO':[-12,18],'CM':[4,12],'CD':[-4,24],
            'IN':[21,78],'PK':[30,70],'BD':[24,90],'LK':[7,81],'NP':[28,84],
            'CN':[35,105],'JP':[36,138],'KR':[36,128],'TW':[23,121],'HK':[22,114],
            'SG':[1,104],'MY':[4,110],'TH':[15,101],'VN':[16,108],'PH':[12,122],
            'ID':[-5,120],'MM':[17,96],'KH':[13,105],'KZ':[48,68],
            'AU':[-25,134],'NZ':[-41,174],
        }

        regions = list(cc_counter.keys())
        markers = [
            {'coords': centroids_pw[cc], 'name': f"{cc_names.get(cc,cc)} ({cnt} IPs)"}
            for cc, cnt in cc_counter.items() if cc in centroids_pw
        ]

        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/css/jsvectormap.min.css"/>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0d1117}}
#map{{width:1200px;height:500px;background:#0d1117}}
.jvm-tooltip{{background:#1c2d3a!important;color:#e6edf3!important;border:1px solid #30363d!important;font-size:11px!important;border-radius:4px!important;padding:4px 8px!important}}
</style></head><body>
<div id="map"></div>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/js/jsvectormap.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/maps/world.js"></script>
<script>
window._ready = false;
try {{
  new jsVectorMap({{
    map:'world', selector:'#map',
    zoomButtons:false, zoomOnScroll:false, draggable:false,
    focusOn:{{ x:0.5, y:0.5, scale:1 }},
    selectedRegions:{_json.dumps(regions)},
    markers:{_json.dumps(markers)},
    regionStyle:{{
      initial:{{fill:'#1c2d3a',stroke:'#2d4a5e',strokeWidth:0.5}},
      selected:{{fill:'#1d3a5e'}},
    }},
    markerStyle:{{
      initial:{{fill:'#58a6ff',stroke:'#79c0ff',strokeWidth:1.5,r:5}},
      selected:{{fill:'#58a6ff'}},
    }},
    backgroundColor:'#0d1117',
  }});
}} catch(e){{console.error(e)}}
window._ready = true;
</script></body></html>"""

        try:
            import os as _os
            import tempfile as _tmp

            from playwright.sync_api import sync_playwright as _swp
            with _swp() as _p:
                _browser = _p.chromium.launch(headless=True)
                _page = _browser.new_page(viewport={'width': 1200, 'height': 500})
                _tf = _tmp.NamedTemporaryFile(suffix='.html', delete=False, mode='w')
                _tf.write(html)
                _tf.close()
                _page.goto(f"file://{_tf.name}", wait_until='networkidle', timeout=20000)
                _page.wait_for_timeout(800)
                _png = _page.locator('#map').screenshot()
                _browser.close()
                _os.unlink(_tf.name)

            if len(_png) < 5000:
                return None

            _buf = _BytesIO(_png)
            _ir = _IR(_buf)
            _iw, _ih = _ir.getSize()
            _w = 175 * mm
            _h = _w * (_ih / _iw)
            # Cap height at 90mm for full-width map
            _max_h = 90 * mm
            if _h > _max_h:
                _w = _max_h * (_iw / _ih)
                _h = _max_h
            return Image(_buf, width=_w, height=_h)
        except Exception as _e:
            return None

    # ── CERT: issuer bar chart ─────────────────────────────────────────────────
    def build_cert_issuer_chart(cert_data):
        issuers = cert_data.get("issuers", {})
        if not issuers:
            return None
        top = sorted(issuers.items(), key=lambda x: x[1], reverse=True)[:8]
        labels = [lbl[:28] for lbl, _ in top]
        vals = [v for _, v in top]
        palette = ["#58a6ff","#3fb950","#bc8cff","#f85149","#d29922","#8b949e","#79c0ff","#56d364"]
        fig, ax = plt.subplots(figsize=(5.5, 2.6))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#0d1117")
        bars = ax.barh(labels[::-1], vals[::-1],
                       color=[palette[i % len(palette)] for i in range(len(labels)-1,-1,-1)],
                       height=0.55)
        for bar, val in zip(bars, vals[::-1]):
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                    str(val), va="center", ha="left", color="#e6edf3", fontsize=7)
        ax.set_xlabel("Certs issued", color="#8b949e", fontsize=7)
        ax.tick_params(colors="#8b949e", labelsize=6.5)
        ax.spines[:].set_color("#30363d")
        ax.set_title("Certificate Issuers", color="#e6edf3", fontsize=8,
                     fontweight="bold", pad=6)
        fig.tight_layout()
        return fig_to_image(fig, width_mm=88)

    # ── CERT: issuance timeline chart ─────────────────────────────────────────
    def build_cert_timeline_chart(cert_data):
        certs = cert_data.get("certs", [])
        if not certs:
            return None
        by_year = {}
        for c in certs:
            yr = (c.get("not_before") or "")[:4]
            if yr and yr.isdigit():
                by_year[yr] = by_year.get(yr, 0) + 1
        if len(by_year) < 2:
            return None
        years = sorted(by_year.keys())
        vals = [by_year[y] for y in years]
        palette = ["#3fb950" if y == max(years) else "#58a6ff" for y in years]
        fig, ax = plt.subplots(figsize=(5, 2.6))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#0d1117")
        bars = ax.bar(years, vals, color=palette, width=0.6)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                    str(val), ha="center", va="bottom", color="#e6edf3", fontsize=6.5)
        ax.tick_params(colors="#8b949e", labelsize=6.5, axis="x", rotation=30)
        ax.tick_params(colors="#8b949e", labelsize=6.5, axis="y")
        ax.spines[:].set_color("#30363d")
        ax.set_title("Cert Issuance by Year", color="#e6edf3", fontsize=8,
                     fontweight="bold", pad=6)
        fig.tight_layout()
        return fig_to_image(fig, width_mm=78)

    # ── GRAPH: ASN bar chart ──────────────────────────────────────────────────
    def build_asn_chart():
        if not org_counter:
            return None
        top = org_counter.most_common(6)
        labels = [o[:22] for o, _ in top]
        vals = [v for _, v in top]
        fig, ax = plt.subplots(figsize=(5.5, 2.8))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#0d1117")
        bars = ax.barh(labels[::-1], vals[::-1], color="#58a6ff", height=0.55)
        for bar, val in zip(bars, vals[::-1]):
            ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                    str(val), va="center", ha="left", color="#e6edf3", fontsize=7)
        ax.set_xlabel("IP count", color="#8b949e", fontsize=7)
        ax.tick_params(colors="#8b949e", labelsize=7)
        ax.spines[:].set_color("#30363d")
        ax.set_title("Hosting / Networks", color="#e6edf3", fontsize=8, fontweight="bold", pad=6)
        fig.tight_layout()
        return fig_to_image(fig, width_mm=82)

    # ── GRAPH: country pie ────────────────────────────────────────────────────
    def build_country_chart():
        if not country_counter:
            return None
        top = country_counter.most_common(5)
        labels = [c for c, _ in top]
        vals = [v for _, v in top]
        palette = ["#58a6ff", "#3fb950", "#bc8cff", "#f85149", "#d29922"]
        fig, ax = plt.subplots(figsize=(3, 2.8))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#161b22")
        wedges, texts, autotexts = ax.pie(
            vals, labels=labels, autopct="%1.0f%%",
            colors=palette[:len(vals)], startangle=140,
            textprops={"color": "#e6edf3", "fontsize": 7},
            pctdistance=0.75,
        )
        for at in autotexts:
            at.set_color("#0d1117")
            at.set_fontsize(6)
        ax.set_title("Locations", color="#e6edf3", fontsize=8, fontweight="bold", pad=6)
        fig.tight_layout()
        return fig_to_image(fig, width_mm=58)

    # ── GRAPH: port heatmap ───────────────────────────────────────────────────
    def build_port_heatmap():
        ports_dict = port_scan.get("ports", {}) if isinstance(port_scan, dict) else {}
        if not ports_dict:
            return None
        open_ports = {p: s for p, s in ports_dict.items() if s == "open"}
        if not open_ports:
            return None

        port_keys = sorted(open_ports.keys(), key=lambda x: int(x))
        matrix = [[1 if ports_dict.get(pk) == "open" else 0] for pk in port_keys]

        fig, ax = plt.subplots(figsize=(4, max(3, len(port_keys) * 0.35)))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#161b22")
        import numpy as np
        from matplotlib.colors import LinearSegmentedColormap
        cmap = LinearSegmentedColormap.from_list("ports", ["#0d1117", "#3fb950"])
        ax.imshow(np.array(matrix), aspect="auto", cmap=cmap, vmin=0, vmax=1)
        ax.set_yticks(range(len(port_keys)))
        ax.set_yticklabels(port_keys, fontsize=6, color="#e6edf3", fontfamily="monospace")
        ax.set_title("Open Ports", color="#e6edf3", fontsize=8, fontweight="bold", pad=6)
        ax.tick_params(colors="#30363d")
        for spine in ax.spines.values():
            spine.set_color("#30363d")
        fig.tight_layout()
        return fig_to_image(fig, width_mm=175)

    # ════════════════════════════════════════════════════════════════════════
    # STORY BUILD
    # ════════════════════════════════════════════════════════════════════════

    # ── Page 1: Cover / header ───────────────────────────────────────────────
    story.append(HRFlowable(width=PW, thickness=4, color=C_RED, spaceAfter=0))

    # Dark header band
    hdr_inner = Table([
        [
            Paragraph('<font color="#f85149"><b>⬡</b></font>', S("logo", fontSize=28, leading=32, textColor=C_RED)),
            Table([
                [Paragraph("Infrastructure Recon Report", s_h1)],
                [Paragraph('<font color="#f85149">OSINT PH  ·  osintph.info</font>',
                            S("tl", fontSize=9, fontName="Helvetica-Bold", textColor=C_RED, leading=13))],
                [Paragraph(f'Target: <font color="#58a6ff"><b>{domain}</b></font>  ·  '
                           f'Investigated: {created}  ·  Generated: {dt.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M UTC")}',
                           S("meta", fontSize=7.5, textColor=C_MUTED, leading=11))],
            ], colWidths=[PW - 20 * mm]),
        ]
    ], colWidths=[16 * mm, PW - 16 * mm])
    hdr_inner.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND", (0,0), (-1,-1), C_BG),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
    ]))
    story.append(hdr_inner)
    story.append(HRFlowable(width=PW, thickness=1, color=C_BORDER, spaceAfter=8))

    # ── Stat strip ───────────────────────────────────────────────────────────
    bf_count = len(bruteforce)
    cert_count = len(passive)
    stat_items = [
        (str(inv.get("subdomain_count") or 0), "SUBDOMAINS"),
        (str(inv.get("resolved_count") or 0), "RESOLVED"),
        (str(bf_count), "BRUTE-FORCED"),
        (str(cert_count), "CERT SANs"),
        (str(len(main_ips)), "IPs"),
        ("⚠ YES" if zt_success else "✓ NO", "ZONE XFR"),
        ("✓" if email_sec.get("spf_valid") else "✗", "SPF"),
        ("✓" if email_sec.get("dmarc_valid") else "✗", "DMARC"),
    ]
    stat_colors = {
        "⚠ YES": C_RED, "✓ NO": C_GREEN,
        "✓": C_GREEN, "✗": C_RED,
    }
    stat_cells = []
    for val, lbl in stat_items:
        vc = stat_colors.get(val, C_ACCENT)
        cell = Table([
            [Paragraph(f'<b>{val}</b>', S(f"sv_{lbl}", fontSize=14, fontName="Helvetica-Bold", textColor=vc, leading=17))],
            [Paragraph(lbl, S(f"sl_{lbl}", fontSize=6, textColor=C_MUTED, leading=8, fontName="Helvetica-Bold"))],
        ], colWidths=[PW / len(stat_items) - 2])
        cell.setStyle(TableStyle([
            ("ALIGN", (0,0), (-1,-1), "CENTER"),
            ("BACKGROUND", (0,0), (-1,-1), C_SURFACE),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 2),
            ("RIGHTPADDING", (0,0), (-1,-1), 2),
            ("BOX", (0,0), (-1,-1), 0.4, C_BORDER),
        ]))
        stat_cells.append(cell)

    stat_tbl = Table([stat_cells], colWidths=[PW / len(stat_items)] * len(stat_items))
    stat_tbl.setStyle(TableStyle([
        ("LEFTPADDING", (0,0), (-1,-1), 2),
        ("RIGHTPADDING", (0,0), (-1,-1), 2),
        ("TOPPADDING", (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
    ]))
    story.append(stat_tbl)
    story.append(Spacer(1, 8))

    # ── Zone transfer alert ──────────────────────────────────────────────────
    if zt_success:
        ns_vuln = [ns for ns, info in zt.items() if isinstance(info, dict) and info.get("success")]
        alert_tbl = Table([[
            Paragraph("🚨", S("alertico", fontSize=16, leading=20)),
            Paragraph(f"<b>CRITICAL: Zone Transfer Succeeded</b><br/>"
                      f"Nameserver(s) {', '.join(ns_vuln)} are leaking full DNS zone data. "
                      f"Restrict AXFR to authorised secondaries immediately.",
                      S("alerttxt", fontSize=8, textColor=C_RED, leading=12)),
        ]], colWidths=[10*mm, PW-10*mm])
        alert_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#3d0000")),
            ("BOX", (0,0), (-1,-1), 1, C_RED),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(alert_tbl)
        story.append(Spacer(1, 6))

    # ── Email security issues ─────────────────────────────────────────────────
    issues = email_sec.get("issues", [])
    if issues:
        for issue in issues:
            story.append(Paragraph(f"⚠ {issue}", s_warn))
        story.append(Spacer(1, 4))

    # ── Page 1: Infrastructure overview (charts side by side) ────────────────
    section_header("Infrastructure Overview")

    asn_img = build_asn_chart()
    cty_img = build_country_chart()
    if asn_img and cty_img:
        overview_tbl = Table([[asn_img, cty_img]], colWidths=[PW * 0.58, PW * 0.42])
        overview_tbl.setStyle(TableStyle([
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING", (0,0), (-1,-1), 0),
            ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(overview_tbl)
    elif asn_img:
        story.append(asn_img)

    # ── World map ─────────────────────────────────────────────────────────────
    wmap = None
    if cc_counter:
        try:
            wmap = build_world_map()
        except Exception:
            wmap = None

    asn_tbl = None
    if org_counter:
        asn_rows = []
        all_geo_by_org = {}
        for sub in resolved:
            for g in (sub.get("geo") or []):
                if g and g.get("org"):
                    org = g["org"]
                    if org not in all_geo_by_org:
                        all_geo_by_org[org] = {"ips": set(), "asn": g.get("as",""), "country": g.get("country","")}
                    all_geo_by_org[org]["ips"].add(g.get("query",""))
        for org, cnt in org_counter.most_common(10):
            info = all_geo_by_org.get(org, {})
            asn_rows.append([
                Paragraph(org[:45], s_body),
                Paragraph(info.get("asn",""), s_small),
                Paragraph(info.get("country",""), s_small),
                Paragraph(str(cnt), S("cnt", fontSize=8, fontName="Helvetica-Bold", textColor=C_ACCENT, leading=12)),
            ])
        asn_tbl = dark_table(
            [Paragraph(h, S(f"ah_{h}", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))
             for h in ["Organisation / ASN Name", "ASN", "Country", "IPs"]],
            asn_rows, [PW*0.46, PW*0.26, PW*0.17, PW*0.11]
        )

    if wmap and asn_tbl:
        story.append(Spacer(1, 6))
        story.append(wmap)
        story.append(Spacer(1, 6))
        story.append(asn_tbl)
    elif wmap:
        story.append(Spacer(1, 6))
        story.append(wmap)
    elif asn_tbl:
        story.append(Spacer(1, 6))
        story.append(asn_tbl)

    # ── Subdomain graph ───────────────────────────────────────────────────────
    story.append(PageBreak())
    section_header("Subdomain Infrastructure Graph")
    story.append(Paragraph(
        f"{len(resolved)} passive subdomains · {len(bruteforce)} brute-forced · "
        f"{sum(len(s.get('ips',[])) for s in resolved)} IP nodes",
        s_small))
    story.append(Spacer(1, 4))
    try:
        graph_img = build_graph_image()
        story.append(graph_img)
    except Exception as e:
        story.append(Paragraph(f"Graph generation failed: {e}", s_warn))

    # ── DNS Records ───────────────────────────────────────────────────────────
    section_header("DNS Records")
    rec_rows = []
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]:
        for val in dns.get(rtype, []):
            geo = ip_geo.get(val, {})
            geo_s = f"{geo.get('city','')} {geo.get('country','')} · {geo.get('org','')}".strip(" ·")
            ptr_s = ptr.get(val, "")
            rec_rows.append([
                Paragraph(rtype, S(f"rt{rtype}", fontSize=7, fontName="Helvetica-Bold",
                    textColor=C_ACCENT, leading=10)),
                Paragraph(val, s_mono),
                Paragraph(ptr_s, s_small),
                Paragraph(geo_s, s_small),
            ])
    if rec_rows:
        story.append(dark_table(
            [Paragraph(h, S(f"rh{h}", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))
             for h in ["Type", "Value", "PTR", "Geolocation / Org"]],
            rec_rows, [PW*0.07, PW*0.27, PW*0.26, PW*0.40]
        ))

    # ── Email security ────────────────────────────────────────────────────────
    section_header("Email Security Analysis")
    spf_v = email_sec.get("spf_valid")
    dmarc_v = email_sec.get("dmarc_valid")
    dkim_sel = email_sec.get("dkim_selectors_found", [])
    score = 100 - (0 if spf_v else 35) - (0 if dmarc_v else 35) - (0 if dkim_sel else 20)
    score_col = C_GREEN if score >= 80 else C_YELLOW if score >= 50 else C_RED

    esec_data = [
        [Paragraph("Record", S("esh", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold")),
         Paragraph("Status", S("esh2", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold")),
         Paragraph("Value", S("esh3", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))],
        [Paragraph("SPF", s_body),
         Paragraph("✓ Valid" if spf_v else "✗ Missing", S("sv2", fontSize=8, fontName="Helvetica-Bold", textColor=C_GREEN if spf_v else C_RED, leading=12)),
         Paragraph(email_sec.get("spf") or "—", s_mono)],
        [Paragraph("DMARC", s_body),
         Paragraph("✓ Valid" if dmarc_v else "✗ Missing", S("dv2", fontSize=8, fontName="Helvetica-Bold", textColor=C_GREEN if dmarc_v else C_RED, leading=12)),
         Paragraph(email_sec.get("dmarc") or "—", s_mono)],
        [Paragraph("DKIM", s_body),
         Paragraph(f"✓ {len(dkim_sel)} selector(s)" if dkim_sel else "✗ Not detected",
                   S("kv2", fontSize=8, fontName="Helvetica-Bold", textColor=C_GREEN if dkim_sel else C_MUTED, leading=12)),
         Paragraph(", ".join(dkim_sel) or "No selectors found", s_small)],
    ]
    esec_tbl = Table(esec_data, colWidths=[PW*0.12, PW*0.2, PW*0.68])
    esec_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), C_BG),
        ("TEXTCOLOR", (0,0), (-1,0), C_TEXT),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_SURFACE, C_BG]),
        ("GRID", (0,0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))

    score_cell = Table([
        [Paragraph(f'<b>{score}</b>', S("sc", fontSize=28, fontName="Helvetica-Bold", textColor=score_col, leading=32))],
        [Paragraph("EMAIL SCORE", S("scl", fontSize=6, textColor=C_MUTED, leading=8, fontName="Helvetica-Bold"))],
        [Paragraph("GOOD" if score>=80 else "MODERATE RISK" if score>=50 else "HIGH RISK",
                   S("scr", fontSize=7, fontName="Helvetica-Bold", textColor=score_col, leading=9))],
    ], colWidths=[25*mm])
    score_cell.setStyle(TableStyle([
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("BACKGROUND", (0,0), (-1,-1), C_SURFACE),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("BOX", (0,0), (-1,-1), 0.4, score_col),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))

    email_layout = Table([[score_cell, esec_tbl]], colWidths=[27*mm, PW-27*mm])
    email_layout.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
        ("RIGHTPADDING", (0,0), (0,0), 6),
    ]))
    story.append(email_layout)

    # ── Subdomains table ──────────────────────────────────────────────────────
    section_header(f"Resolved Subdomains ({len(resolved)} passive · {len(bruteforce)} brute-forced)")
    all_sub_map = {s["subdomain"]: {**s, "src": "passive"} for s in resolved}
    for b in bruteforce:
        if b["subdomain"] not in all_sub_map:
            all_sub_map[b["subdomain"]] = {**b, "src": "brute"}

    sub_rows = []
    for sub in sorted(all_sub_map.values(), key=lambda x: x["subdomain"]):
        ips = ", ".join(sub.get("ips") or [])
        geo = geo_str(sub.get("geo") or [])
        src = sub.get("src", "passive")
        src_col = "#bc8cff" if src == "brute" else "#58a6ff"
        src_lbl = "brute-force" if src == "brute" else "passive"
        sub_rows.append([
            Paragraph(sub["subdomain"], s_mono),
            Paragraph(ips, s_mono),
            Paragraph(geo, s_small),
            Paragraph(f'<font color="{src_col}"><b>{src_lbl}</b></font>',
                      S(f"src_{src}", fontSize=6.5, leading=10)),
        ])
    if sub_rows:
        story.append(dark_table(
            [Paragraph(h, S(f"sbh{h}", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))
             for h in ["Subdomain", "IP Address(es)", "Location", "Source"]],
            sub_rows, [PW*0.38, PW*0.23, PW*0.27, PW*0.12]
        ))

    # ── Certificate Transparency (rich version if available) ──────────────────
    if passive:
        # Try to fetch rich cert data from crt.sh for the PDF
        rich_cert_data = None
        try:
            _cr_result = safe_fetch(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "OSINTPH-PDFGen/1.0", "Accept": "application/json"},
                timeout=20,
            )
            if _cr_result["status"] == 200:
                from datetime import datetime as _dt
                _now = _dt.now(timezone.utc).replace(tzinfo=None)
                _raw = json.loads(_cr_result["body"])
                _certs = []
                _seen = set()
                _issuer_cnt = Counter()
                _san_set = set()
                _expired = _expiring = _active = 0
                for _e in _raw:
                    _cid = _e.get("id")
                    if _cid in _seen:
                        continue
                    _seen.add(_cid)
                    _nb = _e.get("not_before","")
                    _na = _e.get("not_after","")
                    _nb_dt = _na_dt = None
                    for _fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                        try:
                            _nb_dt = _dt.strptime(_nb[:19], _fmt[:len(_nb[:19])])
                            break
                        except Exception:
                            pass
                    for _fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                        try:
                            _na_dt = _dt.strptime(_na[:19], _fmt[:len(_na[:19])])
                            break
                        except Exception:
                            pass
                    _is_exp = (_na_dt < _now) if _na_dt else False
                    _days = (_na_dt - _now).days if (_na_dt and not _is_exp) else None
                    _exp_soon = _days is not None and _days <= 30
                    _sans = sorted(set(s.strip().lower() for s in _e.get("name_value","").split("\n") if s.strip()))
                    _san_set.update(_sans)
                    _issuer_raw = _e.get("issuer_name","")
                    _icn = ""
                    for _p in _issuer_raw.split(","):
                        _p = _p.strip()
                        if _p.startswith("O="):
                            _icn = _p[2:].strip()
                            break
                    if not _icn:
                        for _p in _issuer_raw.split(","):
                            _p = _p.strip()
                            if _p.startswith("CN="):
                                _icn = _p[3:].strip()
                                break
                    if _icn:
                        _issuer_cnt[_icn] += 1
                    if _is_exp:
                        _expired += 1
                    elif _exp_soon:
                        _expiring += 1
                    else:
                        _active += 1
                    _certs.append({
                        "id": _cid, "issuer_org": _icn, "not_before": _nb,
                        "not_after": _na, "not_before_ts": int(_nb_dt.timestamp()) if _nb_dt else 0,
                        "is_expired": _is_exp, "expiring_soon": _exp_soon,
                        "days_remaining": _days, "sans": _sans,
                    })
                _certs.sort(key=lambda c: c.get("not_before_ts", 0), reverse=True)
                rich_cert_data = {
                    "total": len(_certs), "expired": _expired,
                    "expiring_soon": _expiring, "active": _active,
                    "unique_sans": len(_san_set), "issuers": dict(_issuer_cnt),
                    "certs": _certs,
                }
        except Exception:
            rich_cert_data = None

        if rich_cert_data and rich_cert_data.get("total", 0) > 0:
            cd = rich_cert_data
            section_header(f"Certificate Transparency — {cd['total']} certificates")

            # Stat strip
            cert_stat_items = [
                (str(cd["total"]), "TOTAL CERTS"),
                (str(cd["active"]), "ACTIVE"),
                (str(cd["expired"]), "EXPIRED"),
                (str(cd["expiring_soon"]), "EXPIRING SOON"),
                (str(cd["unique_sans"]), "UNIQUE SANs"),
            ]
            cert_stat_cells = []
            for val, lbl in cert_stat_items:
                col = C_RED if lbl == "EXPIRED" and int(val) > 0 else \
                      C_YELLOW if lbl == "EXPIRING SOON" and int(val) > 0 else \
                      C_GREEN if lbl == "ACTIVE" else C_ACCENT
                cell = Table([
                    [Paragraph(f'<b>{val}</b>', S(f"csv_{lbl[:4]}", fontSize=13,
                               fontName="Helvetica-Bold", textColor=col, leading=16))],
                    [Paragraph(lbl, S(f"csl_{lbl[:4]}", fontSize=5.5, textColor=C_MUTED,
                               leading=8, fontName="Helvetica-Bold"))],
                ], colWidths=[PW / len(cert_stat_items) - 2])
                cell.setStyle(TableStyle([
                    ("ALIGN", (0,0), (-1,-1), "CENTER"),
                    ("BACKGROUND", (0,0), (-1,-1), C_SURFACE),
                    ("TOPPADDING", (0,0), (-1,-1), 5),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                    ("BOX", (0,0), (-1,-1), 0.4, C_BORDER),
                ]))
                cert_stat_cells.append(cell)
            cert_stat_tbl = Table([cert_stat_cells],
                                  colWidths=[PW / len(cert_stat_items)] * len(cert_stat_items))
            cert_stat_tbl.setStyle(TableStyle([
                ("LEFTPADDING", (0,0), (-1,-1), 2),
                ("RIGHTPADDING", (0,0), (-1,-1), 2),
                ("TOPPADDING", (0,0), (-1,-1), 0),
                ("BOTTOMPADDING", (0,0), (-1,-1), 0),
            ]))
            story.append(cert_stat_tbl)
            story.append(Spacer(1, 6))

            # Issuer chart + timeline side by side
            try:
                ci_img = build_cert_issuer_chart(cd)
                ct_img = build_cert_timeline_chart(cd)
                if ci_img and ct_img:
                    charts_tbl = Table([[ci_img, ct_img]], colWidths=[PW*0.55, PW*0.45])
                    charts_tbl.setStyle(TableStyle([
                        ("VALIGN", (0,0), (-1,-1), "TOP"),
                        ("LEFTPADDING", (0,0), (-1,-1), 0),
                        ("RIGHTPADDING", (0,0), (-1,-1), 4),
                    ]))
                    story.append(charts_tbl)
                    story.append(Spacer(1, 6))
                elif ci_img:
                    story.append(ci_img)
                    story.append(Spacer(1, 6))
            except Exception:
                pass

            # Cert table — show all, colour-code expired/expiring
            cert_rows = []
            for c in cd["certs"][:150]:
                is_exp = c.get("is_expired")
                exp_soon = c.get("expiring_soon")
                days = c.get("days_remaining")
                status_txt = "EXPIRED" if is_exp else (f"⚠ {days}d" if exp_soon else "✓ Active")
                status_col = C_RED if is_exp else (C_YELLOW if exp_soon else C_GREEN)
                san_preview = (c["sans"][0] if c.get("sans") else "—")
                issuer_s = (c.get("issuer_org") or "—")[:32]
                cert_rows.append([
                    Paragraph(san_preview, s_mono),
                    Paragraph(issuer_s, s_small),
                    Paragraph((c.get("not_after") or "")[:10], s_small),
                    Paragraph(f'<b>{status_txt}</b>',
                              S(f"cst_{c['id']}", fontSize=6.5, fontName="Helvetica-Bold",
                                textColor=status_col, leading=9)),
                ])
            story.append(dark_table(
                [Paragraph(h, S(f"cth{h}", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))
                 for h in ["Subdomain / SAN", "Issuer", "Expires", "Status"]],
                cert_rows, [PW*0.42, PW*0.28, PW*0.14, PW*0.16]
            ))

        else:
            # Fallback: basic cert table from passive subdomains
            section_header(f"Certificate Transparency — {len(passive)} crt.sh certificates")
            cert_rows = []
            for c in passive[:100]:
                issuer = (c.get("issuer") or "").split("O=")[-1].split(",")[0][:35]
                cert_rows.append([
                    Paragraph(c.get("subdomain",""), s_mono),
                    Paragraph(issuer, s_small),
                    Paragraph((c.get("not_after") or "")[:10], s_small),
                ])
            story.append(dark_table(
                [Paragraph(h, S(f"ch{h}", fontSize=7.5, textColor=C_TEXT, fontName="Helvetica-Bold"))
                 for h in ["Subdomain / SAN", "Issuer", "Expires"]],
                cert_rows, [PW*0.5, PW*0.3, PW*0.2]
            ))

    # ── Port scan ─────────────────────────────────────────────────────────────
    ports_dict = port_scan.get("ports", {}) if isinstance(port_scan, dict) else {}
    open_ports = [p for p, s in ports_dict.items() if s == "open"]
    filt_ports = [p for p, s in ports_dict.items() if s == "filtered"]
    if ports_dict:
        story.append(PageBreak())
        section_header("Port Scan Results")

        # Heatmap chart
        try:
            hm = build_port_heatmap()
            if hm:
                story.append(hm)
                story.append(Spacer(1, 6))
        except Exception:
            pass

        # Open ports detail table
        if open_ports:
            story.append(Paragraph(
                f'<font color="#58a6ff"><b>{port_scan.get("ip","")}</b></font> — '
                f'<font color="#3fb950"><b>{len(open_ports)} open</b></font>'
                + (f', <font color="#d29922">{len(filt_ports)} filtered</font>' if filt_ports else ""),
                S("ip_ports", fontSize=8, textColor=C_TEXT, leading=12, spaceBefore=6, spaceAfter=3)
            ))
            port_rows = [[
                Paragraph(str(p), S("pn", fontSize=7, fontName="Helvetica-Bold", textColor=C_GREEN, leading=10)),
                Paragraph(get_port_service_name(p), s_body),
                Paragraph("OPEN", S("po", fontSize=7, fontName="Helvetica-Bold", textColor=C_GREEN, leading=10)),
            ] for p in open_ports]
            story.append(dark_table(
                [Paragraph(h, S(f"ph{h}", fontSize=7, textColor=C_TEXT, fontName="Helvetica-Bold"))
                 for h in ["Port", "Service", "Status"]],
                port_rows, [PW*0.12, PW*0.38, PW*0.50]
            ))

    # ── Directory enumeration ─────────────────────────────────────────────────
    if dir_enum:
        interesting_total = sum(len([p for p in paths if p.get("status_code") not in (404,410)])
                                for paths in dir_enum.values())
        if interesting_total:
            section_header(f"Directory Enumeration — {interesting_total} paths found")
            for target, paths in dir_enum.items():
                interesting = [p for p in paths if p.get("status_code") not in (404, 410)]
                if not interesting:
                    continue
                story.append(Paragraph(
                    f'<font color="#58a6ff"><b>{target}</b></font> — {len(interesting)} paths',
                    S(f"dt_{target[:8]}", fontSize=8, textColor=C_TEXT, leading=12, spaceBefore=6, spaceAfter=3)
                ))
                dir_rows = []
                for p in interesting:
                    sc = p["status_code"]
                    sc_col = "#3fb950" if sc==200 else "#58a6ff" if 300<=sc<400 else "#d29922" if sc in (401,403) else "#f85149"
                    dir_rows.append([
                        Paragraph(f'<font color="{sc_col}"><b>{sc}</b></font>',
                                  S(f"dsc{sc}", fontSize=8, fontName="Helvetica-Bold", leading=12)),
                        Paragraph(p.get("path",""), s_mono),
                        Paragraph(p.get("content_length","") or "—", s_small),
                        Paragraph(p.get("redirect_to","") or "—", s_small),
                    ])
                story.append(dark_table(
                    [Paragraph(h, S(f"dh{h}", fontSize=7, textColor=C_TEXT, fontName="Helvetica-Bold"))
                     for h in ["Code", "Path", "Size", "Redirect"]],
                    dir_rows, [PW*0.08, PW*0.42, PW*0.12, PW*0.38]
                ))

    # ── Zone transfer detail ──────────────────────────────────────────────────
    if zt_success:
        section_header("Zone Transfer Records — CRITICAL", C_RED)
        for ns, info in zt.items():
            if not info.get("success"):
                continue
            story.append(Paragraph(f"Nameserver: {ns} — {info.get('record_count',0)} records exposed", s_warn))
            zt_rows = [
                [Paragraph(rec["name"], s_mono), Paragraph(rec["type"], s_body), Paragraph(rec["value"], s_mono)]
                for rec in (info.get("records") or [])[:80]
            ]
            if zt_rows:
                story.append(dark_table(
                    [Paragraph(h, S(f"zh{h}", fontSize=7, textColor=C_TEXT, fontName="Helvetica-Bold"))
                     for h in ["Name", "Type", "Value"]],
                    zt_rows, [PW*0.3, PW*0.1, PW*0.6],
                    row_colors=[colors.HexColor("#2d0000"), colors.HexColor("#1a0000")]
                ))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width=PW, thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"CONFIDENTIAL — Infrastructure Recon Report  ·  OSINT PH / osintph.info  ·  "
        f"Target: {domain}  ·  Report ID: OSINTPH-DNS-{inv_id}-{dt.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d')}",
        s_foot))

    try:
        doc.build(story, onFirstPage=dark_page, onLaterPages=dark_page)
    except Exception as build_err:
        logger.error("[api_dns_pdf] doc.build failed: %s", build_err, exc_info=True)
        return jsonify({"error": f"PDF build failed: {build_err}"}), 500
    buf.seek(0)
    return Response(
        buf.read(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=osintph-dns-{domain}-{dt.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d')}.pdf"},
    )




# ── Projects API ───────────────────────────────────────────────────────────────


def _check_project_access(project_id: int, require_owner: bool = False):
    """Returns (project_dict, error_response). Checks auth and ownership."""
    storage = get_storage()
    project = storage.get_project(project_id)
    if not project:
        return None, (jsonify({"error": "Project not found"}), 404)
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin and project["owner_id"] != session["user_id"]:
        return None, (jsonify({"error": "Access denied"}), 403)
    return project, None


@dashboard_bp.route("/api/projects", methods=["GET"])
@require_login
def api_projects_list():
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if user.is_admin:
        projects = storage.list_projects()
    else:
        projects = storage.list_projects(owner_id=session["user_id"])
    # attach owner username
    for p in projects:
        owner = storage.get_user_by_id(p["owner_id"])
        p["owner_username"] = owner.username if owner else "unknown"
    return jsonify(projects)


@dashboard_bp.route("/api/projects", methods=["POST"])
@require_login
def api_projects_create():
    body = request.get_json() or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Project name required"}), 400
    storage = get_storage()
    project_id = storage.create_project(
        name=name,
        owner_id=session["user_id"],
        description=(body.get("description") or "").strip() or None,
        color=body.get("color") or "#f85149",
        tags=body.get("tags") or [],
        alert_threshold=int(body.get("alert_threshold") or 1),
    )
    return jsonify({"ok": True, "id": project_id})


@dashboard_bp.route("/api/projects/<int:project_id>", methods=["GET"])
@require_login
def api_projects_get(project_id):
    project, err = _check_project_access(project_id)
    if err:
        return err
    storage = get_storage()
    owner = storage.get_user_by_id(project["owner_id"])
    project["owner_username"] = owner.username if owner else "unknown"
    return jsonify(project)


@dashboard_bp.route("/api/projects/<int:project_id>", methods=["PUT"])
@require_login
def api_projects_update(project_id):
    project, err = _check_project_access(project_id)
    if err:
        return err
    body = request.get_json() or {}
    allowed = ["name", "description", "status", "color", "tags", "alert_threshold"]
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return jsonify({"error": "No valid fields to update"}), 400
    get_storage().update_project(project_id, **updates)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/projects/<int:project_id>", methods=["DELETE"])
@require_login
def api_projects_delete(project_id):
    project, err = _check_project_access(project_id)
    if err:
        return err
    get_storage().delete_project(project_id)
    return jsonify({"ok": True})


@dashboard_bp.route("/api/projects/<int:project_id>/status", methods=["PATCH"])
@require_login
def api_projects_status(project_id):
    project, err = _check_project_access(project_id)
    if err:
        return err
    body = request.get_json() or {}
    status = body.get("status")
    if status not in ("active", "paused", "archived"):
        return jsonify({"error": "status must be active, paused, or archived"}), 400
    get_storage().update_project(project_id, status=status)
    return jsonify({"ok": True})


# Keywords
@dashboard_bp.route("/api/projects/<int:project_id>/keywords", methods=["GET"])
@require_login
def api_project_keywords_get(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    return jsonify(get_storage().get_project_keywords(project_id))


@dashboard_bp.route("/api/projects/<int:project_id>/keywords", methods=["POST"])
@require_login
def api_project_keywords_add(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    body = request.get_json() or {}
    keyword = (body.get("keyword") or "").strip()
    if not keyword:
        return jsonify({"error": "keyword required"}), 400
    kid = get_storage().add_project_keyword(
        project_id, keyword,
        category=body.get("category") or "custom",
        is_regex=bool(body.get("is_regex", False)),
    )
    return jsonify({"ok": True, "id": kid})


@dashboard_bp.route("/api/projects/<int:project_id>/keywords/<int:keyword_id>", methods=["DELETE"])
@require_login
def api_project_keywords_delete(project_id, keyword_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    get_storage().delete_project_keyword(keyword_id)
    return jsonify({"ok": True})


# Domains
@dashboard_bp.route("/api/projects/<int:project_id>/domains", methods=["GET"])
@require_login
def api_project_domains_get(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    return jsonify(get_storage().get_project_domains(project_id))


@dashboard_bp.route("/api/projects/<int:project_id>/domains", methods=["POST"])
@require_login
def api_project_domains_add(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    body = request.get_json() or {}
    domain = (body.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    did = get_storage().add_project_domain(
        project_id, domain,
        priority=int(body.get("priority") or 3),
        notes=body.get("notes"),
    )
    return jsonify({"ok": True, "id": did})


@dashboard_bp.route("/api/projects/<int:project_id>/domains/<int:domain_id>", methods=["DELETE"])
@require_login
def api_project_domains_delete(project_id, domain_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    get_storage().delete_project_domain(domain_id)
    return jsonify({"ok": True})


# Entities
@dashboard_bp.route("/api/projects/<int:project_id>/entities", methods=["GET"])
@require_login
def api_project_entities_get(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    return jsonify(get_storage().get_project_entities(project_id))


@dashboard_bp.route("/api/projects/<int:project_id>/entities", methods=["POST"])
@require_login
def api_project_entities_add(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    body = request.get_json() or {}
    entity_type = (body.get("entity_type") or "").strip()
    value = (body.get("value") or "").strip()
    valid_types = ("person", "organization", "brand", "ip", "email", "bitcoin_address")
    if entity_type not in valid_types:
        return jsonify({"error": f"entity_type must be one of {valid_types}"}), 400
    if not value:
        return jsonify({"error": "value required"}), 400
    eid = get_storage().add_project_entity(project_id, entity_type, value, body.get("notes"))
    return jsonify({"ok": True, "id": eid})


@dashboard_bp.route("/api/projects/<int:project_id>/entities/<int:entity_id>", methods=["DELETE"])
@require_login
def api_project_entities_delete(project_id, entity_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    get_storage().delete_project_entity(entity_id)
    return jsonify({"ok": True})


# Hits & Stats
@dashboard_bp.route("/api/projects/<int:project_id>/hits", methods=["GET"])
@require_login
def api_project_hits(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    limit = int(request.args.get("limit", 100))
    return jsonify(get_storage().get_project_hits(project_id, limit=limit))


@dashboard_bp.route("/api/projects/<int:project_id>/stats", methods=["GET"])
@require_login
def api_project_stats(project_id):
    _, err = _check_project_access(project_id)
    if err:
        return err
    return jsonify(get_storage().get_project_stats(project_id))




# ── Paste Monitor API ──────────────────────────────────────────────────────────

@dashboard_bp.route("/api/paste/hits", methods=["GET"])
@require_login
def api_paste_hits():
    limit = int(request.args.get("limit", 100))
    source = request.args.get("source")
    pattern = request.args.get("pattern")
    hits = get_storage().get_recent_paste_hits(limit=limit, source=source, pattern=pattern)
    logger.info("GET /api/paste/hits: returning %d hits (limit=%d, source=%s, pattern=%s)",
                len(hits), limit, source, pattern)
    logger.info("Paste hits JSON structure: %s", jsonify(hits).get_json())
    return jsonify(hits)


@dashboard_bp.route("/api/paste/stats", methods=["GET"])
@require_login
def api_paste_stats():
    return jsonify(get_storage().get_paste_stats())


@dashboard_bp.route("/api/paste/scan", methods=["POST"])
@require_login
def api_paste_scan():
    """Trigger a one-shot paste scan (admin only)."""
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin:
        return jsonify({"error": "Admin only"}), 403
    try:
        from darkweb_scanner.paste_monitor import run_paste_monitor
        result = run_paste_monitor(storage, single_run=True)
        return jsonify({"ok": True, **result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/paste/scrape", methods=["POST"])
@require_login
def api_paste_scrape():
    """Trigger the new clearnet paste scraper (admin only).

    Scrapes Rentry, Hastebin, Ghostbin, and (if PASTEBIN_API_KEY is set) Pastebin.
    Extracts Kenyan threat indicators and saves hits to the database.
    Also runs dynamic keyword extraction on newly ingested hits.
    """
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin:
        return jsonify({"error": "Admin only"}), 403
    try:
        from darkweb_scanner.scrapers.keyword_extractor import extract_and_store_keywords
        from darkweb_scanner.scrapers.paste_scraper import run_paste_scraper

        # Run the scraper
        scrape_result = run_paste_scraper(storage)

        # Run dynamic keyword extraction on newly ingested hits
        kw_result = extract_and_store_keywords(storage, lookback_days=7)

        return jsonify({
            "ok": True,
            "scraped": scrape_result,
            "keywords": kw_result,
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ── Threat IOC Feeds API ───────────────────────────────────────────────────────
@dashboard_bp.route("/api/iocs", methods=["GET"])
@require_login
def api_iocs():
    """Return threat IOCs (IPs, domains, URLs, hashes) from open-source feeds."""
    storage = get_storage()
    ioc_type = request.args.get("type")
    source = request.args.get("source")
    limit = int(request.args.get("limit", 200))
    iocs = storage.get_threat_iocs(limit=limit, ioc_type=ioc_type, source=source)
    return jsonify(iocs)


@dashboard_bp.route("/api/iocs/scrape", methods=["POST"])
@require_login
def api_iocs_scrape():
    """Trigger IOC scraper (URLhaus, Feodo Tracker, AlienVault OTX). Admin only."""
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin:
        return jsonify({"error": "Admin only"}), 403
    try:
        from darkweb_scanner.scrapers.ioc_scraper import run_ioc_scraper
        result = run_ioc_scraper(storage)
        return jsonify({"ok": True, **result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ── Dark Web (Tor) Scraper API ────────────────────────────────────────────────
@dashboard_bp.route("/api/paste/scrape-onion", methods=["POST"])
@require_login
def api_paste_scrape_onion():
    """Trigger Tor onion scraper. Admin only."""
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin:
        return jsonify({"error": "Admin only"}), 403
    try:
        from darkweb_scanner.scrapers.onion_scraper import scrape_onion
        result = scrape_onion(storage)
        return jsonify({"ok": True, **result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ── Contextual Intel API ──────────────────────────────────────────────────────
@dashboard_bp.route("/api/context/scrape", methods=["POST"])
@require_login
def api_context_scrape():
    """Trigger contextual intel scraper (KE-CIRT, CAK, CBK reports). Admin only."""
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin:
        return jsonify({"error": "Admin only"}), 403
    try:
        from darkweb_scanner.scrapers.context_scraper import scrape_context
        result = scrape_context(storage)
        return jsonify({"ok": True, **result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/context/intel", methods=["GET"])
@require_login
def api_context_intel():
    """Return contextual intel records."""
    storage = get_storage()
    source = request.args.get("source")
    limit = int(request.args.get("limit", 100))
    intel = storage.get_contextual_intel(limit=limit, source=source)
    return jsonify(intel)


# ── Synthetic Log Ingestion API ───────────────────────────────────────────────
@dashboard_bp.route("/api/ingest/logs", methods=["POST"])
@require_login
def api_ingest_logs():
    """Accept CSV file upload, extract Kenyan PII, save hits to database."""
    import csv
    import io

    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin:
        return jsonify({"error": "Admin only"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename or not file.filename.endswith(".csv"):
        return jsonify({"error": "Only CSV files are accepted"}), 400

    try:
        from darkweb_scanner.scrapers.keyword_extractor import extract_kenyan_pii

        content = file.read().decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(content))

        total_rows = 0
        total_pii = 0
        pii_breakdown = {"phone": 0, "mpesa": 0, "kra_pin": 0}

        for row in reader:
            total_rows += 1
            # Combine all column values into a single text string
            row_text = " ".join(str(v) for v in row.values() if v)
            pii_matches = extract_kenyan_pii(row_text)
            for pii in pii_matches:
                total_pii += 1
                pii_breakdown[pii["type"]] = pii_breakdown.get(pii["type"], 0) + 1
                try:
                    paste_id = f"log_{abs(hash(row_text + pii['value']))}"[:200]
                    if not storage.is_paste_seen("LogIngest", paste_id):
                        storage.save_paste_hit(
                            paste_id=paste_id,
                            url="uploaded_csv",
                            source="LogIngest",
                            matched_pattern=f"Log PII: {pii['label']}",
                            matched_value=pii["value"],
                            context=row_text[:500],
                        )
                        storage.mark_paste_seen("LogIngest", paste_id, "uploaded_csv", had_hits=True)
                except Exception as exc:
                    logger.debug("Failed to save log PII hit: %s", exc)

        return jsonify({
            "ok": True,
            "total_rows": total_rows,
            "total_pii": total_pii,
            "pii_breakdown": pii_breakdown,
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/paste/scrape-ransomware", methods=["POST"])
@require_login
def api_paste_scrape_ransomware():
    """Trigger the ransomware.live scraper for Kenyan victims (admin only).

    Fetches recent ransomware victims from https://api.ransomware.live/recentvictims,
    filters for Kenya-based or Kenya-related entities, and inserts them into
    the paste_hits table so they appear in the Paste Monitor UI.
    """
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin:
        return jsonify({"error": "Admin only"}), 403
    try:
        from darkweb_scanner.scrapers.ransomware_scraper import scrape_ransomware

        result = scrape_ransomware(storage)

        return jsonify({
            "ok": True,
            "scraped": result,
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/paste/purge", methods=["POST"])
@require_login
def api_paste_purge():
    """Purge ALL paste_hits records (admin only). One-time cleanup."""
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin:
        return jsonify({"error": "Admin only"}), 403
    try:
        deleted = storage.purge_paste_hits()
        return jsonify({"ok": True, "deleted": deleted})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ── OSINT Toolkit Proxy Routes ────────────────────────────────────────────────
# Server-side proxy so browser CORS restrictions don't block external APIs
# All routes use safe_fetch() which enforces HTTPS, host allowlist, and IP
# blocklist. See dashboard/http_client.py for the full policy.


@dashboard_bp.route("/api/osint/github/<username>")
@require_login
def osint_github(username):
    """Proxy GitHub public API."""
    import json as _json
    try:
        _r1 = safe_fetch(
            f"https://api.github.com/users/{username}",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "OsintTool/1.0"},
        )
        _r2 = safe_fetch(
            f"https://api.github.com/users/{username}/events/public?per_page=10",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "OsintTool/1.0"},
        )
    except SafeFetchError as e:
        logger.warning("GitHub OSINT safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    status, body, ev_body = _r1["status"], _r1["body"], _r2["body"]
    try:
        profile = _json.loads(body)
        events = _json.loads(ev_body) if ev_body else []
        emails = list({
            ev.get("payload", {}).get("commits", [{}])[0].get("author", {}).get("email", "")
            for ev in (events if isinstance(events, list) else [])
            if ev.get("payload", {}).get("commits")
            and "noreply" not in ev.get("payload", {}).get("commits", [{}])[0].get("author", {}).get("email", "noreply")
        } - {""})
        profile["_extracted_emails"] = emails
        return jsonify(profile), status
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/osint/reddit/<username>")
@require_login
def osint_reddit(username):
    import json as _json
    try:
        _r = safe_fetch(
            f"https://www.reddit.com/user/{username}/about.json",
            headers={"User-Agent": "OsintTool/1.0 (research)", "Accept": "application/json"},
        )
    except SafeFetchError as e:
        logger.warning("Reddit OSINT safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    try:
        return jsonify(_json.loads(_r["body"])), _r["status"]
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/osint/discord/<user_id>")
@require_login
def osint_discord(user_id):
    import json as _json
    try:
        _r = safe_fetch(f"https://discordlookup.mesalytic.moe/v1/user/{user_id}")
    except SafeFetchError as e:
        logger.warning("Discord OSINT safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    try:
        return jsonify(_json.loads(_r["body"])), _r["status"]
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/osint/domain/<path:domain>")
@require_login
def osint_domain(domain):
    import json as _json
    domain = domain.strip().lower().split("/")[0]
    results = {}
    # RDAP — rdap.org is allowlisted; registry-specific redirect targets are not.
    # If rdap.org redirects to a non-allowlisted registry RDAP server, SafeFetchError
    # is raised and we return an empty rdap result gracefully.
    try:
        _rdap = safe_fetch(f"https://rdap.org/domain/{domain}", allow_redirects=True)
        rdap_status, rdap_body = _rdap["status"], _rdap["body"]
    except SafeFetchError:
        rdap_status, rdap_body = 0, b""
    try:
        results["rdap"] = _json.loads(rdap_body)
        results["rdap_status"] = rdap_status
    except Exception:
        results["rdap"] = None
        results["rdap_status"] = rdap_status
    # crt.sh
    try:
        _crt = safe_fetch(
            f"https://crt.sh/?q={domain}&output=json",
            headers={"User-Agent": "OsintTool/1.0", "Accept": "application/json"},
        )
        crt_status, crt_body = _crt["status"], _crt["body"]
    except SafeFetchError:
        crt_status, crt_body = 0, b"[]"
    try:
        certs = _json.loads(crt_body) if crt_status == 200 else []
        names = sorted(set(
            n.strip()
            for c in certs
            for n in c.get("name_value", "").split("\n")
            if n.strip()
        ))
        results["crtsh"] = names
    except Exception:
        results["crtsh"] = []
    return jsonify(results)


@dashboard_bp.route("/api/osint/tiktok/<username>")
@require_login
def osint_tiktok(username):
    import json as _json
    try:
        _r = safe_fetch(
            f"https://www.tiktok.com/api/user/detail/?uniqueId={username}&aid=1988",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": "https://www.tiktok.com/",
                "Accept": "application/json",
            },
        )
    except SafeFetchError as e:
        logger.warning("TikTok OSINT safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502
    try:
        data = _json.loads(_r["body"])
        return jsonify(data), _r["status"]
    except Exception as e:
        return jsonify({"error": str(e), "raw": _r["body"][:200].decode("utf-8", errors="replace")}), 500


@dashboard_bp.route("/api/osint/username/<username>")
@require_login
def osint_username_check(username):
    """Check a username against WhatsMyName dataset."""
    import concurrent.futures
    import json as _json
    from urllib.parse import urlparse as _urlparse
    try:
        _wmn = safe_fetch(
            "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
            timeout=15,
        )
        wmn = _json.loads(_wmn["body"])
    except (SafeFetchError, Exception) as e:
        return jsonify({"error": f"Could not fetch WMN data: {e}"}), 500

    sites = [s for s in wmn.get("sites", []) if s.get("uri_check") and s.get("e_code") == 200][:200]
    found = []

    def check(site):
        url = site["uri_check"].replace("{account}", username)
        # WhatsMyName spans 200+ public sites — host allowlist not applied.
        # HTTPS enforced; private-IP blocklist applied to block SSRF.
        if not url.startswith("https://"):
            return None
        try:
            _host = _urlparse(url).hostname or ""
            check_host_ssrf(_host)
            r = requests.get(url, timeout=6, verify=True, allow_redirects=False)
            st, body_b = r.status_code, r.content
        except (SafeFetchError, Exception):
            return None
        text = body_b.decode("utf-8", errors="replace")
        e_string = site.get("e_string", "")
        m_string = site.get("m_string", "")
        if st == site["e_code"] and (not e_string or e_string in text) and (not m_string or m_string not in text):
            return {"name": site["name"], "url": url, "pretty": site.get("uri_pretty", "").replace("{account}", username)}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        for result in pool.map(check, sites):
            if result:
                found.append(result)

    return jsonify({"found": found, "checked": len(sites)})


# ── ThreatFox proxy (avoids browser CORS) ─────────────────────────────────────

@dashboard_bp.route("/api/proxy/threatfox", methods=["POST"])
@require_login
def proxy_threatfox():
    """Proxy ThreatFox API — avoids CORS from browser."""
    try:
        body = request.get_data()
        api_key = os.getenv("THREATFOX_API_KEY", "")
        _hdrs = {"Content-Type": "application/json", "User-Agent": "OSINTPH/1.0"}
        if api_key:
            _hdrs["Auth-Key"] = api_key
        _r = safe_fetch(
            "https://threatfox-api.abuse.ch/api/v1/",
            method="POST",
            headers=_hdrs,
            data=body,
            timeout=15,
        )
        return Response(_r["body"], mimetype="application/json")
    except SafeFetchError as e:
        logger.warning("ThreatFox proxy safe_fetch blocked: %s", e)
        return jsonify({
            'ok': False,
            'error': 'Upstream ThreatFox API unreachable',
            'detail': str(e)[:200],
        }), 502
    except Exception as e:
        logger.exception("ThreatFox proxy failed")
        return jsonify({
            'ok': False,
            'error': 'Internal proxy error',
            'detail': str(e)[:200],
        }), 500


@dashboard_bp.route("/api/proxy/urlhaus", methods=["POST"])
@require_login
def proxy_urlhaus():
    """Proxy URLhaus recent URLs."""
    try:
        _r = safe_fetch(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "OSINTPH/1.0"},
            data=b"limit=200",
            timeout=15,
        )
        return Response(_r["body"], mimetype="application/json")
    except SafeFetchError as e:
        logger.warning("URLhaus proxy safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502


@dashboard_bp.route("/api/proxy/feodo")
@require_login
def proxy_feodo():
    """Proxy Feodo Tracker C2 blocklist."""
    try:
        _r = safe_fetch("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
        return Response(_r["body"], mimetype="application/json")
    except SafeFetchError as e:
        logger.warning("Feodo proxy safe_fetch blocked: %s", e)
        return jsonify({"error": "External request blocked by security policy."}), 502


# ── WhiteIntel proxy ───────────────────────────────────────────────────────────

@dashboard_bp.route("/api/whiteintel/alerts")
@require_login
def whiteintel_alerts():
    """
    Fetch credential exposure alerts from WhiteIntel.
    Requires WHITEINTEL_API_KEY in .env
    GET /api/whiteintel/alerts?page=1&limit=50&severity=critical
    """
    import json as _json
    api_key = os.getenv("WHITEINTEL_API_KEY", "")
    if not api_key:
        return jsonify({"ok": False, "error": "WHITEINTEL_API_KEY not set", "data": []}), 200

    page     = request.args.get("page", "1")
    limit    = request.args.get("limit", "50")
    severity = request.args.get("severity", "")

    params = f"?page={page}&limit={limit}"
    if severity:
        params += f"&severity={severity}"

    try:
        _r = safe_fetch(
            f"https://whiteintel.io/api/v1/alerts{params}",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": "OSINTPH/1.0",
            },
        )
        status, body = _r["status"], _r["body"]
    except SafeFetchError as e:
        logger.warning("WhiteIntel alerts safe_fetch blocked: %s", e)
        return jsonify({"ok": False, "error": "External request blocked by security policy.", "data": []}), 200
    try:
        data = _json.loads(body)
        return jsonify({"ok": True, "data": data})
    except Exception:
        return jsonify({"ok": False, "error": f"HTTP {status}", "raw": body[:200].decode("utf-8", errors="replace")}), 200


@dashboard_bp.route("/api/whiteintel/search")
@require_login
def whiteintel_search():
    """Search WhiteIntel for a specific domain. ?domain=example.com"""
    import json as _json
    api_key = os.getenv("WHITEINTEL_API_KEY", "")
    domain  = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"ok": False, "error": "domain parameter required"}), 400
    if not api_key:
        return jsonify({"ok": False, "error": "WHITEINTEL_API_KEY not set", "data": []}), 200

    try:
        _r = safe_fetch(
            f"https://whiteintel.io/api/v1/search?domain={domain}",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": "OSINTPH/1.0",
            },
        )
        status, body = _r["status"], _r["body"]
    except SafeFetchError as e:
        logger.warning("WhiteIntel search safe_fetch blocked: %s", e)
        return jsonify({"ok": False, "error": "External request blocked by security policy."}), 200
    try:
        data = _json.loads(body)
        return jsonify({"ok": True, "data": data})
    except Exception:
        return jsonify({"ok": False, "error": f"HTTP {status}"}), 200


# ── Quick Scan ─────────────────────────────────────────────────────────────────


def _iso(dt):
    return dt.isoformat() if dt else None


def _quick_scan_session_dict(sess) -> dict:
    return {
        "id": sess.id,
        "target_value": sess.target_value,
        "target_type": sess.target_type,
        "normalized_variants": json.loads(sess.normalized_variants or "[]"),
        "sources_used": json.loads(sess.sources_used or "[]"),
        "status": sess.status,
        "started_at": _iso(sess.started_at),
        "completed_at": _iso(sess.completed_at),
        "urls_visited": sess.urls_visited,
        "findings_count": sess.findings_count,
        "error_message": sess.error_message,
    }


@dashboard_bp.route("/quick-scan")
@require_login
def quick_scan_page():
    from ..quick_scan_sources import ALL_SOURCES

    sources = [
        {"name": s.name, "label": s.label, "kind": s.kind,
         "transport": s.transport, "enabled": s.enabled}
        for s in ALL_SOURCES
    ]
    return render_template(
        "quick_scan.html",
        username=session.get("username"),
        sources=sources,
    )


@dashboard_bp.route("/api/quick-scan/start", methods=["POST"])
@require_login
def api_quick_scan_start():
    import asyncio
    import threading

    from ..quick_scan import (
        VALID_TARGET_TYPES,
        detect_target_type,
        normalize_variants,
        run_quick_scan,
    )
    from ..quick_scan_sources import resolve_sources
    from ..tor_client import create_tor_client

    storage = get_storage()
    user_id = session["user_id"]

    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400

    target_type = body.get("target_type")
    if target_type in (None, "", "auto"):
        target_type = detect_target_type(target)
    elif target_type not in VALID_TARGET_TYPES:
        return jsonify({"error": f"invalid target_type {target_type!r}"}), 400

    variants = normalize_variants(target, target_type)

    requested_sources = body.get("sources")
    sources = resolve_sources(requested_sources)
    if not sources:
        return jsonify({"error": "no enabled sources selected"}), 400
    source_names = [s.name for s in sources]

    # Single active quick scan per user (DB-backed so it holds across workers).
    if storage.has_active_quick_scan(user_id):
        return jsonify({"error": "A quick scan is already running"}), 409

    session_id = storage.create_quick_scan_session(
        user_id=user_id,
        target_value=target,
        target_type=target_type,
        normalized_variants=variants,
        sources_used=source_names,
    )

    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        tor_client = create_tor_client()
        try:
            loop.run_until_complete(run_quick_scan(session_id, storage, tor_client))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Quick scan thread crashed for session %s", session_id)
            try:
                storage.update_quick_scan_session(
                    session_id,
                    status="failed",
                    error_message=f"Scan crashed: {type(exc).__name__}",
                )
            except Exception:
                pass
        finally:
            try:
                loop.run_until_complete(tor_client.close())
            except Exception:
                pass
            loop.close()

    threading.Thread(target=run, daemon=True, name="quick_scan_thread").start()

    return jsonify({"session_id": session_id}), 201


@dashboard_bp.route("/api/quick-scan/status/<int:session_id>")
@require_login
def api_quick_scan_status(session_id):
    storage = get_storage()
    sess = storage.get_quick_scan_session(session_id)
    if sess is None:
        return jsonify({"error": "not found"}), 404
    if sess.user_id != session["user_id"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify({
        "status": sess.status,
        "started_at": _iso(sess.started_at),
        "completed_at": _iso(sess.completed_at),
        "urls_visited": sess.urls_visited,
        "findings_count": sess.findings_count,
        "error_message": sess.error_message,
    })


@dashboard_bp.route("/api/quick-scan/cancel/<int:session_id>", methods=["POST"])
@require_login
def api_quick_scan_cancel(session_id):
    storage = get_storage()
    sess = storage.get_quick_scan_session(session_id)
    if sess is None:
        return jsonify({"error": "not found"}), 404
    if sess.user_id != session["user_id"]:
        return jsonify({"error": "forbidden"}), 403
    if sess.status not in ("pending", "running"):
        return jsonify({"error": f"cannot cancel a scan in status {sess.status!r}"}), 400
    storage.update_quick_scan_session(
        session_id,
        status="cancelled",
        completed_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    logger.info("Quick scan %s cancelled by user %s", session_id, session["user_id"])
    return jsonify(_quick_scan_session_dict(storage.get_quick_scan_session(session_id)))


@dashboard_bp.route("/api/quick-scan/sessions")
@require_login
def api_quick_scan_sessions():
    storage = get_storage()
    sessions = storage.list_quick_scan_sessions(session["user_id"], limit=50)
    return jsonify([_quick_scan_session_dict(s) for s in sessions])


@dashboard_bp.route("/api/quick-scan/findings/<int:session_id>")
@require_login
def api_quick_scan_findings(session_id):
    storage = get_storage()
    sess = storage.get_quick_scan_session(session_id)
    if sess is None:
        return jsonify({"error": "not found"}), 404
    if sess.user_id != session["user_id"]:
        return jsonify({"error": "forbidden"}), 403
    high_signal_only = request.args.get("high_signal_only") == "1"
    findings = storage.list_quick_scan_findings(session_id, high_signal_only=high_signal_only)
    return jsonify([
        {
            "id": f.id,
            "source_name": f.source_name,
            "url": f.url,
            "matched_variant": f.matched_variant,
            "context": f.context,
            "high_signal": f.high_signal,
            "found_at": _iso(f.found_at),
        }
        for f in findings
    ])


# ── Kenya context API ────────────────────────────────────────────────────────


# Comprehensive list of cyber-threat keywords extracted from reports.
# Each keyword becomes its own series in the ATTACK TRENDS chart. A report
# contributes 1 hit per keyword it mentions (de-duplicated per report).
_ATTACK_TYPE_KEYWORDS = [
    "ransomware", "phishing", "malware", "ddos", "breach", "fraud",
    "intrusion", "vulnerability", "data leak", "data breach",
    "mobile banking", "sim swap", "card fraud", "cyberattack",
    "account takeover", "scam", "spyware", "trojan",
]


def _extract_attack_types(text: str) -> list:
    """Return the threat keywords found in the given text (case-insensitive)."""
    low = (text or "").lower()
    found = []
    for kw in _ATTACK_TYPE_KEYWORDS:
        if kw in low:
            found.append(kw)
    return found


def _report_month(row: dict) -> str | None:
    """Return a ``YYYY-MM`` month for a contextual_intel row.

    Prefers a month parsed from the report's own title/summary (quarter+year,
    ISO date, or standalone year); falls back to ``extracted_at`` only when no
    date can be parsed from the report text.
    """
    import re as _re

    text = " ".join([str(row.get("title") or ""), str(row.get("summary") or "")])

    # Quarter + year, e.g. "Q1 2025" or "Q4 2024_25".
    qm = _re.search(r"Q(?:uarter)?[\s\-]*([1-4])[\s\-/]*20(\d{2})", text, _re.IGNORECASE)
    if qm:
        q = int(qm.group(1))
        y = 2000 + int(qm.group(2))
        month = (q - 1) * 3 + 1
        return f"{y:04d}-{month:02d}"

    # ISO date or YYYY-MM.
    m = _re.search(r"\b(19|20)\d{2}-\d{2}(?:-\d{2})?\b", text)
    if m:
        return m.group(0)[:7]

    # Standalone year.
    ym = _re.search(r"\b(20\d{2}|19\d{2})\b", text)
    if ym:
        return f"{ym.group(1)}-01"

    ea = str(row.get("extracted_at") or "").strip()
    if ea and len(ea) >= 7 and ea[4] == "-" and ea[:4].isdigit():
        return ea[:7]

    return None


def _ke_ctx():
    from ..ke_context import KenyaContext

    return KenyaContext(get_storage())


def _ke_ok(data):
    return jsonify({"ok": True, "data": data})


@dashboard_bp.route("/api/ke-context/summary")
@require_login
def api_ke_context_summary():
    ctx = _ke_ctx()
    cirt = ctx.get_latest_ke_cirt()
    if cirt:
        cirt["file_url"] = _ke_cirt_file_url(
            cirt.get("title", ""), cirt.get("quarter", ""), cirt.get("year", "")
        )
    cbk = ctx.get_latest_cbk_totals()
    if cbk and cbk.get("period"):
        cbk["file_url"] = _ke_cbk_file_url(cbk["period"])
    return _ke_ok(
        {
            "ke_cirt_latest": cirt,
            "ca_advisory_count": ctx.count_ca_advisories(),
            "cbk_latest": cbk,
        }
    )


@dashboard_bp.route("/api/ke-context/ca-advisories")
@require_login
def api_ke_context_ca_advisories():
    ctx = _ke_ctx()
    try:
        limit = int(request.args.get("limit", 20))
    except (TypeError, ValueError):
        limit = 20
    advisories = ctx.get_recent_ca_advisories(limit=limit)
    for a in advisories:
        a["file_url"] = _ke_ca_file_url(a.get("title", ""))
    return _ke_ok(advisories)


@dashboard_bp.route("/api/ke-context/cbk-trends")
@require_login
def api_ke_context_cbk_trends():
    """Attack trends derived from ``contextual_intel`` rows.

    Scans only the DB ``title``/``summary`` fields (fast - no PDF reads),
    counts each report once per threat keyword it mentions, pads series arrays
    with 0 for missing months, and returns the top 5 keywords ordered by total
    frequency: ``{"periods": [...], "series": {"<keyword>": [...]}}``.
    """
    from collections import defaultdict

    storage = get_storage()
    rows = storage.get_contextual_intel(limit=10000) or []

    monthly = defaultdict(lambda: defaultdict(int))  # month -> {kw: count}
    totals = defaultdict(int)  # kw -> total count
    months = set()
    for r in rows:
        month = _report_month(r)
        if not month:
            continue
        months.add(month)
        text = " ".join([str(r.get("title") or ""), str(r.get("summary") or "")])
        seen = set()
        for kw in _extract_attack_types(text):
            if kw in seen:
                continue
            seen.add(kw)
            monthly[month][kw] += 1
            totals[kw] += 1

    if not months:
        return _ke_ok({"periods": [], "series": {}})

    periods = sorted(months)
    top5 = sorted(totals, key=lambda a: (-totals[a], a))[:5]
    series = {at: [monthly[m].get(at, 0) for m in periods] for at in top5}
    return _ke_ok({"periods": periods, "series": series})


@dashboard_bp.route("/api/ke-context/ke-cirt")
@require_login
def api_ke_context_ke_cirt():
    reports = _ke_ctx().get_all_ke_cirt()
    for r in reports:
        r["file_url"] = _ke_cirt_file_url(r.get("title", ""), r.get("quarter", ""), r.get("year", ""))
    return _ke_ok(reports)


@dashboard_bp.route("/api/ke-context/correlate")
@require_login
def api_ke_context_correlate():
    """Unified case-insensitive keyword correlation across contextual_intel,
    cves, threat_iocs and paste_hits.

    Returns a unified list ``[{source,title,snippet,url}]`` capped at 50, with
    priority: contextual_intel > cve > ioc > paste.
    """
    keyword = (request.args.get("keyword") or "").strip()
    if not keyword:
        return jsonify({"ok": False, "error": "keyword required"}), 400
    kw = keyword.lower()
    storage = get_storage()

    def _match(text: str) -> bool:
        return kw in str(text or "").lower()

    results = []

    # 1) contextual_intel (highest priority)
    try:
        for r in (storage.get_contextual_intel(limit=10000) or []):
            blob = " ".join([str(r.get("title") or ""), str(r.get("summary") or ""), str(r.get("source") or "")])
            if _match(blob):
                results.append({
                    "source": "contextual_intel",
                    "title": r.get("title") or "Untitled",
                    "snippet": (r.get("summary") or "")[:220],
                    "url": r.get("url") or None,
                })
    except Exception as exc:  # noqa: BLE001
        logger.warning("correlate contextual_intel failed: %s", exc)

    # 2) cve
    try:
        for r in (storage.get_cves(limit=1000) or []):
            blob = " ".join([str(r.get("cve_id") or ""), str(r.get("description") or "")])
            if _match(blob):
                results.append({
                    "source": "cve",
                    "title": r.get("cve_id") or "CVE",
                    "snippet": (r.get("description") or "")[:220],
                    "url": None,
                })
    except Exception as exc:  # noqa: BLE001
        logger.warning("correlate cve failed: %s", exc)

    # 3) threat_iocs (ioc.value == indicator)
    try:
        for r in (storage.get_threat_iocs(limit=1000) or []):
            blob = " ".join([str(r.get("indicator") or ""), str(r.get("threat_type") or ""), str(r.get("type") or "")])
            if _match(blob):
                results.append({
                    "source": "ioc",
                    "title": r.get("indicator") or "IOC",
                    "snippet": (r.get("threat_type") or r.get("type") or "")[:220],
                    "url": None,
                })
    except Exception as exc:  # noqa: BLE001
        logger.warning("correlate ioc failed: %s", exc)

    # 4) paste_hits (lowest priority)
    try:
        for r in (storage.get_paste_hits() or []):
            blob = " ".join([str(r.get("matched_value") or ""), str(r.get("context") or ""), str(r.get("url") or "")])
            if _match(blob):
                results.append({
                    "source": "paste",
                    "title": r.get("matched_value") or "Paste hit",
                    "snippet": (r.get("context") or "")[:220],
                    "url": r.get("url") or None,
                })
    except Exception as exc:  # noqa: BLE001
        logger.warning("correlate paste_hits failed: %s", exc)

    # De-duplicate by (source, title) keeping first occurrence (priority order).
    seen = set()
    deduped = []
    for item in results:
        key = (item["source"], item["title"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return _ke_ok(deduped[:50])


@dashboard_bp.route("/api/ke-context/refresh", methods=["GET", "POST"])
@require_login
def api_ke_context_refresh():
    """Re-ingest KE reports into contextual_intel, then return advisory+CBK results."""
    try:
        from ..scrapers.context_scraper import ingest_ke_reports
        ingest_ke_reports(get_storage())
    except Exception as exc:  # noqa: BLE001 - never fail refresh on ingest error
        logger.warning("ke-context refresh ingest failed: %s", exc)
    ctx = _ke_ctx()
    cbk = ctx.get_latest_cbk_totals()
    if cbk and cbk.get("period"):
        cbk["file_url"] = _ke_cbk_file_url(cbk["period"])
    return _ke_ok(
        {
            "ca_advisory_count": ctx.count_ca_advisories(),
            "cbk_latest": cbk,
        }
    )


# ── Health ─────────────────────────────────────────────────────────────────────


@dashboard_bp.route("/api/breaches/backfill", methods=["POST"])
@require_login
def api_breaches_backfill():
    """Trigger the one-time historical backfill of Kenyan ransomware victims.

    Admin only. Fetches all historical victims from ransomware.live where
    country == KE and inserts them into paste_hits so the Breach Directory
    is populated from day one.
    """
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user.is_admin:
        return jsonify({"error": "Admin only"}), 403
    try:
        from darkweb_scanner.scrapers.ransomware_scraper import (
            backfill_historical_kenyan_victims,
        )
        result = backfill_historical_kenyan_victims(storage)
        return jsonify({"ok": True, **result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/api/breaches/directory", methods=["GET"])
@require_login
def api_breaches_directory():
    """
    Return the breach directory: historical + recent Kenyan ransomware victims.

    Filters paste_hits for ransomware-related sources and patterns, then
    calculates aggregate stats (total_breaches, total_records_exposed,
    years_tracked). Each record includes title, description, sector,
    threat_actor, leak_url, date, status_badges, and records_exposed.
    """

    storage = get_storage()
    try:
        with storage.get_session() as session:
            from ..storage import PasteHit

            # Base filter: ransomware-related sources only.
            base_filter = (
                PasteHit.source.ilike("ransomware%"),
            )

            # Fetch all matching hits ordered by date (latest first).
            raw_hits = session.query(PasteHit).filter(*base_filter).order_by(PasteHit.found_at.desc()).all()

            # Deduplicate in Python
            seen = set()
            hits = []
            for h in raw_hits:
                key = h.victim or h.paste_id or h.id
                if key not in seen:
                    seen.add(key)
                    hits.append(h)

            total_breaches = len(hits)
            records = []
            total_records_exposed = 0
            oldest_date = None

            for h in hits:
                try:
                    records_exposed = int(h.ransom_amount or 0)
                except (ValueError, TypeError):
                    records_exposed = 0
                total_records_exposed += records_exposed

                if h.found_at:
                    if oldest_date is None or h.found_at < oldest_date:
                        oldest_date = h.found_at

                records.append({
                    "id": h.id,
                    "title": h.matched_value or "Unknown",
                    "description": h.context or "",
                    "sector": h.sector or "Unknown",
                    "threat_actor": h.group_name or "Unknown",
                    "leak_url": h.url or "",
                    "date": h.found_at.isoformat() if h.found_at else None,
                    "status_badges": getattr(h, "status_badges", None) or "RANSOMWARE",
                    "records_exposed": records_exposed,
                })

            # Calculate years tracked
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            if oldest_date:
                years_tracked = max(1, (now - oldest_date).days // 365)
            else:
                years_tracked = 0

            print(f"[api_breaches] Total raw: {len(raw_hits)}, Deduped: {len(hits)}", flush=True)

            return jsonify({
                "ok": True,
                "total_breaches": total_breaches,
                "total_records_exposed": total_records_exposed,
                "years_tracked": years_tracked,
                "breaches": records,
            })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route("/settings")
@require_login
def settings_page():
    return render_template("settings.html")


@dashboard_bp.route("/api/settings/profile", methods=["PUT"])
@require_login
def api_profile_update():
    body = request.get_json() or {}
    email = (body.get("email") or "").strip()
    storage = get_storage()
    user = storage.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": "user not found"}), 404
    user.email = email or user.email
    with storage.get_session() as s:
        s.merge(user)
        s.commit()
    return jsonify({"ok": True})


@dashboard_bp.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()})
