"""Read-only Threat Intelligence REST API routes."""

import os
import socket
import ssl
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import jsonify, request, send_file

from ...exposure_intel import shodan_search, urlscan_search
from ...storage import (
    AuditLog,
    CrawlSession,
    KECIRTAdvisory,
    KeywordHitRecord,
    ThreatIOC,
)
from .. import storage_helper as _storage_helper
from . import ti_api
from .audit import write_audit
from .auth import require_api_key
from .schemas import serialize_hit, serialize_ioc, serialize_session

# Sector keyword lists used by the ?sector= filter on /api/v1/threats.
# Additive only — when no sector param is supplied, behavior is unchanged.
SECTOR_KEYWORDS = {
    "fintech": [
        "M-Pesa", "Safaricom", "Airtel Money", "Pesalink", "Flutterwave",
        "Chipper Cash", "SIM swap", "SIM-swap", "agent fraud", "B2C reversal",
        "M-Pesa API", "Fuliza", "mobile money fraud", "pesa", "mpesa agent",
    ],
    "government": [
        "eCitizen", "KRA", "iTax", "IFMIS", "NTSA", "Huduma",
        "Ministry of Health", "Ministry of Interior",
    ],
    "banking": [
        "KCB", "Equity Bank", "Co-operative Bank", "NCBA", "Absa Kenya",
        "Stanbic", "Standard Chartered Kenya", "DTB",
    ],
}


def get_storage():
    return _storage_helper.get_storage()


def _reports_dir():
    try:
        import darkweb_scanner.dashboard.dashboard_routes as dr

        return dr.KE_REPORTS_DIR
    except Exception:
        return Path(os.getenv("DATA_DIR", "/app/data")) / "ke_reports"


def _now_iso():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def _ssl_issuer(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                return issuer.get("organizationName") or issuer.get("commonName")
    except Exception:
        return None


def _resolved_ips(domain):
    try:
        infos = socket.getaddrinfo(domain, None)
        return sorted({info[4][0] for info in infos})
    except Exception:
        return []


@ti_api.route("/", methods=["GET"])
def root():
    return jsonify({"name": "Kenya TI API", "version": "1.0", "docs": "/api/v1/health"})


@ti_api.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0"})


@ti_api.route("/iocs", methods=["GET"])
@require_api_key
def list_iocs():
    storage = get_storage()
    ioc_type = request.args.get("type")
    value = request.args.get("value")
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        offset = 0
    with storage.get_session() as db:
        q = db.query(ThreatIOC)
        if ioc_type:
            q = q.filter(ThreatIOC.type == ioc_type)
        if value:
            q = q.filter(ThreatIOC.indicator.ilike(f"%{value}%"))
        rows = (
            q.order_by(ThreatIOC.date_added.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
    return jsonify([serialize_ioc(r) for r in rows])


@ti_api.route("/advisories", methods=["GET"])
@require_api_key
def list_advisories():
    storage = get_storage()
    with storage.get_session() as db:
        rows = (
            db.query(KECIRTAdvisory)
            .order_by(KECIRTAdvisory.published_at.desc())
            .limit(100)
            .all()
        )
        return jsonify(
            [
                {
                    "id": r.id,
                    "title": r.title,
                    "url": r.url,
                    "published_at": r.published_at.isoformat() if r.published_at else None,
                    "summary": r.summary,
                    "severity": r.severity,
                    "source": r.source,
                }
                for r in rows
            ]
        )


@ti_api.route("/advisories/<int:advisory_id>/download", methods=["GET"])
@require_api_key
def download_advisory(advisory_id):
    storage = get_storage()
    with storage.get_session() as db:
        advisory = db.query(KECIRTAdvisory).filter(KECIRTAdvisory.id == advisory_id).first()
    if advisory is None:
        return jsonify({"error": "Not found"}), 404
    url = advisory.url or ""
    if not url.startswith("file:///"):
        return jsonify({"error": "Advisory is not a local PDF"}), 400
    prefix = "file:///app/data/ke_reports/"
    filename = url[len(prefix):] if url.startswith(prefix) else url.replace("file:///", "", 1)
    path = Path(os.getenv("DATA_DIR", "/app/data")) / "ke_reports" / filename
    if not path.exists():
        return jsonify({"error": "PDF file not found"}), 404
    write_audit(
        actor="api-key:" + (request.headers.get("X-API-Key") or "")[:6],
        action="download_advisory",
        target=f"advisory_id={advisory_id}",
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )
    return send_file(str(path), mimetype="application/pdf", as_attachment=False)


@ti_api.route("/iocs/<path:ioc_value>", methods=["GET"])
@require_api_key
def get_ioc(ioc_value):
    storage = get_storage()
    with storage.get_session() as db:
        ioc = (
            db.query(ThreatIOC)
            .filter(ThreatIOC.indicator == ioc_value)
            .first()
        )
        if ioc is None:
            ioc = (
                db.query(ThreatIOC)
                .filter(ThreatIOC.indicator.ilike(f"%{ioc_value}%"))
                .first()
            )
        if ioc is None:
            return jsonify({"error": "Not found"}), 404
        hits = (
            db.query(KeywordHitRecord)
            .filter(
                (KeywordHitRecord.keyword == ioc_value)
                | (KeywordHitRecord.url.ilike(f"%{ioc_value}%"))
            )
            .order_by(KeywordHitRecord.found_at.desc())
            .limit(50)
            .all()
        )
        session_ids = {h.session_id for h in hits if h.session_id is not None}
        sessions = []
        if session_ids:
            sessions = (
                db.query(CrawlSession)
                .filter(CrawlSession.id.in_(session_ids))
                .all()
            )
    return jsonify(
        {
            "ioc": serialize_ioc(ioc),
            "hits": [serialize_hit(h) for h in hits],
            "sessions": [serialize_session(s) for s in sessions],
        }
    )


@ti_api.route("/sessions", methods=["GET"])
@require_api_key
def list_sessions():
    storage = get_storage()
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        offset = 0
    with storage.get_session() as db:
        rows = (
            db.query(CrawlSession)
            .order_by(CrawlSession.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
    return jsonify([serialize_session(r) for r in rows])


@ti_api.route("/sessions/<int:session_id>/hits", methods=["GET"])
@require_api_key
def session_hits(session_id):
    storage = get_storage()
    try:
        limit = int(request.args.get("limit", 200))
    except (TypeError, ValueError):
        limit = 200
    rows = storage.get_hits_by_session(session_id, limit=limit)
    return jsonify([serialize_hit(r) for r in rows])


@ti_api.route("/threats", methods=["GET"])
@require_api_key
def list_threats():
    storage = get_storage()
    keyword = request.args.get("keyword")
    sector = (request.args.get("sector") or "").strip().lower()
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    if keyword:
        rows = storage.get_hits_by_keyword(keyword, limit=limit)
    elif sector and sector in SECTOR_KEYWORDS:
        with storage.get_session() as db:
            rows = (
                db.query(KeywordHitRecord)
                .filter(KeywordHitRecord.keyword.in_(SECTOR_KEYWORDS[sector]))
                .order_by(KeywordHitRecord.found_at.desc())
                .limit(limit)
                .all()
            )
    else:
        rows = storage.get_recent_hits(limit=limit)
    return jsonify([serialize_hit(r) for r in rows])


@ti_api.route("/audit", methods=["GET"])
@require_api_key
def list_audit():
    storage = get_storage()
    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    with storage.get_session() as db:
        rows = (
            db.query(AuditLog)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .all()
        )
    return jsonify(
        [
            {
                "id": r.id,
                "actor": r.actor,
                "action": r.action,
                "target": r.target,
                "ip": r.ip,
                "user_agent": r.user_agent,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    )


@ti_api.route("/reports", methods=["GET"])
@require_api_key
def list_reports():
    reports_dir = _reports_dir()
    items = []
    if reports_dir.is_dir():
        files = sorted(reports_dir.glob("*.pdf"))
        for idx, path in enumerate(files, start=1):
            try:
                created = datetime.fromtimestamp(
                    path.stat().st_mtime, tz=timezone.utc
                ).replace(tzinfo=None)
            except OSError:
                created = None
            items.append({"id": idx, "filename": path.name, "created_at": created.isoformat() if created else None})
    return jsonify(items)


@ti_api.route("/reports/<int:report_id>/download", methods=["GET"])
@require_api_key
def download_report(report_id):
    reports_dir = _reports_dir()
    files = sorted(reports_dir.glob("*.pdf")) if reports_dir.is_dir() else []
    if report_id < 1 or report_id > len(files):
        return jsonify({"error": "Not found"}), 404
    path = files[report_id - 1]
    write_audit(
        actor="api-key:" + (request.headers.get("X-API-Key") or "")[:6],
        action="download_report",
        target=f"report_id={report_id}",
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )
    return send_file(str(path), mimetype="application/pdf", as_attachment=False)


def _ioc_matches_for(storage, value):
    with storage.get_session() as db:
        rows = (
            db.query(ThreatIOC)
            .filter(ThreatIOC.indicator.ilike(f"%{value}%"))
            .limit(100)
            .all()
        )
    return [serialize_ioc(r) for r in rows]


@ti_api.route("/lookup/domain/<path:domain>", methods=["GET"])
@require_api_key
def lookup_domain(domain):
    storage = get_storage()
    ioc_matches = _ioc_matches_for(storage, domain)
    shodan_key = (os.getenv("SHODAN_API_KEY") or "").strip()
    urlscan_key = (os.getenv("URLSCAN_API_KEY") or "").strip()
    if shodan_key:
        try:
            shodan_result = shodan_search(domain)
        except Exception:
            shodan_result = {"error": "request failed", "results": []}
    else:
        shodan_result = "unavailable"
    if urlscan_key:
        try:
            urlscan_result = urlscan_search(domain)
        except Exception:
            urlscan_result = {"error": "request failed", "results": []}
    else:
        urlscan_result = "unavailable"
    score = 100 - min(50, len(ioc_matches) * 10)
    if score < 0:
        score = 0
    return jsonify(
        {
            "domain": domain,
            "reputation_score": score,
            "sources": {
                "internal": ioc_matches,
                "shodan": shodan_result,
                "urlscan": urlscan_result,
            },
            "ioc_matches": ioc_matches,
            "ssl_issuer": _ssl_issuer(domain),
            "resolved_ips": _resolved_ips(domain),
            "created_at": _now_iso(),
        }
    )


@ti_api.route("/lookup/ip/<ip>", methods=["GET"])
@require_api_key
def lookup_ip(ip):
    storage = get_storage()
    ioc_matches = _ioc_matches_for(storage, ip)
    shodan_key = (os.getenv("SHODAN_API_KEY") or "").strip()
    urlscan_key = (os.getenv("URLSCAN_API_KEY") or "").strip()
    if shodan_key:
        try:
            shodan_result = shodan_search(ip)
        except Exception:
            shodan_result = {"error": "request failed", "results": []}
    else:
        shodan_result = "unavailable"
    if urlscan_key:
        try:
            urlscan_result = urlscan_search(ip)
        except Exception:
            urlscan_result = {"error": "request failed", "results": []}
    else:
        urlscan_result = "unavailable"
    score = 100 - min(50, len(ioc_matches) * 10)
    if score < 0:
        score = 0
    return jsonify(
        {
            "ip": ip,
            "reputation_score": score,
            "sources": {
                "internal": ioc_matches,
                "shodan": shodan_result,
                "urlscan": urlscan_result,
            },
            "ioc_matches": ioc_matches,
            "ssl_issuer": None,
            "resolved_ips": [ip],
            "created_at": _now_iso(),
        }
    )

@ti_api.route("/export/stix", methods=["GET"])
@require_api_key
def export_stix():
    storage = get_storage()
    with storage.get_session() as db:
        rows = (
            db.query(ThreatIOC)
            .order_by(ThreatIOC.date_added.desc())
            .limit(100)
            .all()
        )
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    result = []
    for row in rows:
        ioc_type = (getattr(row, "type", "") or "").strip().lower()
        indicator = getattr(row, "indicator", "") or ""
        if "domain" in ioc_type:
            pattern = f"[domain-name:value = '{indicator}']"
        elif "ip" in ioc_type:
            pattern = f"[ipv4-addr:value = '{indicator}']"
        else:
            pattern = f"[url:value = '{indicator}']"
        created = getattr(row, "date_added", None)
        created_iso = created.isoformat() if hasattr(created, "isoformat") else (created or now)
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": created_iso,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": created_iso,
        }
        result.append(obj)
    write_audit(
        actor="api-key:" + (request.headers.get("X-API-Key") or "")[:6],
        action="export_stix",
        target=f"count={len(result)}",
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )
    return jsonify(result)


@ti_api.route("/alerts/test", methods=["POST"])
@require_api_key
def alerts_test():
    body = request.get_json(silent=True) or {}
    webhook_url = (body.get("webhook_url") or "").strip()
    if not webhook_url:
        return jsonify({"error": "webhook_url required"}), 400
    write_audit(
        actor="api-key:" + (request.headers.get("X-API-Key") or "")[:6],
        action="send_webhook",
        target=webhook_url,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )
    try:
        resp = requests.post(
            webhook_url,
            json={"text": "🚨 Test Alert from Kenya Threat Intel Platform"},
            timeout=10,
        )
        if resp.status_code < 400:
            return jsonify({"success": True, "status_code": resp.status_code})
        return jsonify({"success": False, "status_code": resp.status_code}), 502
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 502
