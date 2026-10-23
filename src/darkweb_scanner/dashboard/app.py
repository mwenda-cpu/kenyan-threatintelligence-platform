"""
Flask application factory — wires up auth + dashboard blueprints.
"""

import json
import logging
import os
from datetime import timedelta
from pathlib import Path

import requests
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import text
from werkzeug.middleware.proxy_fix import ProxyFix

# Config is read-only at /app/config; resolve repo-relative paths so seeding
# works both from the installed package and from a source checkout.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_SOURCES_JSON = _REPO_ROOT / "config" / "sources.json"


def _seed_onion_seeds(storage) -> int:
    """Populate the ``seeds`` table with .onion URLs on every startup.

    Reads ``onion_seeds`` from ``config/sources.json``; when the file is
    missing or empty (no ``onion_seeds``), falls back to the well-known
    ransomware leak-site URLs in ``ransomware_data.py``. Then fetches live
    leak-site URLs from ransomware.live v2/groups (groups whose locations
    have ``available: True`` and an ``fqdn`` ending in ``.onion``).
    Inserts are idempotent (INSERT OR IGNORE on SQLite / ON CONFLICT DO
    NOTHING on PostgreSQL) so re-running is safe. Returns the total number
    of *new* rows inserted.
    """
    from ..ransomware_data import RANSOMWARE_ONION_SEEDS

    urls: list[str] = []
    try:
        if _SOURCES_JSON.exists():
            data = json.loads(_SOURCES_JSON.read_text(encoding="utf-8") or "{}")
            urls = [str(u) for u in (data.get("onion_seeds") or []) if u]
    except Exception:
        urls = []

    if not urls:
        urls = list(RANSOMWARE_ONION_SEEDS)

    dialect = storage.engine.dialect.name
    inserted = 0
    with storage.get_session() as session:
        for url in urls:
            if dialect == "sqlite":
                stmt = text(
                    "INSERT OR IGNORE INTO seeds (url, source_type, active) "
                    "VALUES (:url, 'onion', 1)"
                )
            else:
                stmt = text(
                    "INSERT INTO seeds (url, source_type, active) "
                    "VALUES (:url, 'onion', TRUE) "
                    "ON CONFLICT (url) DO NOTHING"
                )
            result = session.execute(stmt, {"url": url})
            inserted += result.rowcount or 0
        session.commit()

    # ── Live seeding from ransomware.live v2/groups ────────────────────────
    live_urls, skipped = _fetch_live_onion_seeds()
    inserted_live = 0
    if live_urls:
        with storage.get_session() as session:
            for url in live_urls:
                if dialect == "sqlite":
                    stmt = text(
                        "INSERT OR IGNORE INTO seeds (url, source_type, active) "
                        "VALUES (:url, 'onion_live', 1)"
                    )
                else:
                    stmt = text(
                        "INSERT INTO seeds (url, source_type, active) "
                        "VALUES (:url, 'onion_live', TRUE) "
                        "ON CONFLICT (url) DO NOTHING"
                    )
                result = session.execute(stmt, {"url": url})
                inserted_live += result.rowcount or 0
            session.commit()

    # Deactivate static seeds that have failed 3+ crawl attempts.
    try:
        with storage.get_session() as session:
            session.execute(
                text(
                    "UPDATE seeds SET active = FALSE "
                    "WHERE attempt_count >= 3 AND source_type = 'onion'"
                )
            )
            session.commit()
    except Exception:
        # attempt_count column may not exist yet on very first boot before
        # migration; deactivation is best-effort.
        pass

    print(
        f"[startup] seeded {inserted_live} new onion URLs from ransomware.live ({skipped} unavailable skipped)",
        flush=True,
    )
    return inserted + inserted_live


def _fetch_live_onion_seeds() -> tuple[list[str], int]:
    """Fetch live .onion leak-site URLs from ransomware.live v2/groups.

    For each group, scan ``locations[]`` for entries where ``available`` is
    True and ``fqdn`` ends with ``.onion``; take the first match per group.
    Returns ``(urls, skipped_count)`` where skipped counts unavailable
    locations. Best-effort: any network/parse failure yields ([], 0).
    """
    url = "https://api.ransomware.live/v2/groups"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        groups = resp.json()
    except Exception:  # noqa: BLE001 - live seeding is best-effort
        return [], 0

    if not isinstance(groups, list):
        return [], 0

    live_urls: list[str] = []
    skipped = 0
    for group in groups:
        locations = group.get("locations") or []
        if not isinstance(locations, list):
            continue
        for loc in locations:
            if not isinstance(loc, dict):
                continue
            if not loc.get("available"):
                skipped += 1
                continue
            fqdn = str(loc.get("fqdn") or "").strip()
            if fqdn.endswith(".onion"):
                if fqdn.startswith(("http://", "https://")):
                    live_urls.append(fqdn)
                else:
                    live_urls.append(f"http://{fqdn}")
                break

    return live_urls, skipped


def create_app() -> Flask:
    # Guarantee all logger.* calls (scheduler.py, crawler.py, app.py) appear in
    # docker logs regardless of whether gunicorn/werkzeug configured logging.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        force=True,
    )
    app = Flask(__name__)

    _secret = os.getenv("DASHBOARD_SECRET_KEY", "")
    _PLACEHOLDER = "change-me-in-production"
    if not _secret or _secret == _PLACEHOLDER or _secret == "change-me-to-a-long-random-string":
        raise RuntimeError(
            "DASHBOARD_SECRET_KEY is not set or still uses the placeholder value. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
            "and set it in .env before starting the dashboard."
        )
    app.secret_key = _secret
    app.permanent_session_lifetime = timedelta(hours=12)

    # Secure session cookies behind Nginx + ngrok HTTPS termination.
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax'
    )

    # Trust X-Forwarded-Proto from nginx so url_for generates https:// URLs
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    from .auth_routes import auth_bp
    from .channel_monitor_routes import channel_monitor_bp
    from .dashboard_routes import KE_REPORT_MAX_BYTES, check_ke_reports_dir, dashboard_bp
    from .ransomware_live_routes import rw_live_bp
    from .storage_helper import close_db, get_storage
    try:
        from ..scheduler import is_running, start
    except ImportError as _exc:
        print(
            "Scheduler could not be imported (%s); dashboard will boot without it.",
            _exc,
            flush=True,
        )

        def _is_running() -> bool:
            return True

        def _start():
            return None

        is_running = _is_running
        start = _start

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(channel_monitor_bp)
    app.register_blueprint(rw_live_bp)
    app.teardown_appcontext(close_db)

    # ── Database: create tables + populate the onion seed list ──
    # get_storage() runs create_all() (the `seeds` table exists via the
    # Storage.Seed model), then we seed it from config/sources.json.
    _seed_onion_seeds(get_storage())

    # ── Background scheduler (real-time IOC/ransomware/KE-context collection) ──
    print(f"[startup] scheduler.is_running() = {is_running()}", flush=True)
    if not is_running():
        start()
    print("[startup] scheduler.start() invoked", flush=True)

    # Cap request bodies (report uploads); the route enforces the tighter
    # per-file limit itself.
    app.config["MAX_CONTENT_LENGTH"] = KE_REPORT_MAX_BYTES + (1024 * 1024)

    @app.errorhandler(413)
    def _payload_too_large(_exc):
        return jsonify({"ok": False, "error": "Uploaded file is too large."}), 413

    # Report uploads need a writable data dir; warn early if it is not.
    check_ke_reports_dir()

    @app.route("/")
    def root():
        if session.get("logged_in"):
            return redirect(url_for("dashboard.index"))
        return redirect(url_for("auth.login"))

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("DASHBOARD_PORT", "8080"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
