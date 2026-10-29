"""
Channel Monitor blueprint — Telegram channel scraping tab.
Integrates channel_monitor.py into the threat intelligence dashboard.
"""

import csv
import io
import os
import shutil
import tempfile
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, after_this_request, jsonify, request, send_file

from ..auth import require_login
from ..keywords_db import keyword_config
from ..scanner import Scanner
from .storage_helper import get_storage

channel_monitor_bp = Blueprint("channel_monitor", __name__)

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
CHANNEL_MONITOR_DIR = DATA_DIR / "channel_monitor"

# Cap on total source bytes zipped for a single download. Building to a temp
# file (rather than streaming) is bounded by disk, not memory, but we still
# want a clear failure instead of silently filling the data volume.
MAX_DOWNLOAD_SOURCE_BYTES = int(os.getenv("CHANNEL_MONITOR_MAX_DOWNLOAD_GB", "5")) * (1024 ** 3)

# In-memory job store  { job_id: { status, log, output_dir, started_at, config } }
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _ensure_dirs():
    CHANNEL_MONITOR_DIR.mkdir(parents=True, exist_ok=True)


def _new_job_id() -> str:
    import uuid
    return uuid.uuid4().hex[:12]


def _get_telegram_creds() -> dict:
    """Read Telegram API creds from env or DATA_DIR/.env style file."""
    return {
        "api_id":    os.getenv("TELEGRAM_API_ID", ""),
        "api_hash":  os.getenv("TELEGRAM_API_HASH", ""),
        "phone":     os.getenv("TELEGRAM_PHONE", ""),
    }


# ── Status / Credential check ─────────────────────────────────────────────────

@channel_monitor_bp.route("/api/channel-monitor/credentials", methods=["GET"])
@require_login
def api_cm_credentials():
    """Return whether Telegram credentials are configured."""
    creds = _get_telegram_creds()
    configured = bool(creds["api_id"] and creds["api_hash"] and creds["phone"])
    return jsonify({
        "configured": configured,
        "has_api_id":   bool(creds["api_id"]),
        "has_api_hash": bool(creds["api_hash"]),
        "has_phone":    bool(creds["phone"]),
    })


# ── Job management ────────────────────────────────────────────────────────────

@channel_monitor_bp.route("/api/channel-monitor/jobs", methods=["GET"])
@require_login
def api_cm_jobs_list():
    with _jobs_lock:
        jobs = []
        for jid, j in _jobs.items():
            jobs.append({
                "id":         jid,
                "status":     j["status"],
                "channel":    j["config"].get("channel", ""),
                "started_at": j["started_at"],
                "ended_at":   j.get("ended_at"),
                "log_lines":  len(j["log"]),
                "error":      j.get("error"),
            })
        jobs.sort(key=lambda x: x["started_at"], reverse=True)
        return jsonify(jobs)


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>", methods=["GET"])
@require_login
def api_cm_job_get(job_id: str):
    with _jobs_lock:
        j = _jobs.get(job_id)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "id":         job_id,
        "status":     j["status"],
        "channel":    j["config"].get("channel", ""),
        "config":     j["config"],
        "started_at": j["started_at"],
        "ended_at":   j.get("ended_at"),
        "log":        j["log"],
        "error":      j.get("error"),
    })


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>/log", methods=["GET"])
@require_login
def api_cm_job_log(job_id: str):
    """Return only the log lines (optionally since a given index)."""
    since = int(request.args.get("since", 0))
    with _jobs_lock:
        j = _jobs.get(job_id)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({
        "status": j["status"],
        "log":    j["log"][since:],
        "total":  len(j["log"]),
    })


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>/download", methods=["GET"])
@require_login
def api_cm_job_download(job_id: str):
    """Build a ZIP containing a CSV of the saved hits for this job.

    The scrape worker no longer writes files to ``output_dir``; instead every
    hit is persisted to the database (keyed by the job's crawl session). We
    read those hits back and render them into a CSV inside the ZIP so the
    download is never an empty stub.
    """
    with _jobs_lock:
        j = _jobs.get(job_id)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    if j["status"] not in ("completed", "error"):
        return jsonify({"error": "Job still running"}), 400

    storage = get_storage()
    session_id = j["config"].get("session_id")
    hits = storage.get_hits_by_session(session_id, limit=10000) if session_id else []

    channel = j["config"].get("channel", "channel").replace("/", "_").replace("@", "")
    ts = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y%m%d_%H%M")
    zip_filename = f"channel_monitor_{channel}_{ts}.zip"

    # Render hits into a CSV in memory.
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["job_id", "channel", "url", "keyword", "category", "context", "position", "found_at"])
    for h in hits:
        url = h.url or ""
        parts = url.rstrip("/").split("/")
        ch = parts[3] if len(parts) > 3 else ""
        writer.writerow([
            job_id,
            ch,
            url,
            h.keyword or "",
            h.category or "",
            h.context or "",
            h.position if h.position is not None else "",
            h.found_at.isoformat() if h.found_at else "",
        ])
    csv_bytes = buf.getvalue().encode("utf-8")

    _ensure_dirs()
    fd, tmp_path = tempfile.mkstemp(suffix=".zip", prefix="cm_download_", dir=CHANNEL_MONITOR_DIR)
    try:
        with os.fdopen(fd, "wb") as fh:
            with zipfile.ZipFile(fh, "w", zipfile.ZIP_STORED) as zf:
                zf.writestr(f"channel_monitor_{channel}_{ts}.csv", csv_bytes)
            fh.flush()
            os.fsync(fh.fileno())
            bytes_written = fh.tell()

        on_disk_size = os.path.getsize(tmp_path)
        if on_disk_size == 0 or on_disk_size != bytes_written:
            raise IOError(
                f"ZIP write mismatch for job {job_id}: wrote {bytes_written} "
                f"bytes but {on_disk_size} are on disk"
            )
        if not zipfile.is_zipfile(tmp_path):
            raise IOError(f"ZIP integrity check failed for job {job_id}: no valid EOCD record")
    except Exception as exc:
        os.unlink(tmp_path)
        return jsonify({"error": f"Failed to build ZIP: {exc}"}), 500

    @after_this_request
    def _cleanup_tmp_zip(response):
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return response

    return send_file(
        tmp_path,
        mimetype="application/zip",
        as_attachment=True,
        download_name=zip_filename,
    )


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>/results", methods=["GET"])
@require_login
def api_cm_job_results(job_id: str):
    """Return the saved hits for a channel-monitor job as a JSON list.

    Each entry: {channel, time, message_text, keyword_hit}.
    """
    with _jobs_lock:
        j = _jobs.get(job_id)
    if not j:
        return jsonify({"error": "Job not found"}), 404

    storage = get_storage()
    session_id = j["config"].get("session_id")
    hits = storage.get_hits_by_session(session_id, limit=500) if session_id else []

    results = []
    for h in hits:
        url = h.url or ""
        parts = url.rstrip("/").split("/")
        channel = parts[3] if len(parts) > 3 else ""
        results.append({
            "channel": channel,
            "time": h.found_at.isoformat() if h.found_at else "",
            "message_text": h.context or "",
            "keyword_hit": h.keyword or "",
        })

    return jsonify({"job_id": job_id, "results": results})


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>/stop", methods=["POST"])
@require_login
def api_cm_job_stop(job_id: str):
    """Mark a running channel-monitor job for cancellation."""
    with _jobs_lock:
        j = _jobs.get(job_id)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    if j["status"] not in ("running",):
        return jsonify({"status": j["status"]})
    with _jobs_lock:
        j["cancel_requested"] = True
        j["status"] = "stopping"
    return jsonify({"status": "stopping"})


@channel_monitor_bp.route("/api/channel-monitor/jobs/<job_id>", methods=["DELETE"])
@require_login
def api_cm_job_delete(job_id: str):
    with _jobs_lock:
        j = _jobs.pop(job_id, None)
    if not j:
        return jsonify({"error": "Job not found"}), 404
    # Clean up output directory
    try:
        if j.get("output_dir"):
            shutil.rmtree(j["output_dir"], ignore_errors=True)
    except Exception:
        pass
    return jsonify({"ok": True})


# ── Start a scan ──────────────────────────────────────────────────────────────

@channel_monitor_bp.route("/api/channel-monitor/start", methods=["POST"])
@require_login
def api_cm_start():
    body = request.get_json() or {}

    channels_raw = body.get("channels")
    if isinstance(channels_raw, str):
        channels_raw = [c.strip() for c in channels_raw.split(",") if c.strip()]
    channels = [c.strip().lstrip("@") for c in (channels_raw or []) if c and str(c).strip()]
    # Backward compat: single `channel` field
    if not channels and body.get("channel"):
        channels = [str(body.get("channel")).strip().lstrip("@")]
    if not channels:
        return jsonify({"error": "channel(s) required"}), 400

    creds = _get_telegram_creds()
    if not (creds["api_id"] and creds["api_hash"] and creds["phone"]):
        return jsonify({"error": "Telegram credentials not configured. Add TELEGRAM_API_ID, TELEGRAM_API_HASH and TELEGRAM_PHONE to your .env"}), 400

    storage = get_storage()
    session_id = storage.create_crawl_session(channels)

    config = {
        "channels":      channels,
        "channel":       ", ".join(channels),
        "session_id":    session_id,
        "limit":         int(body.get("limit", 200)),
        "days":          int(body.get("days")) if body.get("days") else None,
        "lang":          (body.get("lang") or "").strip() or None,
        "max_video_mb":  int(body.get("max_video_mb", 50)),
        "min_space_gb":  float(body.get("min_space_gb", 1.0)),
        "skip_english":  bool(body.get("skip_english", False)),
    }

    job_id = _new_job_id()
    _ensure_dirs()
    output_dir = CHANNEL_MONITOR_DIR / job_id
    output_dir.mkdir(parents=True, exist_ok=True)

    job = {
        "status":        "running",
        "config":        config,
        "output_dir":    str(output_dir),
        "started_at":    datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "ended_at":      None,
        "log":           [],
        "error":         None,
        "cancel_requested": False,
    }

    with _jobs_lock:
        _jobs[job_id] = job

    def run():
        def log_func(msg: str):
            with _jobs_lock:
                if job_id in _jobs:
                    _jobs[job_id]["log"].append(msg)

        try:
            _run_channel_monitor(config, log_func, job_id)
            with _jobs_lock:
                if job_id in _jobs:
                    _jobs[job_id]["status"] = "completed"
                    _jobs[job_id]["ended_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
            log_func("[✓] Scan completed successfully. Click Download to get results.")
        except Exception as e:
            import traceback
            with _jobs_lock:
                if job_id in _jobs:
                    _jobs[job_id]["status"] = "error"
                    _jobs[job_id]["error"] = str(e)
                    _jobs[job_id]["ended_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
                    _jobs[job_id]["log"].append(f"[✗] Fatal error: {e}")
                    _jobs[job_id]["log"].append(traceback.format_exc())

    t = threading.Thread(target=run, daemon=True, name=f"cm_{job_id}")
    t.start()

    return jsonify({"ok": True, "job_id": job_id})


# ── The channel monitor worker ────────────────────────────────────────────────

def _run_channel_monitor(config: dict, log_func, job_id=None):
    """Run the Telegram channel monitor in an isolated event loop.

    The whole scrape runs inside a brand-new asyncio event loop created on this
    thread, so it never shares or conflicts with Flask's main-thread loop.
    """
    import asyncio

    def run_in_thread(coro):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    from ..telegram_scraper import TelegramConfig, scrape_channels

    storage = get_storage()
    session_id = config["session_id"]

    # Build the keyword scanner from the active keyword list so hits are
    # persisted to the database keyed by this job's crawl session.
    kw_cfg = keyword_config(storage, [Path("/app/data/keywords.yaml")])
    scanner = Scanner(kw_cfg)

    cfg = TelegramConfig(
        api_id=int(os.getenv("TELEGRAM_API_ID")),
        api_hash=os.getenv("TELEGRAM_API_HASH"),
        session_path=os.getenv("TELEGRAM_SESSION_PATH"),
        session_string=os.getenv("TELEGRAM_SESSION_STRING"),
        channels=config["channels"],
        limit_per_channel=config.get("limit", 200),
    )

    log_func(f"[+] Starting channel monitor for: {', '.join(config['channels'])}")
    log_func(f"[i] Settings: limit={cfg.limit_per_channel}, session_id={session_id}")

    # Honor a user-requested stop before beginning the scrape.
    if job_id and _jobs.get(job_id, {}).get("cancel_requested"):
        log_func("[X] Scan cancelled by user before starting.")
        return

    try:
        results = run_in_thread(
            scrape_channels(
                cfg,
                scanner=scanner,
                storage=storage,
                alerter=None,
                session_id=session_id,
            )
        )
        storage.update_crawl_session(
            session_id,
            results.get("pages_scraped", 0),
            results.get("hits_found", 0),
            status="completed",
        )
        log_func(
            f"[+] Scan complete. Processed {results.get('pages_scraped', 0)} "
            f"message(s), {results.get('hits_found', 0)} hit(s)."
        )
    except Exception as e:
        try:
            storage.update_crawl_session(session_id, 0, 0, status="failed")
        except Exception:
            pass
        log_func(f"[X] Telegram connection failed: {e}")
        raise
