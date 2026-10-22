"""
Async port scanning and directory enumeration engine for DNS investigations.

All scans run through the Tor SOCKS5 proxy (127.0.0.1:9050) so that .onion
and Tor-hidden targets are reachable. Results are stored in an in-memory
task registry keyed by a UUID task_id.

Fallback chain:
  1. Try Tor SOCKS5 proxy (socks5h://127.0.0.1:9050)
  2. Fall back to direct socket connection if Tor is unavailable
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Tor SOCKS5 proxy ──────────────────────────────────────────────────────
TOR_PROXY = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

# ── Common ports to scan ──────────────────────────────────────────────────
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]


# ── In-memory task registry ───────────────────────────────────────────────
_task_lock = threading.Lock()
_tasks: dict[str, dict] = {}


def _new_task() -> str:
    tid = uuid.uuid4().hex
    with _task_lock:
        _tasks[tid] = {
            "id": tid,
            "status": "pending",   # pending | running | completed | failed
            "created_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "result": None,
            "error": None,
        }
    return tid


def _set_task(tid: str, **fields):
    with _task_lock:
        if tid in _tasks:
            _tasks[tid].update(fields)


def get_task(tid: str) -> Optional[dict]:
    with _task_lock:
        return _tasks.get(tid)


# ── Port scanner (Tor-routed TCP connect) ─────────────────────────────────
def _is_onion(host: str) -> bool:
    return host.endswith(".onion")


def _resolve_host(host: str) -> Optional[str]:
    """Resolve a hostname to an IP. Returns None if unresolvable."""
    try:
        ip = socket.gethostbyname(host)
        logger.info("[scan_engine] Resolved %s -> %s", host, ip)
        return ip
    except Exception as exc:
        logger.warning("[scan_engine] Could not resolve %s: %s", host, exc)
        return None


def _scan_port_tcp(host: str, port: int, timeout: float = 3.0) -> bool:
    """Attempt a TCP connect to a single port.

    Tries Tor SOCKS5 proxy first, falls back to direct connection.
    """
    # Try Tor proxy first
    try:
        import socks  # type: ignore
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        logger.info("[scan_engine] Port %s/%s OPEN (via Tor)", host, port)
        return True
    except Exception as exc:
        logger.debug("[scan_engine] Port %s/%s Tor failed: %s", host, port, exc)

    # Fallback: direct connection (clearnet targets only, not .onion)
    if not _is_onion(host):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
            logger.info("[scan_engine] Port %s/%s OPEN (direct)", host, port)
            return True
        except Exception as exc:
            logger.debug("[scan_engine] Port %s/%s direct failed: %s", host, port, exc)

    return False


def scan_ports(target: str, ports: Optional[list[int]] = None) -> dict:
    """Scan common ports on a target. Returns {port: open/closed}."""
    ports = ports or COMMON_PORTS
    ip = _resolve_host(target)
    if not ip:
        return {"error": f"Could not resolve {target}", "ports": {}}

    logger.info("[scan_engine] Scanning %s (%s) on %d ports", target, ip, len(ports))
    results = {}
    for port in ports:
        open_flag = _scan_port_tcp(ip, port)
        results[str(port)] = "open" if open_flag else "closed"

    open_count = sum(1 for v in results.values() if v == "open")
    logger.info("[scan_engine] Scan complete: %d open ports out of %d", open_count, len(ports))
    return {"target": target, "ip": ip, "ports": results}


# ── Directory enumerator (HTTP-based, Tor-proxied) ────────────────────────
COMMON_PATHS = [
    "/admin", "/administrator", "/login", "/wp-login", "/wp-admin",
    "/phpmyadmin", "/config", "/.env", "/.git", "/backup", "/api",
    "/api/v1", "/api/v2", "/robots.txt", "/sitemap.xml", "/.well-known",
    "/server-status", "/manager", "/console", "/webmail", "/cpanel",
]


def _enum_path(url: str, timeout: float = 10.0) -> Optional[int]:
    """Try a single path, return HTTP status code or None on failure."""
    try:
        resp = requests.get(
            url,
            proxies=TOR_PROXY,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; OSINTPH-Scanner/1.0)"},
            allow_redirects=False,
        )
        logger.debug("[scan_engine] %s -> %d", url, resp.status_code)
        return resp.status_code
    except Exception as exc:
        logger.debug("[scan_engine] %s failed: %s", url, exc)
        return None


def enumerate_dirs(target: str, paths: Optional[list[str]] = None) -> dict:
    """Enumerate common directories on a target. Returns {path: status_code}."""
    paths = paths or COMMON_PATHS

    # Determine scheme — .onion sites are always http
    if _is_onion(target):
        base = f"http://{target}"
    else:
        base = f"http://{target}"

    logger.info("[scan_engine] Enumerating %d paths on %s", len(paths), target)
    results = {}
    for path in paths:
        url = base.rstrip("/") + path
        status = _enum_path(url)
        if status is not None:
            results[path] = status

    logger.info("[scan_engine] Enum complete: %d paths found with responses", len(results))
    return {"target": target, "base": base, "paths": results}


# ── Combined scan runner (background task) ────────────────────────────────
def run_scan(task_id: str, target: str, scan_ports_flag: bool, scan_dirs_flag: bool):
    """Run port scan and/or directory enumeration in a background thread."""
    _set_task(task_id, status="running")
    result: dict = {}

    try:
        if scan_ports_flag:
            logger.info("[scan_engine] Starting port scan for %s", target)
            result["port_scan"] = scan_ports(target)
        if scan_dirs_flag:
            logger.info("[scan_engine] Starting dir enum for %s", target)
            result["dir_enum"] = enumerate_dirs(target)

        _set_task(task_id, status="completed", result=result,
                  completed_at=datetime.now(timezone.utc).isoformat())
        logger.info("[scan_engine] Task %s completed successfully", task_id)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Scan task %s failed: %s", task_id, exc)
        _set_task(task_id, status="failed", error=str(exc),
                  completed_at=datetime.now(timezone.utc).isoformat())


def start_scan(target: str, scan_ports_flag: bool, scan_dirs_flag: bool) -> str:
    """Start a background scan and return the task_id."""
    tid = _new_task()
    t = threading.Thread(
        target=run_scan, args=(tid, target, scan_ports_flag, scan_dirs_flag),
        daemon=True,
    )
    t.start()
    logger.info("[scan_engine] Started scan task %s for target %s (ports=%s, dirs=%s)",
                tid, target, scan_ports_flag, scan_dirs_flag)
    return tid
