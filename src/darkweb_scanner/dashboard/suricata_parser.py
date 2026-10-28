"""Suricata eve.json log ingestion for DDoS monitoring."""

import json
import os
from datetime import datetime
from pathlib import Path


def _log_path() -> Path:
    return Path(os.getenv("SURICATA_LOG_PATH", "/app/data/suricata-logs/eve.json"))


def _offset_path(log_path: Path) -> Path:
    return log_path.parent / ".offset"


def _rotate_eve_json(log_path: Path) -> None:
    """Rotate eve.json when it exceeds 50 MB, keeping at most 5 rotated files.

    Uses rotate-and-rename so Suricata can keep writing; the renamed file is
    left for Suricata to release on its next reopen (or on container restart).
    """
    try:
        max_size = 50 * 1024 * 1024
        if not log_path.exists():
            return
        size = log_path.stat().st_size
        if size <= max_size:
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rotated = log_path.parent / f"eve.json.{stamp}"
        log_path.rename(rotated)
        # Reset the offset so parsing restarts from the new (empty) file.
        try:
            _offset_path(log_path).write_text("0", encoding="utf-8")
        except Exception:
            pass
        # Keep only the 5 most recent rotated files; delete the oldest beyond 5.
        rotated_files = sorted(
            [p for p in log_path.parent.iterdir()
             if p.name.startswith("eve.json.") and p.is_file()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for old in rotated_files[5:]:
            try:
                old.unlink()
            except Exception:
                pass
        print(f"[Suricata] Rotated eve.json (was {size / (1024 * 1024):.1f} MB)", flush=True)
    except Exception as e:
        print(f"[Suricata] rotation error: {e}", flush=True)


def process_suricata_alerts(storage) -> None:
    """Read new Suricata alerts and save them as hits. Fails silently."""
    print("[Suricata] parser tick", flush=True)
    try:
        log_path = _log_path()
        _rotate_eve_json(log_path)
        if not log_path.exists():
            return

        size = log_path.stat().st_size
        if size == 0:
            return

        offset_path = _offset_path(log_path)

        # First run: if offset file is missing/empty, seek to end so we
        # don't replay the entire file history.
        offset_raw = ""
        try:
            offset_raw = offset_path.read_text(encoding="utf-8").strip()
        except Exception:
            offset_raw = ""

        if offset_raw == "":
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(0, 2)
                    offset = fh.tell()
                offset_path.write_text(str(offset), encoding="utf-8")
            except Exception:
                pass
            return

        try:
            offset = int(offset_raw)
        except Exception:
            offset = 0
        if offset > size or offset < 0:
            offset = 0

        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            while True:
                line = fh.readline()
                if not line:
                    break
                offset = fh.tell()
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except Exception:
                    continue
                if event.get("event_type") != "alert":
                    continue

                alert = event.get("alert") or {}
                src_ip = event.get("src_ip")
                dest_ip = event.get("dest_ip")
                signature = alert.get("signature") or "Suricata Alert"

                try:
                    storage.save_hit(
                        url=f"DDoS: {src_ip} -> {dest_ip}",
                        keyword=signature,
                        category="DDoS",
                        context="",
                        position=0,
                        depth=0,
                        session_id=None,
                    )
                except Exception:
                    pass

                try:
                    from .dashboard_routes import send_webhook_alert

                    send_webhook_alert(f"⚠️ DDoS Alert: {signature} from {src_ip}")
                except Exception:
                    pass

        try:
            offset_path.write_text(str(offset), encoding="utf-8")
        except Exception:
            pass
    except Exception as e:
        print(f"[Suricata] parser error: {e}", flush=True)
