"""Suricata eve.json log ingestion for DDoS monitoring."""

import json
import os
from pathlib import Path


def _log_path() -> Path:
    return Path(os.getenv("SURICATA_LOG_PATH", "/app/data/suricata-logs/eve.json"))


def _offset_path(log_path: Path) -> Path:
    return log_path.parent / ".offset"


def process_suricata_alerts(storage) -> None:
    """Read new Suricata alerts and save them as hits. Fails silently."""
    print("[Suricata] parser tick", flush=True)
    try:
        log_path = _log_path()
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
