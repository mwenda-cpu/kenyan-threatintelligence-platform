"""Plain-dict serializers for the Threat Intelligence REST API."""

from datetime import datetime


def _iso(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def serialize_ioc(row):
    if hasattr(row, "__dict__") and not isinstance(row, dict):
        return {
            "id": getattr(row, "id", None),
            "indicator": getattr(row, "indicator", None),
            "type": getattr(row, "type", None),
            "threat_type": getattr(row, "threat_type", None),
            "source": getattr(row, "source", None),
            "date_added": _iso(getattr(row, "date_added", None)),
        }
    return {
        "id": row.get("id"),
        "indicator": row.get("indicator"),
        "type": row.get("type"),
        "threat_type": row.get("threat_type"),
        "source": row.get("source"),
        "date_added": _iso(row.get("date_added")),
    }


def serialize_session(row):
    if hasattr(row, "__dict__") and not isinstance(row, dict):
        return {
            "id": getattr(row, "id", None),
            "status": getattr(row, "status", None),
            "pages_crawled": getattr(row, "pages_crawled", 0) or 0,
            "hits_found": getattr(row, "hits_found", 0) or 0,
            "started_at": _iso(getattr(row, "started_at", None)),
        }
    return {
        "id": row.get("id"),
        "status": row.get("status"),
        "pages_crawled": row.get("pages_crawled", 0) or 0,
        "hits_found": row.get("hits_found", 0) or 0,
        "started_at": _iso(row.get("started_at")),
    }


def serialize_hit(row):
    if hasattr(row, "__dict__") and not isinstance(row, dict):
        return {
            "id": getattr(row, "id", None),
            "url": getattr(row, "url", None),
            "source_url": getattr(row, "source_url", None),
            "keyword": getattr(row, "keyword", None),
            "category": getattr(row, "category", None),
            "context": getattr(row, "context", None),
            "depth": getattr(row, "depth", None),
            "found_at": _iso(getattr(row, "found_at", None)),
            "alerted": getattr(row, "alerted", None),
            "session_id": getattr(row, "session_id", None),
        }
    return {
        "id": row.get("id"),
        "url": row.get("url"),
        "source_url": row.get("source_url"),
        "keyword": row.get("keyword"),
        "category": row.get("category"),
        "context": row.get("context"),
        "depth": row.get("depth"),
        "found_at": _iso(row.get("found_at")),
        "alerted": row.get("alerted"),
        "session_id": row.get("session_id"),
    }


def serialize_report(filename, created_at=None):
    return {"filename": filename, "created_at": _iso(created_at)}
