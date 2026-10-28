"""Audit-log helper for sensitive Threat Intelligence API actions.

``write_audit`` persists an ``AuditLog`` row for security-relevant actions
(STIX export, webhook tests, report downloads). It is best-effort: any
failure is swallowed so a logging problem can never break the calling
request.
"""

from __future__ import annotations

from ...storage import AuditLog
from .. import storage_helper as _storage_helper


def write_audit(actor: str, action: str, target: str, ip: str, user_agent: str) -> None:
    """Insert an audit row. Never raises."""
    try:
        storage = _storage_helper.get_storage()
        with storage.get_session() as db:
            db.add(
                AuditLog(
                    actor=actor,
                    action=action,
                    target=target,
                    ip=ip,
                    user_agent=user_agent,
                )
            )
            db.commit()
    except Exception:
        pass
