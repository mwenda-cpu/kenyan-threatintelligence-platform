"""
Kenya context service — loaders and readers for KE-CIRT/CC reports,
CA Kenya advisories, and CBK fraud statistics.

Sources (manually downloaded into ./data/ke_reports/):
  - https://ke-cirt.go.ke            (KE-CIRT/CC quarterly reports)
  - https://repository.ca.go.ke      (CA advisories)
  - https://www.centralbank.go.ke    (CBK Financial Sector Stability reports)

The service layer sits on top of the ``Storage`` session helper so it
works both inside Flask requests (request-scoped session) and from the
CLI loader script.
"""

import json
import logging
import re
from datetime import date, datetime

from . import storage_ke  # noqa: F401  (registers KE models on storage.Base)
from .storage_ke import CAAdvisory, CBKFraudStats, KECIRTReport

logger = logging.getLogger(__name__)

# ── Synonym / alias expansion for correlate_keyword ──────────────────────────
SYNONYMS: dict = {
    "ransomware": ["ransomware", "lockbit", "akira", "clop", "qilin", "hunters"],
    "mobile": ["mobile_banking", "mpesa", "m-pesa", "safaricom", "airtel"],
    "phishing": ["phishing", "smishing", "credential theft", "sim swap"],
    "government": ["government", "ecitizen", "ifmis", "kra", "ntsa"],
}


def _normalise_keyword(keyword: str) -> str:
    """Lowercase and strip punctuation, collapsing whitespace."""
    text = re.sub(r"[^\w\s]", " ", (keyword or "").lower())
    return re.sub(r"\s+", " ", text).strip()


def _expand_synonyms(keyword: str) -> list:
    """Expand a keyword to its concept synonym list (or [itself])."""
    norm = _normalise_keyword(keyword)
    if not norm:
        return []
    expanded: list = []
    for _concept, synonyms in SYNONYMS.items():
        if norm == _concept or norm in synonyms:
            for syn in synonyms:
                if syn not in expanded:
                    expanded.append(syn)
    return expanded or [norm]


def _contains_any(text, synonyms: list) -> bool:
    """Case-insensitive substring match of any synonym in text."""
    if not text:
        return False
    low = str(text).lower()
    return any(s in low for s in synonyms)


def _parse_date(value):
    """Accept date/datetime/ISO string; return a date or None."""
    if value is None or value == "":
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        logger.warning("Could not parse date %r; storing NULL", value)
        return None


class KenyaContext:
    """Loaders + readers for Kenyan contextual data sources."""

    def __init__(self, storage):
        self.storage = storage

    # ── Loaders ──────────────────────────────────────────────────

    def load_ke_cirt_report(self, title, quarter, year, stats: dict, summary: str, source_url: str) -> int:
        """Insert one KE-CIRT/CC quarterly report. Returns the new row id."""
        with self.storage.get_session() as session:
            row = KECIRTReport(
                title=title,
                quarter=str(quarter),
                year=int(year),
                summary=summary or "",
                source_url=source_url or "",
                stats_json=json.dumps(stats or {}),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.id

    def load_ca_advisory(self, title, date_published, summary: str, threat_type: str, source_url: str) -> int:
        """Insert one CA Kenya advisory. Returns the new row id."""
        with self.storage.get_session() as session:
            row = CAAdvisory(
                title=title,
                threat_type=(threat_type or "general").strip().lower() or "general",
                summary=summary or "",
                source_url=source_url or "",
                date_published=_parse_date(date_published),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.id

    def load_cbk_fraud_stats(self, period, stats: dict, source_url: str) -> int:
        """Insert one CBK fraud-statistics snapshot. Returns the new row id."""
        with self.storage.get_session() as session:
            row = CBKFraudStats(
                period=str(period),
                stats_json=json.dumps(stats or {}),
                source_url=source_url or "",
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.id

    def delete_cbk_by_period(self, period: str) -> int:
        """Delete all CBK fraud-stat rows for the given period. Returns row count deleted."""
        with self.storage.get_session() as session:
            deleted = session.query(CBKFraudStats).filter(CBKFraudStats.period == str(period)).delete()
            session.commit()
            return deleted

    # ── Readers ──────────────────────────────────────────────────

    @staticmethod
    def _report_to_dict(row):
        try:
            stats = json.loads(row.stats_json or "{}")
        except (TypeError, ValueError):
            stats = {}
        return {
            "id": row.id,
            "title": row.title,
            "quarter": row.quarter,
            "year": row.year,
            "summary": row.summary,
            "source_url": row.source_url,
            "stats": stats if isinstance(stats, dict) else {},
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    @staticmethod
    def _advisory_to_dict(row):
        published = row.date_published
        if isinstance(published, datetime):
            published = published.date().isoformat()
        elif isinstance(published, date):
            published = published.isoformat()
        return {
            "id": row.id,
            "title": row.title,
            "threat_type": row.threat_type,
            "summary": row.summary,
            "source_url": row.source_url,
            "date_published": published,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    @staticmethod
    def _cbk_to_dict(row):
        try:
            stats = json.loads(row.stats_json or "{}")
        except (TypeError, ValueError):
            stats = {}
        return {
            "id": row.id,
            "period": row.period,
            "stats": stats if isinstance(stats, dict) else {},
            "source_url": row.source_url,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    def get_latest_ke_cirt(self) -> dict:
        """Newest KE-CIRT/CC report, or {} when none is loaded."""
        with self.storage.get_session() as session:
            row = (
                session.query(KECIRTReport)
                .order_by(KECIRTReport.year.desc(), KECIRTReport.quarter.desc(), KECIRTReport.id.desc())
                .first()
            )
            return self._report_to_dict(row) if row else {}

    def get_all_ke_cirt(self) -> list:
        with self.storage.get_session() as session:
            rows = (
                session.query(KECIRTReport)
                .order_by(KECIRTReport.year.desc(), KECIRTReport.quarter.desc(), KECIRTReport.id.desc())
                .all()
            )
            return [self._report_to_dict(r) for r in rows]

    def get_recent_ca_advisories(self, limit: int = 20) -> list:
        with self.storage.get_session() as session:
            rows = (
                session.query(CAAdvisory)
                .order_by(CAAdvisory.date_published.desc().nullslast(), CAAdvisory.id.desc())
                .limit(max(int(limit or 20), 1))
                .all()
            )
            return [self._advisory_to_dict(r) for r in rows]

    def count_ca_advisories(self) -> int:
        with self.storage.get_session() as session:
            return session.query(CAAdvisory).count()

    def get_cbk_fraud_trends(self) -> dict:
        """Time series of CBK fraud stats keyed by period."""
        with self.storage.get_session() as session:
            rows = session.query(CBKFraudStats).order_by(CBKFraudStats.id.asc()).all()
            series = []
            categories = {"mobile_banking", "card", "online", "cyber"}
            for row in rows:
                parsed = self._cbk_to_dict(row)
                series.append(parsed)
                if isinstance(parsed.get("stats"), dict):
                    categories.update(k for k in parsed["stats"] if isinstance(k, str))
            return {"periods": series, "categories": sorted(categories)}

    def get_latest_cbk_totals(self) -> dict:
        with self.storage.get_session() as session:
            row = session.query(CBKFraudStats).order_by(CBKFraudStats.id.desc()).first()
            return self._cbk_to_dict(row) if row else {}

    def correlate_keyword(self, keyword: str) -> dict:
        """Match a keyword (expanded via synonyms) against KE-CIRT reports,
        CA advisories, and CBK fraud stats. Always returns the full envelope
        so the UI can distinguish "no matches" from "no data"."""
        synonyms = _expand_synonyms(keyword)
        envelope = {
            "keyword": keyword,
            "expanded": synonyms,
            "ke_cirt": [],
            "ca_advisories": [],
            "cbk_stats": [],
        }
        if not synonyms:
            return envelope

        hits_cirt, hits_ca, hits_cbk = [], [], []
        with self.storage.get_session() as session:
            # ── KE-CIRT reports: title / summary / stats_json values ──
            for row in session.query(KECIRTReport).all():
                try:
                    stats = json.loads(row.stats_json or "{}")
                except (TypeError, ValueError):
                    stats = {}
                matched = []
                if _contains_any(row.title, synonyms):
                    matched.append("title")
                if _contains_any(row.summary, synonyms):
                    matched.append("summary")
                for value in (stats or {}).values():
                    if _contains_any(str(value), synonyms):
                        matched.append(f"stat:{value}")
                if matched:
                    d = self._report_to_dict(row)
                    d["matched_attack_types"] = matched
                    hits_cirt.append(d)

            # ── CA advisories: title / summary / threat_type ──
            for row in session.query(CAAdvisory).all():
                if (
                    _contains_any(row.title, synonyms)
                    or _contains_any(row.summary, synonyms)
                    or _contains_any(row.threat_type, synonyms)
                ):
                    hits_ca.append(self._advisory_to_dict(row))

            # ── CBK fraud stats: stats_json keys / values / period ──
            for row in session.query(CBKFraudStats).all():
                try:
                    stats = json.loads(row.stats_json or "{}")
                except (TypeError, ValueError):
                    stats = {}
                matched = []
                for key in (stats or {}):
                    if _contains_any(key, synonyms):
                        matched.append(key)
                for value in (stats or {}).values():
                    if _contains_any(str(value), synonyms):
                        matched.append(str(value))
                if _contains_any(row.period, synonyms):
                    matched.append("period")
                if matched:
                    d = self._cbk_to_dict(row)
                    d["matched_categories"] = matched
                    hits_cbk.append(d)

        envelope["ke_cirt"] = hits_cirt[:10]
        envelope["ca_advisories"] = hits_ca[:10]
        envelope["cbk_stats"] = hits_cbk[:10]
        return envelope
