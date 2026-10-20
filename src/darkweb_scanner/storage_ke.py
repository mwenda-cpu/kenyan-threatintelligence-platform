"""
Kenya / East Africa contextual data models.

Tables:
  ke_cirt_reports — KE-CIRT/CC quarterly reports
  ca_advisories   — Communications Authority of Kenya advisories
  cbk_fraud_stats — Central Bank of Kenya fraud statistics

Importing this module registers the models on ``storage.Base`` so they
are created by ``Base.metadata.create_all()`` at startup (the Storage
class calls create_all in ``_create_tables``). The dashboard routes and
loader import this module for side effects before touching the DB.
"""

from datetime import date, datetime, timezone

from sqlalchemy import Column, Date, DateTime, Integer, String, Text

from .storage import Base


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class KECIRTReport(Base):
    __tablename__ = "ke_cirt_reports"

    id = Column(Integer, primary_key=True)
    title = Column(String(512))
    quarter = Column(String(16))
    year = Column(Integer)
    summary = Column(Text)
    source_url = Column(String(1024))
    stats_json = Column(Text)  # JSON: attack types, sectors
    created_at = Column(DateTime, default=_utcnow)


class CAAdvisory(Base):
    __tablename__ = "ca_advisories"

    id = Column(Integer, primary_key=True)
    title = Column(String(512))
    threat_type = Column(String(128))
    summary = Column(Text)
    source_url = Column(String(1024))
    date_published = Column(Date, nullable=True)
    created_at = Column(DateTime, default=_utcnow)

    @property
    def date_published_iso(self):
        if isinstance(self.date_published, date):
            return self.date_published.isoformat()
        return self.date_published


class CBKFraudStats(Base):
    __tablename__ = "cbk_fraud_stats"

    id = Column(Integer, primary_key=True)
    period = Column(String(64))  # e.g. "Q2 2025"
    stats_json = Column(Text)  # mobile_banking, card, online, cyber
    source_url = Column(String(1024))
    created_at = Column(DateTime, default=_utcnow)
