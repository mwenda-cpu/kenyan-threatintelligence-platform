"""
Time-series forecasting for KE threat-intel hit volume.

Prefers Facebook Prophet when installed; falls back to a pandas rolling average
so the feature never breaks. Returns the next ``days`` daily hit forecasts.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import pandas as pd

from darkweb_scanner.dashboard.storage_helper import get_storage

logger = logging.getLogger(__name__)


def _daily_counts(storage, days: int = 90) -> list[tuple[str, int]]:
    """Daily keyword-hit counts for the last ``days`` days, zeros filled."""
    since = datetime.now(timezone.utc) - timedelta(days=days - 1)
    counts: dict[str, int] = {}
    for hit in storage.get_recent_hits(limit=5000):
        if hit.found_at is None:
            continue
        if hit.found_at.astimezone(timezone.utc) < since:
            continue
        d = hit.found_at.astimezone(timezone.utc).date().isoformat()
        counts[d] = counts.get(d, 0) + 1
    out = []
    for i in range(days):
        d = (datetime.now(timezone.utc) - timedelta(days=days - 1 - i)).date().isoformat()
        out.append((d, counts.get(d, 0)))
    return out


def forecast_hits(days: int = 7, history_days: int = 90) -> list[dict]:
    """Return the next ``days`` daily hit forecasts as ``[{date, expected_hits}]``."""
    storage = get_storage()
    rows = _daily_counts(storage, history_days)
    df = pd.DataFrame(rows, columns=["ds", "y"])
    df["ds"] = pd.to_datetime(df["ds"])

    try:
        from prophet import Prophet

        model = Prophet(
            daily_seasonality=False,
            weekly_seasonality=True,
            yearly_seasonality=False,
        )
        model.fit(df)
        future = model.make_future_dataframe(periods=days)
        fc = model.predict(future)
        tail = fc.tail(days)
        forecast = [
            {
                "date": pd.Timestamp(row["ds"]).date().isoformat(),
                "expected_hits": max(0, int(round(float(row["yhat"])))),
            }
            for _, row in tail.iterrows()
        ]
        logger.info("Prophet forecast produced %d points", len(forecast))
        return forecast
    except Exception as exc:  # noqa: BLE001 - degrade to rolling average
        logger.warning("Prophet unavailable (%s); using rolling-average forecast", exc)
        return _rolling_average_forecast(df, days)


def _rolling_average_forecast(df: pd.DataFrame, days: int) -> list[dict]:
    window = min(7, max(1, len(df)))
    ma = float(df["y"].rolling(window, min_periods=1).mean().iloc[-1])
    last_date = pd.to_datetime(df["ds"].iloc[-1])
    forecast = []
    for i in range(1, days + 1):
        d = (last_date + timedelta(days=i)).date().isoformat()
        forecast.append({"date": d, "expected_hits": max(0, int(round(ma)))})
    return forecast
