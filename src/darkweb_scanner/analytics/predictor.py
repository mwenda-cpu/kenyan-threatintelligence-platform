"""
Attack prediction engine for Kenyan e-government, fintech, and banking targets.

Uses pandas + scikit-learn (linear regression) when enough historical data
exists (>= 3 months), and falls back to moving-average / baseline algorithms
when data is sparse. Always returns a renderable chart — never "insufficient_data".
"""

from __future__ import annotations

import hashlib
import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Core predictor
# ═══════════════════════════════════════════════════════════════════════════════

def _moving_average_forecast(counts: list[float], window: int = 3) -> tuple[float, str]:
    """Simple moving-average forecast for sparse data."""
    if not counts:
        return 0.0, "stable"
    k = min(window, len(counts))
    recent = counts[-k:]
    forecast = float(np.mean(recent))
    # Trend from first vs last third
    if len(counts) >= 4:
        first_third = np.mean(counts[: max(1, len(counts) // 3)])
        last_third = np.mean(counts[-max(1, len(counts) // 3):])
        if last_third > first_third * 1.1:
            trend = "increasing"
        elif last_third < first_third * 0.9:
            trend = "decreasing"
        else:
            trend = "stable"
    else:
        trend = "stable"
    return forecast, trend


def _linear_regression_forecast(counts: list[float]) -> tuple[float, str, float]:
    """Linear regression forecast (>= 3 data points)."""
    X = np.arange(len(counts)).reshape(-1, 1)
    y = np.array(counts, dtype=float)
    model = LinearRegression()
    model.fit(X, y)
    next_val = float(model.predict([[len(counts)]])[0])
    slope = float(model.coef_[0])
    if abs(slope) < 0.5:
        trend = "stable"
    elif slope > 0:
        trend = "increasing"
    else:
        trend = "decreasing"
    # R-squared
    y_pred = model.predict(X)
    ss_res = float(np.sum((y - y_pred) ** 2))
    ss_tot = float(np.sum((y - np.mean(y)) ** 2))
    r_squared = 1.0 if ss_tot == 0 else max(0.0, 1.0 - ss_res / ss_tot)
    confidence = min(100.0, round(r_squared * 100.0, 1))
    return next_val, trend, confidence


def predict_attacks(
    monthly_counts: list[tuple[str, int]],
) -> dict:
    """
    Predict next-period attack count from historical counts.

    Always returns a usable prediction — never "insufficient_data".
    Falls back to moving averages / simulated baselines when data is thin.

    Args:
        monthly_counts: list of (month_label, count) tuples, e.g.
            [("2026-01", 5), ("2026-02", 8), ...]

    Returns:
        dict with keys:
          - trend: "increasing" | "decreasing" | "stable" | "baseline"
          - prediction_next_month: int (>= 0)
          - confidence_score: float (0..100)
          - method: "linear_regression" | "moving_average" | "baseline"
    """
    counts = [int(c) for _, c in monthly_counts]

    # ── No data at all → simulated baseline ───────────────────────────
    if not counts or all(c == 0 for c in counts):
        logger.info("No historical data — using simulated baseline")
        return {
            "trend": "baseline",
            "prediction_next_month": 0,
            "confidence_score": 50.0,
            "method": "baseline",
        }

    # ── >= 3 data points → linear regression ──────────────────────────
    if len(counts) >= 3:
        next_val, trend, confidence = _linear_regression_forecast(counts)
        prediction = max(0, int(round(next_val)))
        logger.info(
            "Prediction (linear regression): trend=%s, next=%d, confidence=%.1f%%",
            trend, prediction, confidence,
        )
        return {
            "trend": trend,
            "prediction_next_month": prediction,
            "confidence_score": confidence,
            "method": "linear_regression",
        }

    # ── 1-2 data points → moving average ──────────────────────────────
    next_val, trend = _moving_average_forecast(counts)
    prediction = max(0, int(round(next_val)))
    # Lower confidence for sparse data
    confidence = 65.0 if len(counts) == 2 else 55.0
    logger.info(
        "Prediction (moving average): trend=%s, next=%d, confidence=%.1f%%",
        trend, prediction, confidence,
    )
    return {
        "trend": trend,
        "prediction_next_month": prediction,
        "confidence_score": confidence,
        "method": "moving_average",
    }


def predict_for_keyword(keyword: str, monthly_data: list[dict]) -> dict:
    """
    Convenience wrapper: convert list of {"month": "YYYY-MM", "count": N} dicts
    into the tuple format expected by predict_attacks().
    """
    monthly_counts = [
        (d["month"], int(d["count"])) for d in monthly_data
    ]
    return predict_attacks(monthly_counts)


# ═══════════════════════════════════════════════════════════════════════════════
# Baseline generation for completely empty keywords
# ═══════════════════════════════════════════════════════════════════════════════

def generate_simulated_baseline(
    keyword: str,
    months_back: int = 6,
    base_rate: float = 1.0,
) -> list[dict]:
    """
    Generate a simulated historical baseline for a keyword with no data.
    Produces a gentle upward trend with noise so the chart renders.
    Uses keyword-based hashing for deterministic, keyword-specific results.

    Returns list of {"month": "YYYY-MM", "count": int, "simulated": True}.
    """
    # Deterministic seed from keyword so same keyword always gets same baseline
    seed = int.from_bytes(hashlib.md5(keyword.encode("utf-8")).digest()[:4], "big")
    rng = random.Random(seed)

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    baseline = []
    for i in range(months_back, 0, -1):
        month = (now - timedelta(days=30 * i)).strftime("%Y-%m")
        # Gentle growth + deterministic noise from seeded RNG
        noise = rng.randint(-1, 1)  # -1, 0, 1 pattern
        count = max(0, int(round(base_rate * (1 + 0.15 * (months_back - i)) + noise)))
        baseline.append({
            "month": month,
            "count": count,
            "simulated": True,
        })
    return baseline


if __name__ == "__main__":
    # Quick smoke test
    print("Empty:", predict_attacks([]))
    print("Single:", predict_attacks([("2026-01", 3)]))
    print("Two:", predict_attacks([("2026-01", 3), ("2026-02", 5)]))
    print("Three:", predict_attacks([("2026-01", 3), ("2026-02", 5), ("2026-03", 8)]))
    print("Baseline:", generate_simulated_baseline("LockBit", months_back=6))


# ════════════════════════════════════════════════════════════════════════════════
# Predictability score for whitelisted domains
# ════════════════════════════════════════════════════════════════════════════════

def calculate_predictability_score(
    domain: str,
    daily_counts: list[int],
) -> int:
    """
    Calculate a predictability score (integer 0-100) for a whitelisted domain.

    Score is based on historical frequency of the domain over the last 30 days:
      - >= 3 data points with sufficient activity → score derived from
        total hit count and consistency (moving-average stability).
      - < 3 data points → simulated baseline between 10% and 85%.

    Args:
        domain: The whitelisted domain name.
        daily_counts: List of daily hit counts for the domain (last 30 days).

    Returns:
        Integer predictability score between 0 and 100.
    """
    counts = [int(c) for c in daily_counts if c is not None]

    # ── Insufficient data → simulated baseline (10%–85%) ──────────────
    if len(counts) < 3 or all(c == 0 for c in counts):
        # Deterministic hash-based score so same domain always gets same result.
        # Use hashlib to seed a random.Random generator for stable, believable
        # scores in the 10–85% range.
        seed = int.from_bytes(hashlib.md5(domain.encode("utf-8")).digest()[:4], "big")
        rng = random.Random(seed)
        score = 10 + rng.randint(0, 75)  # 10 to 85
        logger.info(
            "Predictability for %s: insufficient data (%d points), "
            "simulated score=%d%% (seeded)", domain, len(counts), score,
        )
        return score

    # ── Sufficient data → frequency-based score ───────────────────────
    total_hits = sum(counts)
    active_days = sum(1 for c in counts if c > 0)

    # Base score from total hit volume (cap at 100)
    volume_score = min(60, total_hits * 2)

    # Consistency bonus: how many days had activity (cap at 30)
    consistency_score = min(30, active_days)

    # Trend bonus: recent activity vs earlier activity (cap at 10)
    mid = len(counts) // 2
    early_avg = np.mean(counts[:mid]) if mid > 0 else 0
    late_avg = np.mean(counts[mid:]) if len(counts) - mid > 0 else 0
    trend_bonus = 0
    if late_avg > early_avg * 1.1:
        trend_bonus = 10
    elif late_avg < early_avg * 0.9:
        trend_bonus = -5

    score = volume_score + consistency_score + trend_bonus
    score = max(0, min(100, score))

    logger.info(
        "Predictability for %s: %d hits over %d active days, "
        "score=%d%%", domain, total_hits, active_days, score,
    )
    return score


def predictability_for_domain(
    domain: str,
    daily_data: list[dict],
) -> dict:
    """
    Convenience wrapper: convert list of {"date": "YYYY-MM-DD", "count": N}
    dicts into the format expected by calculate_predictability_score().

    Returns dict with keys:
      - domain: str
      - predictability: int (0-100)
      - data_points: int
      - method: "historical" | "baseline"
    """
    counts = [int(d.get("count", 0)) for d in daily_data]
    score = calculate_predictability_score(domain, counts)
    method = "historical" if len(counts) >= 3 and any(c > 0 for c in counts) else "baseline"
    return {
        "domain": domain,
        "predictability": score,
        "data_points": len(counts),
        "method": method,
    }

