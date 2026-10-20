"""
Lightweight threat-level scorer for the KE dashboard.

Loads the model/vectorizer produced by ``scripts/train_nlp_model.py`` (stored in
``models/`` by default, configurable via ``MODEL_DIR``) and exposes
:func:`calculate_threat_score`, which returns an integer 0-100 representing how
likely a piece of dark-web text is to be a high-risk threat (ransom note, leak
advertisement, access-broker post, ...).

The model is optional: if it has not been trained yet the scorer falls back to a
transparent keyword heuristic so the dashboard never breaks.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import joblib

logger = logging.getLogger(__name__)

MODEL_DIR = Path(os.getenv("MODEL_DIR", "/app/models"))
MODEL_PATH = MODEL_DIR / "threat_model.pkl"
VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.pkl"

# Keywords that strongly indicate a high-risk dark-web posting. Each match boosts
# the final score by ``KEYWORD_BOOST`` points.
HIGH_RISK_KEYWORDS = [
    "access broker",
    "database dump",
    "wire transfer",
    "leak",
    "ransom",
    "decrypt",
    "bitcoin",
    "monero",
    "tor",
    "onion",
    "payload",
    "exfiltrat",
    "breach",
    "compromised",
    "credentials",
    "sql injection",
    "rce",
    "remote code",
    "0day",
    "zero-day",
    "dox",
    "sale",
    "sensitive",
    "confidential",
    "fullz",
    "ccv",
    "track2",
]
KEYWORD_BOOST = 6


class _ModelStore:
    """Lazy, single-load holder for the sklearn model and vectorizer."""

    _model: Optional[object] = None
    _vectorizer: Optional[object] = None
    _loaded: bool = False

    @classmethod
    def load(cls) -> tuple[Optional[object], Optional[object]]:
        if cls._loaded:
            return cls._model, cls._vectorizer
        cls._loaded = True
        try:
            cls._model = joblib.load(MODEL_PATH)
            cls._vectorizer = joblib.load(VECTORIZER_PATH)
            logger.info("Loaded threat model from %s and %s", MODEL_PATH, VECTORIZER_PATH)
        except FileNotFoundError:
            logger.info(
                "Threat model not found at %s/%s - falling back to keyword heuristic",
                MODEL_PATH,
                VECTORIZER_PATH,
            )
        except Exception as exc:  # noqa: BLE001 - never break the dashboard
            logger.warning("Could not load threat model: %s", exc)
        return cls._model, cls._vectorizer


def _heuristic_score(text: str) -> int:
    """Keyword-based fallback score when the model is unavailable."""
    lower = text.lower()
    hits = sum(1 for kw in HIGH_RISK_KEYWORDS if kw in lower)
    return min(100, hits * KEYWORD_BOOST)


def calculate_threat_score(text: str) -> int:
    """Return a 0-100 threat score for ``text``.

    Uses ``model.predict_proba`` when a trained model is available, falling back
    to a keyword heuristic otherwise. High-risk keywords add a small boost on top
    of the model probability.
    """
    text = text or ""
    lower = text.lower()

    model, vectorizer = _ModelStore.load()
    if model is not None and vectorizer is not None:
        try:
            X = vectorizer.transform([text])
            # Column 1 of predict_proba is the positive ("threat") class.
            proba = float(model.predict_proba(X)[0][1])
            score = int(round(proba * 100))
        except Exception as exc:  # noqa: BLE001 - degrade gracefully
            logger.warning("Model scoring failed: %s", exc)
            score = _heuristic_score(text)
    else:
        score = _heuristic_score(text)

    # Keyword boost on top of the model score.
    boost = sum(KEYWORD_BOOST for kw in HIGH_RISK_KEYWORDS if kw in lower)
    score = min(100, score + boost)
    return max(0, score)


def threat_level(score: int) -> str:
    """Map a 0-100 score to a human-readable level."""
    if score >= 66:
        return "High"
    if score >= 33:
        return "Medium"
    return "Low"
