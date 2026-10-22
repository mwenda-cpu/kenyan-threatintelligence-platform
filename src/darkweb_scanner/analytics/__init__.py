"""Analytics module — attack prediction engine for Kenyan targets."""

from .predictor import predict_attacks, predict_for_keyword

__all__ = ["predict_attacks", "predict_for_keyword"]
