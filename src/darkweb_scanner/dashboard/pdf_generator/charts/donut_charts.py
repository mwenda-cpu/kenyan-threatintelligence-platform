import matplotlib

matplotlib.use('Agg')  # MUST be set before importing pyplot

"""Donut chart re-export."""

from . import donut_chart  # noqa: E402, F401

__all__ = ["donut_chart"]
