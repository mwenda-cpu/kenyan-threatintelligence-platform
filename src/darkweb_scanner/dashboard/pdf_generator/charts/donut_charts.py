import matplotlib
matplotlib.use('Agg')  # MUST be set before importing pyplot
import matplotlib.pyplot as plt

"""Donut chart re-export."""

from . import donut_chart  # noqa: F401

__all__ = ["donut_chart"]
