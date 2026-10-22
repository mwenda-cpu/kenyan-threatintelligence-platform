import matplotlib
matplotlib.use('Agg')  # MUST be set before importing pyplot
import matplotlib.pyplot as plt

"""Bar chart re-export."""

from . import gradient_horizontal_bar  # noqa: F401

__all__ = ["gradient_horizontal_bar"]
