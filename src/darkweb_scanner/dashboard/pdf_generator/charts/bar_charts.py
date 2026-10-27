import matplotlib

matplotlib.use('Agg')  # MUST be set before importing pyplot

"""Bar chart re-export."""

from . import gradient_horizontal_bar  # noqa: E402, F401

__all__ = ["gradient_horizontal_bar"]
