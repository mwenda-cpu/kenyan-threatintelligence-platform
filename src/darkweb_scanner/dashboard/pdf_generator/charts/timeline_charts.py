import matplotlib
matplotlib.use('Agg')  # MUST be set before importing pyplot
import matplotlib.pyplot as plt

"""Timeline chart re-export."""

from . import timeline_line  # noqa: F401

__all__ = ["timeline_line"]
