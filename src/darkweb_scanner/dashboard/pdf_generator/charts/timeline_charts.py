import matplotlib

matplotlib.use('Agg')  # MUST be set before importing pyplot

"""Timeline chart re-export."""

from . import timeline_line  # noqa: E402, F401

__all__ = ["timeline_line"]
