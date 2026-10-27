"""
Chart generators — Hoxhunt-styled matplotlib exports for the KE-CIRT report.

All charts output PNG bytes at 300 DPI, dark-themed, with no spines/borders,
muted labels, and gradient or solid accent fills.
"""

from __future__ import annotations

import io
from typing import List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import FancyBboxPatch

from ..styles.colors import (
    ACCENT_BLUE, ACCENT_PURPLE, ACCENT_PINK, ACCENT_RED, ACCENT_GREEN,
    TEXT_LABEL, TEXT_MUTED, BG_PRIMARY, BG_SECONDARY,
)

DPI = 300
BG_COLOR = BG_PRIMARY
CARD_COLOR = BG_SECONDARY


def _style_axes(ax, hide_spines: bool = True):
    """Apply Hoxhunt chart styling: no spines, muted labels, dark bg."""
    fig = ax.figure
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)

    if hide_spines:
        for spine in ax.spines.values():
            spine.set_visible(False)

    ax.tick_params(colors=TEXT_LABEL, labelsize=9, length=0)
    ax.xaxis.label.set_color(TEXT_LABEL)
    ax.yaxis.label.set_color(TEXT_LABEL)
    ax.title.set_color("#F0F4FF")
    ax.title.set_fontsize(13)
    ax.title.set_fontweight("bold")


def _gradient_bar(ax, y_positions, widths, colors: List[str], height: float = 0.6):
    """Draw horizontal bars with a subtle two-tone gradient feel."""
    for y, w, c in zip(y_positions, widths, colors):
        bar = ax.barh(y, w, height=height, color=c, edgecolor="none", alpha=0.92)
        # value label at end of bar
        ax.text(w + max(widths) * 0.01, y, f"  {int(w)}", va="center",
                ha="left", fontsize=10, color="#F0F4FF", fontweight="bold")


def gradient_horizontal_bar(
    data: List[Tuple[str, int]],
    title: str,
    width_in: float = 6.5,
    height_in: float = 2.6,
    accent_start: str = ACCENT_BLUE,
    accent_end: str = ACCENT_PURPLE,
) -> bytes:
    """
    Horizontal gradient bar chart (blue -> purple).
    data: list of (label, value) sorted ascending for display top->bottom.
    """
    fig, ax = plt.subplots(figsize=(width_in, height_in), dpi=DPI)
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)

    labels = [d[0] for d in data]
    values = [d[1] for d in data]
    if not values:
        # Return a blank placeholder image so the report still builds.
        fig, ax = plt.subplots(figsize=(width_in, height_in), dpi=DPI)
        fig.patch.set_facecolor(BG_COLOR)
        ax.set_facecolor(BG_COLOR)
        ax.text(0.5, 0.5, "No data", ha="center", va="center", color=TEXT_LABEL)
        ax.set_axis_off()
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=DPI, facecolor=BG_COLOR, edgecolor="none")
        plt.close(fig)
        buf.seek(0)
        return buf.read()
    y_pos = list(range(len(data)))[::-1]  # reverse so first item is at top

    # Build a gradient colormap from accent_start -> accent_end
    cmap = LinearSegmentedColormap.from_list("hox_grad", [accent_start, accent_end])
    norm_vals = [(v - min(values)) / (max(values) - min(values) + 1e-9) for v in values]
    bar_colors = [cmap(n) for n in norm_vals]

    _gradient_bar(ax, y_pos, values, bar_colors)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=10, color=TEXT_LABEL)
    ax.invert_yaxis()  # first label at top
    ax.set_xlim(0, max(values) * 1.25)

    _style_axes(ax)
    ax.set_title(title, loc="left", pad=12)

    # light vertical gridlines
    ax.xaxis.grid(True, color="#1F2A44", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=DPI, bbox_inches="tight",
                facecolor=BG_COLOR, edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def donut_chart(
    data: List[Tuple[str, int]],
    title: str,
    center_label: str,
    center_value: str = "",
    width_in: float = 4.2,
    height_in: float = 4.2,
    accent_colors: List[str] | None = None,
) -> bytes:
    """
    Donut chart with centered percentage label, muted legend below.
    """
    if accent_colors is None:
        accent_colors = [ACCENT_BLUE, ACCENT_PURPLE, ACCENT_PINK, ACCENT_RED, ACCENT_GREEN]

    fig, ax = plt.subplots(figsize=(width_in, height_in), dpi=DPI)
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)

    values = [d[1] for d in data]
    labels = [d[0] for d in data]
    if not values or sum(values) == 0:
        fig, ax = plt.subplots(figsize=(width_in, height_in), dpi=DPI)
        fig.patch.set_facecolor(BG_COLOR)
        ax.set_facecolor(BG_COLOR)
        ax.text(0.5, 0.5, "No data", ha="center", va="center", color=TEXT_LABEL)
        ax.set_axis_off()
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=DPI, facecolor=BG_COLOR, edgecolor="none")
        plt.close(fig)
        buf.seek(0)
        return buf.read()
    total = sum(values)

    wedges, _ = ax.pie(
        values,
        colors=accent_colors[: len(values)],
        startangle=90,
        counterclock=False,
        wedgeprops=dict(width=0.42, edgecolor=BG_COLOR, linewidth=2),
    )

    # Center label
    ax.text(0, 0.08, center_label, ha="center", va="center",
            fontsize=13, fontweight="bold", color="#F0F4FF")
    if center_value:
        ax.text(0, -0.14, center_value, ha="center", va="center",
                fontsize=10, color=TEXT_MUTED)

    ax.set_title(title, loc="left", pad=10)

    # Muted legend below
    legend_labels = [f"{lbl}  {val}" for lbl, val in zip(labels, values)]
    ax.legend(
        wedges, legend_labels,
        loc="lower center", bbox_to_anchor=(0.5, -0.18),
        fontsize=9, frameon=False, labelcolor=TEXT_LABEL,
        ncol=1, handlelength=1.2, handleheight=1.2,
    )

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=DPI, bbox_inches="tight",
                facecolor=BG_COLOR, edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def timeline_line(
    points: List[Tuple[str, int]],
    title: str,
    width_in: float = 6.5,
    height_in: float = 2.4,
    line_color: str = ACCENT_BLUE,
) -> bytes:
    """
    Simple line/timeline chart showing hits over time.
    points: list of (date_label, value).
    """
    fig, ax = plt.subplots(figsize=(width_in, height_in), dpi=DPI)
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)

    xs = list(range(len(points)))
    ys = [p[1] for p in points]
    xlabels = [p[0] for p in points]

    ax.plot(xs, ys, color=line_color, linewidth=2.5, marker="o",
            markersize=5, markerfacecolor=ACCENT_PINK, markeredgecolor="none")
    ax.fill_between(xs, ys, color=line_color, alpha=0.12)

    ax.set_xticks(xs)
    ax.set_xticklabels(xlabels, fontsize=8.5, color=TEXT_LABEL, rotation=15)
    ax.set_ylim(0, max(ys) * 1.3 if ys else 1)
    ax.set_yticks([])  # no y-axis labels for clean look

    _style_axes(ax)
    ax.set_title(title, loc="left", pad=10)

    # value labels above points
    for x, y in zip(xs, ys):
        ax.text(x, y + max(ys) * 0.05, str(y), ha="center", va="bottom",
                fontsize=9, color="#F0F4FF", fontweight="bold")

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=DPI, bbox_inches="tight",
                facecolor=BG_COLOR, edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def cbk_fraud_bar(
    data: List[Tuple[str, int]],
    title: str,
    width_in: float = 5.2,
    height_in: float = 2.6,
) -> bytes:
    """
    Vertical bar chart for CBK fraud categories with accent colors.
    """
    fig, ax = plt.subplots(figsize=(width_in, height_in), dpi=DPI)
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)

    labels = [d[0] for d in data]
    values = [d[1] for d in data]
    colors = [ACCENT_BLUE, ACCENT_PURPLE, ACCENT_PINK, ACCENT_RED]

    bars = ax.bar(labels, values, color=colors[: len(values)],
                  edgecolor="none", width=0.55, alpha=0.9)

    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.03,
                f"{v:,}", ha="center", va="bottom", fontsize=9,
                color="#F0F4FF", fontweight="bold")

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=9, color=TEXT_LABEL, rotation=0)
    ax.set_ylim(0, max(values) * 1.3 if values else 1)
    ax.set_yticks([])

    _style_axes(ax)
    ax.set_title(title, loc="left", pad=10)
    ax.xaxis.grid(False)

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=DPI, bbox_inches="tight",
                facecolor=BG_COLOR, edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return buf.read()
