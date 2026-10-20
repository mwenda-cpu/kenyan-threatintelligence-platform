"""
Section 02 — Threat Landscape Overview.
Keyword bar chart, category donut, analyst notes.
"""

from reportlab.platypus import Spacer, Paragraph, PageBreak, Image
from reportlab.lib.utils import ImageReader
from io import BytesIO

from ..components import pull_quote, styled_table, section_divider
from ..styles.colors import (
    TEXT_PRIMARY, TEXT_MUTED, TEXT_LABEL, ACCENT_BLUE, ACCENT_PURPLE,
    ACCENT_PINK, ACCENT_RED, BG_SECONDARY,
)
from ..styles.typography import body_style, heading_style, SIZE_H1
from ..styles.layout import CONTENT_W, SECTIONS
from ..charts import gradient_horizontal_bar, donut_chart


def threat_landscape_flowables(data: dict) -> list:
    story = []

    num, title = SECTIONS[1]
    story.append(section_divider(num, title,
        "Keyword frequency, category distribution, and CBK fraud insights"))
    story.append(Spacer(1, 10))

    # ── Keyword bar chart ──
    kw_data = data.get("top_keywords", [
        ("LockBit", 101), ("BEC", 8), ("KRA", 8), ("DDoS", 2), ("cl0p", 2), ("lockbit", 1),
    ])
    bar_png = gradient_horizontal_bar(kw_data, "Actionable Hits by Keyword")
    bar_img = Image(BytesIO(bar_png), width=CONTENT_W * 0.95,
                    height=CONTENT_W * 0.95 * 2.6 / 6.5)
    story.append(bar_img)
    story.append(Spacer(1, 10))

    # ── Category donut ──
    cat_data = data.get("categories", [
        ("threat_actor", 83), ("threat_type", 8), ("government", 7), ("ransomware", 2),
    ])
    total = sum(v for _, v in cat_data)
    donut_png = donut_chart(cat_data, "Hits by Category",
                            f"{total / 100:.0f}%", "of total",
                            accent_colors=[ACCENT_BLUE, ACCENT_PURPLE, ACCENT_PINK, ACCENT_RED])
    donut_img = Image(BytesIO(donut_png), width=CONTENT_W * 0.45,
                      height=CONTENT_W * 0.45)
    story.append(donut_img)
    story.append(Spacer(1, 14))

    # ── Analyst notes pull quote ──
    notes = data.get("analyst_notes", (
        "Charts are built from actionable threat hits only. Snippets are cleaned at "
        "crawl time: page chrome, leak-site group menus, onion addresses and crypto "
        "dumps are stripped. Search-engine results, privacy and terms pages are excluded."
    ))
    story.append(pull_quote(notes, "Methodology"))
    story.append(Spacer(1, 10))

    story.append(PageBreak())
    return story
