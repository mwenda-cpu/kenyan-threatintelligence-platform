"""
Section 02 — Threat Landscape Overview.
Keyword bar chart, category donut, analyst notes.
"""

from io import BytesIO

from reportlab.platypus import Image, PageBreak, Spacer

from ..charts import donut_chart, gradient_horizontal_bar
from ..components import pull_quote, section_divider
from ..styles.colors import (
    ACCENT_BLUE,
    ACCENT_PINK,
    ACCENT_PURPLE,
    ACCENT_RED,
)
from ..styles.layout import CONTENT_W, SECTIONS


def threat_landscape_flowables(data: dict) -> list:
    story = []

    num, title = SECTIONS[1]
    story.append(section_divider(num, title,
        "Keyword frequency, category distribution, and CBK fraud insights"))
    story.append(Spacer(1, 10))

    # ── Keyword bar chart ──
    kw_data = data.get("top_keywords") or [
        ("LockBit", 101), ("BEC", 8), ("KRA", 8), ("DDoS", 2), ("cl0p", 2), ("lockbit", 1),
    ]
    bar_png = gradient_horizontal_bar(kw_data, "Actionable Hits by Keyword")
    bar_img = Image(BytesIO(bar_png), width=CONTENT_W * 0.95,
                    height=CONTENT_W * 0.95 * 2.6 / 6.5)
    story.append(bar_img)
    story.append(Spacer(1, 10))

    # ── Category donut ──
    cat_data = data.get("categories") or [
        ("threat_actor", 83), ("threat_type", 8), ("government", 7), ("ransomware", 2),
    ]
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
