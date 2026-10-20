"""
Typography definitions for the KE-CIRT Threat Intel Report.

Uses ReportLab built-in Helvetica family (no custom TTF files required).
"""

from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.styles import ParagraphStyle

# ── Font names (ReportLab built-ins) ─────────────────────────────────────────
FONT_REGULAR  = "Helvetica"
FONT_BOLD     = "Helvetica-Bold"
FONT_OBLIQUE  = "Helvetica-Oblique"
FONT_BOLD_OBL = "Helvetica-BoldOblique"
FONT_MONO     = "Courier"

# ── Base sizes ───────────────────────────────────────────────────────────────
SIZE_COVER_TITLE   = 34
SIZE_COVER_SUBTITLE= 16
SIZE_SECTION_NUM   = 48
SIZE_SECTION_TITLE = 26
SIZE_H1            = 20
SIZE_H2            = 14
SIZE_H3            = 12
SIZE_BODY          = 10.5
SIZE_SMALL         = 8.5
SIZE_CAPTION       = 7.5
SIZE_LABEL         = 9
SIZE_VALUE         = 12
SIZE_CHART_TITLE   = 13

# ── Leading multipliers ─────────────────────────────────────────────────────
LEAD_BODY   = 1.6
LEAD_HEAD   = 1.25

# ── Spacing ─────────────────────────────────────────────────────────────────
SPACE_SECTION_TITLE = 14
SPACE_PARAGRAPH     = 8
SPACE_CARD          = 12


def body_style(align: str = "left", **kw) -> ParagraphStyle:
    """Return a body ParagraphStyle."""
    mapping = {"left": TA_LEFT, "center": TA_CENTER, "right": TA_RIGHT, "justify": TA_JUSTIFY}
    kw.setdefault("fontName", FONT_REGULAR)
    kw.setdefault("fontSize", SIZE_BODY)
    kw.setdefault("leading", SIZE_BODY * LEAD_BODY)
    kw.setdefault("textColor", "#F0F4FF")
    kw.setdefault("alignment", mapping.get(align, TA_LEFT))
    kw.setdefault("spaceAfter", SPACE_PARAGRAPH)
    return ParagraphStyle("body", **kw)


def heading_style(size: int, **kw) -> ParagraphStyle:
    kw.setdefault("fontName", FONT_BOLD)
    kw.setdefault("fontSize", size)
    kw.setdefault("leading", size * LEAD_HEAD)
    kw.setdefault("textColor", "#F0F4FF")
    kw.setdefault("spaceBefore", 6)
    kw.setdefault("spaceAfter", SPACE_SECTION_TITLE)
    return ParagraphStyle("heading", **kw)
