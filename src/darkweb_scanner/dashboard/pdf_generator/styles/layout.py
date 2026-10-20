"""
Layout constants and page templates for the KE-CIRT Threat Intel Report.
"""

from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import mm

# ── Page geometry ───────────────────────────────────────────────────────────
MARGIN = 20 * mm          # ~2cm generous margins
PAGE_W, PAGE_H = A4       # 210 x 297 mm portrait
PAGE_LW, PAGE_LH = landscape(A4)  # landscape for chart-heavy pages

# Usable width after margins
CONTENT_W = PAGE_W - 2 * MARGIN
CONTENT_H = PAGE_H - 2 * MARGIN

# ── Section numbering ───────────────────────────────────────────────────────
SECTIONS = [
    ("01", "Executive Summary & Introduction"),
    ("02", "Threat Landscape Overview"),
    ("03", "Human Risk Findings"),
    ("04", "Campaigns, Tooling & Environments"),
    ("05", "Strategic Guidance"),
    ("06", "Appendix & Sources"),
]

REPORT_TITLE   = "2026 Kenya Cyber Threat Intelligence Report"
REPORT_SUBTITLE = "What slips through filters and reaches Kenyan organizations."
REPORT_EDITION = "42nd Edition  \u00b7  April \u2013 June 2026"
REPORT_BRAND   = "KE-CIRT / CC"
REPORT_FILENAME = "KE-CIRT_Threat_Intel_Briefing_2026_Q4.pdf"

# ── Footer text ─────────────────────────────────────────────────────────────
FOOTER_LEFT  = "KE-CIRT / CC \u2014 Kenya Cyber Threat Intelligence"
FOOTER_RIGHT = "CONFIDENTIAL \u00b7 Do not distribute without authorization"
