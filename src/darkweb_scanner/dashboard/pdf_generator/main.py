"""
Main orchestrator — assembles all sections into the Hoxhunt-styled KE-CIRT PDF report.

Output: A4 portrait, dark theme, section dividers, gradient charts,
pull quotes, checklists, and branded footers.
"""

from __future__ import annotations

from io import BytesIO
from datetime import datetime, timezone
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer,
)
from reportlab.lib.styles import ParagraphStyle

from .styles.colors import (
    BG_PRIMARY, ACCENT_BLUE, TEXT_MUTED, TEXT_LABEL,
    KE_RED, KE_GREEN, KE_BLACK,
)
from .styles.layout import (
    CONTENT_W, CONTENT_H, MARGIN, PAGE_W, PAGE_H,
    FOOTER_LEFT, FOOTER_RIGHT,
)
from .sections import cover, toc, executive_summary, threat_landscape
from .sections import human_risk, campaigns, strategic_guidance, appendix


def _footer(canvas, doc):
    """Draw muted footer + cover-page dark navy background on page 1."""
    canvas.saveState()
    if doc.page == 1:
        # Full-bleed deep navy background for cover
        canvas.setFillColor(colors.HexColor(BG_PRIMARY))
        canvas.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
        # Thin accent band near top
        canvas.setFillColor(colors.HexColor(ACCENT_BLUE))
        canvas.rect(0, PAGE_H - 6, PAGE_W, 6, stroke=0, fill=1)
        # Kenyan flag stripe motif at bottom-left
        stripe_h = 3 * mm
        canvas.setFillColor(colors.HexColor(KE_BLACK))
        canvas.rect(2 * mm, PAGE_H - 24 * mm, 20 * mm, stripe_h, stroke=0, fill=1)
        canvas.setFillColor(colors.HexColor(KE_RED))
        canvas.rect(2 * mm, PAGE_H - 27 * mm, 20 * mm, stripe_h, stroke=0, fill=1)
        canvas.setFillColor(colors.HexColor(KE_GREEN))
        canvas.rect(2 * mm, PAGE_H - 30 * mm, 20 * mm, stripe_h, stroke=0, fill=1)

    # Footer line and text (all pages)
    canvas.setFillColor(colors.HexColor(TEXT_LABEL))
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(MARGIN, 12 * mm, FOOTER_LEFT)
    canvas.drawRightString(PAGE_W - MARGIN, 12 * mm, FOOTER_RIGHT)
    canvas.drawCentredString(PAGE_W / 2, 8 * mm,
                             f"<font color='#7B8DB5'>Page {doc.page}</font>")
    canvas.setStrokeColor(colors.HexColor("#1F2A44"))
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, 15 * mm, PAGE_W - MARGIN, 15 * mm)
    canvas.restoreState()


def build_report(data: Optional[dict] = None, logo_path: Optional[str] = None) -> BytesIO:
    """
    Build the complete KE-CIRT Threat Intel Report PDF.

    Returns a BytesIO containing the PDF bytes.
    """
    data = data or {}

    buf = BytesIO()
    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title="2026 Kenya Cyber Threat Intelligence Report",
        author="KE-CIRT / CC",
        subject="Kenya Cyber Threat Intelligence Briefing",
        creator="KE-CIRT Threat Intel Platform",
    )

    # Single portrait frame
    frame = Frame(MARGIN, MARGIN, CONTENT_W, CONTENT_H, id="main")
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[frame], onPage=_footer),
        PageTemplate(id="body", frames=[frame], onPage=_footer),
    ])

    story = []

    # ── Cover ──
    story.extend(cover.cover_flowables(data.get("stats", {}), logo_path))

    # ── TOC ──
    story.extend(toc.toc_flowables())

    # ── Sections ──
    story.extend(executive_summary.exec_summary_flowables(data))
    story.extend(threat_landscape.threat_landscape_flowables(data))
    story.extend(human_risk.human_risk_flowables(data))
    story.extend(campaigns.campaigns_flowables(data))
    story.extend(strategic_guidance.strategic_guidance_flowables(data))
    story.extend(appendix.appendix_flowables(data))

    doc.build(story)
    buf.seek(0)
    return buf
