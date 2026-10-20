"""
Cover page section — full-bleed dark navy, Hoxhunt-styled.
"""

from __future__ import annotations

from io import BytesIO
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable, Spacer, Paragraph, Image, PageBreak, Table, TableStyle,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle

from ..styles.colors import (
    BG_PRIMARY, BG_SECONDARY, ACCENT_BLUE, ACCENT_PURPLE, ACCENT_PINK,
    TEXT_PRIMARY, TEXT_MUTED, TEXT_LABEL, KE_RED, KE_GREEN, KE_BLACK,
)
from ..styles.typography import body_style, heading_style
from ..styles.layout import (
    CONTENT_W, CONTENT_H, MARGIN, PAGE_W, PAGE_H,
    REPORT_TITLE, REPORT_SUBTITLE, REPORT_EDITION, REPORT_BRAND,
)
from ..components import section_divider


class FullBleedCover(Flowable):
    """Full-bleed dark navy cover with brand accents."""

    def __init__(self, stats: dict, logo_path: str | None = None):
        super().__init__()
        self.stats = stats or {}
        self.logo_path = logo_path
        self.width = PAGE_W
        self.height = PAGE_H

    def draw(self):
        c = self.canv
        c.saveState()
        # Full-bleed deep navy background
        c.setFillColor(colors.HexColor(BG_PRIMARY))
        c.rect(0, 0, self.width, self.height, stroke=0, fill=1)

        # Thin accent band near top
        c.setFillColor(colors.HexColor(ACCENT_BLUE))
        c.rect(0, self.height - 6, self.width, 6, stroke=0, fill=1)

        # KE-CIRT brand
        c.setFillColor(colors.HexColor(TEXT_PRIMARY))
        c.setFont("Helvetica-Bold", 13)
        c.drawString(2 * mm, self.height - 18 * mm, REPORT_BRAND)

        # Kenyan flag stripe motif (black, red, green) near bottom
        stripe_h = 3 * mm
        c.setFillColor(colors.HexColor(KE_BLACK))
        c.rect(2 * mm, 2 * mm + 2 * stripe_h, 20 * mm, stripe_h, stroke=0, fill=1)
        c.setFillColor(colors.HexColor(KE_RED))
        c.rect(2 * mm, 2 * mm + stripe_h, 20 * mm, stripe_h, stroke=0, fill=1)
        c.setFillColor(colors.HexColor(KE_GREEN))
        c.rect(2 * mm, 2 * mm, 20 * mm, stripe_h, stroke=0, fill=1)

        c.restoreState()


def cover_flowables(stats: dict, logo_path: str | None = None) -> list:
    """Build the cover page flowables."""
    sessions = stats.get("total_sessions", 0)
    pages = stats.get("total_pages", 0)
    hits = stats.get("total_hits", 0)

    story = []

    # Top brand
    story.append(Spacer(1, 26 * mm))
    story.append(Paragraph(
        f"<font color='#4A7CFF'><b>{REPORT_BRAND}</b></font>",
        body_style(align="left", fontSize=11, textColor="#4A7CFF"),
    ))
    story.append(Spacer(1, 6))

    # Reporting period + edition
    story.append(Paragraph(
        f"<font color='#A0AEC0'>{REPORT_EDITION}</font>",
        body_style(align="left", fontSize=10, textColor=TEXT_MUTED),
    ))
    story.append(Spacer(1, 18 * mm))

    # Main title
    story.append(Paragraph(
        f"<font color='#F0F4FF'><b>{REPORT_TITLE}</b></font>",
        ParagraphStyle("covtitle", fontName="Helvetica-Bold", fontSize=30,
                       leading=36, textColor=TEXT_PRIMARY, spaceAfter=8),
    ))
    story.append(Paragraph(
        f"<font color='#9D6FFF'><i>{REPORT_SUBTITLE}</i></font>",
        body_style(align="left", fontSize=13, leading=18, textColor="#9D6FFF"),
    ))
    story.append(Spacer(1, 22 * mm))

    # Single powerful stat card
    big_stat = f"{hits:,} actionable hits"
    sub_stat = f"{sessions} crawl sessions  \u00b7  {pages:,} pages crawled"
    stat_tbl = Table(
        [[Paragraph(f"<font color='#F0F4FF'><b>{big_stat}</b></font>",
                    ParagraphStyle("bstat", fontName="Helvetica-Bold", fontSize=24,
                                   leading=30, textColor=TEXT_PRIMARY, alignment=TA_CENTER))],
         [Paragraph(f"<font color='#7B8DB5'>{sub_stat}</font>",
                    ParagraphStyle("bsub", fontName="Helvetica", fontSize=10,
                                   leading=14, textColor=TEXT_LABEL, alignment=TA_CENTER))]],
        colWidths=[CONTENT_W * 0.7],
    )
    stat_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(BG_SECONDARY)),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1F2A44")),
        ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(ACCENT_PURPLE)),
        ("LEFTPADDING", (0, 0), (-1, -1), 20),
        ("RIGHTPADDING", (0, 0), (-1, -1), 20),
        ("TOPPADDING", (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(stat_tbl)
    story.append(Spacer(1, 20 * mm))

    # Tagline
    story.append(Paragraph(
        f"<font color='#F0A6FF'><b>Kenya-focused threat intelligence from dark-web monitoring.</b></font>",
        body_style(align="left", fontSize=10.5, leading=16, textColor="#F0A6FF"),
    ))
    story.append(Spacer(1, 14))

    story.append(Paragraph(
        f"<font color='#7B8DB5'>Data sources: KE-CIRT/CC, Communications Authority of Kenya, "
        f"Central Bank of Kenya, Tor network dark-web crawl sessions.</font>",
        body_style(align="left", fontSize=8.5, leading=12, textColor=TEXT_LABEL),
    ))

    story.append(PageBreak())
    return story
