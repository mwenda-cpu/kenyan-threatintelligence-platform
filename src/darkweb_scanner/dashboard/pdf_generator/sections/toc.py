"""
Table of contents section — Hoxhunt-styled with large section numbers.
"""

from reportlab.platypus import Spacer, Paragraph, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_LEFT, TA_RIGHT

from ..styles.colors import TEXT_PRIMARY, TEXT_MUTED, TEXT_LABEL, ACCENT_BLUE, ACCENT_PURPLE, BG_SECONDARY
from ..styles.typography import body_style, heading_style, SIZE_H1
from ..styles.layout import CONTENT_W, SECTIONS
from ..components import section_divider


def toc_flowables() -> list:
    story = []

    story.append(Paragraph(
        "<font color='#F0F4FF'><b>Contents</b></font>",
        heading_style(SIZE_H1),
    ))
    story.append(Spacer(1, 10))

    rows = []
    for number, title in SECTIONS:
        rows.append([
            Paragraph(
                f"<font color='#4A7CFF'><b>{number}</b></font>",
                body_style(align="left", fontSize=16, textColor=ACCENT_BLUE),
            ),
            Paragraph(
                f"<font color='#F0F4FF'><b>{title}</b></font>",
                body_style(align="left", fontSize=11, textColor=TEXT_PRIMARY),
            ),
            Paragraph(
                f"<font color='#7B8DB5'>0{len(rows) + 1}</font>",
                body_style(align="right", fontSize=11, textColor=TEXT_LABEL),
            ),
        ])

    tbl = Table(rows, colWidths=[30, CONTENT_W - 120, 40])
    tbl.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, "#1F2A44"),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 14))

    story.append(Paragraph(
        "<font color='#A0AEC0'>Sections are ordered to move from executive context "
        "through technical detail to strategic guidance.</font>",
        body_style(align="left", fontSize=8.5, textColor=TEXT_MUTED),
    ))

    story.append(PageBreak())
    return story
