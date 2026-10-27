"""
Table of contents section — Hoxhunt-styled with large section numbers.
"""

from reportlab.platypus import PageBreak, Paragraph, Spacer, Table, TableStyle

from ..styles.colors import (
    ACCENT_BLUE,
    TEXT_LABEL,
    TEXT_MUTED,
    TEXT_PRIMARY,
)
from ..styles.layout import CONTENT_W, SECTIONS
from ..styles.typography import SIZE_H1, body_style, heading_style


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
