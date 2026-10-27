"""
Reusable UI components for the KE-CIRT Threat Intel Report.

Cards, pull quotes, checklists, KPI cards, and section dividers
matching the Hoxhunt visual design system.
"""

from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    Paragraph,
    Table,
    TableStyle,
)

from ..styles.colors import (
    ACCENT_BLUE,
    ACCENT_GREEN,
    ACCENT_PINK,
    ACCENT_PURPLE,
    ACCENT_RED,
    BG_PRIMARY,
    BG_SECONDARY,
    BG_TERTIARY,
    TEXT_LABEL,
    TEXT_MUTED,
    TEXT_PRIMARY,
)
from ..styles.layout import CONTENT_W
from ..styles.typography import body_style, heading_style

# ── Section divider ─────────────────────────────────────────────────────────

# ── Section divider ─────────────────────────────────────────────────────────

def section_divider(number: str, title: str, subtitle: str = "") -> Table:
    """Full-width dark bar with large section number + title (Hoxhunt style).
    Returns a Table (more reliable than a custom Flowable in ReportLab).
    """
    num_para = Paragraph(
        f"<font color='#9D6FFF'><b>{number}</b></font>",
        ParagraphStyle("sd_num", fontName="Helvetica-Bold", fontSize=30,
                       leading=34, textColor=ACCENT_PURPLE),
    )
    title_para = Paragraph(
        f"<font color='#F0F4FF'><b>{title}</b></font>",
        ParagraphStyle("sd_title", fontName="Helvetica-Bold", fontSize=15,
                       leading=18, textColor=TEXT_PRIMARY),
    )
    sub_para = Paragraph(
        f"<font color='#7B8DB5'>{subtitle}</font>" if subtitle else "",
        ParagraphStyle("sd_sub", fontName="Helvetica", fontSize=9,
                       leading=12, textColor=TEXT_MUTED),
    )

    inner = Table(
        [[num_para, title_para],
         ["", sub_para]],
        colWidths=[70, CONTENT_W - 90],
    )
    inner.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    card = Table([[inner]], colWidths=[CONTENT_W])
    card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(BG_SECONDARY)),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1F2A44")),
        ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(ACCENT_BLUE)),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return card


def pull_quote(text: str, author: str = "") -> Table:
    """Hoxhunt-style >> pull-quote callout box."""
    quote_para = Paragraph(
        f'&gt;&gt; <font color="#F0F4FF"><b>{text}</b></font>',
        body_style(align="left", fontSize=11, leading=16, textColor=TEXT_PRIMARY),
    )
    author_para = Paragraph(
        f"<font color='#7B8DB5'>{author}</font>" if author else "",
        body_style(align="right", fontSize=8.5, leading=11, textColor=TEXT_MUTED),
    )

    inner = Table(
        [[quote_para], [author_para]],
        colWidths=[CONTENT_W - 40],
    )
    inner.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))

    card = Table([[inner]], colWidths=[CONTENT_W - 20])
    card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(BG_TERTIARY)),
        ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(ACCENT_PINK)),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("ROUNDEDCORNERS", [6, 6, 6, 6]),
    ]))
    return card


def kpi_card(label: str, value: str, trend: str = "", trend_color: str = ACCENT_GREEN) -> Table:
    """KPI metric card: large value + label + optional trend."""
    val_para = Paragraph(
        f"<font color='#F0F4FF'><b>{value}</b></font>",
        ParagraphStyle("kpiv", fontName="Helvetica-Bold", fontSize=22,
                       leading=26, textColor=TEXT_PRIMARY, alignment=TA_CENTER),
    )
    lab_para = Paragraph(
        f"<font color='#7B8DB5'>{label}</font>",
        ParagraphStyle("kpil", fontName="Helvetica", fontSize=8.5,
                       leading=11, textColor=TEXT_LABEL, alignment=TA_CENTER),
    )
    trend_para = Paragraph(
        f"<font color='{trend_color}'><b>{trend}</b></font>" if trend else "",
        ParagraphStyle("kpit", fontName="Helvetica-Bold", fontSize=8.5,
                       leading=11, textColor=trend_color, alignment=TA_CENTER),
    )

    inner = Table(
        [[val_para], [lab_para], [trend_para]],
        colWidths=[CONTENT_W / 3 - 12],
    )
    inner.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))

    card = Table([[inner]], colWidths=[CONTENT_W / 3])
    card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(BG_SECONDARY)),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1F2A44")),
        ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(ACCENT_BLUE)),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return card


def checklist_box(title: str, items: list, audience: str = "") -> Table:
    """Start / Continue / Stop style checklist box for strategic guidance."""
    item_rows = []
    for item in items:
        item_rows.append([
            Paragraph(
                f"<font color='#4ADE80'>\u2713</font>  {item}",
                body_style(align="left", fontSize=9.5, leading=14, textColor=TEXT_PRIMARY),
            )
        ])

    header_para = Paragraph(
        f"<font color='#F0F4FF'><b>{title}</b></font>"
        + (f" <font color='#7B8DB5'>— {audience}</font>" if audience else ""),
        heading_style(12),
    )

    rows = [[header_para]] + item_rows
    tbl = Table(rows, colWidths=[CONTENT_W - 24])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(BG_SECONDARY)),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1F2A44")),
        ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(ACCENT_GREEN)),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (0, 0), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -2), 2),
    ]))
    return tbl


def start_continue_stop(start_items: list, continue_items: list, stop_items: list) -> Table:
    """Three-column Start / Continue / Stop panel."""
    def _col(title, items, accent):
        rows = [[Paragraph(
            f"<font color='#F0F4FF'><b>{title}</b></font>",
            heading_style(11, textColor=accent),
        )]]
        for item in items:
            rows.append([Paragraph(
                f"\u2022  {item}",
                body_style(align="left", fontSize=8.8, leading=13, textColor=TEXT_PRIMARY),
            )])
        t = Table(rows, colWidths=[CONTENT_W / 3 - 8])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(BG_SECONDARY)),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1F2A44")),
            ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(accent)),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return t

    panel = Table(
        [[_col("START", start_items, ACCENT_GREEN),
          _col("CONTINUE", continue_items, ACCENT_BLUE),
          _col("STOP", stop_items, ACCENT_RED)]],
        colWidths=[CONTENT_W / 3] * 3,
    )
    panel.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return panel


def styled_table(headers: list, rows: list, col_widths: list,
                 header_bg: str = BG_TERTIARY,
                 row_bg_1: str = BG_SECONDARY,
                 row_bg_2: str = BG_PRIMARY,
                 font_size: int = 8.5) -> Table:
    """Styled table with dark header, alternating row colors, rounded corners."""
    data = [[Paragraph(f"<font color='#F0F4FF'><b>{h}</b></font>",
                       ParagraphStyle("th", fontName="Helvetica-Bold",
                                      fontSize=font_size, leading=11,
                                      textColor=TEXT_PRIMARY)) for h in headers]]
    for r in rows:
        row_data = []
        for c in r:
            if isinstance(c, Paragraph):
                # Cell is already a Paragraph — use it directly (avoids str() gibberish).
                row_data.append(c)
            else:
                row_data.append(Paragraph(f"<font color='#F0F4FF'>{c}</font>",
                                          ParagraphStyle("td", fontName="Helvetica",
                                                         fontSize=font_size, leading=11,
                                                         textColor=TEXT_PRIMARY)))
        data.append(row_data)

    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_bg)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#1F2A44")),
    ]
    # Alternating row backgrounds
    for i in range(1, len(data)):
        bg = row_bg_1 if i % 2 == 1 else row_bg_2
        style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor(bg)))
    tbl.setStyle(TableStyle(style))
    return tbl
