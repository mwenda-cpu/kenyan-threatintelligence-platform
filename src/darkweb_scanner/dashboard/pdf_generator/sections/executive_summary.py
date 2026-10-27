"""
Section 01 — Executive Summary & Introduction.
3 key developments + narrative + data source note.
"""

from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import PageBreak, Paragraph, Spacer

from ..components import pull_quote, section_divider
from ..styles.colors import (
    TEXT_LABEL,
    TEXT_PRIMARY,
)
from ..styles.layout import SECTIONS
from ..styles.typography import body_style, heading_style


def exec_summary_flowables(data: dict) -> list:
    story = []

    # Section divider
    num, title = SECTIONS[0]
    story.append(section_divider(num, title,
        "LockBit dominance, BEC and KRA impersonation, emerging DDoS and cl0p threats"))
    story.append(Spacer(1, 10))

    # 3 Key Developments — simple paragraphs (avoids Table height issues)
    dev = data.get("key_developments", [
        "LockBit dominates: 101 of 122 actionable hits are LockBit-related, "
        "signaling active leak-site monitoring and sustained ransomware pressure "
        "on Kenyan organizations.",
        "BEC and KRA impersonation: 8 BEC hits and 8 KRA-related hits highlight "
        "targeted social engineering against government and financial sectors.",
        "DDoS and cl0p: 2 hits each suggest adversary diversification beyond ransomware.",
    ])

    story.append(Paragraph(
        "<font color='#F0F4FF'><b>3 Key Developments</b></font>",
        heading_style(13),
    ))
    for i, d in enumerate(dev, 1):
        story.append(Paragraph(
            f"<font color='#4A7CFF'><b>{i}.</b></font>  {d}",
            ParagraphStyle(f"dev_{i}", fontName="Helvetica", fontSize=9.5,
                           leading=14, textColor=TEXT_PRIMARY, alignment=TA_LEFT),
        ))
        story.append(Spacer(1, 6))

    # Pull quote
    story.append(pull_quote(
        "LockBit's dominance in the dataset does not mean other threats are dormant — "
        "it means defenders must not conflate volume with risk.",
        "KE-CIRT Analyst Team"
    ))
    story.append(Spacer(1, 8))

    # Threat landscape narrative
    story.append(Paragraph(
        "<font color='#F0F4FF'><b>Threat Landscape Overview</b></font>",
        heading_style(13),
    ))
    narrative = data.get("narrative", (
        "While ransomware dominated headlines in 2026, these attacks accounted for "
        "the majority of observed activity against Kenyan targets. The convergence "
        "of LockBit leak-site listings, business email compromise attempts, and "
        "Kenya Revenue Authority impersonation signals a sustained adversary focus "
        "on Kenya's public sector and banking ecosystem. Analysts should monitor "
        "trends across sessions for emerging threats targeting Kenyan government "
        "e-services and financial institutions."
    ))
    story.append(Paragraph(narrative, body_style(align="justify", fontSize=10, leading=16, textColor=TEXT_PRIMARY)))
    story.append(Spacer(1, 8))

    # Data source note
    src = data.get("source_note", (
        "This report's data set is based on 24 crawl sessions, 5,186 pages, "
        "and 122 actionable threat hits from Tor network monitoring."
    ))
    story.append(Paragraph(
        f"<font color='#7B8DB5'><b>Data source note:</b> {src}</font>",
        body_style(align="left", fontSize=8.5, leading=11, textColor=TEXT_LABEL),
    ))

    story.append(PageBreak())
    return story
