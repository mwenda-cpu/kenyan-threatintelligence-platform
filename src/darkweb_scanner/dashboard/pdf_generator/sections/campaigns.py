"""
Section 04 — Campaigns, Tooling & Environments Research.
LockBit killchain, BEC/KRA analysis, tooling, charts.
"""

from reportlab.platypus import Spacer, Paragraph, PageBreak, Image
from reportlab.lib.utils import ImageReader
from io import BytesIO

from ..components import pull_quote, styled_table, section_divider
from ..styles.colors import (
    TEXT_PRIMARY, TEXT_MUTED, TEXT_LABEL, ACCENT_BLUE, ACCENT_PURPLE,
    ACCENT_PINK, BG_SECONDARY,
)
from ..styles.typography import body_style, heading_style, SIZE_H1
from ..styles.layout import CONTENT_W, SECTIONS
from ..charts import timeline_line, donut_chart


def campaigns_flowables(data: dict) -> list:
    story = []

    num, title = SECTIONS[3]
    story.append(section_divider(num, title,
        "LockBit campaign deep-dive, BEC & KRA impersonation, and tooling analysis"))
    story.append(Spacer(1, 10))

    # LockBit killchain phases
    story.append(Paragraph(
        "<font color='#F0F4FF'><b>LockBit Campaign — Killchain Phases</b></font>",
        heading_style(13),
    ))
    phases = [
        ("Reconnaissance", "Scanning Kenyan government and financial perimeters"),
        ("Weaponization", "Phishing kits and access-broker listings prepared"),
        ("Exploitation", "Edge vulnerabilities and credential theft exploited"),
        ("Actions on Objectives", "Data exfiltration, encryption, leak-site posting"),
    ]
    phase_rows = []
    for name, desc in phases:
        phase_rows.append([
            Paragraph(f"<font color='#4A7CFF'><b>{name}</b></font>",
                      body_style(align="left", fontSize=9.5, textColor=TEXT_PRIMARY)),
            Paragraph(desc, body_style(align="left", fontSize=9, textColor=TEXT_MUTED)),
        ])
    phase_tbl = styled_table(
        ["Phase", "Activity"], phase_rows,
        col_widths=[CONTENT_W * 0.3, CONTENT_W * 0.7],
    )
    story.append(phase_tbl)
    story.append(Spacer(1, 10))

    # BEC & KRA analysis
    story.append(Paragraph(
        "<font color='#F0F4FF'><b>BEC & KRA Impersonation Analysis</b></font>",
        heading_style(13),
    ))
    story.append(Paragraph(
        "Attackers impersonate the Kenya Revenue Authority, commercial banks, and "
        "government e-services (eCitizen, IFMIS) using lookalike domains and "
        "social engineering. The goal is credential harvesting and fraudulent "
        "funds transfers via M-Pesa and bank accounts.",
        body_style(align="justify", fontSize=9.5, leading=14, textColor=TEXT_PRIMARY),
    ))
    story.append(Spacer(1, 8))

    # Tooling
    story.append(Paragraph(
        "<font color='#F0F4FF'><b>Tooling & Environments</b></font>",
        heading_style(13),
    ))
    tool_rows = [
        ("Tor-based leak sites", "LockBit, cl0p, and RansomHub leak-site listings"),
        ("DDoS-for-hire", "Stresser/booter services mentioned in dark-web posts"),
        ("Phishing kits", "KRA and banking portal clones targeting Kenyan users"),
        ("Access brokers", "Initial access listings for Kenyan corporate networks"),
    ]
    tool_tbl = styled_table(
        ["Tool / Vector", "Observed Use"], tool_rows,
        col_widths=[CONTENT_W * 0.3, CONTENT_W * 0.7],
    )
    story.append(tool_tbl)
    story.append(Spacer(1, 10))

    # Timeline chart
    timeline = data.get("timeline", [
        ("Session 1", 4), ("Session 6", 12), ("Session 12", 28),
        ("Session 18", 41), ("Session 24", 35),
    ])
    tl_png = timeline_line(timeline, "Keyword Hits per Crawl Session")
    tl_img = Image(BytesIO(tl_png), width=CONTENT_W * 0.9,
                   height=CONTENT_W * 0.9 * 2.4 / 6.5)
    story.append(tl_img)
    story.append(Spacer(1, 10))

    # Source breakdown donut
    source_data = data.get("sources", [
        ("Onion sites", 78), ("Clearnet", 15), ("Social/paste", 7),
    ])
    src_total = sum(v for _, v in source_data)
    src_png = donut_chart(source_data, "Source Breakdown",
                          f"{src_total / 100:.0f}%", "of total",
                          accent_colors=[ACCENT_BLUE, ACCENT_PURPLE, ACCENT_PINK])
    src_img = Image(BytesIO(src_png), width=CONTENT_W * 0.4,
                    height=CONTENT_W * 0.4)
    story.append(src_img)
    story.append(Spacer(1, 10))

    story.append(pull_quote(
        "Tor-based leak sites remain the primary source of actionable intelligence, "
        "but clearnet and social channels are increasingly used for initial access advertising.",
        "Tooling Assessment"
    ))
    story.append(Spacer(1, 8))

    story.append(PageBreak())
    return story
