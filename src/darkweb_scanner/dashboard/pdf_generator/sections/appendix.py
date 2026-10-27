"""
Section 06 — Appendix & Sources.
Source list, methodology, compliance note.
"""

from reportlab.platypus import PageBreak, Paragraph, Spacer

from ..components import pull_quote, section_divider, styled_table
from ..styles.colors import (
    TEXT_LABEL,
    TEXT_PRIMARY,
)
from ..styles.layout import CONTENT_W, SECTIONS
from ..styles.typography import body_style, heading_style


def appendix_flowables(data: dict) -> list:
    story = []

    num, title = SECTIONS[5]
    story.append(section_divider(num, title,
        "Sources, methodology, and compliance references"))
    story.append(Spacer(1, 10))

    # Sources table
    story.append(Paragraph(
        "<font color='#F0F4FF'><b>Data Sources</b></font>",
        heading_style(13),
    ))
    source_rows = [
        ("KE-CIRT / CC", "National Computer Security Centre, Kenya",
         "Quarterly threat reports, ke-cirt.go.ke"),
        ("CA Kenya", "Communications Authority of Kenya",
         "Cybersecurity advisories, ca.go.ke"),
        ("CBK", "Central Bank of Kenya",
         "Financial Sector Stability reports, fraud statistics"),
        ("Dark Web Monitor", "Tor network crawl sessions",
         "24 sessions, 5,186 pages, keyword-matched hits"),
    ]
    src_tbl = styled_table(
        ["Source", "Organization", "Details"], source_rows,
        col_widths=[CONTENT_W * 0.22, CONTENT_W * 0.38, CONTENT_W * 0.40],
    )
    story.append(src_tbl)
    story.append(Spacer(1, 10))

    # Methodology
    story.append(Paragraph(
        "<font color='#F0F4FF'><b>Methodology</b></font>",
        heading_style(13),
    ))
    story.append(Paragraph(
        "Data collected from Tor network crawl sessions (24 sessions, 5,186 pages). "
        "Keyword hits are matched against the platform keyword database. Only "
        "actionable hits — excluding search engines, legal pages, and navigation "
        "noise — are reported. Snippets are cleaned at crawl time to remove page "
        "chrome, leak-site menus, onion addresses, and crypto dumps.",
        body_style(align="justify", fontSize=9.5, leading=14, textColor=TEXT_PRIMARY),
    ))
    story.append(Spacer(1, 10))

    # Compliance
    story.append(pull_quote(
        "This report handles potentially sensitive threat data in accordance with "
        "Kenya's Data Protection Act (2019). Distribution is restricted to authorized "
        "personnel within Kenyan government and critical infrastructure organizations.",
        "Compliance"
    ))
    story.append(Spacer(1, 10))

    # Disclaimer
    story.append(Paragraph(
        "<font color='#7B8DB5'><b>Disclaimer:</b> This report is for informational "
        "purposes only. KE-CIRT / CC makes no warranties regarding the completeness "
        "or accuracy of third-party data. Do not distribute without authorization.</font>",
        body_style(align="left", fontSize=8, leading=10, textColor=TEXT_LABEL),
    ))

    story.append(PageBreak())
    return story
