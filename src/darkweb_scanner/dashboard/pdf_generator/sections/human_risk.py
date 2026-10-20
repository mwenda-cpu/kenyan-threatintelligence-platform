"""
Section 03 — Human Risk Findings (Kenyan adaptation).
Lures, CBK fraud stats, reporting guidance.
"""

from reportlab.platypus import Spacer, Paragraph, PageBreak, Image
from reportlab.lib.utils import ImageReader
from io import BytesIO

from ..components import pull_quote, styled_table, checklist_box, section_divider
from ..styles.colors import (
    TEXT_PRIMARY, TEXT_MUTED, TEXT_LABEL, ACCENT_BLUE, ACCENT_PURPLE,
    ACCENT_PINK, BG_SECONDARY,
)
from ..styles.typography import body_style, heading_style, SIZE_H1
from ..styles.layout import CONTENT_W, SECTIONS
from ..charts import cbk_fraud_bar


def human_risk_flowables(data: dict) -> list:
    story = []

    num, title = SECTIONS[2]
    story.append(section_divider(num, title,
        "Kenyan user lures, CBK fraud statistics, and reporting guidance"))
    story.append(Spacer(1, 10))

    # Lures
    lures = data.get("lures", [
        "BEC (business email compromise) — spoofed supplier and executive emails",
        "KRA impersonation — fake tax notices and refund scams",
        "M-Pesa / banking fraud — SIM-swap and OTP interception",
        "Wangiri scams — missed-call callback fraud targeting mobile users",
        "eCitizen / IFMIS credential harvesting — government portal lookalikes",
    ])
    story.append(Paragraph(
        "<font color='#F0F4FF'><b>Lures Kenyan Users Fall For</b></font>",
        heading_style(13),
    ))
    for lure in lures:
        story.append(Paragraph(
            f"\u2022  {lure}", body_style(align="left", fontSize=9.5, leading=14, textColor=TEXT_PRIMARY)))
    story.append(Spacer(1, 10))

    # CBK fraud chart
    cbk = data.get("cbk_stats", {
        "mobile_banking": 8420, "card": 3910, "online": 1875, "cyber": 1240,
    })
    cbk_items = list(cbk.items())
    cbk_png = cbk_fraud_bar(cbk_items, "CBK Fraud Statistics by Category")
    cbk_img = Image(BytesIO(cbk_png), width=CONTENT_W * 0.7,
                    height=CONTENT_W * 0.7 * 2.6 / 5.2)
    story.append(cbk_img)
    story.append(Spacer(1, 12))

    # Reporting guidance pull quote
    story.append(pull_quote(
        "Pause + Verify + Act: verify KRA requests via the official iTax portal, "
        "confirm M-Pesa transactions through official callbacks, and report "
        "suspicious activity to KE-CIRT/CC before acting.",
        "Reporting Guidance"
    ))
    story.append(Spacer(1, 10))

    story.append(PageBreak())
    return story
