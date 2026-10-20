"""
Section 05 — Strategic Guidance.
Per-audience checklists + Start/Continue/Stop panels.
"""

from reportlab.platypus import Spacer, Paragraph, PageBreak

from ..components import pull_quote, start_continue_stop, checklist_box, section_divider
from ..styles.colors import (
    TEXT_PRIMARY, TEXT_MUTED, TEXT_LABEL, ACCENT_BLUE, ACCENT_PURPLE,
    BG_SECONDARY,
)
from ..styles.typography import body_style, heading_style, SIZE_H1
from ..styles.layout import CONTENT_W, SECTIONS


def strategic_guidance_flowables(data: dict) -> list:
    story = []

    num, title = SECTIONS[4]
    story.append(section_divider(num, title,
        "Executive overview and per-audience strategic guidance"))
    story.append(Spacer(1, 10))

    # Executive overview pull quote
    story.append(pull_quote(
        "Turn intelligence into action: prioritize LockBit detections, run KRA "
        "impersonation simulations, and harden MFA across Kenyan banking targets.",
        "Executive Overview"
    ))
    story.append(Spacer(1, 10))

    # CISO checklist
    story.append(checklist_box(
        "CISOs — Turn Intel into Action",
        [
            "Deploy LockBit-specific detections on leak-site IOCs",
            "Run KRA impersonation and BEC phishing simulations",
            "Establish KE-CIRT/CC liaison for indicator sharing",
            "Review cyber insurance coverage for ransomware events",
        ],
        "CISO",
    ))
    story.append(Spacer(1, 8))

    # SOC/IT/Defenders checklist
    story.append(checklist_box(
        "SOC / IT / Defenders — Operational Hardening",
        [
            "Monitor Tor leak sites on a weekly cadence for Kenyan org mentions",
            "Implement token-centric incident response for credential theft",
            "Harden MFA for all CBK-regulated banking applications",
            "Block known access-broker and DDoS-for-hire infrastructure",
        ],
        "SOC / IT / Defenders",
    ))
    story.append(Spacer(1, 8))

    # Security Awareness Leaders checklist
    story.append(checklist_box(
        "Security Awareness Leaders — Localized Training",
        [
            "Train against routine-looking KRA and BEC lures in Kenyan English",
            "Use CBK fraud data (mobile banking, card, online) in simulations",
            "Cover Wangiri and SIM-swap scams in mobile-security modules",
            "Promote 'Pause + Verify + Act' reporting culture",
        ],
        "Security Awareness",
    ))
    story.append(Spacer(1, 14))

    # Start / Continue / Stop panel
    story.append(start_continue_stop(
        start_items=[
            "Weekly Tor leak-site monitoring for Kenyan targets",
            "KRA impersonation tabletop exercises quarterly",
            "MFA rollout across all government e-services",
        ],
        continue_items=[
            "KE-CIRT/CC indicator sharing partnership",
            "CBK fraud statistics trend analysis",
            "Dark-web keyword monitoring for .ke and .go.ke",
        ],
        stop_items=[
            "Relying solely on email gateway filters for BEC",
            "Treating LockBit volume as low risk",
            "Ignoring Wangiri and SIM-swap as minor threats",
        ],
    ))
    story.append(Spacer(1, 14))

    story.append(PageBreak())
    return story
