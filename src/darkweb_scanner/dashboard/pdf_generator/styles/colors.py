"""
Hoxhunt-matched color palette for the KE-CIRT Threat Intel Report.

Deep navy / dark theme with accent colors for charts and highlights.
"""

# ── Core palette (Hoxhunt-matched) ──────────────────────────────────────────
BG_PRIMARY   = "#0A1128"   # Page background (deep navy)
BG_SECONDARY = "#1B2A4A"   # Section card backgrounds
BG_TERTIARY  = "#233554"   # Table header backgrounds
ACCENT_BLUE  = "#4A7CFF"   # Primary accent, bar charts
ACCENT_PURPLE= "#9D6FFF"   # Secondary accent, donut charts
ACCENT_PINK  = "#F0A6FF"   # Highlight elements
ACCENT_RED   = "#FF4D6D"   # Alerts, critical threats
ACCENT_GREEN = "#4ADE80"   # Positive metrics

TEXT_PRIMARY = "#F0F4FF"   # Main text
TEXT_MUTED   = "#A0AEC0"   # Secondary text
TEXT_LABEL   = "#7B8DB5"   # Chart labels, captions

# ── Semantic aliases ────────────────────────────────────────────────────────
NAVY      = BG_PRIMARY
SURFACE   = BG_SECONDARY
HEADER    = BG_TERTIARY
INK       = TEXT_PRIMARY
MUTED     = TEXT_MUTED
LABEL     = TEXT_LABEL

# ── Kenyan national colors (secondary palette accents) ──────────────────────
KE_BLACK = "#000000"
KE_RED   = "#CE1126"
KE_GREEN = "#006B3F"
KE_WHITE = "#FFFFFF"

# ── Gradient stop pairs for chart fills ─────────────────────────────────────
GRADIENT_BLUE_PURPLE = (ACCENT_BLUE, ACCENT_PURPLE)
GRADIENT_PURPLE_PINK = (ACCENT_PURPLE, ACCENT_PINK)
