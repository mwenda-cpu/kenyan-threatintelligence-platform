#!/usr/bin/env python3
"""
Extract all ONLINE .onion URLs from deepdarkCTI ransomware_gang.md
and generate a clean PDF.
"""

import re
import requests
from fpdf import FPDF

# ── Config ──────────────────────────────────────────────
SOURCE_URL = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/ransomware_gang.md"
OUTPUT_PDF = "online_onion_urls.pdf"

# ── Fetch the markdown ──────────────────────────────────
print(f"Fetching {SOURCE_URL} ...")
resp = requests.get(SOURCE_URL, timeout=30)
resp.raise_for_status()
text = resp.text
lines = text.splitlines()

# ── Parse rows ──────────────────────────────────────────
# Each table row looks like:
# |[Name](URL)|STATUS|...|
# We want rows where STATUS == ONLINE and URL ends with .onion
urls = []
for line in lines:
    if "|ONLINE|" not in line and "|ONLINE " not in line:
        continue

    # Find all markdown links [text](url)
    links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', line)

    for name, url in links:
        url = url.strip()
        # Keep only .onion URLs
        if ".onion" not in url:
            continue
        # Skip obvious non-http entries
        if not url.startswith("http"):
            continue
        urls.append((name.strip(), url.strip()))

# Deduplicate by URL, preserve order
seen = set()
unique = []
for name, url in urls:
    if url not in seen:
        seen.add(url)
        unique.append((name, url))

print(f"Found {len(unique)} unique ONLINE .onion URLs")

# ── Generate PDF ────────────────────────────────────────
pdf = FPDF()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()

# Title
pdf.set_font("Helvetica", "B", 16)
pdf.cell(0, 10, "ONLINE Ransomware .onion URLs", ln=True, align="C")
pdf.set_font("Helvetica", "", 9)
pdf.cell(0, 8, f"Source: deepdarkCTI ransomware_gang.md", ln=True, align="C")
pdf.ln(4)

# Column headers
pdf.set_font("Helvetica", "B", 10)
pdf.set_fill_color(230, 230, 230)
pdf.cell(60, 8, "Group / Name", border=1, fill=True)
pdf.cell(130, 8, "Onion URL", border=1, fill=True, ln=True)

# Rows
pdf.set_font("Helvetica", "", 8)
for name, url in unique:
    # Truncate long names
    name_disp = (name[:57] + "...") if len(name) > 60 else name
    # Wrap URL if too long (rare for .onion)
    url_disp = url
    pdf.cell(60, 6, name_disp, border=1)
    pdf.cell(130, 6, url_disp, border=1, ln=True)

pdf.output(OUTPUT_PDF)
print(f"✅ PDF written to {OUTPUT_PDF}")