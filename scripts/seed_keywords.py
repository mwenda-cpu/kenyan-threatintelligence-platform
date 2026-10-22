"""
Seed high-value Kenyan target keywords into the `keywords` table.

Categories: E-Government, Fintech, Banks.
Inserts only if the keyword does not already exist (idempotent).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from darkweb_scanner.storage import Storage

KENYAN_KEYWORDS = {
    "E-Government": [
        "eCitizen", "KRA", "iTax", "IFMIS", "NTSA", "Huduma",
        "Ministry of Health", "Ministry of Interior",
    ],
    "Fintech": [
        "M-Pesa", "Safaricom", "Airtel Money", "Pesalink",
        "Flutterwave", "Chipper Cash",
    ],
    "Banks": [
        "KCB", "Equity Bank", "Co-operative Bank", "NCBA",
        "Absa Kenya", "Stanbic", "Standard Chartered Kenya", "DTB",
    ],
}


def main() -> int:
    storage = Storage()
    total_added = 0

    for category, keywords in KENYAN_KEYWORDS.items():
        for kw in keywords:
            if storage.add_keyword(kw, category=category, severity="high"):
                total_added += 1
                print(f"  + [{category}] {kw}")
            else:
                print(f"  - [{category}] {kw} (already exists)")

    print(f"\nSeeded {total_added} new Kenyan target keywords.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
