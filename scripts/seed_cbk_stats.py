"""
Seed known CBK fraud stats into the cbk_fraud_stats table.

Bypasses the PDF parser entirely. Uses hardcoded values from KE-CIRT reports.
Skips periods that already exist.

CLI: python scripts/seed_cbk_stats.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from darkweb_scanner.storage import Storage
from darkweb_scanner.ke_context import KenyaContext

SEED_DATA = [
    {
        "period": "2026-08",
        "stats": {"card_fraud": 3000, "cyber": 1000, "mobile_banking": 400, "online": 60},
        "source_url": "https://www.centralbank.go.ke",
    },
    {
        "period": "2026-09",
        "stats": {"card_fraud": 3500, "cyber": 1100, "mobile_banking": 500, "online": 70},
        "source_url": "https://www.centralbank.go.ke",
    },
    {
        "period": "2026-10",
        "stats": {"card_fraud": 3910, "cyber": 1234, "mobile_banking": 567, "online": 89},
        "source_url": "https://www.centralbank.go.ke",
    },
]


def main() -> int:
    storage = Storage()
    ctx = KenyaContext(storage)

    # Get existing periods to skip duplicates
    existing = {
        str(r.get("period") or "").strip()
        for r in (ctx.get_cbk_fraud_trends().get("periods") or [])
    }

    inserted = 0
    skipped = 0
    for entry in SEED_DATA:
        period = entry["period"].strip()
        if period in existing:
            skipped += 1
            print(f"Skipped {period}: already exists")
            continue
        try:
            row_id = ctx.load_cbk_fraud_stats(
                period,
                entry["stats"],
                entry["source_url"],
            )
            print(f"Seeded {period} (row_id={row_id}): {entry['stats']}")
            inserted += 1
        except Exception as exc:
            print(f"Failed to seed {period}: {exc}")

    print(f"Seeded {inserted} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
