"""
Seed mock paste records into the paste_hits / seen_pastes tables.

Inserts 5-10 realistic paste hits so the Paste Monitor UI can be verified.
Idempotent: uses ON CONFLICT DO NOTHING on seen_pastes (source, paste_id unique).
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from darkweb_scanner.storage import Storage

PASTE_RECORDS = [
    # (paste_id, url, source, matched_pattern, matched_value, context, minutes_ago)
    ("r3n7ry_a", "https://rentry.co/r3n7ry_a", "rentry", "ke_mobile", "+254712345678",
     "Leaked Safaricom agent float credentials: +254712345678, PIN: 1234", 120),
    ("r3n7ry_b", "https://rentry.co/r3n7ry_b", "rentry", "ke_bank", "Equity Bank",
     "Equity Bank employee payroll dump - internal emails and contacts", 300),
    ("r3n7ry_c", "https://rentry.co/r3n7ry_c", "rentry", "ke_domain", "safaricom.ke",
     "safaricom.ke subdomain takeover - forgot password endpoint exposed", 600),
    ("hst_x9y2", "https://hastebin.com/x9y2", "hastebin", "ke_gov_domain", "ecitizen.go.ke",
     "eCitizen portal session tokens found in public paste", 180),
    ("hst_z8w1", "https://hastebin.com/z8w1", "hastebin", "ke_mobile", "0722334455",
     "M-Pesa transaction logs - merchant codes and phone numbers", 450),
    ("gst_k4m9", "https://ghostbin.com/k4m9", "ghostbin", "ke_bank", "KCB",
     "Kenya Commercial Bank API keys and webhook secrets", 720),
    ("gst_p2q8", "https://ghostbin.com/p2q8", "ghostbin", "ke_domain", "equity.ke",
     "equity.ke employee directory - names, emails, extensions", 900),
    ("r3n7ry_d", "https://rentry.co/r3n7ry_d", "rentry", "ke_mpesa_txn", "XQ9R2T8L",
     "M-Pesa transaction reference XQ9R2T8L - KSh 45,000 transfer", 150),
]


def main() -> int:
    storage = Storage()
    inserted = 0
    skipped = 0

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    for paste_id, url, source, pattern, value, context, minutes_ago in PASTE_RECORDS:
        # Mark paste as seen (idempotent via unique constraint)
        try:
            storage.mark_paste_seen(source, paste_id, url, had_hits=True)
        except Exception:
            # ON CONFLICT DO NOTHING — if already seen, just continue
            skipped += 1
            continue

        # Save the hit with a staggered timestamp
        found_at = now - timedelta(minutes=minutes_ago)
        try:
            # We need to set found_at directly; save_paste_hit uses default now()
            # So we insert via SQL for timestamp control
            with storage.get_session() as session:
                from darkweb_scanner.storage import PasteHit
                existing = session.query(PasteHit).filter(
                    PasteHit.paste_id == paste_id,
                    PasteHit.matched_pattern == pattern,
                ).first()
                if existing:
                    skipped += 1
                    continue
                h = PasteHit(
                    paste_id=paste_id, url=url, source=source,
                    matched_pattern=pattern, matched_value=value,
                    context=context, found_at=found_at,
                )
                session.add(h)
                session.commit()
                inserted += 1
                print(f"  + [{source}] {paste_id} — {pattern}: {value[:40]}")
        except Exception as exc:
            print(f"  ! [{source}] {paste_id} — error: {exc}")
            skipped += 1

    print(f"\nSeeded {inserted} paste hits ({skipped} skipped/duplicates).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
