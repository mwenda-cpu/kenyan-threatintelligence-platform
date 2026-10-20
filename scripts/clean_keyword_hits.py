"""Purge and sanitise the keyword-hit table.

Early versions of the scanner compiled the literal words "category" and
"severity" (the YAML seed stores those as metadata, and the config was read
with the wrong shape), so the table is full of junk hits. Those rows are
deleted here, and every remaining snippet is re-cleaned so the dashboard and
the PDF report stop showing raw page dumps.

Usage:
    python -m scripts.clean_keyword_hits --dry-run     # report only
    python -m scripts.clean_keyword_hits --apply        # write changes
"""

import argparse
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from darkweb_scanner.snippets import MAX_SNIPPET_LEN, clean_snippet  # noqa: E402

logger = logging.getLogger(__name__)

# Keywords that were produced by the broken config — they are never real hits.
JUNK_KEYWORDS = ("category", "severity")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Clean the keyword_hits table")
    parser.add_argument("--apply", action="store_true", help="write the changes (default: dry run)")
    parser.add_argument("--dry-run", action="store_true", help="report only (default)")
    parser.add_argument("--max-len", type=int, default=500,
                        help="truncate snippets longer than this (default: 500)")
    parser.add_argument("--keep-junk", action="store_true",
                        help="do not delete the 'category'/'severity' keyword rows")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from darkweb_scanner.dashboard.storage_helper import get_storage
    from darkweb_scanner.storage import KeywordHitRecord

    storage = get_storage()
    limit = max(50, min(args.max_len, MAX_SNIPPET_LEN))

    with storage.get_session() as session:
        rows = session.query(KeywordHitRecord).all()
        logger.info("keyword_hits rows before cleanup: %s", len(rows))

        deleted_junk = 0
        deleted_unreadable = 0
        truncated = 0
        cleaned = 0
        keep = []

        for row in rows:
            keyword = (row.keyword or "").strip()

            # 1) junk keywords from the broken config
            if not args.keep_junk and keyword.lower() in JUNK_KEYWORDS:
                session.delete(row)
                deleted_junk += 1
                continue

            # 2) empty / missing keywords
            if not keyword:
                session.delete(row)
                deleted_junk += 1
                continue

            context = row.context or ""

            # 3) re-clean the snippet (menu lists, onion/crypto dumps, ...)
            new_context = clean_snippet(context, keep=keyword, max_len=limit)
            if not new_context or keyword.lower() not in new_context.lower():
                # Nothing readable is left: the keyword only appeared in
                # navigation chrome, so the hit is not actionable.
                session.delete(row)
                deleted_unreadable += 1
                continue

            if new_context != context:
                if len(context) > limit:
                    truncated += 1
                else:
                    cleaned += 1
                row.context = new_context
            keep.append(row.id)

        if args.apply:
            session.commit()
            logger.info("committed")
        else:
            session.rollback()
            logger.info("dry run - nothing written (use --apply)")

        logger.info("deleted junk-keyword rows : %s", deleted_junk)
        logger.info("deleted unreadable rows   : %s", deleted_unreadable)
        logger.info("truncated snippets        : %s", truncated)
        logger.info("re-cleaned snippets       : %s", cleaned)
        logger.info("rows remaining            : %s", len(keep))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
