"""Keyword store: the database is the source of truth, YAML is only a seed.

``config/keywords.yaml`` ships with the repository and is used to populate an
empty ``keywords`` table the first time the platform runs. Every later edit
(through the dashboard, the API or the CLI) goes to the database, and the
crawler reads its keyword list from there.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_SEVERITY = "medium"
DEFAULT_CATEGORY = "custom"


def parse_seed_yaml(path) -> list[dict]:
    """Parse the seed YAML into ``[{keyword, category, severity}, ...]``.

    Two shapes are supported:

    * ``keywords: {eCitizen: {severity: high, category: government}}`` — the
      shipped format, one entry per keyword.
    * ``keywords: {government: [eCitizen, KRA]}`` — the legacy category map.
    """
    import yaml

    path = Path(path)
    if not path.exists():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001 - a bad seed must not break startup
        logger.warning("Could not parse keyword seed %s: %s", path, exc)
        return []

    entries = raw.get("keywords", raw) or {}
    if not isinstance(entries, dict):
        return []

    rows: list[dict] = []
    for key, value in entries.items():
        if isinstance(value, dict):
            keyword = str(key).strip()
            if not keyword:
                continue
            rows.append({
                "keyword": keyword,
                "category": str(value.get("category") or DEFAULT_CATEGORY).strip(),
                "severity": str(value.get("severity") or DEFAULT_SEVERITY).strip(),
            })
        elif isinstance(value, (list, tuple, set)):
            category = str(key).strip() or DEFAULT_CATEGORY
            for item in value:
                keyword = str(item).strip()
                if keyword:
                    rows.append({"keyword": keyword, "category": category,
                                 "severity": DEFAULT_SEVERITY})
    return rows


def _as_paths(seed_path) -> list[Path]:
    if seed_path is None:
        return []
    if isinstance(seed_path, (str, Path)):
        return [Path(seed_path)]
    return [Path(p) for p in seed_path]


def seed_keywords(storage, seed_path=None) -> int:
    """Add every seed keyword that is not in the table yet (never overwrites)."""
    added = 0
    for path in _as_paths(seed_path):
        rows = parse_seed_yaml(path)
        if not rows:
            continue
        added += storage.add_keywords(rows)
    if added:
        logger.info("Seeded %s keywords from the YAML seed", added)
    return added


def seed_if_empty(storage, seed_path=None) -> int:
    """Populate an empty keywords table from the YAML seed. Returns rows added."""
    try:
        if storage.keyword_count() > 0:
            return 0
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not read keyword count: %s", exc)
        return 0

    seeds = _as_paths(seed_path) or [_default_seed_path()]
    return seed_keywords(storage, seeds)


def _default_seed_path() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "config" / "keywords.yaml"


def keyword_config(storage, seed_path=None):
    """Build a ``KeywordConfig`` from the database (seeding it when empty)."""
    from .scanner import KeywordConfig

    seed_if_empty(storage, seed_path)
    categories = storage.keyword_categories()
    if not categories:
        logger.warning("Keyword table is empty — the crawler will not match anything")
    return KeywordConfig(categories=categories)
