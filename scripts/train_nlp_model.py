"""
Train the NLP threat classifier used by ``darkweb_scanner.dashboard.predictor``.

Data sources (tried in order; each step degrades gracefully so the script always
produces a usable model):

1. ThreatLabz ``ransomware_notes`` (GitHub)
   ``https://github.com/ThreatLabz/ransomware_notes`` - 900+ real ransom notes.
   Fetched via the unauthenticated GitHub API (no credentials required).
2. Kaggle dark-web posts (``ransomhub_posts.csv``, ``play_posts.csv``,
   ``bianlian_posts.csv``, ``cracked_combo.csv``)
   Requires the ``kaggle`` CLI with ``KAGGLE_USERNAME``/``KAGGLE_KEY`` set.
   Skipped automatically when credentials are absent.
3. Synthetic fallback - representative ransom-note / benign text so training can
   always complete offline.

Benign text comes from scikit-learn's built-in ``20 Newsgroups`` dataset, with a
synthetic fallback.

The trained ``LogisticRegression`` model and ``TfidfVectorizer`` are written to
``models/`` (configurable via ``MODEL_DIR``, default ``/app/models``) as
``threat_model.pkl`` and ``tfidf_vectorizer.pkl`` and consumed by
``darkweb_scanner.dashboard.predictor``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

import joblib
from sklearn.datasets import fetch_20newsgroups
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)

MODEL_DIR = Path(os.getenv("MODEL_DIR", "/app/models"))
MODEL_PATH = MODEL_DIR / "threat_model.pkl"
VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.pkl"

THREATLABZ_REPO = "ThreatLabz/ransomware_notes"
THREATLABZ_TREE_URL = (
    f"https://api.github.com/repos/{THREATLABZ_REPO}/git/trees/main?recursive=1"
)
THREATLABZ_RAW_URL = (
    f"https://raw.githubusercontent.com/{THREATLABZ_REPO}/main/"
)

MAX_THREAT_NOTES = 200
REQUEST_TIMEOUT = 20
REQUEST_DELAY = 0.05  # seconds between raw-file fetches

HIGH_RISK_KEYWORDS = [
    "access broker",
    "database dump",
    "wire transfer",
    "leak",
    "ransom",
    "decrypt",
    "bitcoin",
    "monero",
    "tor",
    "onion",
    "payload",
    "exfiltrat",
    "breach",
    "compromised",
    "credentials",
    "sql injection",
    "rce",
    "remote code",
    "0day",
    "zero-day",
    "dox",
    "sale",
    "sensitive",
    "confidential",
    "fullz",
    "ccv",
    "track2",
]


def _http_get_text(url: str) -> str:
    req = urllib.request.Request(
        url, headers={"User-Agent": "darkweb-scanner-train/1.0"}
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_threatlabz_notes(limit: int = MAX_THREAT_NOTES) -> list[str]:
    """Download ransom notes from the ThreatLabz GitHub archive."""
    notes: list[str] = []
    try:
        tree = json.loads(_http_get_text(THREATLABZ_TREE_URL))
    except Exception as exc:  # noqa: BLE001 - network may be unavailable
        logger.warning("Could not fetch ThreatLabz tree: %s", exc)
        return notes

    paths = [
        node["path"]
        for node in tree.get("tree", [])
        if node.get("type") == "blob"
        and node.get("path", "").lower().endswith((".txt", ".html", ".hta"))
    ]
    logger.info("ThreatLabz tree lists %d note files", len(paths))

    for path in paths[:limit]:
        try:
            text = _http_get_text(THREATLABZ_RAW_URL + path)
            if len(text.strip()) > 20:
                notes.append(text.strip())
        except Exception as exc:  # noqa: BLE001 - one file must not stop training
            logger.debug("Skipping %s: %s", path, exc)
        time.sleep(REQUEST_DELAY)

    logger.info("Loaded %d ThreatLabz ransom notes", len(notes))
    return notes


def fetch_kaggle_posts() -> list[str]:
    """Attempt to download the Kaggle dark-web post CSVs (needs credentials)."""
    import shutil

    if shutil.which("kaggle") is None:
        logger.warning(
            "kaggle CLI not found - skipping Kaggle datasets "
            "(set KAGGLE_USERNAME/KAGGLE_KEY and install kaggle to use them)"
        )
        return []

    datasets = [
        "ransomhub_posts.csv",
        "play_posts.csv",
        "bianlian_posts.csv",
        "cracked_combo.csv",
    ]
    texts: list[str] = []
    for ds in datasets:
        try:
            out = Path("data/kaggle_%s" % ds)
            out.parent.mkdir(parents=True, exist_ok=True)
            import subprocess

            subprocess.run(
                [
                    "kaggle",
                    "datasets",
                    "download",
                    "-f",
                    ds,
                    "--file",
                    ds,
                    "--path",
                    str(out.parent),
                    "--unzip",
                ],
                check=True,
                capture_output=True,
                timeout=120,
            )
            # kaggle writes <ds>.zip contents; find any csv we just dropped
            for candidate in out.parent.glob("*.csv"):
                try:
                    import csv as _csv

                    with open(candidate, encoding="utf-8", errors="replace") as fh:
                        reader = _csv.DictReader(fh)
                        for row in reader:
                            for val in row.values():
                                if val and len(str(val)) > 20:
                                    texts.append(str(val).strip())
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Skipping %s: %s", candidate, exc)
        except Exception as exc:  # noqa: BLE001 - auth/network failure is expected
            logger.warning("Kaggle download of %s skipped: %s", ds, exc)
    logger.info("Loaded %d Kaggle post texts", len(texts))
    return texts


def fetch_benign_texts() -> list[str]:
    """Benign English text from scikit-learn's 20 Newsgroups."""
    try:
        data = fetch_20newsgroups(subset="all", remove=("headers", "footers", "quotes"))
        texts = [t for t in data.data if len(t.strip()) > 30]
        logger.info("Loaded %d 20 Newsgroups benign texts", len(texts))
        return texts
    except Exception as exc:  # noqa: BLE001 - network may be unavailable
        logger.warning("Could not load 20 Newsgroups: %s", exc)
        return []


def synthetic_threat_notes() -> list[str]:
    """Synthetic ransom notes so training always has threat data."""
    templates = [
        "YOUR FILES HAVE BEEN ENCRYPTED by {group}. Pay {amount} {coin} to {addr} "
        "within {days} days or all data will be published on our leak site. "
        "Contact us on Tor at {onion}. Do not contact the police.",
        "All your important files are encrypted. To recover them send {amount} "
        "Bitcoin to wallet {addr}. We are {group}, an access broker with full "
        "domain admin. Database dump included in the leak.",
        "{group} ransomware: your network is compromised. We exfiltrated {amount} "
        "GB of sensitive data including credentials and database dumps. Pay the "
        "ransom via wire transfer to avoid public disclosure on our onion blog.",
    ]
    groups = ["LockBit", "Clop", "Conti", "BlackCat", "Akira", "Royal", "DarkSide"]
    coins = ["BTC", "XMR", "Monero"]
    notes: list[str] = []
    for i in range(60):
        t = templates[i % len(templates)].format(
            group=groups[i % len(groups)],
            amount=str(5000 + i * 100),
            coin=coins[i % len(coins)],
            addr="1" + "".join("abcdef0123456789"[(j * 7) % 16] for j in range(34)),
            days=7 + i % 7,
            onion="".join("abcdefghijklmnopqrstuvwxyz012345"[(k * 3) % 32] for k in range(16))
            + ".onion",
        )
        notes.append(t)
    return notes


def build_dataset() -> tuple[list[str], list[int]]:
    """Return (texts, labels) where label 1 = threat, 0 = benign."""
    threats: list[str] = []
    threats += fetch_threatlabz_notes()
    threats += fetch_kaggle_posts()
    if len(threats) < 10:
        logger.warning(
            "Few threat texts collected (%d); augmenting with synthetic notes",
            len(threats),
        )
        threats += synthetic_threat_notes()

    benigns: list[str] = []
    benigns += fetch_benign_texts()
    if len(benigns) < 10:
        logger.warning(
            "Few benign texts collected (%d); augmenting with synthetic text",
            len(benigns),
        )
        benigns += [
            "The quick brown fox jumps over the lazy dog.",
            "Today's weather forecast calls for mild temperatures.",
            "Please review the attached meeting agenda for tomorrow.",
            "Our quarterly earnings report is available in the portal.",
        ] * 20

    # Balance classes.
    n = min(len(threats), len(benigns))
    threats = threats[:n]
    benigns = benigns[:n]
    texts = threats + benigns
    labels = [1] * n + [0] * n
    logger.info(
        "Training dataset: %d threat, %d benign (total %d)", n, n, len(texts)
    )
    return texts, labels


def train(texts: list[str], labels: list[int], model_dir: Path = MODEL_DIR) -> None:
    vectorizer = TfidfVectorizer(
        max_features=5000, ngram_range=(1, 2), stop_words="english", min_df=2
    )
    X = vectorizer.fit_transform(texts)
    model = LogisticRegression(class_weight="balanced", max_iter=1000)
    model.fit(X, labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.2, random_state=42, stratify=labels
    )
    model.fit(X_train, y_train)
    acc = model.score(X_test, y_test)
    logger.info("Test accuracy: %.3f", acc)
    try:
        print(classification_report(y_test, model.predict(X_test)))
    except Exception:  # noqa: BLE001 - reporting is optional
        pass

    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_dir / "threat_model.pkl")
    joblib.dump(vectorizer, model_dir / "tfidf_vectorizer.pkl")
    logger.info("Saved model to %s", model_dir / "threat_model.pkl")
    logger.info("Saved vectorizer to %s", model_dir / "tfidf_vectorizer.pkl")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(
        description="Train the KE threat classifier and save model artifacts."
    )
    parser.add_argument(
        "--model-dir", default=str(MODEL_DIR), help="Directory to write model files"
    )
    args = parser.parse_args(argv)

    model_dir = Path(args.model_dir)

    texts, labels = build_dataset()
    train(texts, labels, model_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
