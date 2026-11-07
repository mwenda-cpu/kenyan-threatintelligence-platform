"""
Unit tests for the scraped-text sanitizer.

Covers base64-blob removal, clean-text preservation, bytes decoding,
crypto/onion stripping, minified-content rejection, JSON/SQL/HTML noise
rejection, repetition-artifact rejection and truncation.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from darkweb_scanner.utils.text_cleaner import FALLBACK, sanitize_scraped_text  # noqa: E402


def test_clean_text_preserved():
    raw = "Kenya experienced a rise in phishing attacks targeting the banking sector."
    out = sanitize_scraped_text(raw)
    assert out == raw


def test_base64_blob_dropped():
    blob = "a" * 80  # >50 chars, no spaces -> base64-looking
    raw = f"Normal sentence here. {blob} More normal text."
    out = sanitize_scraped_text(raw)
    assert blob not in out
    assert "Normal sentence here." in out
    assert "More normal text." in out


def test_bytes_input_decoded():
    raw = b"Decoded bytes content about ransomware in Kenya."
    out = sanitize_scraped_text(raw)
    assert out == "Decoded bytes content about ransomware in Kenya."


def test_crypto_and_onion_stripped():
    raw = "Visit 0xAbcdef1234567890abcdef1234567890abcdef12 and abcdefghijklmnop.onion for info."
    out = sanitize_scraped_text(raw)
    assert "0xAbcdef1234567890abcdef1234567890abcdef12" not in out
    assert "abcdefghijklmnop.onion" not in out
    assert "Visit" in out and "for info" in out


def test_json_dump_returns_fallback():
    raw = '{"status":"ok","data":{"id":123,"name":"Acme Corp","url":"http://example.com"}}'
    out = sanitize_scraped_text(raw)
    assert out == FALLBACK


def test_sql_dump_returns_fallback():
    raw = "SELECT * FROM victims; INSERT INTO leaks (id, name) VALUES (1, 'Acme'); UNION ALL SELECT password FROM users;"
    out = sanitize_scraped_text(raw)
    assert out == FALLBACK


def test_metadata_dump_returns_fallback():
    raw = "industrial company in Saudi Arabia... 2026/04/28 10:00:00 UTC +0 (views: 144663) Published ifmis.go.ke"
    out = sanitize_scraped_text(raw)
    assert out == FALLBACK


def test_minified_js_returns_fallback():
    minified = (
        "function(a,b){return a+b;}var c=eval(d);const e=>f;"
        "document.getElementById('x');window.localStorage;"
        "{};;;;function(){}};"
    )
    out = sanitize_scraped_text(minified)
    assert out == FALLBACK


def test_repeated_scraping_artifact_returns_fallback():
    raw = "Industrial company in Saudi Arabia. " * 40
    out = sanitize_scraped_text(raw)
    assert out == FALLBACK


def test_html_table_noise_returns_fallback():
    raw = "<table><tr><td>a</td><td>1</td></tr><tr><td>b</td><td>2</td></tr></table>"
    out = sanitize_scraped_text(raw)
    assert out == FALLBACK


def test_empty_input_returns_empty():
    assert sanitize_scraped_text("") == ""
    assert sanitize_scraped_text(None) == ""
    assert sanitize_scraped_text(b"") == ""


def test_truncation_at_word_boundary():
    long_text = " ".join(f"uniqueword{i}" for i in range(2000))
    out = sanitize_scraped_text(long_text)
    assert len(out) <= 1000
    assert not out.endswith(" ")  # ends cleanly at word boundary


def test_control_characters_removed():
    raw = "Hello\x00\x01World\n\n\nThere"
    out = sanitize_scraped_text(raw)
    assert "\x00" not in out and "\x01" not in out
    assert "\n" not in out
    assert "Hello World There" in out
