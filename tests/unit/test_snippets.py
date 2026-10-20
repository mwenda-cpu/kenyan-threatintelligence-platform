"""Tests for the snippet cleaner, the actionable-hit filter and the scanner.

The scanner used to store a raw window around a keyword, which captured leak
site menus ("v3 Open Bl4ckt0r v3 Open CL0P"), onion addresses and crypto
dumps. These tests pin the cleaned behaviour.
"""

from types import SimpleNamespace

from darkweb_scanner.scanner import KeywordConfig, Scanner
from darkweb_scanner.snippets import clean_snippet, is_actionable_hit

MENU_PAGE = (
    "Group Name Onion V. Link Arvin Club v3 Open Babuk v3 Open Black Basta v3 Open "
    "AlphaVM/BlackCat v3 Open BlackByte v3 Open Bl4ckt0r v3 Open CL0P v3 Open CONTI v3 "
    "Open Cuba v3 Open Everest v3 Open Grief v3 Open Hive v3 Open HolyGhost v3 Open "
    "Karakurt v3 Open BTC: 1FyCD8kp9ekiTTgdyhFtZRgzR1QCHV4i84 XMR: "
    "48FgeW4fUpyjPDGxJdHaA441F5c9szYtLSVWbNv8T3ZXe9ZN3iLUSSdASof2vDQqdbgRYom9aMeQMWPQkr3SPZUJE2uM8fc"
)

REAL_SENTENCE = (
    "LockBit claimed to have encrypted Kenya Revenue Authority systems on Monday, "
    "demanding a $4 million ransom in Bitcoin."
)


# ── clean_snippet ─────────────────────────────────────────────────────────────


def test_clean_snippet_strips_group_menus():
    cleaned = clean_snippet(MENU_PAGE, keep="cl0p", max_len=250)
    assert "Bl4ckt0r" not in cleaned
    assert "CL0P" not in cleaned
    assert "v3 Open" not in cleaned
    assert "1FyCD8kp9ekiTTgdyhFtZRgzR1QCHV4i84" not in cleaned


def test_clean_snippet_keeps_real_sentences():
    cleaned = clean_snippet(REAL_SENTENCE, keep="lockbit", max_len=250)
    assert "LockBit" in cleaned
    assert "Kenya Revenue Authority" in cleaned


def test_clean_snippet_is_capped():
    filler = " ".join(f"word{i}" for i in range(200))
    long_text = f"LockBit {filler}"
    cleaned = clean_snippet(long_text, keep="lockbit", max_len=250)
    assert len(cleaned) <= 254
    assert cleaned.endswith("...")


def test_clean_snippet_returns_empty_for_pure_noise():
    assert clean_snippet("...", keep="cl0p") == ""
    assert clean_snippet("", keep="cl0p") == ""


# ── is_actionable_hit ─────────────────────────────────────────────────────────


def _hit(**kw):
    base = {"keyword": "cl0p", "category": "ransomware", "url": "http://x.onion",
            "context": "LockBit hit"}
    base.update(kw)
    return SimpleNamespace(**base)


def test_actionable_accepts_threat_hits():
    assert is_actionable_hit(_hit()) is True
    assert is_actionable_hit(_hit(keyword="lockbit", category="custom",
                                  context="LockBit and Kenya")) is True


def test_actionable_rejects_junk_keywords():
    assert is_actionable_hit(_hit(keyword="category")) is False
    assert is_actionable_hit(_hit(keyword="severity")) is False
    assert is_actionable_hit(_hit(keyword="")) is False
    assert is_actionable_hit(_hit(keyword=None)) is False


def test_actionable_rejects_search_and_legal_pages():
    assert is_actionable_hit(_hit(url="http://ahmia.fi/search/?q=lockbit")) is False
    assert is_actionable_hit(_hit(url="http://x.onion/terms")) is False
    assert is_actionable_hit(_hit(url="http://x.onion/privacy")) is False


# ── scanner ───────────────────────────────────────────────────────────────────


def test_scanner_drops_navigation_noise_hits():
    scanner = Scanner(KeywordConfig(categories={"ransomware": ["cl0p", "lockbit"]}))
    hits = scanner.scan("http://x.onion/menu", MENU_PAGE)
    assert hits == [], "menu listings must not produce hits"


def test_scanner_keeps_readable_hits():
    scanner = Scanner(KeywordConfig(categories={"ransomware": ["lockbit"]}))
    hits = scanner.scan("http://x.onion/post", REAL_SENTENCE)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.keyword == "lockbit"
    assert "LockBit" in hit.context
    assert len(hit.context) <= 254
    assert "claimed to have encrypted" in hit.context


def test_scanner_snippet_is_short():
    body = ("Kenya " * 200) + "LockBit " + ("attack " * 200)
    scanner = Scanner(KeywordConfig(categories={"ransomware": ["lockbit"]}))
    hits = scanner.scan("http://x.onion/post", body)
    assert len(hits) == 1
    assert len(hits[0].context) <= 254
