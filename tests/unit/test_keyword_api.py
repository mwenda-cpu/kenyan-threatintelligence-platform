"""Tests for the DB-backed keyword store and the /api/keywords endpoints.

The keywords table is the source of truth; ``config/keywords.yaml`` is only a
seed that is imported the first time the table is empty.
"""

import pytest
from flask import Blueprint, Flask

from darkweb_scanner.dashboard import dashboard_routes as dr
from darkweb_scanner.dashboard.dashboard_routes import dashboard_bp
from darkweb_scanner.dashboard.storage_helper import close_db
from darkweb_scanner.keywords_db import parse_seed_yaml, seed_if_empty
from darkweb_scanner.storage import Storage


def _make_app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test-keyword-api-secret"
    app.teardown_appcontext(close_db)

    auth_bp = Blueprint("auth", __name__)

    @auth_bp.route("/login")
    def login():
        return "login", 200

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    return app


@pytest.fixture
def env(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'kw.db'}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    storage = Storage(db_url)
    admin_id = storage.create_user(
        "admin", password_hash="x", email="admin@example.com", is_admin=True
    )
    monkeypatch.setattr(dr, "get_storage", lambda: storage)
    # The YAML is only a seed: point it at an empty file so the tests are
    # independent of the shipped config.
    seed = tmp_path / "keywords.yaml"
    seed.write_text("keywords:\n  eCitizen: {severity: critical, category: government}\n",
                    encoding="utf-8")
    monkeypatch.setattr(dr, "KEYWORDS_DEFAULT", seed)
    return type("Env", (), {"storage": storage, "admin_id": admin_id, "seed": seed})()


@pytest.fixture
def client(env):
    app = _make_app()
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user_id"] = env.admin_id
            sess["username"] = "admin"
        yield c


# ── Seed parsing ─────────────────────────────────────────────────────────────


def test_parse_seed_yaml_keyword_first_format(tmp_path):
    path = tmp_path / "kw.yaml"
    path.write_text(
        "keywords:\n  eCitizen: {severity: critical, category: government}\n"
        "  KRA: {severity: high, category: identifier}\n",
        encoding="utf-8",
    )
    rows = parse_seed_yaml(path)
    assert {r["keyword"] for r in rows} == {"eCitizen", "KRA"}
    ecitizen = next(r for r in rows if r["keyword"] == "eCitizen")
    assert ecitizen["category"] == "government"
    assert ecitizen["severity"] == "critical"


def test_parse_seed_yaml_legacy_category_format(tmp_path):
    path = tmp_path / "kw.yaml"
    path.write_text("keywords:\n  government:\n    - eCitizen\n    - KRA\n", encoding="utf-8")
    rows = parse_seed_yaml(path)
    assert {r["keyword"] for r in rows} == {"eCitizen", "KRA"}
    assert all(r["category"] == "government" for r in rows)


def test_seed_if_empty_is_idempotent(env):
    assert seed_if_empty(env.storage, env.seed) == 1
    assert seed_if_empty(env.storage, env.seed) == 0
    assert env.storage.keyword_count() == 1


# ── Storage ──────────────────────────────────────────────────────────────────


def test_add_keyword_is_case_insensitive(env):
    assert env.storage.add_keyword("KRA", "identifier", "high") is True
    assert env.storage.add_keyword("kra", "identifier", "high") is False
    assert env.storage.keyword_count() == 1


def test_keyword_categories_shape(env):
    env.storage.add_keyword("eCitizen", "government", "critical")
    env.storage.add_keyword("KRA", "identifier", "high")
    cats = env.storage.keyword_categories()
    assert cats == {"government": ["eCitizen"], "identifier": ["KRA"]}


def test_delete_keyword(env):
    env.storage.add_keyword("KRA", "identifier", "high")
    assert env.storage.delete_keyword("kra") is True
    assert env.storage.keyword_count() == 0
    assert env.storage.delete_keyword("kra") is False


# ── API ──────────────────────────────────────────────────────────────────────


def test_get_keywords_returns_a_json_array(client):
    res = client.get("/api/keywords")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert data[0]["keyword"] == "eCitizen"
    assert data[0]["category"] == "government"


def test_add_and_remove_keyword_through_the_api(client):
    res = client.post("/api/keywords", json={"keyword": "credential dump",
                                             "category": "credentials"})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["created"] is True

    rows = client.get("/api/keywords").get_json()
    assert any(r["keyword"] == "credential dump" for r in rows)

    res = client.delete("/api/keywords", json={"keyword": "credential dump",
                                               "category": "credentials"})
    assert res.status_code == 200
    assert res.get_json()["removed"] is True
    rows = client.get("/api/keywords").get_json()
    assert not any(r["keyword"] == "credential dump" for r in rows)


def test_add_keyword_requires_a_keyword(client):
    res = client.post("/api/keywords", json={"category": "custom"})
    assert res.status_code == 400


def test_bulk_add_keywords(client):
    res = client.post("/api/keywords/bulk", json={"keywords": [
        {"keyword": "alpha", "category": "custom"},
        {"keyword": "beta", "category": "custom"},
    ]})
    assert res.status_code == 200
    assert res.get_json()["added"] == 2
    assert len(client.get("/api/keywords").get_json()) >= 3


def test_export_keywords_is_csv(client):
    res = client.get("/api/keywords/export")
    assert res.status_code == 200
    assert "text/csv" in res.headers["Content-Type"]
    body = res.get_data(as_text=True)
    assert "keyword,category,severity" in body
    assert "eCitizen" in body
