"""Regression tests for the dashboard PDF report (/api/report/pdf).

The report used to fail with
``ParagraphStyle() got multiple values for keyword argument 'parent'`` and to
abort on any '&' or '<' inside a crawled URL or snippet (ReportLab parses
Paragraph content as XML).
"""

from datetime import datetime

import pytest
from flask import Blueprint, Flask

from darkweb_scanner.dashboard import dashboard_routes as dr
from darkweb_scanner.dashboard.dashboard_routes import dashboard_bp
from darkweb_scanner.dashboard.storage_helper import close_db
from darkweb_scanner.storage import KeywordHitRecord, Storage


def _make_app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test-report-pdf-secret"
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
    db_url = f"sqlite:///{tmp_path / 'pdf.db'}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    storage = Storage(db_url)
    user_id = storage.create_user(
        "admin", password_hash="x", email="admin@example.com", is_admin=True
    )
    monkeypatch.setattr(dr, "get_storage", lambda: storage)
    return type("Env", (), {"storage": storage, "user_id": user_id})()


@pytest.fixture
def client(env):
    app = _make_app()
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user_id"] = env.user_id
            sess["username"] = "admin"
        yield c


def _add_hit(storage, url, context, keyword="eCitizen", category="government"):
    with storage.get_session() as session:
        session.add(KeywordHitRecord(
            session_id=None, url=url, keyword=keyword, category=category,
            context=context, found_at=datetime(2026, 1, 2, 3, 4, 5),
        ))
        session.commit()


def test_report_pdf_is_generated(client):
    res = client.get("/api/report/pdf")
    assert res.status_code == 200
    assert res.mimetype == "application/pdf"
    assert res.data.startswith(b"%PDF-")
    assert len(res.data) > 1000


def test_report_pdf_escapes_amps_and_angle_brackets(client, env):
    """A crawled URL with '&' and '<' must not break the Paragraph parser."""
    _add_hit(env.storage,
             url="http://example.test/path?a=1&b=2&c=<script>",
             context="leaked <password> & PIN for eCitizen")
    res = client.get("/api/report/pdf")
    assert res.status_code == 200
    assert res.data.startswith(b"%PDF-")


def test_report_pdf_with_charts(client, env):
    """Charts need hit data; the document must still build."""
    for i in range(3):
        _add_hit(env.storage, f"http://example.test/{i}", f"context {i}",
                 keyword="KRA" if i else "eCitizen")
    res = client.get("/api/report/pdf")
    assert res.status_code == 200
    assert res.data.startswith(b"%PDF-")


def test_report_pdf_session_scope(client, env):
    _add_hit(env.storage, "http://example.test/x", "ctx")
    res = client.get("/api/report/pdf?session_id=1")
    assert res.status_code == 200
    assert res.data.startswith(b"%PDF-")


def test_report_pdf_requires_login(env):
    app = _make_app()
    with app.test_client() as c:
        res = c.get("/api/report/pdf")
    assert res.status_code in (301, 302)
