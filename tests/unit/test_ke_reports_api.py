"""
Unit tests for the KE report routes: file download, PDF upload and the
``file_url`` links returned by the /api/ke-context/* endpoints.

The upload route shells out to scripts/load_ke_reports.py, so the upload test
needs a real (file backed) SQLite database — an in-memory one cannot be shared
with the subprocess — and the pdfplumber dependency.
"""

import io
import os
from types import SimpleNamespace

import pytest
from flask import Blueprint, Flask

from darkweb_scanner.dashboard import dashboard_routes as dr
from darkweb_scanner.dashboard.dashboard_routes import dashboard_bp
from darkweb_scanner.dashboard.storage_helper import close_db
from darkweb_scanner.storage import Storage

ADVISORY_TEXT = "Press Statement on Test Advisory for Ransomware Attacks in Kenya"


def make_pdf(text: str = ADVISORY_TEXT) -> bytes:
    """Build a minimal one-page PDF with a single line of text."""
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("latin-1")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
    )
    return bytes(out)


def _make_app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test-ke-reports-secret"
    app.teardown_appcontext(close_db)

    # Stub auth blueprint so require_login's redirect target resolves.
    auth_bp = Blueprint("auth", __name__)

    @auth_bp.route("/login")
    def login():
        return "login", 200

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    return app


@pytest.fixture
def env(tmp_path, monkeypatch):
    reports_dir = tmp_path / "ke_reports"
    reports_dir.mkdir()
    db_url = f"sqlite:///{tmp_path / 'ke.db'}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setattr(dr, "KE_REPORTS_DIR", reports_dir)
    monkeypatch.setattr(dr, "KE_REPORTS_INDEX", tmp_path / "ke_reports_index.json")
    monkeypatch.setattr(dr, "_KE_INDEX_CACHE", {"stamp": 0.0, "data": {}})

    storage = Storage(db_url)
    admin_id = storage.create_user(
        "admin", password_hash="x", email="admin@example.com", is_admin=True
    )
    user_id = storage.create_user(
        "user", password_hash="x", email="user@example.com", is_admin=False
    )
    # The routes use the module-level get_storage(); point it at the test
    # storage so nothing leaks from the cached singleton.
    monkeypatch.setattr(dr, "get_storage", lambda: storage)
    return SimpleNamespace(
        storage=storage,
        reports_dir=reports_dir,
        admin_id=admin_id,
        user_id=user_id,
        db_url=db_url,
    )


@pytest.fixture
def app(env):
    return _make_app()


def _login(client, user_id):
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["user_id"] = user_id
        sess["username"] = "tester"


def _upload(client, filename="Test Advisory.pdf", data=b"%PDF-1.4 fake", source="ca", **extra):
    payload = {"file": (io.BytesIO(data), filename)}
    if source is not None:
        payload["source"] = source
    payload.update(extra)
    return client.post("/api/reports/upload", data=payload, content_type="multipart/form-data")


# ── Download ─────────────────────────────────────────────────────────────────


def test_download_serves_pdf(app, env):
    (env.reports_dir / "ca_report.pdf").write_bytes(make_pdf())
    with app.test_client() as client:
        _login(client, env.user_id)
        res = client.get("/api/reports/download/ca_report.pdf")
    assert res.status_code == 200
    assert res.mimetype == "application/pdf"


def test_download_blocks_traversal(app, env):
    secret = env.reports_dir.parent / "secret.txt"
    secret.write_text("top secret")
    with app.test_client() as client:
        _login(client, env.user_id)
        for path in (
            "/api/reports/download/../secret.txt",
            "/api/reports/download/..%2Fsecret.txt",
            "/api/reports/download/....//secret.txt",
        ):
            res = client.get(path)
            assert res.status_code == 404, path
            assert b"top secret" not in res.data


def test_download_requires_login(app, env):
    with app.test_client() as client:
        res = client.get("/api/reports/download/ca_report.pdf")
    assert res.status_code in (301, 302)


# ── Upload ───────────────────────────────────────────────────────────────────


def test_upload_requires_admin(app, env):
    with app.test_client() as client:
        _login(client, env.user_id)
        res = _upload(client)
    assert res.status_code == 403
    assert not list(env.reports_dir.glob("*.pdf"))


def test_upload_requires_login(app, env):
    with app.test_client() as client:
        res = _upload(client)
    assert res.status_code == 401
    assert not list(env.reports_dir.glob("*"))


def test_upload_rejects_non_pdf(app, env):
    with app.test_client() as client:
        _login(client, env.admin_id)
        res = _upload(client, filename="notes.txt", data=b"hello")
    assert res.status_code == 400
    assert not list(env.reports_dir.glob("*"))


def test_upload_rejects_fake_pdf(app, env):
    with app.test_client() as client:
        _login(client, env.admin_id)
        res = _upload(client, filename="fake.pdf", data=b"this is not a pdf")
    assert res.status_code == 400
    assert not list(env.reports_dir.glob("*"))


def test_upload_requires_a_known_source(app, env):
    with app.test_client() as client:
        _login(client, env.admin_id)
        res = _upload(client, source="something-else")
    assert res.status_code == 400
    assert not list(env.reports_dir.glob("*"))


def test_upload_sanitises_filename(app, env):
    with app.test_client() as client:
        _login(client, env.admin_id)
        res = _upload(client, filename="../../evil.pdf", data=b"%PDF-1.4 evil")
    assert res.status_code == 200
    saved = list(env.reports_dir.glob("*.pdf"))
    assert len(saved) == 1
    assert saved[0].parent == env.reports_dir
    assert not (env.reports_dir.parent / "evil.pdf").exists()


def test_upload_parses_and_links_the_report(app, env):
    pytest.importorskip("pdfplumber")
    with app.test_client() as client:
        _login(client, env.admin_id)
        res = _upload(client, filename="Test Advisory.pdf", data=make_pdf(), source="ca")
        assert res.status_code == 200
        body = res.get_json()
        assert body["ok"] is True
        assert body["file"] == "ca_Test_Advisory.pdf"
        assert (env.reports_dir / "ca_Test_Advisory.pdf").is_file()

        listing = client.get("/api/ke-context/ca-advisories").get_json()
        advisories = listing["data"]
        assert advisories, "the uploaded advisory should be stored"
        advisory = advisories[0]
        assert advisory["file_url"] == "/api/reports/download/ca_Test_Advisory.pdf"

        # The link actually serves the PDF.
        res = client.get(advisory["file_url"])
        assert res.status_code == 200
        assert res.mimetype == "application/pdf"


# ── Title → file matching ────────────────────────────────────────────────────


def test_file_url_matches_the_right_pdf(app, env):
    (env.reports_dir / "ca_Press_Statement_on_Emotet_Malware_pdf.pdf").write_bytes(make_pdf())
    (env.reports_dir / "ca_Press_Statement_on_Online_Shopping_Fraud_pdf.pdf").write_bytes(
        make_pdf()
    )
    url = dr._ke_ca_file_url("Press Statement on Emotet Malware")
    assert url == "/api/reports/download/ca_Press_Statement_on_Emotet_Malware_pdf.pdf"


def test_file_url_ignores_other_sources(app, env):
    (env.reports_dir / "ke_cirt_2024_25_Q2_Cyber_Security_Report_pdf.pdf").write_bytes(make_pdf())
    assert dr._ke_cbk_file_url("2024") is None


def test_ke_report_kind_aliases():
    assert dr._ke_report_kind("CA") == "ca"
    assert dr._ke_report_kind("ke-cirt") == "ke_cirt"
    assert dr._ke_report_kind("CBK") == "cbk"
    assert dr._ke_report_kind("nonsense") is None


def test_repo_root_finds_the_loader_script():
    root = dr._ke_repo_root()
    assert (root / "scripts" / "load_ke_reports.py").is_file()


def test_env_has_data_dir_default():
    assert os.getenv("DATA_DIR") is None or isinstance(os.getenv("DATA_DIR"), str)
