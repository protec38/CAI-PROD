from app.time_utils import utcnow
from datetime import datetime, timedelta
from io import BytesIO
import re

import pytest

from app.extensions import db
from app.models import Utilisateur
from app.routes import _build_safe_redirect


@pytest.mark.parametrize("path,method", [
    ("/fiche/2", "get"), ("/fiche/2/pdf", "get"),
    ("/fiche/edit/2", "post"), ("/fiche/2/timeline/add", "post"),
    ("/evenement/2/export/pdf", "get"), ("/evenement/2/autorite_json", "get"),
    ("/evenement/2/autorite", "get"), ("/evenement/2/share/create", "post"),
    ("/evenement/2/news", "post"), ("/news/1/toggle", "post"), ("/news/1/delete", "post"),
])
def test_other_event_forbidden(client, path, method):
    assert getattr(client, method)(path).status_code == 403


@pytest.mark.parametrize("expired", [False, True])
def test_invalidated_account_loses_access(app, client, expired):
    with app.app_context():
        user = db.session.get(Utilisateur, 2)
        if expired:
            user.type_utilisateur = "provisoire"
            user.provisional_expires_at = utcnow() - timedelta(seconds=1)
        else:
            user.actif = False
        db.session.commit()
    assert client.get("/fiche/1").status_code == 302


def test_login_connects_flask_login(app):
    client = app.test_client()
    assert client.post("/", data={"username": "member", "password": "test-password-123"}).status_code == 302
    with client.session_transaction() as session:
        assert session["user_id"] == 2
        assert session["_user_id"] == "2"
        assert session.permanent
    assert client.get("/evenement/1/autorite_json").status_code == 200


def test_mutations_require_post_and_csrf(app, client):
    assert client.get("/admin/utilisateur/delete/1").status_code == 405
    assert client.get("/logout").status_code == 405
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/logout").status_code == 400
    assert client.post("/admin/utilisateur/delete/1").status_code == 400


@pytest.mark.parametrize("target", ["https://evil.test", "//evil.test", "/\\evil.test", "///evil.test", "http://localhost//evil.test", "/\r\nLocation: https://evil.test"])
def test_redirects(app, target):
    with app.test_request_context("/"):
        assert _build_safe_redirect(target, "main_bp.login") == "/"


def test_safe_redirect_keeps_query(app):
    with app.test_request_context("/"):
        assert _build_safe_redirect("/admin/logs?page=2", "main_bp.login") == "/admin/logs?page=2"


def test_health_has_one_route_and_no_https_redirect(app, client):
    from app import create_app
    app = create_app("prod", {"TESTING": True, "DEBUG": False,
                             "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                             "RATELIMIT_STORAGE_URI": "memory://", "FORCE_HTTPS": True})
    client = app.test_client()
    assert len([rule for rule in app.url_map.iter_rules() if rule.rule == "/healthz"]) == 1
    assert client.get("/healthz", base_url="http://localhost").status_code == 200
    assert client.get("/", base_url="http://localhost").status_code == 302
    assert client.get("/", base_url="http://localhost", headers={"X-Forwarded-Proto": "https"}).status_code == 302


@pytest.mark.parametrize("data", [
    {"evenement_id": "abc"},
    {"evenement_id": "1", "title": "x", "assigned_to_id": "abc"},
    {"evenement_id": "1", "title": "x", "assigned_to_id": "999"},
    {"evenement_id": "1", "title": "x", "status": "invalid"},
])
def test_ticket_validation(client, data):
    assert client.post("/tickets/create", data=data).status_code == 400


def test_news_icon_validation(client):
    assert client.post("/evenement/1/news", data={"message": "x", "icon": '<img src=x>'}).status_code == 400


def test_untrusted_forwarded_ip(app):
    from app.routes import _get_client_ip
    with app.test_request_context("/", headers={"X-Forwarded-For": "1.2.3.4"}, environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        assert _get_client_ip() == "127.0.0.1"


def test_templates_compile(app):
    for name in app.jinja_env.list_templates():
        app.jinja_env.get_template(name)


def test_export_formula_is_text(app, client):
    from openpyxl import load_workbook
    from app.models import FicheImplique
    with app.app_context():
        db.session.get(FicheImplique, 1).nom = '=HYPERLINK("https://evil.test")'
        db.session.commit()
    response = client.get("/evenement/1/export/csv")
    assert response.status_code == 200
    book = load_workbook(BytesIO(response.data))
    matching = [cell for row in book.active for cell in row if cell.value == '=HYPERLINK("https://evil.test")']
    assert matching and matching[0].data_type == "s"


def test_restore_rejects_invalid_payload_without_deletion(app, client):
    from app.models import Evenement
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["_user_id"] = "1"
    response = client.post("/admin/restore", data={"force": "on", "backup_file": (BytesIO(b'{}'), "invalid.json")})
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Evenement, 2) is not None


def test_invalid_backup_selection_does_not_export_everything(client):
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["_user_id"] = "1"
    assert client.get("/admin/backup?evenement_id=invalid").status_code == 400


def test_csrf_login_can_be_submitted(app):
    app.config["WTF_CSRF_ENABLED"] = True
    client = app.test_client()
    html = client.get("/").get_data(as_text=True)
    token = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    assert token
    assert client.post("/", data={"csrf_token": token[1], "username": "member", "password": "test-password-123"}).status_code == 302


@pytest.mark.parametrize("path", [
    "/evenement/1/dashboard", "/fiche/1", "/fiche/edit/1", "/fiche/1/pdf",
    "/evenement/1/export/pdf", "/evenement/1/tickets", "/evenement/1/autorite",
])
def test_authorized_pages_and_exports(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.data
