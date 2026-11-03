import importlib

from click.testing import CliRunner

from app.extensions import db
from app.models import Utilisateur


def management(app, monkeypatch):
    monkeypatch.setenv("FLASK_CONFIG", "dev")
    module = importlib.import_module("manage")
    monkeypatch.setattr(module, "app", app)
    return module


def test_bootstrap_requires_explicit_password(app, monkeypatch):
    module = management(app, monkeypatch)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    with app.app_context():
        db.session.get(Utilisateur, 1).nom_utilisateur = "existing-admin"
        db.session.commit()
    result = CliRunner().invoke(module.cli, ["init-db"])
    assert result.exit_code != 0
    assert "ADMIN_PASSWORD" in result.output
    monkeypatch.setenv("ADMIN_PASSWORD", "a-secure-test-password")
    result = CliRunner().invoke(module.cli, ["init-db"])
    assert result.exit_code == 0, result.output
    with app.app_context():
        assert Utilisateur.query.filter_by(nom_utilisateur="admin").one().check_password("a-secure-test-password")


def test_bootstrap_replaces_insecure_default(app, monkeypatch):
    module = management(app, monkeypatch)
    with app.app_context():
        db.session.get(Utilisateur, 1).set_password("admin")
        db.session.commit()
    monkeypatch.setenv("ADMIN_PASSWORD", "a-secure-test-password")
    result = CliRunner().invoke(module.cli, ["init-db"])
    assert result.exit_code == 0, result.output
    with app.app_context():
        assert db.session.get(Utilisateur, 1).check_password("a-secure-test-password")
