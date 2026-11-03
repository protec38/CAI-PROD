"""Offline delivery, authorization and retry invariants."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from uuid import uuid4

import pytest

from app.extensions import db
from app.models import FicheImplique, TimelineEntry


def payload(**overrides):
    return {"client_uuid": str(uuid4()), "user_id": "2", "type_fiche": "humain",
            "nom": "Dupont", "prenom": "Alice", "date_naissance": "1990-01-31",
            "heure_arrivee_utc": "2026-10-30T12:15:00.000Z", **overrides}


def test_sync_renumbers_and_retry_does_not_duplicate(app, client):
    data = payload(numero="001-0001")
    with app.app_context():
        db.session.add(FicheImplique(numero="001-0001", utilisateur_id=1, evenement_id=1))
        db.session.commit()
    first = client.post("/api/evenement/1/fiches/sync", data=data)
    assert first.status_code == 200
    assert first.json["numero"] == "001-0002"
    assert first.json["synced"] is True
    # Simulate a lost acknowledgement, followed by another delivery.
    second = client.post("/api/evenement/1/fiches/sync", data=data)
    assert second.json == first.json
    with app.app_context():
        fiche = FicheImplique.query.filter_by(client_uuid=data["client_uuid"]).one()
        assert fiche.heure_arrivee == datetime(2026, 10, 30, 12, 15)
        assert TimelineEntry.query.filter_by(fiche_id=fiche.id, kind="create").count() == 1


def test_sync_uses_explicit_event_instead_of_session(client):
    with client.session_transaction() as session:
        session["evenement_id"] = 2
    assert client.post("/api/evenement/1/fiches/sync", data=payload()).status_code == 200
    assert client.post("/api/evenement/2/fiches/sync", data=payload()).status_code == 403


@pytest.mark.parametrize("overrides", [
    {"client_uuid": "not-a-uuid"}, {"date_naissance": ""},
    {"date_naissance": "2999-01-01"}, {"nom": "x" * 101},
    {"type_fiche": "animal", "animal_nom": ""},
    {"type_fiche": "animal", "animal_nom": "Chat", "animal_referent_id": "2"},
])
def test_sync_invalid_data_keeps_server_unchanged(app, client, overrides):
    with app.app_context():
        count = FicheImplique.query.count()
    response = client.post("/api/evenement/1/fiches/sync", data=payload(**overrides))
    assert response.status_code == 422
    assert response.json["error"]
    with app.app_context():
        assert FicheImplique.query.count() == count


def test_account_binding_and_authentication(app, client):
    assert client.post("/api/evenement/1/fiches/sync", data=payload(user_id="1")).status_code == 403
    assert app.test_client().get("/api/offline/session").status_code == 401
    assert app.test_client().post("/api/evenement/1/fiches/sync", data=payload()).status_code == 401
    session = client.get("/api/offline/session")
    assert session.json["user_id"] == 2
    assert session.json["csrf_token"]
    assert "no-store" in session.headers["Cache-Control"]


def test_sync_still_checks_permissions_on_retry(app, client):
    data = payload()
    assert client.post("/api/evenement/1/fiches/sync", data=data).status_code == 200
    with app.app_context():
        from app.models import Utilisateur
        user = db.session.get(Utilisateur, 2)
        user.evenements.clear()
        db.session.commit()
    assert client.post("/api/evenement/1/fiches/sync", data=data).status_code == 403


def test_sync_requires_csrf(app, client):
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/api/evenement/1/fiches/sync", data=payload()).status_code == 400
    csrf = client.get("/api/offline/session").json["csrf_token"]
    assert client.post("/api/evenement/1/fiches/sync", data=payload(),
                       headers={"X-CSRFToken": csrf}).status_code == 200


def test_animal_can_refer_to_synchronized_offline_human(client):
    human = payload()
    result = client.post("/api/evenement/1/fiches/sync", data=human)
    animal = payload(type_fiche="animal", animal_nom="Milo", animal_referent_id=human["client_uuid"])
    assert client.post("/api/evenement/1/fiches/sync", data=animal).status_code == 200
    fiches = client.get("/evenement/1/fiches_json").json["fiches"]
    assert fiches[-1]["referent"]["id"] == result.json["id"]


def test_online_and_offline_creation_share_numbering(client):
    assert client.post("/api/evenement/1/fiches/sync", data=payload()).json["numero"] == "001-0001"
    data = payload(evenement_id="1")
    assert client.post("/fiche/new", data=data).status_code == 302
    assert client.post("/api/evenement/1/fiches/sync", data=payload()).json["numero"] == "001-0003"


def test_public_shell_has_no_account_data(app, client):
    response = app.test_client().get("/hors-ligne")
    assert response.status_code == 200
    assert b"Example" not in response.data
    assert b'fiches-table-body' in response.data
    assert b'filter-statut' in response.data
    assert b'modal-bagage' in response.data
    assert b'modal-sortie' in response.data
    assert b'cai-offline-fiches' not in response.data
    assert b'"userId"' not in response.data
    assert "Set-Cookie" not in response.headers
    assert client.get("/hors-ligne").data == response.data
    form = app.test_client().get("/hors-ligne/fiche")
    assert form.status_code == 200
    assert b"cai-offline-form-page" in form.data
    assert b'name="csrf_token"' not in form.data
    assert b'"userId"' not in form.data
    assert "Set-Cookie" not in form.headers
    # The cached form must be identical regardless of the connected account.
    assert client.get("/hors-ligne/fiche").data == form.data
    worker = client.get("/service-worker.js")
    assert worker.status_code == 200
    assert worker.headers["Service-Worker-Allowed"] == "/"
    for path in ("/evenement/1/dashboard", "/fiche/new?evenement_id=1", "/fiche/1", "/fiche/edit/1"):
        assert client.get(path).status_code == 200


def test_concurrent_deliveries_have_unique_numbers(app):
    with app.app_context():
        if db.engine.dialect.name != "postgresql":
            pytest.skip("Concurrency validation uses PostgreSQL in CI.")

    def send(data):
        client = app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = 2
        response = client.post("/api/evenement/1/fiches/sync", data=data)
        assert response.status_code == 200
        return response.json

    repeated = payload()
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(send, [repeated, payload(), repeated, payload()]))
    assert results[0] == results[2]
    assert len({result["numero"] for result in results}) == 3


def test_legacy_database_receives_uuid_column_and_unique_index():
    from app import create_app, _ensure_database_schema
    legacy = create_app("dev", {"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
    with legacy.app_context():
        db.session.execute(db.text("CREATE TABLE fiche_implique (id INTEGER PRIMARY KEY, numero VARCHAR(20), est_animal BOOLEAN)"))
        db.session.commit()
        _ensure_database_schema(legacy)
        _ensure_database_schema(legacy)
        inspector = db.inspect(db.engine)
        assert "client_uuid" in {column["name"] for column in inspector.get_columns("fiche_implique")}
        assert any(index["unique"] and index["column_names"] == ["client_uuid"]
                   for index in inspector.get_indexes("fiche_implique"))
