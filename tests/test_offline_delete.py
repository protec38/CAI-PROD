"""Offline detail snapshots and deletion receipts, including lost replies."""
from uuid import uuid4
import json

import pytest

from app.extensions import db
from app.models import Bagage, FicheImplique, OfflineDeletion, TimelineEntry, Utilisateur

URL = "/api/evenement/1/fiches/actions/sync"


def deletion(client, **changes):
    fiche = client.get("/evenement/1/fiches_json").json["fiches"][0]
    return {"operation_uuid": str(uuid4()), "user_id": "2", "kind": "delete",
            "fiche_id": str(fiche["id"]), "identity_token": fiche["identity_token"], "numero": fiche["numero"], **changes}


def test_detail_snapshot_has_full_information_and_history(app, client):
    with app.app_context():
        fiche = db.session.get(FicheImplique, 1)
        fiche.telephone = "0612345678"
        fiche.adresse = "Adresse complète"
        fiche.autres_informations = "Notes privées"
        db.session.add(TimelineEntry(fiche_id=1, user_id=2, content="Suivi", kind="comment"))
        db.session.commit()
    snapshot = client.get("/evenement/1/fiches_json?details=1")
    assert snapshot.status_code == 200
    fiche = snapshot.json["fiches"][0]
    assert fiche["telephone"] == "0612345678"
    assert fiche["adresse"] == "Adresse complète"
    assert fiche["autres_informations"] == "Notes privées"
    assert fiche["timeline"][0]["content"] == "Suivi"
    assert client.get("/evenement/2/fiches_json?details=1").status_code == 403


def test_detail_shell_is_generic_and_has_no_session_data(app, client):
    public = app.test_client().get("/hors-ligne/fiche/detail")
    assert public.status_code == 200
    assert b"cai-detail-content" in public.data
    assert b"Example" not in public.data
    assert b'"userId"' not in public.data
    assert "Set-Cookie" not in public.headers
    assert client.get("/hors-ligne/fiche/detail").data == public.data


def test_delete_retry_survives_removal_of_fiche_and_children(app, client):
    with app.app_context():
        db.session.add_all([Bagage(numero="BAG", fiche_id=1, evenement_id=1),
                            TimelineEntry(fiche_id=1, user_id=2, content="History", kind="comment")])
        db.session.commit()
    data = deletion(client)
    first = client.post(URL, data=data)
    assert first.status_code == 200 and first.json["deleted"] is True
    assert client.post(URL, data=data).json == first.json
    with app.app_context():
        assert db.session.get(FicheImplique, 1) is None
        assert Bagage.query.count() == TimelineEntry.query.count() == 0
        assert OfflineDeletion.query.count() == 1
    assert data["operation_uuid"] in client.get("/evenement/1/fiches_json").json["applied_operations"]


def test_id_reuse_never_deletes_a_new_fiche(app, client):
    data = deletion(client)
    assert client.post(URL, data=data).status_code == 200
    with app.app_context():
        db.session.add(FicheImplique(id=1, numero="REPLACEMENT", evenement_id=1, utilisateur_id=1))
        db.session.commit()
    assert client.post(URL, data=data).status_code == 200  # Old receipt, no second deletion.
    assert client.post(URL, data={**data, "operation_uuid": str(uuid4())}).status_code == 409
    with app.app_context():
        assert db.session.get(FicheImplique, 1).numero == "REPLACEMENT"


def test_retry_of_deleted_creation_does_not_resurrect_fiche(app, client):
    data = {"client_uuid": str(uuid4()), "user_id": "2", "type_fiche": "humain",
            "nom": "Deleted", "prenom": "Local", "date_naissance": "1990-01-31"}
    created = client.post("/api/evenement/1/fiches/sync", data=data).json
    assert client.post(f"/fiche/delete/{created['id']}").status_code == 302
    retry = client.post("/api/evenement/1/fiches/sync", data=data)
    assert retry.status_code == 200 and retry.json["deleted"] is True
    with app.app_context():
        assert FicheImplique.query.filter_by(client_uuid=data["client_uuid"]).count() == 0


def test_deletion_permissions_and_csrf(app, client):
    data = deletion(client)
    assert app.test_client().post(URL, data=data).status_code == 401
    assert client.post(URL, data={**data, "user_id": "1"}).status_code == 403
    assert client.post(URL, data={**data, "fiche_id": "2"}).status_code == 403
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post(URL, data=data).status_code == 400
    app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        user = db.session.get(Utilisateur, 2)
        user.role = "technicien"
        db.session.commit()
    assert client.post(URL, data=data).status_code == 403
    with app.app_context():
        assert db.session.get(FicheImplique, 1) is not None


def test_receipt_rejects_changed_request_and_revoked_access(app, client):
    data = deletion(client)
    assert client.post(URL, data=data).status_code == 200
    assert client.post(URL, data={**data, "identity_token": "changed"}).status_code == 409
    with app.app_context():
        user = db.session.get(Utilisateur, 2)
        user.evenements.clear()
        db.session.commit()
    assert client.post(URL, data=data).status_code == 403


def test_deletion_receipt_survives_backup_restore(app, client):
    from app.backup_utils import backup_to_bytesio, bulk_restore
    data = deletion(client)
    assert client.post(URL, data=data).status_code == 200
    with app.app_context():
        bulk_restore(json.loads(backup_to_bytesio().getvalue()))
    assert client.post(URL, data=data).status_code == 200


def test_concurrent_deletion_retries(app):
    from concurrent.futures import ThreadPoolExecutor
    with app.app_context():
        if db.engine.dialect.name != "postgresql":
            pytest.skip("Concurrency validation uses PostgreSQL in CI.")

    def logged_client():
        client = app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = 2
        return client

    data = deletion(logged_client())

    def send(_):
        result = logged_client().post(URL, data=data)
        assert result.status_code == 200
        return result.json

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(send, range(4)))
    assert all(result == results[0] for result in results)
